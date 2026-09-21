package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/registry"
)

const defaultReconnectDelay = 10 * time.Second

// reconnectDelay is how long a dialer waits between attempts. A test that has
// to see the loop come round again overrides it; zero means the default.
func (c *Client) reconnectDelay() time.Duration {
	if c.dialRetry > 0 {
		return c.dialRetry
	}
	return defaultReconnectDelay
}

// runPeer maintains one peer connection for the client's lifetime,
// reconnecting on any failure (network blip, peer restart, etc.) rather
// than requiring a manual restart.
func (c *Client) runPeer(ctx context.Context, local config.Endpoint, p config.Peer) {
	reg := c.registry()
	name := fmt.Sprintf("%s/%s@%s", p.Org, p.Name, local.Serial)
	// A node the registry does not name is not dialed at all. The check runs
	// whether or not the peer pins a serial number: without it a peer that
	// pins none enters the retry loop and logs the same lookup failure every
	// reconnect delay for the life of the process, which a decommissioned
	// entry left in peers: does.
	_, node, ok := reg.FindNode(p.Org, p.Name)
	if !ok {
		log.Printf("peer %s: node not found", name)
		return
	}
	// And a node with no endpoint in this local endpoint's address family is
	// not dialable from it, whether or not the peer pins a serial number.
	// syncPeers starts one dialer per (local endpoint, peer) pair while the
	// startup check only asks whether some endpoint of the node matches some
	// local family, so a dual-stack node with single-stack peers is the
	// ordinary configuration: without this the v4 dialer for a v6-only peer
	// logs the same resolution failure every reconnect delay for the life of
	// the process.
	if p.Serial != "" {
		ep, ok := node.FindEndpoint(p.Serial)
		if !ok {
			log.Printf("peer %s: endpoint serial %q not found", name, p.Serial)
			return
		}
		if ep.AddressFamily != local.Family {
			log.Printf("peer %s: endpoint serial %q is %s, not %s", name, p.Serial, ep.AddressFamily, local.Family)
			return
		}
		if !ep.Dialable() {
			log.Printf("peer %s: endpoint serial %q carries no address", name, p.Serial)
			return
		}
	} else if !slices.ContainsFunc(node.Endpoints, func(ep registry.Endpoint) bool {
		return ep.AddressFamily == local.Family && ep.Dialable()
	}) {
		slog.Debug("peer has no endpoint carrying an address in this address family", "peer", name, "family", local.Family)
		return
	}
	var failure repeatedFailure
	for {
		if ctx.Err() != nil {
			return
		}
		// Re-checked every pass, not only before the loop: a node removed from
		// the registry while this dialer is running hits exactly the case the
		// check above exists to prevent, and logs the same lookup failure
		// every reconnect delay for the life of the process. Leaving the loop
		// also makes Reload's "so nothing will dial it" true, which it was not
		// while syncPeers kept the dialer alive. forgetDialer drops the map
		// entry, so the next reload starts a new one if the node comes back.
		if _, _, ok := c.registry().FindNode(p.Org, p.Name); !ok {
			log.Printf("peer %s: no longer in the registry, giving up", name)
			return
		}
		err := c.connectPeer(ctx, local, p, name)
		if ctx.Err() != nil || c.stopping() {
			return
		}
		switch {
		case err == nil:
		case errors.Is(err, errSessionEstablished):
			// Not a failure and not worth a log line every reconnect delay.
			// The loop keeps running so this dialer takes over the moment the
			// peer's session ends.
		case failure.alreadySaid(err):
			slog.Debug("peer dial failed again", "peer", name, "err", err)
		default:
			log.Printf("peer %s: %v, reconnecting in %s", name, err, c.reconnectDelay())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(c.reconnectDelay()):
		}
	}
}

// repeatedFailure spaces one dialer's repeats. A peer it cannot reach fails on
// every attempt, and the ones it cannot refuse outright are the names, since
// only a resolver can answer for one: 250 lines in 93 seconds from 25 of them,
// measured. A changed reason is said as soon as the floor allows, and the
// floor is there because a reason is not a category, a resolver failure
// carrying the ephemeral source port of its own query.
type repeatedFailure struct {
	reason string
	said   time.Time
}

const (
	dialFailureInterval = 10 * time.Minute
	dialFailureFloor    = time.Minute
)

// alreadySaid reports whether an equivalent failure has been said recently
// enough to keep this one at debug, and records the one it says. What it
// records is the reason last said out loud, not the reason last seen, so a
// reason that changed under the floor is said when the floor passes rather
// than waiting out the interval against itself.
func (f *repeatedFailure) alreadySaid(err error) bool {
	reason, since := err.Error(), time.Since(f.said)
	if since >= dialFailureInterval || (reason != f.reason && since >= dialFailureFloor) {
		f.reason, f.said = reason, time.Now()
		return false
	}
	return true
}

// resolveEndpoint picks which of a node's endpoints to dial and the address it
// resolved to: the config-specified serial if given, otherwise the first one
// whose address actually resolves (a node commonly has endpoints for address
// families or links that aren't currently usable, e.g. address: null). The
// address is returned rather than looked up again by the caller, because a
// name costs a resolver round trip and an unpinned dial made two of them.
func resolveEndpoint(ctx context.Context, node registry.Node, serial, family string) (registry.Endpoint, net.IP, error) {
	if serial != "" {
		ep, ok := node.FindEndpoint(serial)
		if !ok {
			return registry.Endpoint{}, nil, fmt.Errorf("no endpoint with serial %q", serial)
		}
		if ep.AddressFamily != family {
			return registry.Endpoint{}, nil, fmt.Errorf("endpoint %q is %s, want %s", serial, ep.AddressFamily, family)
		}
		address, err := ep.ResolveRemote(ctx)
		if err != nil {
			return registry.Endpoint{}, nil, err
		}
		return ep, address, nil
	}
	for _, ep := range node.Endpoints {
		if ep.AddressFamily != family || !ep.Dialable() {
			continue
		}
		if address, err := ep.ResolveRemote(ctx); err == nil {
			return ep, address, nil
		}
	}
	return registry.Endpoint{}, nil, fmt.Errorf("no endpoint currently resolves to an address")
}

// connectPeer runs one IKE session against a peer end to end: handshake,
// ESP setup, mesh/babel registration, and servicing the connection until
// it dies (network failure, peer restart, DPD timeout). Returning means
// the connection is gone; runPeer decides whether/when to retry.
func (c *Client) connectPeer(ctx context.Context, local config.Endpoint, p config.Peer, name string) error {
	cfg, reg := c.config(), c.registry()
	crypto := cfg.Crypto()
	org, node, ok := reg.FindNode(p.Org, p.Name)
	if !ok {
		return fmt.Errorf("node %q not found in organization %q", p.Name, p.Org)
	}
	ep, remoteIP, err := resolveEndpoint(ctx, node, p.Serial, local.Family)
	if err != nil {
		return err
	}
	remotePub, err := org.ParsePublicKey()
	if err != nil {
		return err
	}
	sessionName := fmt.Sprintf("%s/%s/%s@%s", p.Org, p.Name, ep.SerialNumber, local.Serial)
	if c.sessions.holds(sessionName) {
		// The peer already reached us over this same pair of endpoints. Dialing
		// anyway opens a second SA that one end or the other has to resolve
		// away, and doing that on every reconnect delay is how two nodes spend
		// a full mesh replacing each other's sessions.
		return errSessionEstablished
	}
	log.Printf("peer %s: dialing %s:%d", sessionName, remoteIP, ep.Port)

	ikeCfg := ike.PeerConfig{
		Organization:       cfg.Node.Org,
		LocalCommonName:    cfg.Node.Name,
		LocalSerial:        local.Serial,
		LocalPrivateKey:    c.privateKey,
		RemoteCommonName:   node.CommonName,
		RemoteOrganization: p.Org,
		RemoteSerial:       ep.SerialNumber,
		RemotePublicKey:    remotePub,
		RemoteAddr:         remoteIP,
		RemotePort:         int(ep.Port),
		Hub:                c.hub,
		ChildRekeyInterval: crypto.ChildInterval(),
		IKERekeyInterval:   crypto.IKEInterval(),
		RekeyMargin:        crypto.Margin(),
		RekeyJitter:        crypto.Jitter(),
		RekeyRetryInitial:  crypto.RetryFirst(),
		RekeyRetryMax:      crypto.RetryMax(),
	}
	sess, err := ike.InitiateContext(ctx, ikeCfg)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	localIdentity := ike.Identity{Organization: cfg.Node.Org, CommonName: cfg.Node.Name, SerialNumber: local.Serial}
	remoteIdentity := ike.Identity{Organization: p.Org, CommonName: node.CommonName, SerialNumber: ep.SerialNumber}
	return c.serveSession(ctx, sess, name, sessionName, localIdentity, remoteIdentity, remoteIdentity)
}

// errSessionEstablished means this peer is already reachable over a session
// the other end opened, so there is nothing to dial and nothing wrong.
var errSessionEstablished = errors.New("a session for this endpoint pair is already established")
