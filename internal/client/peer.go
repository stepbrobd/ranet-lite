package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
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
	name := fmt.Sprintf("%s/%s@%s", p.Organization, p.CommonName, local.SerialNumber)
	// A node the registry does not name is not dialed at all. The check runs
	// whether or not the peer pins a serial number: without it a peer that
	// pins none enters the retry loop and logs the same lookup failure every
	// reconnect delay for the life of the process, which is what a
	// decommissioned entry left in peers: does.
	_, node, ok := reg.FindNode(p.Organization, p.CommonName)
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
	if p.SerialNumber != "" {
		ep, ok := node.FindEndpoint(p.SerialNumber)
		if !ok {
			log.Printf("peer %s: endpoint serial %q not found", name, p.SerialNumber)
			return
		}
		if ep.AddressFamily != local.AddressFamily {
			log.Printf("peer %s: endpoint serial %q is %s, not %s", name, p.SerialNumber, ep.AddressFamily, local.AddressFamily)
			return
		}
	} else if !slices.ContainsFunc(node.Endpoints, func(ep registry.Endpoint) bool {
		return ep.AddressFamily == local.AddressFamily
	}) {
		slog.Debug("peer has no endpoint in this address family", "peer", name, "family", local.AddressFamily)
		return
	}
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
		if _, _, ok := c.registry().FindNode(p.Organization, p.CommonName); !ok {
			log.Printf("peer %s: no longer in the registry, giving up", name)
			return
		}
		switch err := c.connectPeer(ctx, local, p, name); {
		case err == nil:
		case errors.Is(err, errSessionEstablished):
			// Not a failure and not worth a log line every reconnect delay.
			// The loop keeps running so this dialer takes over the moment the
			// peer's session ends.
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

// resolveEndpoint picks which of a node's endpoints to dial: the
// config-specified serial if given, otherwise the first one whose address
// actually resolves (a node commonly has endpoints for address families or
// links that aren't currently usable, e.g. address: null).
func resolveEndpoint(ctx context.Context, node registry.Node, serial, family string) (registry.Endpoint, error) {
	if serial != "" {
		ep, ok := node.FindEndpoint(serial)
		if !ok {
			return registry.Endpoint{}, fmt.Errorf("no endpoint with serial %q", serial)
		}
		if ep.AddressFamily != family {
			return registry.Endpoint{}, fmt.Errorf("endpoint %q is %s, want %s", serial, ep.AddressFamily, family)
		}
		return ep, nil
	}
	for _, ep := range node.Endpoints {
		if ep.AddressFamily == family {
			if _, err := ep.ResolveRemote(ctx); err == nil {
				return ep, nil
			}
		}
	}
	return registry.Endpoint{}, fmt.Errorf("no endpoint currently resolves to an address")
}

// connectPeer runs one IKE session against a peer end to end: handshake,
// ESP setup, mesh/babel registration, and servicing the connection until
// it dies (network failure, peer restart, DPD timeout). Returning means
// the connection is gone; runPeer decides whether/when to retry.
func (c *Client) connectPeer(ctx context.Context, local config.Endpoint, p config.Peer, name string) error {
	cfg, reg := c.config(), c.registry()
	org, node, ok := reg.FindNode(p.Organization, p.CommonName)
	if !ok {
		return fmt.Errorf("node %q not found in organization %q", p.CommonName, p.Organization)
	}
	ep, err := resolveEndpoint(ctx, node, p.SerialNumber, local.AddressFamily)
	if err != nil {
		return err
	}
	remoteIP, err := ep.ResolveRemote(ctx)
	if err != nil {
		return err
	}
	remotePub, err := org.ParsePublicKey()
	if err != nil {
		return err
	}
	sessionName := fmt.Sprintf("%s/%s/%s@%s", p.Organization, p.CommonName, ep.SerialNumber, local.SerialNumber)
	if c.sessions.holds(sessionName) {
		// The peer already reached us over this same pair of endpoints. Dialing
		// anyway opens a second SA that one end or the other has to resolve
		// away, and doing that on every reconnect delay is how two nodes spend
		// a full mesh replacing each other's sessions.
		return errSessionEstablished
	}
	log.Printf("peer %s: dialing %s:%d", sessionName, remoteIP, ep.Port)

	ikeCfg := ike.PeerConfig{
		Organization:       cfg.Organization,
		LocalCommonName:    cfg.CommonName,
		LocalSerial:        local.SerialNumber,
		LocalPrivateKey:    c.privateKey,
		RemoteCommonName:   node.CommonName,
		RemoteOrganization: p.Organization,
		RemoteSerial:       ep.SerialNumber,
		RemotePublicKey:    remotePub,
		RemoteAddr:         remoteIP,
		RemotePort:         int(ep.Port),
		Hub:                c.hub,
		ChildRekeyInterval: cfg.ChildRekeyIntervalValue(),
		IKERekeyInterval:   cfg.IKERekeyIntervalValue(),
		RekeyMargin:        cfg.RekeyMarginValue(),
		RekeyJitter:        cfg.RekeyJitterValue(),
		RekeyRetryInitial:  cfg.RekeyRetryInitialValue(),
		RekeyRetryMax:      cfg.RekeyRetryMaxValue(),
	}
	sess, err := ike.InitiateContext(ctx, ikeCfg)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	localIdentity := ike.Identity{Organization: cfg.Organization, CommonName: cfg.CommonName, SerialNumber: local.SerialNumber}
	remoteIdentity := ike.Identity{Organization: p.Organization, CommonName: node.CommonName, SerialNumber: ep.SerialNumber}
	return c.serveSession(ctx, sess, name, sessionName, localIdentity, remoteIdentity, remoteIdentity)
}

// errSessionEstablished means this peer is already reachable over a session
// the other end opened, so there is nothing to dial and nothing wrong.
var errSessionEstablished = errors.New("a session for this endpoint pair is already established")
