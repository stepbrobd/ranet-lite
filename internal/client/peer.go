package client

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/registry"
)

const reconnectDelay = 10 * time.Second

// runPeer maintains one peer connection for the client's lifetime,
// reconnecting on any failure (network blip, peer restart, etc.) rather
// than requiring a manual restart.
func (c *Client) runPeer(ctx context.Context, local config.Endpoint, p config.Peer) {
	reg := c.registry
	name := fmt.Sprintf("%s/%s@%s", p.Organization, p.CommonName, local.SerialNumber)
	if p.SerialNumber != "" {
		_, node, ok := reg.FindNode(p.Organization, p.CommonName)
		if !ok {
			log.Printf("peer %s: node not found", name)
			return
		}
		ep, ok := node.FindEndpoint(p.SerialNumber)
		if !ok {
			log.Printf("peer %s: endpoint serial %q not found", name, p.SerialNumber)
			return
		}
		if ep.AddressFamily != local.AddressFamily {
			return
		}
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := c.connectPeer(ctx, local, p, name); err != nil {
			log.Printf("peer %s: %v; reconnecting in %s", name, err, reconnectDelay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(reconnectDelay):
		}
	}
}

// resolveEndpoint picks which of a node's endpoints to dial: the
// config-specified serial if given, otherwise the first one whose address
// actually resolves (a node commonly has endpoints for address families or
// links that aren't currently usable, e.g. address: null).
func resolveEndpoint(node registry.Node, serial, family string) (registry.Endpoint, error) {
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
			if _, err := ep.ResolveRemote(); err == nil {
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
	cfg, reg := c.cfg, c.registry
	org, node, ok := reg.FindNode(p.Organization, p.CommonName)
	if !ok {
		return fmt.Errorf("node %q not found in organization %q", p.CommonName, p.Organization)
	}
	ep, err := resolveEndpoint(node, p.SerialNumber, local.AddressFamily)
	if err != nil {
		return err
	}
	remoteIP, err := ep.ResolveRemote()
	if err != nil {
		return err
	}
	remotePub, err := org.ParsePublicKey()
	if err != nil {
		return err
	}
	sessionName := fmt.Sprintf("%s/%s/%s@%s", p.Organization, p.CommonName, ep.SerialNumber, local.SerialNumber)
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
	release := c.sessions.adopt(name, sess.Mux())
	defer release()
	return c.serveSession(ctx, sess, name, sessionName)
}
