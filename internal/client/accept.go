package client

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/registry"
)

// acceptPeers answers peers that dial us, as a full mesh needs and
// what a node behind no reachable address cannot do without. It returns when
// ctx ends or the hub's socket is gone.
func (c *Client) acceptPeers(ctx context.Context) error {
	cfg := c.config()
	crypto := cfg.Crypto()
	local := make([]ike.Identity, 0, len(cfg.Link.Endpoints))
	for _, endpoint := range cfg.Link.Endpoints {
		local = append(local, ike.Identity{
			Organization: cfg.Node.Org,
			CommonName:   cfg.Node.Name,
			SerialNumber: endpoint.Serial,
		})
	}
	responder, err := ike.NewResponder(ike.ResponderConfig{
		Hub:                c.hub,
		Local:              local,
		LocalPrivateKey:    c.privateKey,
		Lookup:             c.lookupPeerKey,
		ChildRekeyInterval: crypto.ChildInterval(),
		IKERekeyInterval:   crypto.IKEInterval(),
		RekeyMargin:        crypto.Margin(),
		RekeyJitter:        crypto.Jitter(),
		RekeyRetryInitial:  crypto.RetryFirst(),
		RekeyRetryMax:      crypto.RetryMax(),
	})
	if err != nil {
		return err
	}
	var serving sync.WaitGroup
	defer serving.Wait()
	err = responder.Serve(ctx, func(sess *ike.Session, accepted ike.Accepted) {
		serving.Go(func() {
			peer := accepted.Peer
			name := fmt.Sprintf("%s/%s@%s", peer.Organization, peer.CommonName, accepted.Local.SerialNumber)
			// The same shape a dialed session uses, so one path through the
			// mesh has one name whichever end opened it and the replace rule
			// in sessionSet applies across both directions.
			sessionName := fmt.Sprintf("%s/%s/%s@%s", peer.Organization, peer.CommonName, peer.SerialNumber, accepted.Local.SerialNumber)
			// We answered, so the peer is this SA's initiator and we are its
			// responder. Losing to a session the other end also prefers is
			// ordinary on a full mesh and is not worth a line in the log.
			err := c.serveSession(ctx, sess, name, sessionName, peer, accepted.Local, peer)
			if err != nil && !errors.Is(err, errSessionEstablished) && ctx.Err() == nil {
				log.Printf("peer %s: %v", name, err)
			}
		})
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// lookupPeerKey resolves an authenticated identity to the key that must verify
// its AUTH. The registry is the trust root, exactly as it is for ranet's own
// reconcile, so any node in it may dial us; the config's peers list says who
// we dial, not who we answer.
//
// The serial number has to name one of that node's registered endpoints. It
// is the initiator's own claim about which of its endpoints it is calling
// from, so a value the registry does not know means the registry and the peer
// disagree about what exists.
func (c *Client) lookupPeerKey(peer ike.Identity) (ed25519.PublicKey, bool) {
	key, node, ok := c.peerKey(peer)
	if !ok {
		return nil, false
	}
	if _, named := node.FindEndpoint(peer.SerialNumber); !named {
		return nil, false
	}
	return key, true
}

// stillTrusted reports whether the registry still stands behind a peer this
// node has already authenticated, which a reload asks of every live session.
// The endpoint serial is left out: it selects which endpoint a dial uses, and
// renumbering one is a registry edit rather than a revocation, so asking for it
// here closes a session whose peer has done nothing to lose it.
func (c *Client) stillTrusted(peer ike.Identity) bool {
	_, _, ok := c.peerKey(peer)
	return ok
}

// peerKey is the organization key that must verify a peer's AUTH, with the
// node the registry holds for it, and whether the registry stands behind the
// identity at all.
func (c *Client) peerKey(peer ike.Identity) (ed25519.PublicKey, registry.Node, bool) {
	cfg := c.config()
	organization, node, ok := c.registry().FindNode(peer.Organization, peer.CommonName)
	if !ok {
		return nil, registry.Node{}, false
	}
	if peer.Organization == cfg.Node.Org && peer.CommonName == cfg.Node.Name {
		// Our own name in another node's IDi is either a misconfiguration or
		// an attempt to reuse the organization key under our identity.
		return nil, registry.Node{}, false
	}
	publicKey, err := organization.ParsePublicKey()
	if err != nil {
		return nil, registry.Node{}, false
	}
	return publicKey, node, true
}
