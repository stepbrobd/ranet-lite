package client

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"sync"

	"github.com/NickCao/ranet-lite/internal/ike"
)

// acceptPeers answers peers that dial us, which is what a full mesh needs and
// what a node behind no reachable address cannot do without. It returns when
// ctx ends or the hub's socket is gone.
func (c *Client) acceptPeers(ctx context.Context) error {
	local := make([]ike.Identity, 0, len(c.cfg.Endpoints))
	for _, endpoint := range c.cfg.Endpoints {
		local = append(local, ike.Identity{
			Organization: c.cfg.Organization,
			CommonName:   c.cfg.CommonName,
			SerialNumber: endpoint.SerialNumber,
		})
	}
	responder, err := ike.NewResponder(ike.ResponderConfig{
		Hub:                c.hub,
		Local:              local,
		LocalPrivateKey:    c.privateKey,
		Lookup:             c.lookupPeerKey,
		ChildRekeyInterval: c.cfg.ChildRekeyIntervalValue(),
		IKERekeyInterval:   c.cfg.IKERekeyIntervalValue(),
		RekeyMargin:        c.cfg.RekeyMarginValue(),
		RekeyJitter:        c.cfg.RekeyJitterValue(),
		RekeyRetryInitial:  c.cfg.RekeyRetryInitialValue(),
		RekeyRetryMax:      c.cfg.RekeyRetryMaxValue(),
	})
	if err != nil {
		return err
	}
	var serving sync.WaitGroup
	defer serving.Wait()
	err = responder.Serve(ctx, func(sess *ike.Session, accepted ike.Accepted) {
		serving.Go(func() {
			peer := accepted.Peer
			name := fmt.Sprintf("%s/%s", peer.Organization, peer.CommonName)
			sessionName := fmt.Sprintf("%s/%s/%s", peer.Organization, peer.CommonName, peer.SerialNumber)
			release := c.sessions.adopt(name, sess.Mux())
			defer release()
			if err := c.serveSession(ctx, sess, name, sessionName); err != nil && ctx.Err() == nil {
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
	organization, node, ok := c.registry.FindNode(peer.Organization, peer.CommonName)
	if !ok {
		return nil, false
	}
	if peer.Organization == c.cfg.Organization && peer.CommonName == c.cfg.CommonName {
		// Our own name in another node's IDi is either a misconfiguration or
		// an attempt to reuse the organization key under our identity.
		return nil, false
	}
	if _, ok := node.FindEndpoint(peer.SerialNumber); !ok {
		return nil, false
	}
	publicKey, err := organization.ParsePublicKey()
	if err != nil {
		return nil, false
	}
	return publicKey, true
}
