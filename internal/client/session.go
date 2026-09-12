package client

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/transport"
)

// serveSession runs one established IKE SA until it ends, whichever side
// opened it: ESP keying, mesh and Babel registration, inbound delivery and the
// IKE control loop. Only the handshake differs between dialing and answering.
//
// name appears in logs; sessionName identifies this peer to the mesh and to
// Babel, so it must be stable and unique per peer.
func (c *Client) serveSession(ctx context.Context, sess *ike.Session, name, sessionName string) error {
	defer sess.Mux().Close()
	log.Printf("peer %s: connected (SPI %08x/%08x)", name, sess.Child.LocalSPI, sess.Child.RemoteSPI)

	tunnel := &tunnel{replayWindow: c.cfg.ReplayWindowSize()}
	tunnel.rekey = func() {
		go func() {
			if err := sess.RekeyChildProactively(); err != nil && !sess.Mux().IsClosed() {
				log.Printf("peer %s: proactive Child SA rekey: %v", name, err)
				_ = sess.Mux().Close()
			}
		}()
	}
	if err := tunnel.install(sess.Child); err != nil {
		return err
	}
	sess.SetChildHandler(tunnel.install)
	sess.SetChildRetireHandler(tunnel.retire)
	peer := netstack.NewPeerReserved(sessionName, func(count int) (netstack.BatchSealer, error) {
		sealer, err := tunnel.reserve(count)
		if err != nil {
			_ = sess.Mux().Close()
		}
		return sealer, err
	}, sess.Mux().SendESPBatch)
	defer peer.Close()
	handle := c.speaker.AddPeer(peer)
	defer handle.Close()

	plain := make([][]byte, 0, 128)
	emit := func(results []inboundDecrypted) {
		esp.CommitBatch(results)
		plain = plain[:0]
		var dropped int
		var lastError error
		for _, result := range results {
			raw, nextHeader, err := result.Plaintext()
			if err != nil {
				dropped, lastError = dropped+1, err
				continue
			}
			sess.NoteTraffic()
			deliver, err := validateESPTunnelPayload(raw, nextHeader)
			if err != nil {
				dropped, lastError = dropped+1, err
				continue
			}
			if deliver && !c.speaker.Receive(peer, raw) {
				plain = append(plain, raw)
			}
		}
		if dropped > 0 {
			log.Printf("peer %s: dropped %d ESP packets in batch; last error: %v", name, dropped, lastError)
		}
		c.Mesh.DeliverInboundBatch(plain)
		clear(plain)
	}
	type sessionResult struct {
		component string
		err       error
	}
	results := make(chan sessionResult, 2)
	go func() { results <- sessionResult{"IKE control", sess.Run(ctx)} }()
	go func() {
		results <- sessionResult{"ESP receive", receiveESP(sess.Mux(), c.workers, tunnel.decryptBatch, emit)}
	}()
	first := <-results
	_ = sess.Mux().Close()
	<-results
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%s session ended: %w", first.component, first.err)
}

// sessionSet keeps at most one live SA per peer. In a full mesh every node
// dials every other one, so both ends opening an SA at once is ordinary rather
// than exceptional; ranet's strongSwan settles it with unique=replace and this
// is the same rule, newest wins. Without it the two directions each install
// keys into the mesh under the same peer name and the loser's ESP is dropped
// by a peer that no longer holds its SPI.
type sessionSet struct {
	mu   sync.Mutex
	live map[string]*transport.Mux
}

func newSessionSet() *sessionSet { return &sessionSet{live: make(map[string]*transport.Mux)} }

// adopt makes mux the live session for peer, closing whatever held that name
// before. The returned release drops it again, and only if it is still ours,
// so a session that has already been replaced cannot evict its replacement.
func (s *sessionSet) adopt(peer string, mux *transport.Mux) func() {
	s.mu.Lock()
	previous := s.live[peer]
	s.live[peer] = mux
	s.mu.Unlock()
	if previous != nil && previous != mux {
		log.Printf("peer %s: replacing the previous session", peer)
		_ = previous.Close()
	}
	return func() {
		s.mu.Lock()
		if s.live[peer] == mux {
			delete(s.live, peer)
		}
		s.mu.Unlock()
	}
}
