package client

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/netstack"
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
// than exceptional, and both directions land on the same path name.
//
// Newest wins is not enough to settle it. Both ends have to choose the same
// survivor, or each keeps the SA the other just closed and neither carries
// traffic until dead peer detection notices; and the end whose SA loses has to
// know not to dial straight back in, or the two take turns evicting each other
// for as long as the process runs. strongSwan's unique=replace resolves the
// far end by sending a Delete, which this does too, but it also needs a rule
// that does not depend on arrival order.
//
// preferred is that rule. Both nodes compare the same two identity strings and
// so agree on which of them should be the initiator; the SA opened in that
// direction is the one both keep, whichever order the two handshakes finish
// in. Only when the two sessions are equally preferred, which is a genuine
// reconnect rather than a collision, does the newer one win.
type sessionSet struct {
	mu   sync.Mutex
	live map[string]*liveSession

	// close is closeSession and active is (*ike.Session).Active in production.
	// A test drives the resolution rule without standing up two real SAs by
	// replacing them.
	close  func(*ike.Session)
	active func(*ike.Session) bool
}

type liveSession struct {
	session   *ike.Session
	preferred bool
}

func newSessionSet() *sessionSet {
	return &sessionSet{
		live:   make(map[string]*liveSession),
		close:  closeSession,
		active: (*ike.Session).Active,
	}
}

// preferInitiator reports whether, of the two nodes, this one is the end that
// should be the initiator. Both ends compute it from the same pair of names
// and reach opposite answers, which is what makes the choice agree.
func preferInitiator(local, remote ike.Identity) bool {
	return identityOrder(local) < identityOrder(remote)
}

func identityOrder(id ike.Identity) string {
	return id.Organization + "/" + id.CommonName + "/" + id.SerialNumber
}

// adopt makes mux the live session for one path unless an equally named
// session both ends prefer, and is still carrying traffic, already holds it.
//
// The liveness half matters as much as the preference. A peer that has just
// completed a handshake is telling us it has no session, and a peer that has
// rebooted leaves an SA on this side that looks established until dead peer
// detection reaps it a minute later. Declining a fresh session in favor of
// that one locks the peer out for the whole of that minute, and because the
// stale entry also stops our own dialer, neither end would open anything. The name is the remote and local
// endpoint pair, not just the peer, so a node reaching one peer over both
// address families keeps both sessions while a duplicate of either resolves
// against its twin.
//
// It reports whether the session was adopted. A caller told false has lost and
// must stop: its mux is already closed. The returned release drops the entry
// again, and only if it is still ours, so a session that has already been
// replaced cannot evict its replacement.
func (s *sessionSet) adopt(path string, sess *ike.Session, preferred bool) (func(), bool) {
	s.mu.Lock()
	previous := s.live[path]
	if previous != nil && previous.session != sess && previous.preferred && !preferred &&
		s.active(previous.session) {
		s.mu.Unlock()
		log.Printf("peer %s: keeping the session the other end also prefers", path)
		s.close(sess)
		return func() {}, false
	}
	s.live[path] = &liveSession{session: sess, preferred: preferred}
	s.mu.Unlock()
	if previous != nil && previous.session != sess {
		log.Printf("peer %s: replacing the previous session", path)
		s.close(previous.session)
	}
	return func() {
		s.mu.Lock()
		if current := s.live[path]; current != nil && current.session == sess {
			delete(s.live, path)
		}
		s.mu.Unlock()
	}, true
}

// deleteGrace bounds how long a teardown waits for the peer to acknowledge the
// Delete. The point is to tell it, not to be sure it heard.
const deleteGrace = 2 * time.Second

// closeSession tells the peer the SA is gone and then drops it, whether or not
// the Delete was answered.
func closeSession(sess *ike.Session) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sess.DeleteIKE()
	}()
	select {
	case <-done:
	case <-time.After(deleteGrace):
	}
	_ = sess.Mux().Close()
}

// holds reports whether a session that is actually carrying traffic serves this
// path, which is what lets a dialer stand down instead of opening a second one
// that would only be resolved away. A session that has stopped proving the peer
// is there does not count, so a dialer takes over from a dead one rather than
// waiting out dead peer detection behind it.
func (s *sessionSet) holds(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.live[path]
	return live != nil && s.active(live.session)
}

// closeAll tells every live peer the session is ending and drops it. Each is
// closed in parallel, so one unreachable peer costs deleteGrace rather than
// deleteGrace per peer.
func (s *sessionSet) closeAll() {
	s.mu.Lock()
	sessions := make([]*ike.Session, 0, len(s.live))
	for _, live := range s.live {
		sessions = append(sessions, live.session)
	}
	s.mu.Unlock()
	var closing sync.WaitGroup
	for _, sess := range sessions {
		closing.Go(func() { s.close(sess) })
	}
	closing.Wait()
	// Dropped here rather than left for each serveSession to unwind, so a
	// scrape taken during shutdown does not report sessions that have already
	// been told to go.
	s.mu.Lock()
	clear(s.live)
	s.mu.Unlock()
}
