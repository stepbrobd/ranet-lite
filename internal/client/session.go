package client

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/ike"
	"github.com/NickCao/ranet-lite/internal/netstack"
)

// serveSession runs one established IKE SA until it ends, whichever side
// opened it: ESP keying, mesh and Babel registration, inbound delivery and the
// IKE control loop. Only the handshake differs between dialing and answering,
// which is also why the resolution against a competing session happens here
// rather than in each caller: the babel registration has to go in under the
// same decision, and this is where the peer exists.
//
// It returns errSessionEstablished when another session already holds the
// path, which is not a failure. name appears in logs; sessionName identifies
// this peer to the mesh and to babel, so it must be stable and unique per
// peer. initiator and responder are this SA's own roles, the end that opened
// it and the end that answered.
func (c *Client) serveSession(ctx context.Context, sess *ike.Session, name, sessionName string, initiator, responder, remote ike.Identity) error {
	defer sess.Mux().Close()
	log.Printf("peer %s: connected (SPI %08x/%08x)", name, sess.Child.LocalSPI, sess.Child.RemoteSPI)

	tunnel := &tunnel{replayWindow: c.config().Crypto().ReplayWindow(), started: time.Now()}
	tunnel.askedAt.Store(-int64(rekeyAskInterval))
	// requestRekey owns the goroutine and the one-at-a-time guard, so this
	// runs on its own and may block.
	//
	// A rekey that fails is reported and left alone. RFC 7296 section 1.3.1:
	// "A failed attempt to create a Child SA SHOULD NOT tear down the IKE SA:
	// there is no reason to lose the work done to set up the IKE SA." Every
	// notify below 16384 arrives here as an error, TEMPORARY_FAILURE and
	// NO_ADDITIONAL_SAS included, and both are ordinary: two ends recreating a
	// deleted Child SA at once produce exactly the second. The schedule
	// retries, and the session keeps carrying what it has.
	tunnel.rekey = func() {
		if err := sess.RekeyChildProactively(); err != nil && !sess.Mux().IsClosed() {
			log.Printf("peer %s: proactive Child SA rekey: %v", name, err)
		}
	}
	if err := tunnel.install(sess.Child); err != nil {
		return err
	}
	sess.SetChildHandler(tunnel.install)
	sess.SetChildRetireHandler(tunnel.retire)
	peer := netstack.NewPeerReserved(sessionName, func(count int) (netstack.BatchSealer, error) {
		sealer, err := tunnel.reserve(count)
		// Closing the mux here turns the first babel hello after a refusal,
		// four seconds later, into a full session teardown that withdraws
		// every route through this peer. See fatalReserveError for the two
		// refusals that do not deserve that.
		if fatalReserveError(err) {
			_ = sess.Mux().Close()
		}
		return sealer, err
	}, sess.Mux().SendESPBatch)
	// The mux is closed before the peer's sender is waited for, not after.
	// Peer.Close waits with no deadline for a sender that may be inside
	// SendESPBatch on this very mux, and the defer at the top of this function
	// runs last, so on that ordering a send that would not return held the
	// whole shutdown. Mux.Close is written to be called twice.
	defer func() {
		_ = sess.Mux().Close()
		peer.Close()
	}()
	release, adopted := c.sessions.adopt(sessionName, sess, initiator, responder, remote, func() func() {
		return c.speaker.AddPeer(peer).Close
	})
	defer release()
	if !adopted {
		return errSessionEstablished
	}
	// A dialer that a reload dropped cancels this context while the node keeps
	// running, and this end then stops: the peer carries on sending ESP
	// into an SPI nobody answers until its own liveness check expires, which
	// is up to seventy seconds. closeAll does this for every session at
	// shutdown, for exactly the reason its doc gives, and this is the same
	// thing for one peer. Shutdown is not this case, because closeAll has
	// already swept by the time c.ctx is canceled.
	defer func() {
		if dialerWasDropped(ctx, c.ctx) {
			closeSession(sess)
		}
	}()

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
			inner, deliver, err := validateESPTunnelPayload(raw, nextHeader)
			if err != nil {
				dropped, lastError = dropped+1, err
				continue
			}
			if deliver && !c.speaker.Receive(peer, inner) {
				plain = append(plain, inner)
			}
		}
		if dropped > 0 {
			c.noteInboundDropped(name, dropped, lastError)
		}
		c.countInbound(len(results) - dropped)
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
	// shut refuses any further session once the node is going. A handshake
	// still in flight completes after closeAll has swept, and without this it
	// would install a session nobody is left to tell the peer about.
	shut bool

	// close is closeSession, active is (*ike.Session).Active and rekey is
	// (*ike.Session).RekeyChildProactively in production. A test drives the
	// resolution rule and the rekey verb without standing up two real SAs by
	// replacing them.
	close  func(*ike.Session)
	active func(*ike.Session) bool
	rekey  func(*ike.Session) error
}

type liveSession struct {
	session   *ike.Session
	preferred bool
	// peer is the identity the far end authenticated as, kept so a reload can
	// ask whether the registry still names it. The registry is the trust root
	// this node checks a handshake against, so a node taken out of it has to
	// stop being carried; without this, revoking a node left every tunnel it
	// already held up until each of the other nodes restarted.
	peer ike.Identity
}

func newSessionSet() *sessionSet {
	return &sessionSet{
		live:   make(map[string]*liveSession),
		close:  closeSession,
		active: (*ike.Session).Active,
		rekey:  (*ike.Session).RekeyChildProactively,
	}
}

// preferInitiator reports whether, of the two nodes, the first is the end that
// should be the initiator. Both ends compute it from the same pair of names
// and reach the same answer, so the choice agrees.
func preferInitiator(initiator, responder ike.Identity) bool {
	return identityOrder(initiator) < identityOrder(responder)
}

func identityOrder(id ike.Identity) string {
	return id.Organization + "/" + id.CommonName + "/" + id.SerialNumber
}

// adopt makes sess the live session for one path unless an equally named
// session both ends prefer already holds it. The name is the remote and local
// endpoint pair, not just the peer, so a node reaching one peer over both
// address families keeps both sessions while a duplicate of either resolves
// against its twin.
//
// The rule reads only the two sessions' preference, which both ends compute
// from the same pair of names and so always agree on. Nothing local enters it.
// Gating it on whether the incumbent still looks alive made the outcome depend
// on a clock the two ends are not obliged to agree about: each would keep the
// session the other closed, both SAs would die, both ends would redial, and
// every route through that peer would be withdrawn on each flap. A stale
// incumbent is handled where it belongs instead, in holds, which lets
// this node's own dialer take over rather than wait behind a dead session.
//
// It reports whether the session was adopted. A caller told false has lost and
// must stop: its mux is already closed. The returned release drops the entry
// again, and only if it is still ours, so a session that has already been
// replaced cannot evict its replacement.
//
// The two identities are this SA's roles, not this node's point of view: the
// end that opened it and the end that answered. Naming them that way keeps a
// dialer and a responder from deriving opposite answers for one SA,
// which is invisible from either end alone.
func (s *sessionSet) adopt(path string, sess *ike.Session, initiator, responder, remote ike.Identity, attach func() func()) (func(), bool) {
	return s.adoptFor(path, sess, preferInitiator(initiator, responder), remote, attach)
}

// adoptPreferred is adopt with the rule already applied and no peer identity,
// for a test that drives the resolution without two identities to derive it
// from.
func (s *sessionSet) adoptPreferred(path string, sess *ike.Session, preferred bool, attach func() func()) (func(), bool) {
	return s.adoptFor(path, sess, preferred, ike.Identity{}, attach)
}

func (s *sessionSet) adoptFor(path string, sess *ike.Session, preferred bool, remote ike.Identity, attach func() func()) (func(), bool) {
	s.mu.Lock()
	if s.shut {
		s.mu.Unlock()
		// Told rather than dropped: this handshake finished after the node
		// started going, and its peer would otherwise carry the session until
		// its own dead peer detection expires, which is over a minute.
		s.close(sess)
		return func() {}, false
	}
	previous := s.live[path]
	if previous != nil && previous.session != sess && previous.preferred && !preferred {
		s.mu.Unlock()
		log.Printf("peer %s: keeping the session the other end also prefers", path)
		s.close(sess)
		return func() {}, false
	}
	// Whatever else this session registers under the path's name registers
	// here, while the decision is still held. Two sessions resolving against
	// each other reach this in the order they take the path, so a session
	// already replaced cannot take the babel neighbor away from the one that
	// replaced it, which would leave the speaker holding a peer whose mux is
	// closed and the adjacency down until that session unwound.
	var detach func()
	if attach != nil {
		detach = attach()
	}
	s.live[path] = &liveSession{session: sess, preferred: preferred, peer: remote}
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
		if detach != nil {
			detach()
		}
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

// liveSessionView is one entry of the set, copied out so that a caller reads
// it without holding the lock every handshake and every teardown needs.
type liveSessionView struct {
	path      string
	session   *ike.Session
	preferred bool
	peer      ike.Identity
}

// snapshot copies the live set. The sessions themselves are pointers, so a
// caller reads each one through its own accessors afterwards; what the lock
// protects is the map, and it is released before any of that happens.
func (s *sessionSet) snapshot() []liveSessionView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]liveSessionView, 0, len(s.live))
	for path, live := range s.live {
		out = append(out, liveSessionView{path: path, session: live.session, preferred: live.preferred, peer: live.peer})
	}
	return out
}

// holds reports whether a session that has recently proved the peer is there
// serves this path, which lets a dialer stand down instead of opening a second
// one that would only be resolved away. A session that has stopped proving it
// does not count, so a dialer takes over from a dead one instead of waiting
// out dead peer detection behind it.
func (s *sessionSet) holds(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.live[path]
	return live != nil && s.active(live.session)
}

// liveCount is how many paths a session that has recently proved its peer is
// there serves, which is the same test holds applies to one path. A Client
// built by hand in a test carries no set and reports none.
func (s *sessionSet) liveCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, live := range s.live {
		if s.active(live.session) {
			count++
		}
	}
	return count
}

// revoke closes every live session whose peer the registry no longer
// authenticates, and reports which paths went. A reload is the only moment
// this node learns that a node has been taken out of the mesh, and until it
// acts on it the tunnels that node already holds keep carrying traffic: the
// handshake check alone only refuses the next one.
func (s *sessionSet) revoke(trusted func(ike.Identity) bool) []string {
	if s == nil {
		return nil // a Client built by hand in a test carries no sessions
	}
	s.mu.Lock()
	var paths []string
	var sessions []*ike.Session
	for path, live := range s.live {
		if live.peer == (ike.Identity{}) || trusted(live.peer) {
			continue
		}
		paths = append(paths, path)
		sessions = append(sessions, live.session)
		delete(s.live, path)
	}
	s.mu.Unlock()
	var closing sync.WaitGroup
	for _, sess := range sessions {
		closing.Go(func() { s.close(sess) })
	}
	closing.Wait()
	slices.Sort(paths)
	return paths
}

// closeMatching closes every live session naming one peer and reports which
// went, which is the half of a redial this side can do about a peer holding a
// session this node no longer has.
//
// The entry leaves the map before the session is closed, as revoke does, so
// the dialer woken straight afterwards sees the path as free rather than
// standing down behind a session that is already going. serveSession's own
// release then finds the path held by nobody and leaves it alone.
func (s *sessionSet) closeMatching(peer string) []string {
	if s == nil {
		return nil // a Client built by hand in a test carries no sessions
	}
	s.mu.Lock()
	var paths []string
	var sessions []*ike.Session
	for path, live := range s.live {
		if !matchesPeer(path, peer) {
			continue
		}
		paths = append(paths, path)
		sessions = append(sessions, live.session)
		delete(s.live, path)
	}
	s.mu.Unlock()
	var closing sync.WaitGroup
	for _, sess := range sessions {
		closing.Go(func() { s.close(sess) })
	}
	closing.Wait()
	slices.Sort(paths)
	return paths
}

// rekeyMatching asks every live session naming one peer, or every session at
// all, to replace its Child SA, and reports which were asked.
//
// Each exchange runs on its own and none of them is waited for. A rekey is two
// messages and a retransmit schedule against a peer that may be gone, so
// waiting would make the answer to a mesh-wide ask depend on its least
// reachable member. The new SPIs appear under Sessions as each one lands.
func (s *sessionSet) rekeyMatching(peer string, all bool) []string {
	if s == nil {
		return nil
	}
	var paths []string
	for _, live := range s.snapshot() {
		if !all && !matchesPeer(live.path, peer) {
			continue
		}
		paths = append(paths, live.path)
		go func() {
			if err := s.rekey(live.session); err != nil {
				log.Printf("peer %s: rekey asked for on the control socket: %v", live.path, err)
			}
		}()
	}
	slices.Sort(paths)
	return paths
}

// matchesPeer reports whether a dialer or session path names the peer somebody
// asked about. A path is "org/name/serial@local", and the argument is compared
// against the whole of it, against "org/name" and against the name alone, so a
// fleet with one organization is named the short way and two nodes sharing a
// name across organizations are still told apart.
func matchesPeer(path, peer string) bool {
	if path == peer {
		return true
	}
	organization, rest, ok := strings.Cut(path, "/")
	if !ok {
		return false
	}
	name, _, ok := strings.Cut(rest, "/")
	if !ok {
		return false
	}
	return peer == name || peer == organization+"/"+name
}

// closeAll tells every live peer the session is ending and drops it, and shuts
// the set so nothing can be adopted behind the sweep. Each is closed in
// parallel, so one unreachable peer costs deleteGrace rather than deleteGrace
// per peer.
func (s *sessionSet) closeAll() {
	s.mu.Lock()
	s.shut = true
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
