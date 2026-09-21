// Package babel implements RFC 8966 over ESP tunnels. It originates local
// prefixes, learns ordinary and source-specific routes, and re-advertises the
// routes it selects. Control packets bypass the TUN.
//
// Re-advertising learned routes makes this node transit, so loop freedom rests
// on the feasibility condition of RFC 8966 section 3.5.1 and the source table
// in source.go, not on the structural argument of Appendix E. The invariant
// that keeps it is that every finite update leaves through Speaker.advertiseTo,
// which records the feasibility distance before the packet is built.
//
// Deliberate deviations, in RFC 8966 section order:
//
//   - 3.7.2: a triggered update or retraction is sent once, not repeated and
//     not acknowledged. Each link is one ESP tunnel with in-order delivery
//     rather than lossy multicast, and the periodic dump plus the retraction
//     hold cover a loss.
//   - 3.8.1.2: a seqno request is forwarded whenever this node has a route to
//     the prefix, not only while it is advertising one. The case that most
//     needs forwarding is exactly the one where every route has become
//     unfeasible and nothing is being advertised.
//   - 3.8.1.1 and 3.8.1.2: split horizon applies to replies as well, so a
//     request for a prefix whose selected next hop is the requester is
//     answered with a retraction, and a seqno request in that position is
//     forwarded onwards instead of answered at all.
//   - 3.8.2.3: a selected route is not refreshed with a route request shortly
//     before it expires.
//   - Appendix A.3: the smoothed metric follows an increase immediately and
//     only damps improvements, so that a selected route which has genuinely
//     gone bad is left at once. See routeInfo.smooth.
package babel

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

var multicastGroup = netip.MustParseAddr("ff02::1:6")

// pendingSeqno is one entry of the table of pending seqno requests, RFC 8966
// section 3.2.7, extended by RFC 9079 section 3.3 with the source prefix that
// sourceKey already carries.
type pendingSeqno struct {
	seqno  uint16
	sentAt time.Time
	// asker is the peer whose request created this entry, or empty for one
	// this node sent on its own behalf. It is the peer's name rather than its
	// state, so an entry left behind cannot pin a retired neighbor.
	asker string
}

// Request timeout, RFC 8966 Appendix B. A request for the same source within
// this window is redundant (section 3.8.1.2) and is dropped instead of
// forwarded.
const seqnoRequestSuppress = 2 * time.Second

// maxPendingSeqno bounds that table, and maxPendingSeqnoPerNeighbor bounds
// what any one neighbor can spend of it. An entry is only ever created for a
// prefix this node has a route for, which bounds one half of the index. The
// other half is the router id the requester wrote into the packet, which
// nothing bounds, and eighty seqno requests fit in a single packet. Past a cap
// the request is not forwarded, as the suppression above does with a
// redundant one, and is the list of recently forwarded requests RFC 8966
// section 3.8.1.2 asks a node to keep.
//
// The per-neighbor share keeps one of them from turning forwarding off for
// the rest: a flood that filled a single global table would stop every
// other neighbor's requests being relayed, and a prefix that starves behind
// this node would stop recovering until the flood did.
const (
	maxPendingSeqno            = 1 << 12
	maxPendingSeqnoPerNeighbor = 1 << 10
)

// maxStarveRetries bounds the prefixes this node is repeating a seqno request
// for, and maxStarveRetriesPerNeighbor is one neighbor's share of that. The
// index carries a router id a neighbor writes into a packet, so nothing else
// bounds it, and every entry is walked under s.mu on each wake of the run
// loop. Without the share one neighbor fills the table from the ordinary route
// acquisition path, and RFC 8966 section 3.8.2.1's "repeat such a request a
// small number of times" then stops happening for every other neighbor, so a
// lost request or a lost reply is never covered.
const (
	maxStarveRetries            = 1 << 12
	maxStarveRetriesPerNeighbor = 1 << 10
)

// Hop count for locally originated seqno requests: "64 is a suitable default
// value", RFC 8966 section 3.8.2.1.
const seqnoRequestHopCount = 64

// The same section says a node "SHOULD repeat such a request a small number of
// times if no route becomes feasible within a short time". One request is not
// enough: losing it, or its reply, leaves the prefix starved for as long as the
// unfeasible route keeps being refreshed, and the unfeasible route pins the
// feasibility distance so that never expires either. BIRD repeats four times,
// doubling the delay. The first delay is longer than seqnoRequestSuppress so a
// retry is not dropped as redundant by our own suppression table.
const (
	seqnoRequestRetries = 4
	seqnoRetryInitial   = 3 * time.Second
)

// askedKey indexes a seqno request this node sent on its own behalf.
type askedKey struct {
	source   sourceKey
	neighbor *neighborState
}

// starveRetry is one prefix waiting for a seqno that has not arrived.
type starveRetry struct {
	key      routeKey
	routerID [8]byte
	seqno    uint16
	attempts int
	nextAt   time.Time
	// asker is the neighbor whose route starved, so the share it spent can be
	// given back. It is the peer's name rather than its state, so an entry
	// left behind cannot pin a retired neighbor.
	asker string
}

// Speaker.mu serializes all protocol state and forwarding-table changes.
// Packet transmission always happens after unlocking: a slow peer cannot
// prevent a route retraction, and in-memory transports may re-enter Receive.
type Speaker struct {
	// The capability as resolved at construction: the intervals and the cost
	// with their defaults filled in, the runtime the caller supplied, and
	// whether this node relays what it learns. Every one of them is read-only
	// for the life of the speaker, so a change to any of them is a restart.
	hello, update time.Duration
	cost          CostParams
	routerID      [8]byte
	linkLocal     netip.Addr
	packetSize    int
	noTransit     bool

	mesh *netstack.Mesh

	mu           sync.Mutex
	neighbors    map[string]*neighborState
	originate    map[routeKey]struct{}
	routes       *routeTable
	pendingSeqno map[sourceKey]pendingSeqno
	// pendingByAsker is how much of pendingSeqno each neighbor is holding, so
	// one of them cannot spend the whole table.
	pendingByAsker map[string]int
	// askedSeqno is the same suppression for requests this node originates,
	// but indexed by neighbor as well. RFC 8966 section 3.8.2.1 wants every
	// neighbor holding an unfeasible route asked, and pendingSeqno's index has
	// no neighbor in it, so it cannot tell "already asked this one" from
	// "already asked somebody".
	askedSeqno    map[askedKey]time.Time
	starveRetries map[sourceKey]*starveRetry
	// starveBy is how much of that each neighbor is holding.
	starveBy    map[string]int
	originSeqno uint16
	// raisedSeqno bounds originSeqno to one raise per received packet.
	raisedSeqno   bool
	updatePending bool
	// routeChanges and routeLogged bound the selection-change log, see
	// routeLogInterval. Both are touched only under s.mu, with installRoute.
	routeChanges int
	routeLogged  time.Time
	changed      chan struct{}

	// lost holds the undos of packets a peer's sender queued and then could
	// not transmit. The sender reports them from its own goroutine, so they
	// are collected under a lock of their own and applied by the next pass
	// rather than taken straight into the protocol state. See noteLost.
	lostMu   sync.Mutex
	lost     []lostUndo
	lostWoke time.Time
	// nextHello and nextUpdate are the run loop's own timers, and sleepUntil
	// is the deadline it is currently waiting on. They are loop state kept on
	// the Speaker rather than in Run so the receive path can tell whether an
	// arriving packet moved a deadline earlier than the one already set; all
	// three are touched only under s.mu.
	nextHello  time.Time
	nextUpdate time.Time
	sleepUntil time.Time
	// nextRequestSweep is the earliest seqnoRequestSuppress window that has
	// still to be cleaned up, kept the way the route table keeps its expiry
	// minimum. The window is two seconds and every other deadline the loop has
	// is a hello interval or longer, so without this the two suppression
	// tables are swept a hello interval late and their per-neighbor budgets
	// are held that long by entries that suppress nothing. Only ever moved
	// earlier between sweeps; sweepRequestsLocked rebuilds it exactly.
	nextRequestSweep time.Time
	// passes counts what wakeForPacketLocked exists to keep down: one pass is
	// a reselection of the whole route table. Kept because the decision is
	// otherwise unobservable from outside -- a test can watch the wake
	// channel, but nothing else can tell whether Run actually recorded the
	// deadline it slept on -- and one increment per pass costs nothing.
	passes uint64
	// retryAt is when a pass that could not send everything it built tries
	// again. See noteSendRetryLocked.
	retryAt time.Time
	// nextStarveRetry is the earliest starveRetries deadline, kept the way the
	// route table keeps its own: deadlineLocked runs on the receive path now,
	// and maxStarveRetries is four thousand, so walking the map there would
	// hand a neighbor a walk of it per packet. Only ever moved earlier between
	// passes, so it can be early -- one pass that finds nothing due -- and
	// never late. retryStarvedLocked rebuilds it exactly.
	nextStarveRetry time.Time
}

// PeerHandle owns one exact registration. Closing a stale handle cannot
// disturb a new session that reused the same peer ID.
type PeerHandle struct {
	speaker *Speaker
	state   *neighborState
	once    sync.Once
}

func (h *PeerHandle) Close() {
	if h != nil {
		h.once.Do(func() { h.speaker.removePeer(h.state) })
	}
}

// New builds the speaker from the two capabilities that configure it and the
// runtime the caller resolved. cap.route is taken here as well as by
// SetRoutes, because whether this node relays is read while a packet is being
// built and is therefore fixed for the speaker's life, while the
// announcements are not.
func New(cfg Config, routes Routes, rt Runtime, mesh *netstack.Mesh) (*Speaker, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := routes.Validate(); err != nil {
		return nil, err
	}
	rt, err := rt.resolve()
	if err != nil {
		return nil, err
	}
	s := &Speaker{
		hello: cfg.HelloInterval(), update: cfg.UpdateInterval(), cost: cfg.CostEffective(),
		routerID: rt.RouterID, linkLocal: rt.LinkLocalAddr, packetSize: rt.PacketSize,
		noTransit: !routes.Transits(),
		mesh:      mesh,

		neighbors:      make(map[string]*neighborState),
		originate:      make(map[routeKey]struct{}),
		pendingSeqno:   make(map[sourceKey]pendingSeqno),
		pendingByAsker: make(map[string]int),
		askedSeqno:     make(map[askedKey]time.Time),
		starveRetries:  make(map[sourceKey]*starveRetry),
		starveBy:       make(map[string]int),
		originSeqno:    1,
		changed:        make(chan struct{}, 1),
	}
	s.routes = newRouteTable(s.installRoute)
	s.routes.cost = s.cost
	s.routes.forget = func(key routeKey) { s.mesh.Routes.Remove(key.source, key.dest) }
	// RFC 8966 Appendix A.3 recommends a hysteresis time constant of a small
	// multiple of the Hello interval. One link's base cost is the scale at
	// which a metric change is worth a triggered update rather than a wait for
	// the next periodic dump.
	s.routes.tau, s.routes.trigger = 3*s.hello, s.cost.RxCost
	s.SetRoutes(routes)
	return s, nil
}

func (s *Speaker) AddPeer(peer *netstack.Peer) *PeerHandle {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.neighbors[peer.ID]; old != nil {
		s.routes.expireNeighbor(old, time.Now())
	}
	n := &neighborState{peer: peer,
		advertised: make(map[routeKey]struct{}), owed: make(map[routeKey]struct{})}
	s.neighbors[peer.ID] = n
	s.updatePending = true
	s.wake()
	return &PeerHandle{speaker: s, state: n}
}

func (s *Speaker) removePeer(n *neighborState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.neighbors[n.peer.ID] != n {
		return
	}
	delete(s.neighbors, n.peer.ID)
	// Dropping this neighbor's suppression entries with it keeps a retired
	// neighborState from being pinned until the next sweep, and lets the next
	// session for the same peer ask immediately rather than inheriting a
	// window it never opened.
	for index := range s.askedSeqno {
		if index.neighbor == n {
			delete(s.askedSeqno, index)
		}
	}
	s.routes.expireNeighbor(n, time.Now())
	s.wake()
}

// Receive consumes Babel packets from the exact registered ESP session.
// Everything else is returned to the caller for normal IP delivery.
func (s *Speaker) Receive(peer *netstack.Peer, raw []byte) bool {
	if !isBabelPacket(raw) {
		return false
	}
	src, payload, err := parsePacket(raw, s.linkLocal)
	if err != nil {
		return false
	}
	s.mu.Lock()
	n := s.neighbors[peer.ID]
	if n == nil || n.peer != peer {
		s.mu.Unlock()
		return true // never deliver a retired session's control traffic to TUN
	}
	n.addr = src
	send := s.emitLocked(s.handlePacketLocked(n, payload, time.Now()))
	s.wakeForPacketLocked()
	s.mu.Unlock()
	send()
	return true
}

// Originate prefers this directly attached prefix over any reflected route,
// including announcements carrying the router ID from before a restart.
func (s *Speaker) Originate(prefix netip.Prefix) {
	s.OriginateFrom(prefix, netip.Prefix{})
}

// OriginateFrom announces a source-specific prefix, BIRD's
// `route <dest> from <source>`. A zero-length source prefix announces an
// ordinary route, the meaning RFC 9079 section 5 gives such an entry.
func (s *Speaker) OriginateFrom(dest, source netip.Prefix) {
	key, ok := originatedKey(dest, source)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.originate[key] = struct{}{}
	s.adoptOriginatedLocked(key)
	s.updatePending = true
	s.wake()
}

// adoptOriginatedLocked takes over a prefix this node now originates itself.
// Whatever it had learned has to go: a learned route left selected keeps
// advertiseTo's split horizon comparing its next hop against nil, so it never
// fires and the node advertises the prefix at metric 0 back to the neighbor it
// is still forwarding to, which is a loop until the entry expires.
//
// The forwarding entry is held unreachable rather than removed, and the hold
// goes in whether or not anything was learned. Originating a prefix is a claim
// to be its origin, not a promise that every address in it is reachable. With
// no entry at all, a packet for an address in the prefix that is not assigned
// locally falls through to a covering route, and on a node holding one that is
// straight back out to a neighbor which learned this prefix from here at
// metric 0 and returns it.
func (s *Speaker) adoptOriginatedLocked(key routeKey) {
	delete(s.routes.entries, key)
	s.mesh.Routes.Set(key.source, key.dest, netstack.Unreachable)
}

// releaseOriginatedLocked gives a prefix back after it stops being originated,
// so a route to it can be learned from a neighbor again rather than staying
// held against the hold adoptOriginatedLocked installed.
func (s *Speaker) releaseOriginatedLocked(key routeKey) {
	s.mesh.Routes.Remove(key.source, key.dest)
}

// SetRoutes applies the cap.route capability, which a reload may replace. Only
// the announcements are read: whether this node relays was taken at
// construction and a reload refuses a change to it, see New.
func (s *Speaker) SetRoutes(routes Routes) { s.SetOriginated(routes.Originated()) }

// SetOriginated replaces the whole originated set, as a
// configuration reload needs: a prefix that is no longer configured has to be
// retracted rather than announced forever, and adding one at a time cannot
// express a removal. Each element is a destination and an optional source
// prefix, the same pair OriginateFrom takes.
func (s *Speaker) SetOriginated(routes []OriginatedRoute) {
	wanted := make(map[routeKey]struct{}, len(routes))
	for _, route := range routes {
		key, ok := originatedKey(route.Destination, route.Source)
		if !ok {
			continue
		}
		wanted[key] = struct{}{}
	}
	s.mu.Lock()
	changed := len(wanted) != len(s.originate)
	for key := range s.originate {
		if _, keep := wanted[key]; !keep {
			changed = true
		}
	}
	if !changed {
		s.mu.Unlock()
		return
	}
	// A prefix that has gone away is dropped here. Neighbors learn of
	// it through the retraction the next advertisement carries, since
	// advertiseTo reports an unknown route as infinity.
	for key := range s.originate {
		if _, keep := wanted[key]; !keep {
			s.releaseOriginatedLocked(key)
		}
	}
	s.originate = wanted
	for key := range wanted {
		s.adoptOriginatedLocked(key)
	}
	s.updatePending = true
	s.wake()
	s.mu.Unlock()
}

// OriginatedRoute is one configured announcement, an ordinary prefix when
// Source is zero.
type OriginatedRoute struct {
	Destination netip.Prefix
	Source      netip.Prefix
}

// originatedKey is the forwarding key one configured announcement takes.
func originatedKey(dest, source netip.Prefix) (routeKey, bool) {
	if !dest.IsValid() {
		return routeKey{}, false
	}
	key := routeKey{dest: dest.Masked()}
	if source.IsValid() && source.Bits() > 0 {
		if source.Addr().Is4() != dest.Addr().Is4() {
			// The Source Prefix sub-TLV is read under the destination's address
			// encoding, so the pair cannot even be expressed on the wire.
			slog.Warn("babel ignoring source-specific origination across address families",
				"route", dest, "from", source)
			return routeKey{}, false
		}
		key.source = source.Masked()
	}
	return key, true
}

// Passes is how many times the run loop has reselected the whole route table.
func (s *Speaker) Passes() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.passes
}

func (s *Speaker) wake() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// wakeForPacketLocked wakes the run loop for a packet that left it something
// to do, and leaves it asleep for one that did not. A pass is a reselection of
// the whole route table, 22 ms at maxRouteKeys prefixes over eight neighbors
// and under the lock that is also every other neighbor's receive path, the
// hello emitter and route installation, so a wake for every arriving packet
// let one neighbor charge this node that much for a sixty byte Hello as fast
// as the link carries them. Deciding instead costs the 230 ns of
// deadlineLocked, and the Hello and IHU a packet refreshes move their own
// deadlines later, never earlier, which is the case this leaves asleep. Both
// figures are floors, taken on an idle machine; see BenchmarkRunLoopPass.
//
// It does not make an arriving packet free. Every Hello and IHU calls
// routes.recomputeNeighbor on the receive path, which reselects every prefix
// that neighbor holds under the same lock, and the cost is the same order as
// the pass it no longer also pays for: on the eight-neighbor table at
// maxRouteKeys, 7.6 ms against 19 ms, both measured on the same fixture by
// BenchmarkReceiveHello and BenchmarkRunLoopPass. Comparing a one-neighbor
// receive against an eight-neighbor pass, which an earlier note here did, puts
// the ratio out by a factor of five. maxRouteKeys is a table-wide cap with no
// per-neighbor share, so one neighbor can fill it and then charge that.
//
// The recompute fires on every Hello rather than on one that moves the link
// cost: linkChanged is set unconditionally by both TLVs, while linkCost is
// reportedCost gated on liveness, which a refreshing Hello from a live
// neighbor does not move. Gating it on the cost actually changing is the next
// thing worth doing here.
func (s *Speaker) wakeForPacketLocked() {
	if s.pendingWorkLocked() || s.sleepUntil.IsZero() || s.deadlineLocked().Before(s.sleepUntil) {
		s.wake()
	}
}

// pendingWorkLocked is work that has arrived since the last pass and that a
// pass has not tried yet: a prefix whose selection changed, which owes a
// triggered update under RFC 8966 section 3.7.2, or a dump somebody asked for.
// Every pass drains both, and `updateActions` clears what a periodic dump
// supersedes, so neither survives a pass that ran.
//
// What a pass tried and could not send is deliberately not here. A rollback
// restores the neighbor's `owed` and its `sentHello`, and both stay restored
// for as long as that one peer cannot be sent to: a peer whose Child SA the
// other end deleted refuses every reservation, and RFC 7296 section 1.4.1
// lets it stay that way. "A pass is owed something" would then be true
// forever, and every packet from every other neighbor would pay for a full
// sweep, which is the amplification this function exists to close.
// noteSendRetryLocked puts that on a timer instead.
//
// `routes.starved` is drained by `starvedActions` on the last line of
// handlePacketLocked, so it is empty by the time the receive path asks. It is
// here for a writer that does not go through that path, and the run loop asks
// too.
func (s *Speaker) pendingWorkLocked() bool {
	return s.updatePending || len(s.routes.dirty) != 0 || len(s.routes.starved) != 0
}

// noteSendRetryLocked schedules the retry for a pass that built something it
// could not send. The rollback has put the work back, and nothing else will
// pick it up: a Hello is retried by `!n.sentHello` and a triggered update by
// the neighbor's own `owed`, both on the next pass, whenever that is. A
// quarter of the hello interval gives a refused Hello fourteen attempts inside
// the three and a half intervals that withdraw the routes through this
// neighbor, and costs a pass rather than a packet. The floor is a millisecond
// rather than anything larger: at the ten millisecond interval Validate
// accepts, a fifty millisecond floor put the first retry after the remote had
// already declared this node dead.
func (s *Speaker) noteSendRetryLocked(now time.Time) {
	s.retryAt = earlier(s.retryAt, now.Add(s.sendRetryInterval()))
}

// sendRetryInterval is how long a pass waits before trying again what it could
// not send. Read from cfg, which New settles and nothing writes afterwards, so
// the sender goroutine may ask too.
func (s *Speaker) sendRetryInterval() time.Duration {
	return max(s.hello/4, time.Millisecond)
}

// deadlineLocked is when the run loop next has to do something on its own,
// with nothing arriving. Run sets the timer from it and records it as
// sleepUntil, and the receive path recomputes it to decide whether a packet
// brought that moment forward.
func (s *Speaker) deadlineLocked() time.Time {
	deadline := earlier(earlier(s.nextHello, s.nextUpdate), s.routes.nextExpiry())
	deadline = earlier(earlier(deadline, s.nextStarveRetry), s.retryAt)
	deadline = earlier(deadline, s.nextRequestSweep)
	for _, n := range s.neighbors {
		if n.alive {
			deadline = earlier(deadline, n.helloExpiry())
			if !n.nextHelloDue.IsZero() {
				deadline = earlier(deadline, n.nextHelloDue)
			}
		}
		if n.haveReportedCost {
			deadline = earlier(deadline, n.ihuExpiry)
		}
		// Carried separately from ihuExpiry, because the two only move
		// together while RTT samples keep arriving. A neighbor that stops
		// sending Timestamp sub-TLVs, or whose clock steps so
		// validTimestampGap refuses every sample, keeps refreshing ihuExpiry
		// and leaves this one where it was; without a term of its own the
		// sweep that drops the stale measurement waits for whatever pass comes
		// next, and the advertised rxcost keeps moving to a measurement that
		// has already expired.
		if n.haveRTT {
			deadline = earlier(deadline, n.rttExpiry)
		}
	}
	return deadline
}

// Run owns the timers and waits for all of its work before returning.
// Remote Hello, IHU and Update deadlines are independent of our send intervals.
func (s *Speaker) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	s.mu.Lock()
	s.nextHello, s.nextUpdate = time.Now(), time.Now()
	s.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := time.Now()
		s.mu.Lock()
		// Cleared before the pass and set again by emitLocked if this pass
		// also fails to send what it builds, so it always names the most
		// recent attempt rather than an old one.
		s.retryAt = time.Time{}
		s.passes++
		s.applyLostLocked()
		s.sweepExpiredLocked(now)
		var actions []sendAction
		helloDue := !now.Before(s.nextHello)
		if helloDue {
			s.nextHello = now.Add(s.hello)
		}
		for _, n := range s.neighbors {
			if helloDue || !n.sentHello {
				actions = append(actions, s.helloAction(n, now))
			}
		}
		if !now.Before(s.nextUpdate) || s.updatePending {
			actions = append(actions, s.updateActions(now)...)
			s.updatePending = false
			if !now.Before(s.nextUpdate) {
				s.nextUpdate = now.Add(s.update)
			}
		} else {
			actions = append(actions, s.triggeredActions(now)...)
		}
		actions = append(actions, s.starvedActions(now)...)
		actions = append(actions, s.retryStarvedLocked(now)...)
		// Emitted before the deadline is computed: emitLocked is where a
		// refused packet is learned about, and the retry it schedules for that is
		// a term of the deadline. Recorded as sleepUntil before the lock goes,
		// so a packet arriving between here and the select compares against
		// the deadline this pass settled on.
		send := s.emitLocked(actions)
		deadline := s.deadlineLocked()
		s.sleepUntil = deadline
		s.mu.Unlock()
		send()
		timer.Reset(max(0, time.Until(deadline)))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.changed:
		case <-timer.C:
		}
	}
}

// routeLogInterval bounds how often a selection change is said out loud at
// info. One neighbor alternating an update and a retraction for one prefix
// drives a change per TLV, and sixty-six of those fit in one packet, each a
// synchronous write on the goroutine holding s.mu. Every change is still
// written at debug, where it costs a level comparison unless somebody asked
// for it, and the info line carries how many it stands for.
//
// Kept at or below a second so an operator watching a flapping mesh still sees
// it move; TestSelectionChangesAreNotOneLogLineEach holds that bound.
const routeLogInterval = time.Second

// installRoute publishes one selection to the forwarding table. Called only
// with s.mu held, after route selection, so the log line and the forwarding
// entry see the same immutable selection.
func (s *Speaker) installRoute(key routeKey, sel routeSelection) {
	desc := key.dest.String()
	if key.source.IsValid() {
		desc = fmt.Sprintf("%s from %s", key.dest, key.source)
	}
	peer := ""
	if sel.neighbor != nil {
		peer = sel.neighbor.peer.ID
		s.mesh.Routes.Set(key.source, key.dest, sel.neighbor.peer)
		slog.Debug("babel route installed", "route", desc, "peer", peer, "metric", sel.cost)
	} else {
		// Held as unreachable rather than removed. The entry still exists,
		// RFC 8966 section 3.5.4, and until it is flushed a packet for this
		// prefix must not follow a shorter one instead.
		s.mesh.Routes.Set(key.source, key.dest, netstack.Unreachable)
		slog.Debug("babel route retracted", "route", desc)
	}
	s.routeChanges++
	now := time.Now()
	if now.Sub(s.routeLogged) < routeLogInterval {
		return
	}
	changes := s.routeChanges
	s.routeChanges, s.routeLogged = 0, now
	if sel.neighbor != nil {
		slog.Info("babel route installed", "route", desc, "peer", peer,
			"metric", sel.cost, "changes_since_last", changes)
	} else {
		slog.Info("babel route retracted", "route", desc, "changes_since_last", changes)
	}
}

func (s *Speaker) sweepExpiredLocked(now time.Time) {
	for _, n := range s.neighbors {
		// The timer half of RFC 8966 Appendix A.1, before liveness, so a
		// neighbor going quiet writes zeros into its history on the way down
		// rather than keeping the quality of its last Hello. Bounded by the
		// vector width: a link silent for an hour costs the same walk as one
		// silent for two intervals.
		for i := 0; i < historyDepth && n.helloInterval > 0 &&
			!n.nextHelloDue.IsZero() && !now.Before(n.nextHelloDue); i++ {
			n.multicastHistory.missed()
			n.nextHelloDue = n.nextHelloDue.Add(n.helloInterval)
		}
		if n.alive && !n.isAlive(now) {
			slog.Info("babel neighbor down", "peer", n.peer.ID)
			n.alive, n.haveReportedCost = false, false
			n.forgetLink()
		}
		if n.haveReportedCost && !now.Before(n.ihuExpiry) {
			n.haveReportedCost = false
		}
		if n.haveRTT && !now.Before(n.rttExpiry) {
			n.haveRTT = false
		}
	}
	// Selection reruns for every prefix, which covers both the link costs that
	// have just gone infinite and the routes that have expired. The routes of
	// an unreachable neighbor are kept: they are unselectable while its link
	// cost is infinite and recover at once if it comes back.
	s.routes.sweepExpired(now)
	s.sweepRequestsLocked(now)
}

// allowSeqnoRequest applies the duplicate suppression of RFC 8966 section
// 3.8.1.2: a request is redundant while a recent one for the same source
// carried a sequence number that is no smaller.
func (s *Speaker) allowSeqnoRequest(index sourceKey, seqno uint16, asker string, now time.Time) bool {
	pending, known := s.pendingSeqno[index]
	if known && now.Before(pending.sentAt.Add(seqnoRequestSuppress)) && !seqnoGT(seqno, pending.seqno) {
		return false
	}
	// The share is checked whether or not the index already exists: taking
	// over an entry another neighbor created would otherwise be free, and one
	// neighbor could hold the whole table through entries it never made.
	if s.pendingByAsker[asker] >= maxPendingSeqnoPerNeighbor && (!known || pending.asker != asker) {
		return false // see maxPendingSeqno
	}
	if !known && len(s.pendingSeqno) >= maxPendingSeqno {
		return false
	}
	s.recordSeqnoRequest(index, seqno, asker, now)
	return true
}

// recordSeqnoRequest replaces one entry of the suppression table, keeping the
// per-asker counts in step with it.
func (s *Speaker) recordSeqnoRequest(index sourceKey, seqno uint16, asker string, now time.Time) {
	if previous, known := s.pendingSeqno[index]; known {
		s.releaseSeqnoRequest(previous)
	}
	s.pendingSeqno[index] = pendingSeqno{seqno: seqno, sentAt: now, asker: asker}
	s.pendingByAsker[asker]++
	s.noteRequestSweep(now)
}

func (s *Speaker) releaseSeqnoRequest(entry pendingSeqno) {
	if s.pendingByAsker[entry.asker] <= 1 {
		delete(s.pendingByAsker, entry.asker)
		return
	}
	s.pendingByAsker[entry.asker]--
}

// noteRequestSweep folds one suppression window into the sweep deadline.
func (s *Speaker) noteRequestSweep(at time.Time) {
	s.nextRequestSweep = earlier(s.nextRequestSweep, at.Add(seqnoRequestSuppress))
}

func (s *Speaker) sweepRequestsLocked(now time.Time) {
	// Cleared first and rebuilt by the walk, which is the one pass that reads
	// every window, so the kept minimum is exact again afterwards.
	s.nextRequestSweep = time.Time{}
	for index, pending := range s.pendingSeqno {
		if !now.Before(pending.sentAt.Add(seqnoRequestSuppress)) {
			s.releaseSeqnoRequest(pending)
			delete(s.pendingSeqno, index)
			continue
		}
		s.noteRequestSweep(pending.sentAt)
	}
	// askedSeqno expires on the same window. It is keyed by router id, which
	// the peer chooses, and by neighbor pointer, so an entry left behind pins
	// a retired neighborState and everything it advertised.
	for index, at := range s.askedSeqno {
		if !now.Before(at.Add(seqnoRequestSuppress)) {
			delete(s.askedSeqno, index)
			continue
		}
		s.noteRequestSweep(at)
	}
}

// NeighborStat is one neighbor as an operator sees it: what `birdc show babel
// neighbors` reports, plus the packets this node's own dataplane could not
// hand to that peer, which BIRD has no equivalent of.
type NeighborStat struct {
	Peer string
	// Addr is the neighbor's link-local address inside the tunnel, which is
	// the address BIRD prints in its first column.
	Addr  netip.Addr
	Alive bool
	Cost  uint16
	// ReportedCost is the rxcost the neighbor last sent back in an IHU, and
	// HaveReportedCost is false until one has arrived. Cost is this node's
	// view of the link and this is the neighbor's, so a link that carries in
	// one direction only can be told from one that carries in neither.
	ReportedCost     uint16
	HaveReportedCost bool
	// RTT is the round trip RFC 9616 measured, valid only when HaveRTT is.
	RTT     time.Duration
	HaveRTT bool
	// Expires is how long the neighbor has left before its Hello deadline
	// passes, zero once it already has.
	Expires time.Duration
	Routes  int
	// Dropped counts the packets the dataplane refused to queue for this
	// neighbor, both its control traffic and whatever the mesh was forwarding
	// through it.
	Dropped uint64
	// SendFailed counts the packets the transport lost after this node had
	// sealed them, which is the link failing rather than this node running
	// out of room.
	SendFailed uint64
}

// Stats is a consistent snapshot of the speaker for a metrics endpoint. It
// takes the same lock the protocol runs under, so it is a point in time rather
// than a set of independently sampled counters.
type Stats struct {
	Neighbors []NeighborStat
	Selected  int
	// Prefixes is every key this speaker holds, learned and originated
	// together, so a node whose routes are all retracted can be told from one
	// that has heard nothing at all.
	Prefixes   int
	Originated int
}

func (s *Speaker) Stats() Stats {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := Stats{
		Neighbors:  make([]NeighborStat, 0, len(s.neighbors)),
		Originated: len(s.originate),
	}
	received := make(map[*neighborState]int, len(s.neighbors))
	for _, entry := range s.routes.entries {
		if entry.selected.neighbor != nil {
			stats.Selected++
		}
		for neighbor := range entry.routes {
			received[neighbor]++
		}
	}
	// adoptOriginatedLocked deletes an originated prefix's entry, so the two
	// maps are disjoint in the steady state and the sum is the key count. The
	// membership test covers the window where a neighbor has re-advertised a
	// prefix this node originates and the entry is back.
	stats.Prefixes = len(s.routes.entries)
	for key := range s.originate {
		if _, present := s.routes.entries[key]; !present {
			stats.Prefixes++
		}
	}
	for _, neighbor := range s.neighbors {
		stats.Neighbors = append(stats.Neighbors, NeighborStat{
			Peer:             neighbor.peer.ID,
			Addr:             neighbor.addr,
			Alive:            neighbor.isAlive(now),
			Cost:             neighbor.linkCost(now, s.cost),
			ReportedCost:     neighbor.reportedCost,
			HaveReportedCost: neighbor.haveReportedCost,
			RTT:              neighbor.measuredRTT,
			HaveRTT:          neighbor.haveRTT,
			Expires:          remaining(now, neighbor.helloExpiry()),
			Routes:           received[neighbor],
			Dropped:          neighbor.peer.Dropped(),
			SendFailed:       neighbor.peer.SendFailed(),
		})
	}
	sort.Slice(stats.Neighbors, func(i, j int) bool { return stats.Neighbors[i].Peer < stats.Neighbors[j].Peer })
	return stats
}

// remaining is how long is left until deadline, and zero once it has passed or
// was never set. A negative duration in an operator's "expires" column reads
// as a bug in the column rather than as a neighbor that is already late.
func remaining(now, deadline time.Time) time.Duration {
	if deadline.IsZero() || !now.Before(deadline) {
		return 0
	}
	return deadline.Sub(now)
}

// Originated is every prefix this node announces itself, as configured and as
// the speaker holds it. A caller comparing it against the config file is
// comparing what took effect against what was asked for.
func (s *Speaker) Originated() []OriginatedRoute {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]OriginatedRoute, 0, len(s.originate))
	for key := range s.originate {
		out = append(out, OriginatedRoute{Destination: key.dest, Source: key.source})
	}
	slices.SortFunc(out, func(a, b OriginatedRoute) int {
		return compareKey(a.Destination, a.Source, b.Destination, b.Source)
	})
	return out
}

// compareKey orders two route keys by destination and then by source prefix,
// on the addresses rather than on their text. Comparing the text puts
// 10.0.0.0/8 before 9.0.0.0/8, and it allocates two strings per comparison,
// which at the route table's own limit is where a whole dump's cost goes.
func compareKey(aDest, aSource, bDest, bSource netip.Prefix) int {
	if c := comparePrefix(aDest, bDest); c != 0 {
		return c
	}
	return comparePrefix(aSource, bSource)
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return cmp.Compare(a.Bits(), b.Bits())
}

// RouteStat is one prefix of the Babel route table as an operator reads it:
// the selected route, where it points, and how many neighbors offered one.
// Via is empty for a prefix held unreachable, which a retraction leaves behind
// so a packet does not follow a shorter prefix instead.
type RouteStat struct {
	Destination netip.Prefix
	// Source is invalid on an ordinary route and set on a source-specific one,
	// where the pair is the key rather than the destination alone.
	Source     netip.Prefix
	Via        string
	Metric     uint16
	RouterID   [8]byte
	Seqno      uint16
	Candidates int
	Originated bool
}

// RouteDump is every prefix this speaker holds, taken under the same lock the
// protocol runs under so the table is a moment rather than a walk across
// several. It is the diagnostic BIRD answered with `show route`, and it is
// deliberately the route table rather than the forwarding table: a prefix with
// no usable route still appears, which is the case an operator is looking for.
func (s *Speaker) RouteDump() []RouteStat {
	out := s.routeStats()
	// Ordered outside the lock. The walk has to be one moment and an ordering
	// of its result does not, and at maxRouteKeys the sort is an order of
	// magnitude more work than the walk, so holding s.mu across it stops every
	// neighbor's receive path for as long as a reader takes.
	slices.SortFunc(out, func(a, b RouteStat) int {
		return compareKey(a.Destination, a.Source, b.Destination, b.Source)
	})
	return out
}

func (s *Speaker) routeStats() []RouteStat {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Both maps, the way advertisableKeys reads both: adoptOriginatedLocked
	// deletes a prefix's entry when this node takes it over, so a walk of the
	// route table alone omits everything this node announces, which is the
	// half an operator checks first.
	out := make([]RouteStat, 0, len(s.originate)+len(s.routes.entries))
	seen := make(map[routeKey]struct{}, len(s.originate)+len(s.routes.entries))
	add := func(key routeKey) {
		if _, done := seen[key]; done {
			return
		}
		seen[key] = struct{}{}
		_, originated := s.originate[key]
		stat := RouteStat{
			Destination: key.dest,
			Source:      key.source,
			Metric:      MetricInfinity,
			Originated:  originated,
		}
		if originated {
			// A prefix this node originates is advertised at metric zero and
			// points at nowhere else, whatever a neighbor is still saying
			// about it.
			stat.Metric = 0
		}
		if entry := s.routes.entries[key]; entry != nil {
			stat.Candidates = len(entry.routes)
			if !originated && entry.selected.neighbor != nil {
				stat.Via = entry.selected.neighbor.peer.ID
				stat.Metric = entry.selected.cost
				stat.RouterID = entry.selected.routerID
				stat.Seqno = entry.selected.seqno
			}
		}
		out = append(out, stat)
	}
	for key := range s.originate {
		add(key)
	}
	for key := range s.routes.entries {
		add(key)
	}
	return out
}
