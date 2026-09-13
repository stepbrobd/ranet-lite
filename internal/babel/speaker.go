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
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/netip"
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
}

// Request timeout, RFC 8966 Appendix B. A request for the same source within
// this window is redundant (section 3.8.1.2) and is dropped instead of
// forwarded.
const seqnoRequestSuppress = 2 * time.Second

// maxPendingSeqno bounds that table. An entry is only ever created for a
// prefix this node has a route for, which bounds one half of the index; the
// other half is the router id the requester wrote into the packet, which
// nothing bounds, and eighty seqno requests fit in a single packet. Past the
// cap the request is not forwarded, which is what the suppression above does
// with a redundant one and is the rate limiting RFC 8966 section 3.8.1.2 asks
// for. Requests this node sends on its own behalf are not subject to it: they
// come from its own route table, which is already bounded.
const maxPendingSeqno = 1 << 12

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
}

// Speaker.mu serializes all protocol state and forwarding-table changes.
// Packet transmission always happens after unlocking: a slow peer cannot
// prevent a route retraction, and in-memory transports may re-enter Receive.
type Speaker struct {
	cfg  Config
	mesh *netstack.Mesh

	mu           sync.Mutex
	neighbors    map[string]*neighborState
	originate    map[routeKey]struct{}
	routes       *routeTable
	pendingSeqno map[sourceKey]pendingSeqno
	// askedSeqno is the same suppression for requests this node originates,
	// but indexed by neighbor as well. RFC 8966 section 3.8.2.1 wants every
	// neighbor holding an unfeasible route asked, and pendingSeqno's index has
	// no neighbor in it, so it cannot tell "already asked this one" from
	// "already asked somebody".
	askedSeqno    map[askedKey]time.Time
	starveRetries map[sourceKey]*starveRetry
	originSeqno   uint16
	// raisedSeqno bounds originSeqno to one raise per received packet.
	raisedSeqno   bool
	updatePending bool
	changed       chan struct{}
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

func New(cfg Config, mesh *netstack.Mesh) (*Speaker, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.setDefaults()
	if cfg.RouterID == ([8]byte{}) {
		rand.Read(cfg.RouterID[:])
	}
	if !cfg.LinkLocalAddr.IsValid() {
		cfg.LinkLocalAddr = randomLinkLocal()
	}
	s := &Speaker{
		cfg: cfg, mesh: mesh,
		neighbors:     make(map[string]*neighborState),
		originate:     make(map[routeKey]struct{}),
		pendingSeqno:  make(map[sourceKey]pendingSeqno),
		askedSeqno:    make(map[askedKey]time.Time),
		starveRetries: make(map[sourceKey]*starveRetry),
		originSeqno:   1,
		changed:       make(chan struct{}, 1),
	}
	s.routes = newRouteTable(s.installRoute)
	s.routes.forget = func(key routeKey) { s.mesh.Routes.Remove(key.source, key.dest) }
	// RFC 8966 Appendix A.3 recommends a hysteresis time constant of a small
	// multiple of the Hello interval. One link's base cost is the scale at
	// which a metric change is worth a triggered update rather than a wait for
	// the next periodic dump.
	s.routes.tau, s.routes.trigger = 3*cfg.HelloInterval, cfg.Cost.RxCost
	return s, nil
}

func (s *Speaker) AddPeer(peer *netstack.Peer) *PeerHandle {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.neighbors[peer.ID]; old != nil {
		s.routes.expireNeighbor(old, time.Now())
	}
	n := &neighborState{peer: peer, advertised: make(map[routeKey]struct{})}
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
	src, payload, err := parsePacket(raw, s.cfg.LinkLocalAddr)
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
	actions := s.handlePacketLocked(n, payload, time.Now())
	s.wake()
	s.mu.Unlock()
	s.sendActions(actions)
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

func (s *Speaker) wake() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// Run owns the timers and waits for all of its work before returning.
// Remote Hello, IHU and Update deadlines are independent of our send intervals.
func (s *Speaker) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	nextHello, nextUpdate := time.Now(), time.Now()
	var seqno uint16
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := time.Now()
		s.mu.Lock()
		s.sweepExpiredLocked(now)
		var actions []sendAction
		helloDue := !now.Before(nextHello)
		if helloDue {
			seqno++
			nextHello = now.Add(s.cfg.HelloInterval)
		}
		for _, n := range s.neighbors {
			if helloDue || !n.sentHello {
				actions = append(actions, s.helloAction(n, seqno, now))
			}
		}
		if !now.Before(nextUpdate) || s.updatePending {
			actions = append(actions, s.updateActions(now)...)
			s.updatePending = false
			if !now.Before(nextUpdate) {
				nextUpdate = now.Add(s.cfg.UpdateInterval)
			}
		} else {
			actions = append(actions, s.triggeredActions(now)...)
		}
		actions = append(actions, s.starvedActions(now)...)
		actions = append(actions, s.retryStarvedLocked(now)...)
		deadline := earlier(earlier(nextHello, nextUpdate), s.routes.nextExpiry())
		for _, retry := range s.starveRetries {
			deadline = earlier(deadline, retry.nextAt)
		}
		for _, n := range s.neighbors {
			if n.alive {
				deadline = earlier(deadline, n.helloExpiry())
			}
			if n.haveReportedCost {
				deadline = earlier(deadline, n.ihuExpiry)
			}
		}
		s.mu.Unlock()
		s.sendActions(actions)
		timer.Reset(max(0, time.Until(deadline)))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.changed:
		case <-timer.C:
		}
	}
}

// Called only with s.mu held, after route selection. Logging and forwarding
// publication see the same immutable selection.
func (s *Speaker) installRoute(key routeKey, sel routeSelection) {
	desc := key.dest.String()
	if key.source.IsValid() {
		desc = fmt.Sprintf("%s from %s", key.dest, key.source)
	}
	if sel.neighbor != nil {
		s.mesh.Routes.Set(key.source, key.dest, sel.neighbor.peer)
		slog.Info("babel route installed", "route", desc, "peer", sel.neighbor.peer.ID, "metric", sel.cost)
	} else {
		// Held as unreachable rather than removed. The entry still exists,
		// RFC 8966 section 3.5.4, and until it is flushed a packet for this
		// prefix must not follow a shorter one instead.
		s.mesh.Routes.Set(key.source, key.dest, netstack.Unreachable)
		slog.Info("babel route retracted", "route", desc)
	}
}

func (s *Speaker) sweepExpiredLocked(now time.Time) {
	for _, n := range s.neighbors {
		if n.alive && !n.isAlive(now) {
			slog.Info("babel neighbor down", "peer", n.peer.ID)
			n.alive, n.haveReportedCost = false, false
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
func (s *Speaker) allowSeqnoRequest(index sourceKey, seqno uint16, now time.Time) bool {
	pending, known := s.pendingSeqno[index]
	if known && now.Before(pending.sentAt.Add(seqnoRequestSuppress)) && !seqnoGT(seqno, pending.seqno) {
		return false
	}
	if !known && len(s.pendingSeqno) >= maxPendingSeqno {
		return false // see maxPendingSeqno
	}
	s.pendingSeqno[index] = pendingSeqno{seqno: seqno, sentAt: now}
	return true
}

func (s *Speaker) sweepRequestsLocked(now time.Time) {
	for index, pending := range s.pendingSeqno {
		if !now.Before(pending.sentAt.Add(seqnoRequestSuppress)) {
			delete(s.pendingSeqno, index)
		}
	}
	// askedSeqno expires on the same window. It is keyed by router id, which
	// the peer chooses, and by neighbor pointer, so an entry left behind pins
	// a retired neighborState and everything it advertised.
	for index, at := range s.askedSeqno {
		if !now.Before(at.Add(seqnoRequestSuppress)) {
			delete(s.askedSeqno, index)
		}
	}
}

// NeighborStat is one neighbor as an operator sees it, the same three facts
// `birdc show babel neighbors` reports.
type NeighborStat struct {
	Peer   string
	Alive  bool
	Cost   uint16
	Routes int
	// Dropped is what the dataplane refused to queue for this neighbor, both
	// its control traffic and whatever the mesh was forwarding through it.
	Dropped uint64
}

// Stats is a consistent snapshot of the speaker for a metrics endpoint. It
// takes the same lock the protocol runs under, so it is a point in time rather
// than a set of independently sampled counters.
type Stats struct {
	Neighbors  []NeighborStat
	Selected   int
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
	for _, neighbor := range s.neighbors {
		stats.Neighbors = append(stats.Neighbors, NeighborStat{
			Peer:    neighbor.peer.ID,
			Alive:   neighbor.isAlive(now),
			Cost:    neighbor.linkCost(now),
			Routes:  received[neighbor],
			Dropped: neighbor.peer.Dropped(),
		})
	}
	sort.Slice(stats.Neighbors, func(i, j int) bool { return stats.Neighbors[i].Peer < stats.Neighbors[j].Peer })
	return stats
}
