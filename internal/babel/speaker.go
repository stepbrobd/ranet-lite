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
//   - 3.8.1.2: a request for a prefix whose selected next hop is the requester
//     is forwarded onwards rather than answered, since split horizon would
//     make the answer a retraction.
//   - 3.8.2.1 and 3.8.2.3: seqno requests are suppressed for a short window
//     instead of being resent on a timer, and a selected route is not
//     refreshed with a route request shortly before it expires.
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

// Speaker.mu serializes all protocol state and forwarding-table changes.
// Packet transmission always happens after unlocking: a slow peer cannot
// prevent a route retraction, and in-memory transports may re-enter Receive.
type Speaker struct {
	cfg  Config
	mesh *netstack.Mesh

	mu            sync.Mutex
	neighbors     map[string]*neighborState
	originate     map[routeKey]struct{}
	routes        *routeTable
	pendingSeqno  map[sourceKey]pendingSeqno
	originSeqno   uint16
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
		neighbors:    make(map[string]*neighborState),
		originate:    make(map[routeKey]struct{}),
		pendingSeqno: make(map[sourceKey]pendingSeqno),
		originSeqno:  1,
		changed:      make(chan struct{}, 1),
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
// ordinary route, which is what RFC 9079 section 5 says such an entry means.
func (s *Speaker) OriginateFrom(dest, source netip.Prefix) {
	if !dest.IsValid() {
		return
	}
	key := routeKey{dest: dest.Masked()}
	if source.IsValid() && source.Bits() > 0 {
		if source.Addr().Is4() != dest.Addr().Is4() {
			// The Source Prefix sub-TLV is read under the destination's address
			// encoding, so the pair cannot even be expressed on the wire.
			slog.Warn("babel ignoring source-specific origination across address families",
				"route", dest, "from", source)
			return
		}
		key.source = source.Masked()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.originate[key] = struct{}{}
	if entry := s.routes.entries[key]; entry != nil {
		if entry.selected.neighbor != nil {
			s.installRoute(key, routeSelection{})
		}
		delete(s.routes.entries, key)
	}
	s.updatePending = true
	s.wake()
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
		deadline := earlier(earlier(nextHello, nextUpdate), s.routes.nextExpiry())
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
}
