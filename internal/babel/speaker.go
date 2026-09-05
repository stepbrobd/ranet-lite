// Package babel implements an RFC 8966 Appendix E stub over ESP tunnels.
// It originates local prefixes, learns ordinary and source-specific routes,
// and never redistributes learned routes. Control packets bypass the TUN.
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

// Speaker.mu serializes all protocol state and forwarding-table changes.
// Packet transmission always happens after unlocking: a slow peer cannot
// prevent a route retraction, and in-memory transports may re-enter Receive.
type Speaker struct {
	cfg  Config
	mesh *netstack.Mesh

	mu            sync.Mutex
	neighbors     map[string]*neighborState
	originate     map[netip.Prefix]struct{}
	routes        *routeTable
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
		neighbors:   make(map[string]*neighborState),
		originate:   make(map[netip.Prefix]struct{}),
		originSeqno: 1,
		changed:     make(chan struct{}, 1),
	}
	s.routes = newRouteTable(s.installRoute)
	return s, nil
}

func (s *Speaker) AddPeer(peer *netstack.Peer) *PeerHandle {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.neighbors[peer.ID]; old != nil {
		s.routes.expireNeighbor(old, time.Now())
	}
	n := &neighborState{peer: peer}
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
	if !prefix.IsValid() {
		return
	}
	prefix = prefix.Masked()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.originate[prefix] = struct{}{}
	for key, entry := range s.routes.entries {
		if key.dest == prefix {
			if entry.selected.neighbor != nil {
				s.installRoute(key, routeSelection{})
			}
			delete(s.routes.entries, key)
		}
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
			actions = append(actions, s.updateActions()...)
			s.updatePending = false
			if !now.Before(nextUpdate) {
				nextUpdate = now.Add(s.cfg.UpdateInterval)
			}
		}
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
		s.mesh.Routes.Remove(key.source, key.dest)
		slog.Info("babel route retracted", "route", desc)
	}
}

func (s *Speaker) sweepExpiredLocked(now time.Time) {
	for _, n := range s.neighbors {
		if n.alive && !n.isAlive(now) {
			slog.Info("babel neighbor down", "peer", n.peer.ID)
			n.alive, n.haveReportedCost = false, false
			s.routes.expireNeighbor(n, now)
		}
		if n.haveReportedCost && !now.Before(n.ihuExpiry) {
			n.haveReportedCost = false
		}
	}
	s.routes.sweepExpired(now)
}
