package babel

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

// fillRouteTable builds a speaker holding prefixes routes, each one learned
// from every neighbor, which is the shape a full mesh produces.
func fillRouteTable(tb testing.TB, neighbors, prefixes int) *Speaker {
	tb.Helper()
	// The table is built through the real acquisition path, which says every
	// selection out loud. Without this the measurement is interleaved with
	// sixteen thousand log lines.
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	tb.Cleanup(func() { slog.SetDefault(previous) })
	s, err := New(Config{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		tb.Fatal(err)
	}
	now := time.Now()
	var states []*neighborState
	for i := range neighbors {
		handle := s.AddPeer(netstack.NewPeer(fmt.Sprintf("peer%d", i), nil, nil))
		n := handle.state
		n.alive, n.lastHelloTime, n.helloInterval = true, now, 4*time.Second
		n.haveReportedCost, n.reportedCost, n.ihuExpiry = true, 96, now.Add(time.Minute)
		states = append(states, n)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range prefixes {
		addr := netip.AddrFrom16([16]byte{0xfd, 0, byte(i >> 8), byte(i), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		key := routeKey{dest: netip.PrefixFrom(addr, 128)}
		for j, n := range states {
			s.routes.update(n, key, advertisement{routerID: [8]byte{byte(j)}, seqno: 1, metric: uint16(100 + j)},
				time.Minute, now)
		}
	}
	if got := len(s.routes.entries); got != prefixes {
		tb.Fatalf("the table holds %d prefixes, want %d", got, prefixes)
	}
	return s
}

// BenchmarkRunLoopPass measures what one wake of the run loop costs, which is
// a reselection of every prefix in the table under the lock that also carries
// every neighbor's receive path, the hello emitter and route installation. It
// is the number wakeForPacketLocked exists for: a pass is affordable at the
// rate the timers ask for one, and not at the rate a neighbor can send.
//
// The figures quoted at wakeForPacketLocked were taken on an otherwise idle
// Apple M2 Max. A machine doing anything else multiplies them -- measured at
// six times with the cores saturated -- which makes the argument stronger
// rather than weaker, so they are a floor and not an estimate.
func BenchmarkRunLoopPass(b *testing.B) {
	for _, prefixes := range []int{1000, maxRouteKeys} {
		b.Run(fmt.Sprintf("prefixes=%d", prefixes), func(b *testing.B) {
			s := fillRouteTable(b, 8, prefixes)
			b.ResetTimer()
			for b.Loop() {
				now := time.Now()
				s.mu.Lock()
				s.sweepExpiredLocked(now)
				actions := s.triggeredActions(now)
				actions = append(actions, s.starvedActions(now)...)
				actions = append(actions, s.retryStarvedLocked(now)...)
				_, _ = actions, s.deadlineLocked()
				s.mu.Unlock()
			}
		})
	}
}

// BenchmarkRunLoopDeadline is the part of a pass the receive path repeats to
// decide whether an arriving packet brought a deadline forward. It has to stay
// far below the pass it is there to avoid.
func BenchmarkRunLoopDeadline(b *testing.B) {
	s := fillRouteTable(b, 8, maxRouteKeys)
	b.ResetTimer()
	for b.Loop() {
		s.mu.Lock()
		_ = s.deadlineLocked()
		s.mu.Unlock()
	}
}
