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
	s, err := New(Config{}, Routes{}, Runtime{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
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
				// The pass drains what it advertises, so without this every
				// iteration after the first measures a pass with the
				// advertise half absent: 20.7 ms against 77.6 ms at
				// maxRouteKeys, and the figures quoted elsewhere are the
				// second number.
				b.StopTimer()
				s.mu.Lock()
				for key := range s.routes.entries {
					s.routes.dirty[key] = struct{}{}
				}
				s.mu.Unlock()
				b.StartTimer()

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

// BenchmarkEmitDump is the other half of a pass: taking a place for every
// packet of a full dump and recording the undo of every prefix in it. The
// rollback is per packet, so the undos have to be split across the packets
// that carry them, and the split walks the list rather than rescanning it for
// each packet. See takeUndos.
func BenchmarkEmitDump(b *testing.B) {
	for _, prefixes := range []int{1000, maxRouteKeys} {
		b.Run(fmt.Sprintf("prefixes=%d", prefixes), func(b *testing.B) {
			s := fillRouteTable(b, 8, prefixes)
			// fillRouteTable's peers carry no transport, because nothing else
			// here sends. These do, so the reservation and the split across
			// packets are measured rather than skipped.
			s.mu.Lock()
			for _, n := range s.neighbors {
				n.peer = netstack.NewPeer(n.peer.ID,
					func(raw []byte, _ byte) ([]byte, error) { return raw, nil },
					func([]byte) error { return nil })
			}
			s.mu.Unlock()
			b.ResetTimer()
			for b.Loop() {
				now := time.Now()
				s.mu.Lock()
				send := s.emitLocked(s.updateActions(now))
				s.mu.Unlock()
				send()
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

// BenchmarkReceiveHello measures what an arriving Hello costs, the figure
// the wake decision in wakeForPacketLocked trades against a full pass. It is
// measured on the same eight-neighbor table BenchmarkRunLoopPass uses, because
// a figure taken on a one-neighbor table and set against a pass taken on this
// one compares two different fixtures.
//
// The neighbor holds the whole table, which is the shape one peer can build:
// maxRouteKeys is table-wide and has no per-neighbor share.
func BenchmarkReceiveHello(b *testing.B) {
	hello := EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 1, Interval: 400})})
	for _, neighbors := range []int{1, 8} {
		b.Run(fmt.Sprintf("neighbors=%d", neighbors), func(b *testing.B) {
			s := fillRouteTable(b, neighbors, maxRouteKeys)
			n := s.neighbors["peer0"]
			n.addr = netip.MustParseAddr("fe80::2")
			b.ResetTimer()
			for b.Loop() {
				s.mu.Lock()
				s.handlePacketLocked(n, hello, time.Now())
				s.mu.Unlock()
			}
		})
	}
}
