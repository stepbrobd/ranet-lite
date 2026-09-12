package babel

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

func routePacket(prefix netip.Prefix, routerID byte, metric, interval uint16) []byte {
	return buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup, EncodePacket([]RawTLV{
		EncodeRouterID([8]byte{routerID}),
		EncodeUpdate(Update{AE: aeFor(prefix), Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(),
			Seqno: 1, Metric: metric, Interval: interval}),
	}))
}

func addReachablePeer(s *Speaker, id string, cost uint16) *netstack.Peer {
	p := netstack.NewPeer(id, func(raw []byte, _ byte) ([]byte, error) { return raw, nil }, func([]byte) error { return nil })
	s.AddPeer(p)
	s.Receive(p, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup, EncodePacket([]RawTLV{
		EncodeHello(Hello{Seqno: 1, Interval: 1000}), EncodeIHU(IHU{RxCost: cost, Interval: 1000}),
	})))
	return p
}

func TestStubSelectsLowestCostAndReselectsOnWorsening(t *testing.T) {
	s, _, _ := captureSpeaker(t, Config{})
	dest := netip.MustParsePrefix("10.5.0.0/16")
	src := netip.MustParseAddr("192.0.2.1")
	a := addReachablePeer(s, "a", 100)
	b := addReachablePeer(s, "b", 10)
	s.Receive(a, routePacket(dest, 1, 20, 1000))
	s.Receive(b, routePacket(dest, 2, 20, 1000))
	if got, _ := s.mesh.Routes.Lookup(src, dest.Addr()); got != b {
		t.Error("did not select the cheaper link to an independent origin")
	}
	// Establish b even on an implementation with a feasibility restriction,
	// then worsen its advertised metric while a remains a usable fallback.
	s.Receive(b, routePacket(dest, 2, 1, 1000))
	s.Receive(b, routePacket(dest, 2, 500, 1000))
	if got, _ := s.mesh.Routes.Lookup(src, dest.Addr()); got != a {
		t.Error("kept a worsened route instead of selecting the existing fallback")
	}
}

func TestStubPrefersLocalPrefixAfterRouterIDChanges(t *testing.T) {
	s, _, _ := captureSpeaker(t, Config{})
	p := addReachablePeer(s, "remote", 10)
	dest := netip.MustParsePrefix("10.5.0.0/16")
	s.Originate(dest)
	s.Receive(p, routePacket(dest, 99, 10, 1000))
	if _, ok := s.mesh.Routes.Lookup(netip.MustParseAddr("192.0.2.1"), dest.Addr()); ok {
		t.Fatal("installed a reflected local prefix from a previous router ID")
	}
}

func TestReceiveFromReplacedPeerCannotChangeRoutes(t *testing.T) {
	s, _, _ := captureSpeaker(t, Config{})
	old := addReachablePeer(s, "remote", 10)
	addReachablePeer(s, "remote", 10)
	dest := netip.MustParsePrefix("10.5.0.0/16")
	s.Receive(old, routePacket(dest, 99, 10, 1000))
	if _, ok := s.mesh.Routes.Lookup(netip.MustParseAddr("192.0.2.1"), dest.Addr()); ok {
		t.Fatal("a retired session installed a route through its replacement")
	}
}

func TestExpiryUsesRemoteDeadlines(t *testing.T) {
	for _, expiry := range []string{"update", "ihu", "hello"} {
		t.Run(expiry, func(t *testing.T) {
			s, _, _ := captureSpeaker(t, Config{HelloInterval: time.Second, UpdateInterval: 4 * time.Second})
			p := addReachablePeer(s, "remote", 10)
			dest := netip.MustParsePrefix("10.5.0.0/16")
			interval := uint16(1000)
			switch expiry {
			case "update":
				interval = 1
			case "ihu":
				s.Receive(p, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup,
					EncodePacket([]RawTLV{EncodeIHU(IHU{RxCost: 10, Interval: 1})})))
			case "hello":
				s.Receive(p, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup,
					EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 2, Interval: 1})})))
			}
			s.Receive(p, routePacket(dest, 1, 20, interval))
			if len(s.mesh.Routes.Debug()) != 1 {
				t.Fatal("route never became reachable")
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); _ = s.Run(ctx) }()
			defer func() { cancel(); <-done }()
			// The prefix stops forwarding at expiry. Its entry is held a while
			// longer as unreachable, RFC 8966 section 3.5.4, so what is under
			// test here is the lookup rather than the size of the table.
			deadline := time.Now().Add(500 * time.Millisecond)
			for forwards(s.mesh, dest) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if forwards(s.mesh, dest) {
				t.Fatal("route expiry waited for the much slower local timers")
			}
		})
	}
}

// forwards reports whether the mesh would send a packet for this prefix to a
// peer. A prefix held as unreachable answers false, which is the point of the
// hold: it does not forward and it does not fall through to a covering route.
func forwards(mesh *netstack.Mesh, dest netip.Prefix) bool {
	_, ok := mesh.Routes.Lookup(dest.Addr(), dest.Addr())
	return ok
}
