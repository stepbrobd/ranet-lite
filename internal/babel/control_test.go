package babel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

func routePacket(prefix netip.Prefix, routerID byte, metric, interval uint16) []byte {
	return buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup, EncodePacket([]RawTLV{
		EncodeRouterID([8]byte{routerID}),
		EncodeUpdate(Update{AE: updateAE(prefix), Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(),
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
			s, _, _ := captureSpeaker(t, Config{Hello: dur(time.Second), Update: dur(4 * time.Second)})
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
// peer. A prefix held as unreachable answers false: it does not forward and it
// does not fall through to a covering route.
func forwards(mesh *netstack.Mesh, dest netip.Prefix) bool {
	_, ok := mesh.Routes.Lookup(dest.Addr(), dest.Addr())
	return ok
}

// RFC 8966 section 4.6.9: the next hop for an Update "is taken from the last
// preceding Next Hop TLV with a matching address family ... if no such TLV
// exists, it is taken from the network-layer source address of this packet if
// it belongs to the same address family as the prefix being announced;
// otherwise, this Update MUST be ignored." Every babel packet here is IPv6, so
// an AE 1 prefix has neither unless the packet says so, and installing one
// anyway points a route at an address this node was never given.
func TestIPv4UpdateWithNoNextHopIsIgnored(t *testing.T) {
	dest := netip.MustParsePrefix("10.5.0.0/16")
	src := netip.MustParseAddr("192.0.2.1")
	plain := EncodeUpdate(Update{AE: AEIPv4, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
		Seqno: 1, Metric: 20, Interval: 1000})

	s, _, _ := captureSpeaker(t, Config{})
	a := addReachablePeer(s, "a", 100)
	s.Receive(a, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup,
		EncodePacket([]RawTLV{EncodeRouterID([8]byte{1}), plain})))
	if got, _ := s.mesh.Routes.Lookup(src, dest.Addr()); got != nil {
		t.Error("an IPv4 update with no next hop of its own family was installed")
	}

	// Nor does an IPv6 next hop that happens to spell an IPv4 address. Section
	// 4.6.9 matches "the last preceding Next Hop TLV with a matching address
	// family (IPv4 or IPv6)", and the family is the address encoding, not the
	// shape of the bytes: net.IP.To4 reports ::ffff:a.b.c.d as IPv4 and would
	// enable every AE 1 Update behind an AE 2 TLV.
	mapped := RawTLV{Type: TLVNextHop, Body: append([]byte{AEIPv6, 0},
		net.ParseIP("::ffff:192.0.2.254").To16()...)}
	s.Receive(a, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup, EncodePacket([]RawTLV{
		mapped, EncodeRouterID([8]byte{1}), plain,
	})))
	if got, _ := s.mesh.Routes.Lookup(src, dest.Addr()); got != nil {
		t.Error("an IPv4 update behind a v4-mapped IPv6 next hop was installed")
	}

	// The same prefix with a next hop the packet actually names is taken.
	s.Receive(a, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup, EncodePacket([]RawTLV{
		EncodeNextHop(net.ParseIP("192.0.2.254")),
		EncodeRouterID([8]byte{1}), plain,
	})))
	if got, _ := s.mesh.Routes.Lookup(src, dest.Addr()); got != a {
		t.Error("an IPv4 update carrying a next hop was ignored too")
	}

	// And the withdrawal of it needs no next hop, by RFC 8966 section 4.6.9:
	// "If the metric field is FFFF hexadecimal, this TLV specifies a
	// retraction. In that case, the router-id, next hop, and seqno are not
	// used." RFC 9229 section 2.1 says a node "MAY send IPv4 retractions only"
	// on a link with no IPv4 address, which is this one.
	s.Receive(a, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup, EncodePacket([]RawTLV{
		EncodeRouterID([8]byte{1}),
		EncodeUpdate(Update{AE: AEIPv4, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
			Seqno: 2, Metric: MetricInfinity, Interval: 1000}),
	})))
	if got, _ := s.mesh.Routes.Lookup(src, dest.Addr()); got == a {
		t.Error("an IPv4 retraction was ignored, so the prefix is held until it expires and advertised onward meanwhile")
	}
}

// RFC 8966 section 4.6.6 on the IHU's Interval: "An upper bound, expressed in
// centiseconds, on the time after which the sending node will send a new IHU;
// this MUST NOT be 0." The hold is computed from it, so honoring a zero puts
// the expiry at the moment it arrived, takes the link cost to infinity and
// unselects every route through this neighbor in the same call. One eight-byte
// TLV then retracts everything the neighbor carries, and the retraction goes
// on to the rest of the mesh. PrefixDecoder refuses the identical rule on the
// Update TLV; this is the other half of it.
func TestZeroIHUIntervalIsIgnoredRatherThanHonored(t *testing.T) {
	dest := netip.MustParsePrefix("10.5.0.0/16")
	src := netip.MustParseAddr("192.0.2.1")
	s, _, _ := captureSpeaker(t, Config{})
	a := addReachablePeer(s, "a", 100)
	s.Receive(a, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup, EncodePacket([]RawTLV{
		EncodeNextHop(net.ParseIP("192.0.2.254")), EncodeRouterID([8]byte{1}),
		EncodeUpdate(Update{AE: AEIPv4, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
			Seqno: 1, Metric: 20, Interval: 1000}),
	})))
	if got, _ := s.mesh.Routes.Lookup(src, dest.Addr()); got != a {
		t.Fatal("the route was not selected, so this proves nothing")
	}
	s.Receive(a, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup,
		EncodePacket([]RawTLV{EncodeIHU(IHU{RxCost: 100, Interval: 0})})))
	if got, _ := s.mesh.Routes.Lookup(src, dest.Addr()); got != a {
		t.Error("an IHU with a zero interval unselected every route through the neighbor that sent it")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cost := s.neighbors[a.ID].linkCost(time.Now(), s.cost); cost == MetricInfinity {
		t.Error("an IHU with a zero interval took the link cost to infinity")
	}
}

// What an operator reads on the metrics endpoint. Asserting these at zero,
// their value on a node with no neighbors, cannot tell a correct
// count from no counting at all: the loop that produces both can be deleted
// with such an assertion still passing.
func TestStatsCountWhatEachNeighborSent(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	s, err := New(Config{}, Routes{}, Runtime{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	s.Originate(netip.MustParsePrefix("10.66.0.5/32"))
	a := addReachablePeer(s, "a", 100)
	b := addReachablePeer(s, "b", 10)
	// Two prefixes from a, one of which b also has, so the counts differ from
	// each other and from the selected total.
	s.Receive(a, routePacket(netip.MustParsePrefix("10.5.0.0/16"), 1, 20, 1000))
	s.Receive(a, routePacket(netip.MustParsePrefix("10.6.0.0/16"), 1, 20, 1000))
	s.Receive(b, routePacket(netip.MustParsePrefix("10.5.0.0/16"), 2, 20, 1000))

	stats := s.Stats()
	if got := len(stats.Neighbors); got != 2 {
		t.Fatalf("stats report %d neighbors, want two", got)
	}
	for _, want := range []struct {
		peer   string
		routes int
	}{{"a", 2}, {"b", 1}} {
		for _, neighbor := range stats.Neighbors {
			if neighbor.Peer != want.peer {
				continue
			}
			if neighbor.Routes != want.routes {
				t.Errorf("%s is reported with %d routes, want %d", want.peer, neighbor.Routes, want.routes)
			}
			if !neighbor.Alive {
				t.Errorf("%s is reported down after a hello and an IHU", want.peer)
			}
		}
	}
	if stats.Selected != 2 {
		t.Errorf("stats report %d selected routes, want the two distinct prefixes", stats.Selected)
	}
	if stats.Originated != 1 {
		t.Errorf("stats report %d originated prefixes, want one", stats.Originated)
	}
}

// RFC 8966 section 4.6.8 sets the next hop "even if it is otherwise ignored
// due to an unknown mandatory sub-TLV", and the decoder reporting that is only
// half of it: the receive path has to disregard the ignore for this TLV, the
// way it already does for Router-Id. Honoring it would drop every following
// IPv4 Update in the packet under the section 4.6.9 rule.
func TestIgnoredNextHopStillSetsTheParserState(t *testing.T) {
	dest := netip.MustParsePrefix("10.5.0.0/16")
	src := netip.MustParseAddr("192.0.2.1")
	s, _, _ := captureSpeaker(t, Config{})
	a := addReachablePeer(s, "a", 100)

	nextHop := EncodeNextHop(net.ParseIP("192.0.2.254"))
	nextHop.Body = append(append([]byte(nil), nextHop.Body...), 0x80, 0) // unknown, mandatory
	s.Receive(a, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup, EncodePacket([]RawTLV{
		nextHop,
		EncodeRouterID([8]byte{1}),
		EncodeUpdate(Update{AE: AEIPv4, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
			Seqno: 1, Metric: 20, Interval: 1000}),
	})))
	if got, _ := s.mesh.Routes.Lookup(src, dest.Addr()); got != a {
		t.Error("the update after an ignored next hop was dropped, so the whole packet's IPv4 routes go with it")
	}
}
