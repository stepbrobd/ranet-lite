package babel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

// wireSpeakerPair connects two Speakers via a plain in-memory relay (no
// ESP/crypto — that's validated separately) that threads peer identity
// correctly: each side's netstack.Peer represents "the other side" from
// its own point of view, exactly as in the real client where each peer
// object corresponds to one ESP session. Non-Babel traffic (Receive
// returns false) falls through to the mesh, mirroring how a real
// per-peer ESP receive loop would dispatch between babel and app traffic.
func wireSpeakerPair(t *testing.T, cfg Config) (meshA, meshB *netstack.Mesh, speakerA, speakerB *Speaker) {
	t.Helper()
	// Babel only uses Mesh.Routes. Avoid creating a privileged TUN device for
	// protocol tests that never inject non-Babel data into the mesh.
	meshA = &netstack.Mesh{Routes: netstack.NewRouteTable()}
	meshB = &netstack.Mesh{Routes: netstack.NewRouteTable()}

	speakerA, err := New(cfg, meshA)
	if err != nil {
		t.Fatal(err)
	}
	speakerB, err = New(cfg, meshB)
	if err != nil {
		t.Fatal(err)
	}

	// Crypto and transport are tested separately; this pair only exercises
	// Babel and mesh delivery.
	noopEncrypt := func(raw []byte, nh byte) ([]byte, error) { return raw, nil }

	var peerAForB, peerBForA *netstack.Peer
	peerBForA = netstack.NewPeer("b", noopEncrypt, func(raw []byte) error {
		if !speakerB.Receive(peerAForB, raw) {
			meshB.DeliverInbound(raw)
		}
		return nil
	})
	peerAForB = netstack.NewPeer("a", noopEncrypt, func(raw []byte) error {
		if !speakerA.Receive(peerBForA, raw) {
			meshA.DeliverInbound(raw)
		}
		return nil
	})
	speakerA.AddPeer(peerBForA)
	speakerB.AddPeer(peerAForB)
	return meshA, meshB, speakerA, speakerB
}

func TestSpeakerLearnsRouteAndRTT(t *testing.T) {
	fast := Config{HelloInterval: 50 * time.Millisecond, UpdateInterval: 100 * time.Millisecond}
	meshA, _, speakerA, speakerB := wireSpeakerPair(t, fast)

	extra := netip.MustParsePrefix("10.66.9.9/32")
	speakerB.Originate(extra)

	// extra is an ordinary (any-source) route, so the source address
	// passed to Lookup is irrelevant — any placeholder works.
	dummySrc := netip.MustParseAddr("192.0.2.1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go speakerA.Run(ctx)
	go speakerB.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := meshA.Routes.Lookup(dummySrc, extra.Addr()); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	peer, ok := meshA.Routes.Lookup(dummySrc, extra.Addr())
	if !ok {
		t.Fatal("A never learned B's originated route within the deadline")
	}
	if peer.ID != "b" {
		t.Fatalf("route installed via peer %q, want \"b\"", peer.ID)
	}

	// RTT should get measured over the local (near-zero-latency) link.
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		speakerA.mu.Lock()
		n := speakerA.neighbors["b"]
		have := n.haveRTT
		speakerA.mu.Unlock()
		if have {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("A never measured RTT to B within the deadline")
}

// A peer may reflect an originated route back to us across a mesh. A stub
// must prefer its direct route, including when the reflected router ID is ours.
func TestSpeakerIgnoresEchoedOwnPrefix(t *testing.T) {
	meshA, _, speakerA, _ := wireSpeakerPair(t, Config{})

	mine := netip.MustParsePrefix("fd00:68::9/128")
	speakerA.Originate(mine)

	n := speakerA.neighbors["b"]
	if n == nil {
		t.Fatal("peer \"b\" not registered")
	}
	n.alive = true
	n.lastHelloTime = time.Now()
	n.helloInterval = time.Minute
	n.haveReportedCost = true
	n.reportedCost = 32
	n.ihuExpiry = time.Now().Add(time.Minute)
	pkt := buildPacket(netip.MustParseAddr("fe80::b"), multicastGroup, EncodePacket([]RawTLV{
		EncodeRouterID(speakerA.cfg.RouterID), // as if reflected back via another mesh node
		EncodeUpdate(Update{AE: AEIPv6, Plen: mine.Bits(), Seqno: 1, Metric: 32, Prefix: net.IP(mine.Addr().AsSlice())}),
	}))
	speakerA.handlePacket(n, pkt[ipv6HeaderLen+udpHeaderLen:])

	if peer, ok := meshA.Routes.Lookup(netip.MustParseAddr("192.0.2.1"), mine.Addr()); ok {
		t.Fatalf("A installed a learned route for its own originated prefix via peer %q", peer.ID)
	}
}

// sourceSpecificUpdateTLV hand-builds an Update TLV with a trailing Source
// Prefix sub-TLV (RFC 9079 section 5.1) — EncodeUpdate
// doesn't support this (we never originate source-specific routes), so
// tests exercising receive-side handling build the bytes directly, same
// as tlv_test.go's TestUpdateWithSourcePrefix.
func sourceSpecificUpdateTLV(dest netip.Prefix, source netip.Prefix, metric uint16) RawTLV {
	ae := updateAE(dest)
	destBytes := dest.Addr().AsSlice()
	if dest.Addr().Is4() {
		b := dest.Addr().As4()
		destBytes = b[:]
	}
	srcBytes := source.Addr().AsSlice()
	if source.Addr().Is4() {
		b := source.Addr().As4()
		srcBytes = b[:]
	}
	srcBytes = srcBytes[:prefixByteLen(source.Bits())]

	body := make([]byte, 0, 32)
	body = append(body, ae, 0, byte(dest.Bits()), 0)   // AE, Flags, Plen, Omitted
	body = append(body, 0, 200)                        // Interval: 200 centiseconds, long enough to outlive the test
	body = append(body, 0, 1)                          // Seqno
	body = append(body, byte(metric>>8), byte(metric)) // Metric
	body = append(body, destBytes[:prefixByteLen(dest.Bits())]...)
	body = append(body, SubTLVSourcePrefix, byte(1+len(srcBytes)), byte(source.Bits()))
	body = append(body, srcBytes...)
	return RawTLV{Type: TLVUpdate, Body: body}
}

func makeNeighborReachable(n *neighborState) {
	n.alive = true
	n.lastHelloTime = time.Now()
	n.helloInterval = time.Minute
	n.haveReportedCost = true
	n.reportedCost = 32
	n.ihuExpiry = time.Now().Add(time.Minute)
}

// TestSpeakerSADR covers genuine source-specific (SADR) route handling:
// a Source Prefix sub-TLV is installed as a real (source, destination)
// entry in the mesh's route table, not approximated by checking whether
// it happens to cover some fixed local address. Two source-specific
// routes to the same destination, from different peers/prefixes, must
// coexist independently and only resolve for lookups whose source
// address actually falls within their respective source prefix.
func TestSpeakerSADR(t *testing.T) {
	_, _, speakerA, _ := wireSpeakerPair(t, Config{})

	n := speakerA.neighbors["b"]
	if n == nil {
		t.Fatal("peer \"b\" not registered")
	}
	makeNeighborReachable(n)

	dest := netip.MustParsePrefix("10.77.0.0/24")
	covering := netip.MustParsePrefix("10.66.0.0/16")
	other := netip.MustParsePrefix("10.99.0.0/16")

	pkt := buildPacket(netip.MustParseAddr("fe80::b"), multicastGroup, EncodePacket([]RawTLV{
		EncodeRouterID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		sourceSpecificUpdateTLV(dest, other, 64),
	}))
	speakerA.handlePacket(n, pkt[ipv6HeaderLen+udpHeaderLen:])

	// A source inside `other`'s prefix must resolve via the
	// source-specific route just installed.
	if _, ok := speakerA.mesh.Routes.Lookup(netip.MustParseAddr("10.99.1.1"), dest.Addr()); !ok {
		t.Fatal("did not install the source-specific route for a source within its prefix")
	}
	// A source outside `other`'s prefix, and with no any-source fallback
	// route to dest, must not match at all.
	if _, ok := speakerA.mesh.Routes.Lookup(netip.MustParseAddr("10.66.1.1"), dest.Addr()); ok {
		t.Fatal("a source-specific route matched a source outside its prefix")
	}

	// A second, independent source-specific route to the *same*
	// destination must coexist rather than replacing the first.
	pkt = buildPacket(netip.MustParseAddr("fe80::b"), multicastGroup, EncodePacket([]RawTLV{
		EncodeRouterID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		sourceSpecificUpdateTLV(dest, covering, 64),
	}))
	speakerA.handlePacket(n, pkt[ipv6HeaderLen+udpHeaderLen:])

	if _, ok := speakerA.mesh.Routes.Lookup(netip.MustParseAddr("10.66.1.1"), dest.Addr()); !ok {
		t.Fatal("did not install the second source-specific route")
	}
	if _, ok := speakerA.mesh.Routes.Lookup(netip.MustParseAddr("10.99.1.1"), dest.Addr()); !ok {
		t.Fatal("installing a second source-specific route disturbed the first")
	}
}

func TestSpeakerRetractsRouteOnNeighborDown(t *testing.T) {
	fast := Config{HelloInterval: 30 * time.Millisecond, UpdateInterval: 60 * time.Millisecond}
	meshA, _, speakerA, speakerB := wireSpeakerPair(t, fast)

	extra := netip.MustParsePrefix("10.67.9.9/32")
	speakerB.Originate(extra)
	dummySrc := netip.MustParseAddr("192.0.2.1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go speakerA.Run(ctx)
	bCtx, bCancel := context.WithCancel(ctx)
	go speakerB.Run(bCtx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := meshA.Routes.Lookup(dummySrc, extra.Addr()); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := meshA.Routes.Lookup(dummySrc, extra.Addr()); !ok {
		t.Fatal("A never learned the route before the down test could proceed")
	}

	bCancel() // B stops sending Hello entirely, simulating a dead link

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := meshA.Routes.Lookup(dummySrc, extra.Addr()); !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("A never retracted the route after B went silent")
}

func TestPeerHandleRemovesExactNeighborAndRoutes(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(Config{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	peer := netstack.NewPeer("peer", nil, nil)
	handle := speaker.AddPeer(peer)
	n := speaker.neighbors[peer.ID]
	dest := netip.MustParsePrefix("10.88.0.0/16")
	key := routeKey{dest: dest}
	makeNeighborReachable(n)
	speaker.routes.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, time.Minute, time.Now())

	handle.Close()
	handle.Close()
	if speaker.neighbors[peer.ID] != nil {
		t.Fatal("closed peer remains registered")
	}
	if _, ok := mesh.Routes.Lookup(netip.MustParseAddr("192.0.2.1"), dest.Addr()); ok {
		t.Fatal("closed peer route remains installed")
	}

	newPeer := netstack.NewPeer("peer", nil, nil)
	newHandle := speaker.AddPeer(newPeer)
	defer newHandle.Close()
	handle.Close()
	if speaker.neighbors[peer.ID] == nil {
		t.Fatal("stale handle removed replacement peer")
	}
}

func TestWildcardUpdateRetractsEveryRouteFromNeighbor(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(Config{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	peer := netstack.NewPeer("peer", nil, nil)
	handle := speaker.AddPeer(peer)
	defer handle.Close()
	neighbor := speaker.neighbors[peer.ID]
	makeNeighborReachable(neighbor)
	for _, dest := range []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("10.2.0.0/16")} {
		key := routeKey{dest: dest}
		speaker.routes.update(neighbor, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, time.Minute, time.Now())
	}
	body := []byte{AEWildcard, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{{Type: TLVUpdate, Body: body}}))
	// The entries survive as unreachable holds, RFC 8966 section 3.5.4, but
	// nothing may forward through them any more.
	for _, dest := range []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("10.2.0.0/16")} {
		if forwards(mesh, dest) {
			t.Fatalf("wildcard retraction left %s forwarding: %v", dest, mesh.Routes.Debug())
		}
	}
}

func TestAcknowledgmentUsesUnicastDestination(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(Config{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	var sent []byte
	peer := netstack.NewPeer("peer", func(raw []byte, _ byte) ([]byte, error) { return raw, nil }, func(raw []byte) error {
		sent = append([]byte(nil), raw...)
		return nil
	})
	handle := speaker.AddPeer(peer)
	defer handle.Close()
	neighbor := speaker.neighbors[peer.ID]
	destination := netip.MustParseAddr("fe80::2")
	neighbor.addr = destination
	if reserved := speaker.reserveTo(neighbor, destination, []RawTLV{EncodeAck(1)}); reserved != nil {
		reserved.Send()
	}
	got, ok := netip.AddrFromSlice(sent[24:40])
	if !ok || got != destination {
		t.Fatalf("Ack destination = %v, want %v", got, destination)
	}
}

func captureSpeaker(t *testing.T, cfg Config) (*Speaker, *neighborState, *[][]byte) {
	t.Helper()
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(cfg, mesh)
	if err != nil {
		t.Fatal(err)
	}
	packets := new([][]byte)
	peer := netstack.NewPeer("peer", func(raw []byte, _ byte) ([]byte, error) { return raw, nil }, func(raw []byte) error {
		*packets = append(*packets, append([]byte(nil), raw...))
		return nil
	})
	speaker.AddPeer(peer)
	neighbor := speaker.neighbors[peer.ID]
	neighbor.addr = netip.MustParseAddr("fe80::2")
	return speaker, neighbor, packets
}

func TestUnscheduledAndUnicastHelloState(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 1, Interval: 100})}))
	deadline := neighbor.lastHelloTime.Add(deadTimeout(neighbor.helloInterval))
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 2, Interval: 0})}))
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 3, Interval: 200, Unicast: true})}))
	if got := neighbor.lastHelloTime.Add(deadTimeout(neighbor.helloInterval)); !got.Equal(deadline) {
		t.Fatalf("unscheduled Hello moved deadline from %v to %v", deadline, got)
	}
	if neighbor.unicastHelloInterval != 2*time.Second {
		t.Fatalf("unicast interval = %v", neighbor.unicastHelloInterval)
	}
}

func TestIHUAddressAndRTTOrder(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	now := nowMicros()
	// First, an explicitly addressed IHU for another interface is ignored.
	body := make([]byte, 22)
	body[0] = AEIPv6
	body[2], body[3], body[4], body[5] = 0, 77, 0, 100
	copy(body[6:], net.ParseIP("fe80::dead").To16())
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{{Type: TLVIHU, Body: body}}))
	haveCost := neighbor.haveReportedCost
	if haveCost {
		t.Fatal("accepted IHU addressed to a different local interface")
	}

	// IHU preceding Hello in the same packet still yields a valid sample.
	ihu := EncodeIHU(IHU{RxCost: 64, Interval: 100, OriginTS: now - 10_000, ReceiveTS: 1_000, HasTS: true})
	hello := EncodeHello(Hello{Seqno: 1, Interval: 100, TxTS: 1_500, HasTS: true})
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{ihu, hello}))
	haveRTT := neighbor.haveRTT
	if !haveRTT {
		t.Fatal("IHU-before-Hello packet did not produce an RTT sample")
	}
}

func TestOriginRequestsAndUpdateSplitting(t *testing.T) {
	routerID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	speaker, neighbor, packets := captureSpeaker(t, Config{RouterID: routerID, PacketSize: 64})
	first := netip.MustParsePrefix("10.0.0.1/32")
	second := netip.MustParsePrefix("2001:db8::1/128")
	speaker.Originate(first)
	speaker.Originate(second)
	*packets = nil
	speaker.flushUpdates()
	if len(*packets) < 2 {
		t.Fatalf("oversized update dump used %d packet(s), want multiple", len(*packets))
	}
	for _, packet := range *packets {
		if got := len(packet) - ipv6HeaderLen - udpHeaderLen; got > speaker.cfg.PacketSize {
			t.Fatalf("Babel packet is %d bytes, limit %d", got, speaker.cfg.PacketSize)
		}
	}

	*packets = nil
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{EncodeSeqnoRequest(SeqnoRequest{
		AE: AEIPv4, Prefix: first, Seqno: 9, HopCount: 64, RouterID: routerID,
	})}))
	if len(*packets) != 1 || speaker.originSeqno != 2 {
		t.Fatalf("Seqno Request produced %d replies and seqno %d", len(*packets), speaker.originSeqno)
	}

	*packets = nil
	missing := netip.MustParsePrefix("10.0.0.9/32")
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{EncodeRouteRequest(RouteRequest{AE: AEIPv4, Prefix: missing})}))
	if len(*packets) != 1 {
		t.Fatalf("missing Route Request produced %d replies", len(*packets))
	}
	payload := (*packets)[0][ipv6HeaderLen+udpHeaderLen:]
	tlvs, err := DecodePacket(payload)
	if err != nil {
		t.Fatal(err)
	}
	update, err := (&PrefixDecoder{}).Decode(tlvs[len(tlvs)-1].Body)
	if err != nil || update.Metric != MetricInfinity {
		t.Fatalf("missing route reply = %+v, %v", update, err)
	}
}

// The speaker sends to every neighbor from one goroutine, and Receive runs on
// the sending peer's own decrypt path. A send that waits on a peer whose queue
// is backed up therefore stops hellos, updates and retractions to every other
// neighbor, and at the default dead timeout each of them declares this node
// down fourteen seconds later.
func TestStalledNeighborDoesNotHoldOthers(t *testing.T) {
	speaker, err := New(Config{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		t.Fatal(err)
	}
	seal := func(int) (netstack.BatchSealer, error) {
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			return append(out[:0], raw...), nil
		}, nil
	}
	block := make(chan struct{})
	stalled := netstack.NewPeerReserved("stalled", seal, func([][]byte) error {
		<-block
		return nil
	})
	// The transport has to be released before Close, which waits for the
	// sender goroutine sitting inside it.
	defer func() { close(block); stalled.Close() }()
	healthy := make(chan struct{}, 64)
	moving := netstack.NewPeerReserved("moving", seal, func(sealed [][]byte) error {
		for range sealed {
			select {
			case healthy <- struct{}{}:
			default:
			}
		}
		return nil
	})
	defer moving.Close()
	speaker.AddPeer(stalled)
	speaker.AddPeer(moving)

	// Something to say to both of them, and enough rounds to fill the stalled
	// peer's queue several times over.
	speaker.Originate(netip.MustParsePrefix("fd00:a::/64"))
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for range 200 {
			speaker.mu.Lock()
			actions := speaker.updateActions(time.Now())
			speaker.mu.Unlock()
			speaker.mu.Lock()
			send := speaker.emitLocked(actions)
			speaker.mu.Unlock()
			send()
		}
	}()
	select {
	case <-sent:
	case <-time.After(20 * time.Second):
		t.Fatal("the speaker was held by one neighbor whose transport never returned")
	}
	// Waited for rather than sampled: a place is taken under the lock and the
	// peer's own sender goroutine transmits it afterwards, so a machine that
	// has not scheduled that goroutine yet is not a speaker that is stuck.
	select {
	case <-healthy:
	case <-time.After(20 * time.Second):
		t.Error("the healthy neighbor received nothing")
	}
}

// Three things reach the route table only through New, and each can be nulled
// out with the rest of the suite green: dropping a forwarding entry, and the
// smoothing time constant of RFC 8966 Appendix A.3 and the triggered-update
// threshold of section 3.7.2, both of which the config decides.
func TestNewSpeakerCarriesItsConfigurationIntoTheRouteTable(t *testing.T) {
	cfg := Config{HelloInterval: 4 * time.Second, UpdateInterval: 16 * time.Second}
	cfg.Cost = DefaultCostParams()
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(cfg, mesh)
	if err != nil {
		t.Fatal(err)
	}
	if speaker.routes.forget == nil {
		t.Error("the route table cannot drop a forwarding entry, so every expired route leaks one")
	} else {
		key := routeKey{dest: netip.MustParsePrefix("fd00:a::/64")}
		mesh.Routes.Set(key.source, key.dest, netstack.Unreachable)
		speaker.routes.forget(key)
		if _, ok := mesh.Routes.Lookup(netip.Addr{}, key.dest.Addr().Next()); ok {
			t.Error("forget left the forwarding entry behind")
		}
	}
	// RFC 8966 Appendix A.3 recommends a hysteresis time constant of a small
	// multiple of the Hello interval, and one link's base cost is the scale at
	// which a metric change is worth a triggered update. Zero for either turns
	// that off: a flapping link would change the selected route on every
	// update and send one for every change.
	if want := 3 * cfg.HelloInterval; speaker.routes.tau != want {
		t.Errorf("hysteresis time constant is %s, want %s", speaker.routes.tau, want)
	}
	if speaker.routes.trigger != cfg.Cost.RxCost {
		t.Errorf("triggered-update threshold is %d, want one link's base cost, %d",
			speaker.routes.trigger, cfg.Cost.RxCost)
	}
}

// The defaults are a fleet interoperability choice, not an arbitrary number.
func TestBabelDefaultsMatchFleet(t *testing.T) {
	cost := DefaultCostParams()
	// BABEL_RXCOST_WIRED, the value BIRD uses and the fleet sets
	// explicitly. At 32 a ranet-lite hop looks three times cheaper than a BIRD
	// hop and a mixed fleet pulls transit onto whichever nodes run this.
	if cost.RxCost != 96 {
		t.Errorf("default rxcost is %d, want 96", cost.RxCost)
	}
	if cost.RTTCost != 1024 || cost.RTTMax != 1024*time.Millisecond {
		t.Errorf("default rtt costing is %d over %s, want 1024 over 1024ms", cost.RTTCost, cost.RTTMax)
	}
	var cfg Config
	cfg.setDefaults()
	if cfg.HelloInterval != 4*time.Second || cfg.UpdateInterval != 16*time.Second {
		t.Errorf("default intervals are %s and %s, want the 4s and 16s of RFC 8966 Appendix B",
			cfg.HelloInterval, cfg.UpdateInterval)
	}
}

// A retraction consumes the record that says the neighbor was ever told about
// the prefix, and advertisableKeys reads that record. If a dropped packet
// consumed it anyway, the prefix leaves every later dump too and the neighbor
// black-holes it until its own expiry, which at the defaults is 56 seconds.
func TestDroppedRetractionIsSentAgain(t *testing.T) {
	speaker, err := New(Config{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		t.Fatal(err)
	}
	seal := func(int) (netstack.BatchSealer, error) {
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			return append(out[:0], raw...), nil
		}, nil
	}
	block := make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(block) }) }
	var blocking atomic.Bool
	blocking.Store(true)
	var delivered atomic.Int64
	peer := netstack.NewPeerReserved("peer", seal, func(sealed [][]byte) error {
		if blocking.Load() {
			<-block
		}
		delivered.Add(int64(len(sealed)))
		return nil
	})
	defer func() { unblock(); peer.Close() }()
	defer speaker.AddPeer(peer).Close()

	dest := netip.MustParsePrefix("fd00:a::/64")
	key := routeKey{dest: dest}
	speaker.Originate(dest)
	speaker.mu.Lock()
	announce := speaker.updateActions(time.Now())
	speaker.mu.Unlock()
	emit(speaker, announce)
	speaker.mu.Lock()
	_, told := speaker.neighbors["peer"].advertised[key]
	speaker.mu.Unlock()
	if !told {
		t.Fatal("the announcement was not recorded, so there is no record for a retraction to consume")
	}

	// The peer's transport is stuck, so fill its queue through the same path
	// babel uses until it starts refusing, and the retraction is then dropped.
	for range 4096 {
		place, err := peer.ReserveRawOrDrop([]byte("bulk"), 41)
		if errors.Is(err, netstack.ErrSendQueueFull) {
			break
		}
		place.Send()
	}
	speaker.SetOriginated(nil)
	speaker.mu.Lock()
	retract := speaker.updateActions(time.Now())
	speaker.mu.Unlock()
	emit(speaker, retract)

	speaker.mu.Lock()
	_, stillTold := speaker.neighbors["peer"].advertised[key]
	speaker.mu.Unlock()
	if !stillTold {
		t.Fatal("a dropped retraction consumed the record, so no later dump will carry it")
	}

	// With the transport working again the very next dump carries it.
	blocking.Store(false)
	unblock()
	speaker.mu.Lock()
	again := speaker.updateActions(time.Now())
	speaker.mu.Unlock()
	var retractions int
	for _, action := range again {
		for _, tlv := range action.tlvs {
			if tlv.Type != TLVUpdate {
				continue
			}
			var decoder PrefixDecoder
			if u, err := decoder.Decode(tlv.Body); err == nil && u.Metric == MetricInfinity {
				retractions++
			}
		}
	}
	if retractions == 0 {
		t.Error("the next dump did not carry the retraction the dropped packet lost")
	}
}

// RFC 8966 section 3.4.1 lets a node send an unscheduled Hello "for any
// reason", and it carries no interval, so it promises nothing about the next
// one. Treating it as proof of life makes the neighbor up and immediately down
// again, which costs a reselection and a pair of log lines per Hello.
func TestUnscheduledHelloDoesNotFlapANeighbor(t *testing.T) {
	s, neighbor, _ := captureSpeaker(t, Config{})
	now := time.Now()
	unscheduled := EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 1})})
	for range 5 {
		s.handlePacket(neighbor, unscheduled)
	}
	if neighbor.alive {
		t.Error("an unscheduled Hello alone brought the neighbor up, with nothing to keep it there")
	}

	// A scheduled one does, and an unscheduled one then keeps it up rather
	// than being ignored.
	s.handlePacket(neighbor, EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 2, Interval: 100})}))
	if !neighbor.alive || !neighbor.isAlive(now) {
		t.Fatal("a scheduled Hello did not bring the neighbor up")
	}
	s.handlePacket(neighbor, unscheduled)
	if !neighbor.isAlive(now) {
		t.Error("an unscheduled Hello took a live neighbor down")
	}
}

// Two goroutines emit: Run, and Receive on the sending peer's own decrypt
// path. Both decide under s.mu and both have to send after releasing it,
// because an in-memory transport delivers inline and would otherwise re-enter
// Receive. Whichever reaches the peer first would then win, so a retraction
// decided before the update that replaces it can reach the neighbor after it,
// and the neighbor holds the wrong answer until the next periodic dump.
func TestEmittersCannotInvertWhatTheyDecided(t *testing.T) {
	speaker, err := New(Config{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		t.Fatal(err)
	}
	metrics := make(chan uint16, 4)
	peer := netstack.NewPeerReserved("peer",
		func(int) (netstack.BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func(sealed [][]byte) error {
			for _, raw := range sealed {
				tlvs, err := DecodePacket(raw[ipv6HeaderLen+udpHeaderLen:])
				if err != nil {
					return err
				}
				var decoder PrefixDecoder
				for _, tlv := range tlvs {
					if tlv.Type != TLVUpdate {
						continue
					}
					update, err := decoder.Decode(tlv.Body)
					if err != nil {
						return err
					}
					metrics <- update.Metric
				}
			}
			return nil
		})
	defer peer.Close()
	handle := speaker.AddPeer(peer)
	defer handle.Close()
	neighbor := speaker.neighbors[peer.ID]
	neighbor.addr = netip.MustParseAddr("fe80::2")

	prefix := netip.MustParsePrefix("fd00:1::/64")
	update := func(metric uint16) []sendAction {
		return []sendAction{{neighbor: neighbor, dest: neighbor.addr, tlvs: []RawTLV{
			EncodeRouterID([8]byte{1}),
			EncodeUpdate(Update{AE: AEIPv6, Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(),
				Interval: 6000, Seqno: 1, Metric: metric}),
		}}}
	}

	// The retraction is decided first and sent last, which is the interleaving
	// the two emitters produce whenever the second one is not descheduled.
	speaker.mu.Lock()
	sendRetraction := speaker.emitLocked(update(MetricInfinity))
	speaker.mu.Unlock()
	speaker.mu.Lock()
	sendReplacement := speaker.emitLocked(update(64))
	speaker.mu.Unlock()
	sendReplacement()
	sendRetraction()

	var order []uint16
	for range 2 {
		select {
		case metric := <-metrics:
			order = append(order, metric)
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of the two updates reached the peer", len(order))
		}
	}
	if order[0] != MetricInfinity || order[1] != 64 {
		t.Fatalf("the neighbor was told %v, so it ends up holding the retraction that was decided first", order)
	}
}

// Originating a prefix holds it unreachable, so a stale route to it learned
// from a neighbor cannot take traffic this node is supposed to deliver
// locally. Giving it back when the prefix stops being originated is the other
// half: a reload that drops one from the configuration would otherwise leave
// it black-holed for the life of the process, with a neighbor announcing a
// perfectly good path to it the whole time.
func TestPrefixNoLongerOriginatedCanBeReachedAgain(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	covering := netip.MustParsePrefix("fd00::/16")
	specific := netip.MustParsePrefix("fd00:1::/64")
	inside := netip.MustParseAddr("fd00:1::1")
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{
		EncodeRouterID([8]byte{1}),
		EncodeUpdate(Update{AE: AEIPv6, Plen: covering.Bits(), Prefix: covering.Addr().AsSlice(),
			Interval: 6000, Seqno: 1, Metric: 64}),
	}))
	if _, ok := speaker.mesh.Routes.Lookup(netip.Addr{}, inside); !ok {
		t.Fatal("the covering route the neighbor announced never reached the forwarding table")
	}

	speaker.Originate(specific)
	if peer, ok := speaker.mesh.Routes.Lookup(netip.Addr{}, inside); ok {
		t.Fatalf("an originated prefix still forwards to %q, so the hold is doing nothing", peer.ID)
	}
	speaker.SetOriginated(nil)
	if _, ok := speaker.mesh.Routes.Lookup(netip.Addr{}, inside); !ok {
		t.Fatal("the prefix stayed held after this node stopped originating it, so it is black-holed for good")
	}
}

// These four numbers are what a node announces itself as costing and how fast
// it notices a neighbor has gone. They are not internal tuning: the fleet this
// replaces runs BIRD, and a ranet-lite node whose hop looks cheaper than a BIRD
// hop pulls transit onto itself across the whole mesh, while one that takes
// seventy seconds to notice a silent peer is a different network from the one
// being replaced. Nothing else in the suite would notice them changing.
func TestDefaultsMatchFleetTheyReplace(t *testing.T) {
	cost := DefaultCostParams()
	// RFC 8966 Appendix B's wired rxcost, which is BIRD's BABEL_RXCOST_WIRED.
	if cost.RxCost != 96 {
		t.Errorf("default rxcost is %d, want 96: at anything lower a hop through this node looks cheaper than a BIRD hop", cost.RxCost)
	}
	// RFC 9616's RTT term, weighted as babeld weights it.
	if cost.RTTCost != 1024 {
		t.Errorf("default rtt cost is %d, want 1024", cost.RTTCost)
	}
	// RFC 9616 section 4.2 RECOMMENDS rtt-min = 10 ms and asks for the mapping
	// to be "constant around 0". rtt-max stays wider than the 120 ms it
	// RECOMMENDS because this is a global mesh, where 120 ms saturates every
	// intercontinental path and the penalty stops ranking them.
	if cost.RTTMax != 1024*time.Millisecond || cost.RTTMin != 10*time.Millisecond {
		t.Errorf("default rtt window is %s..%s, want 10ms..1024ms", cost.RTTMin, cost.RTTMax)
	}

	var cfg Config
	cfg.setDefaults()
	// RFC 8966 Appendix B's hello interval, which sets how long a peer that is
	// up but silent takes to be declared dead.
	if cfg.HelloInterval != 4*time.Second {
		t.Errorf("default hello interval is %s, want 4s", cfg.HelloInterval)
	}
	if got, want := deadTimeout(cfg.HelloInterval), 14*time.Second; got > want {
		t.Errorf("a silent peer is declared dead after %s, want no more than %s", got, want)
	}
	// Appendix B again: the update interval is four hellos.
	if cfg.UpdateInterval != 4*cfg.HelloInterval {
		t.Errorf("default update interval is %s, want four hello intervals", cfg.UpdateInterval)
	}
	if cfg.Cost != cost {
		t.Error("a config with no costs configured does not get the defaults above")
	}
}

// The route table's hysteresis and its trigger threshold are configuration,
// not constants, and both are wired up once in New. With tau at zero the
// smoothed metric of RFC 8966 Appendix A.3 follows the instantaneous one
// exactly, so a flapping challenger takes the route on its first good sample;
// with the trigger at zero every metric fluctuation earns a triggered update.
func TestRouteTableTakesHysteresisFromConfig(t *testing.T) {
	cfg := Config{HelloInterval: 3 * time.Second, Cost: CostParams{RxCost: 77, RTTMax: time.Second}}
	speaker, err := New(cfg, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		t.Fatal(err)
	}
	if want := 3 * cfg.HelloInterval; speaker.routes.tau != want {
		t.Errorf("the smoothing time constant is %s, want %s, three hello intervals", speaker.routes.tau, want)
	}
	if speaker.routes.trigger != cfg.Cost.RxCost {
		t.Errorf("the triggered-update threshold is %d, want one link's base cost %d", speaker.routes.trigger, cfg.Cost.RxCost)
	}
}

// A prefix flushed from the route table has to take its unreachable hold with
// it. The hold is what RFC 8966 section 3.5.4 asks for while a retracted
// prefix is still remembered, and it deliberately stops a covering route from
// serving the destination. Once the entry is gone there is nothing left to
// hold, and nothing else ever removes it: no later selection will name a
// prefix the table no longer has, so the destination stays black-holed for the
// life of the process with a perfectly good covering route in place.
func TestFlushedPrefixGivesUpItsHold(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	covering := netip.MustParsePrefix("fd00::/16")
	specific := netip.MustParsePrefix("fd00:1::/64")
	inside := specific.Addr().Next()
	announce := func(prefix netip.Prefix, metric uint16) {
		speaker.handlePacket(neighbor, EncodePacket([]RawTLV{
			EncodeRouterID([8]byte{1}),
			EncodeUpdate(Update{AE: AEIPv6, Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(),
				Interval: 6000, Seqno: 1, Metric: metric}),
		}))
	}
	announce(covering, 64)
	announce(specific, 64)
	if _, ok := speaker.mesh.Routes.Lookup(netip.Addr{}, inside); !ok {
		t.Fatal("the route never reached the forwarding table")
	}

	// Retracted: held rather than removed, so the covering route does not
	// quietly take traffic the neighbor has just said it cannot carry.
	announce(specific, MetricInfinity)
	if peer, ok := speaker.mesh.Routes.Lookup(netip.Addr{}, inside); ok {
		t.Fatalf("a retracted prefix fell through to %q instead of being held", peer.ID)
	}

	// Expired out of the table entirely, which is the flush. The sweep takes
	// the covering route with it, so the neighbor announces that again: what
	// is being tested is whether the hold left with the prefix, not whether
	// the covering route survived.
	speaker.mu.Lock()
	speaker.routes.sweepExpired(time.Now().Add(time.Hour))
	_, held := speaker.routes.entries[routeKey{dest: specific}]
	speaker.mu.Unlock()
	if held {
		t.Fatal("the retracted route was not flushed, so this proves nothing")
	}
	announce(covering, 64)
	if _, ok := speaker.mesh.Routes.Lookup(netip.Addr{}, inside); !ok {
		t.Errorf("%s is still held after its prefix was flushed, so the covering route can never serve it", inside)
	}
}

// emit is the two emitters' own sequence for a test that built its actions
// with the lock released: take it, fix the transmission order, release, send.
func emit(s *Speaker, actions []sendAction) {
	s.mu.Lock()
	send := s.emitLocked(actions)
	s.mu.Unlock()
	send()
}

// RFC 8966 section 3.8.1.1 asks for a full dump to be rate limited, and what
// it costs is the table walk under the lock the whole protocol runs under, not
// the packets. Giving the allowance back when those packets are dropped turns
// the limit off exactly while this node is too congested to deliver, so every
// later request walks the table again and holds the lock that also carries
// hellos and retractions.
func TestDroppedDumpDoesNotRefundTheRateLimit(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	for i := range 8 {
		speaker.Originate(netip.MustParsePrefix(fmt.Sprintf("fd00:%x::/64", i)))
	}
	// A peer whose transport never returns, so every packet is refused. The
	// transport has to be released before Close, which waits for the sender
	// goroutine sitting inside it.
	blocked := make(chan struct{})
	stuck := netstack.NewPeerReserved("peer",
		func(int) (netstack.BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { <-blocked; return nil })
	defer func() { close(blocked); stuck.Close() }()
	speaker.mu.Lock()
	neighbor.peer = stuck
	speaker.mu.Unlock()
	for {
		place, err := stuck.ReserveRawOrDrop([]byte("bulk"), 41)
		if errors.Is(err, netstack.ErrSendQueueFull) {
			break
		}
		place.Send()
	}

	wildcard := EncodeRouteRequest(RouteRequest{AE: AEWildcard})
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{wildcard}))
	speaker.mu.Lock()
	charged := neighbor.lastFullDump
	speaker.mu.Unlock()
	if charged.IsZero() {
		t.Fatal("the allowance was given back when the packets were dropped, so the next request walks the whole table again")
	}

	// The second request falls inside the window and has to be refused, even
	// though nothing the first one produced reached the neighbor.
	speaker.mu.Lock()
	again := speaker.routeReply(neighbor, RouteRequest{AE: AEWildcard}, time.Now())
	speaker.mu.Unlock()
	if len(again) != 0 {
		t.Error("a second wildcard request drew another whole dump, so the rate limit is off while congested")
	}
}

// A place is taken for every packet of a pass before any is sent, so a pass
// that fills the peer's budget drops whatever it reached last. The periodic
// dump is both the largest action and the one that can wait for the next
// interval; a seqno request cannot, because allowAsk and rememberStarved have
// already recorded it as asked and nothing rolls that back, so a dropped
// request is a prefix that stops being asked about at all.
func TestDumpDoesNotStarveRequestsDecidedWithIt(t *testing.T) {
	speaker, err := New(Config{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		t.Fatal(err)
	}
	asked := make(chan struct{})
	var arrived sync.Once
	blocked := make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(blocked) }) }
	peer := netstack.NewPeerReserved("peer",
		func(int) (netstack.BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func(sealed [][]byte) error {
			<-blocked
			for _, raw := range sealed {
				tlvs, err := DecodePacket(raw[ipv6HeaderLen+udpHeaderLen:])
				if err != nil {
					return err
				}
				for _, tlv := range tlvs {
					if tlv.Type == TLVSeqnoRequest {
						arrived.Do(func() { close(asked) })
					}
				}
			}
			return nil
		})
	defer func() { unblock(); peer.Close() }()
	handle := speaker.AddPeer(peer)
	defer handle.Close()
	neighbor := speaker.neighbors[peer.ID]
	neighbor.addr = netip.MustParseAddr("fe80::2")

	// More dump packets than the peer can hold, decided in the same pass as
	// one request. The updates coalesce into full packets, so the count is
	// what it takes to overrun the control budget several times over.
	var actions []sendAction
	for i := range 1 << 15 {
		prefix := netip.MustParsePrefix(fmt.Sprintf("fd00:%x::/64", i))
		actions = append(actions, sendAction{neighbor: neighbor, dest: multicastGroup, priority: priorityDump, tlvs: []RawTLV{
			EncodeRouterID([8]byte{1}),
			EncodeUpdate(Update{AE: AEIPv6, Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(),
				Interval: 6000, Seqno: 1, Metric: 64}),
		}})
	}
	actions = append(actions, sendAction{neighbor: neighbor, dest: neighbor.destination(), priority: priorityRequest, tlvs: []RawTLV{
		EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: netip.MustParsePrefix("fd00:ffff::/64"),
			Seqno: 9, HopCount: 8, RouterID: [8]byte{1}}),
	}})
	speaker.mu.Lock()
	send := speaker.emitLocked(actions)
	speaker.mu.Unlock()
	send()
	if dropped := peer.Dropped(); dropped == 0 {
		t.Fatal("the whole pass fit inside the peer's budget, so nothing had to be given up and this proves nothing")
	}
	unblock()

	select {
	case <-asked:
	case <-time.After(10 * time.Second):
		t.Fatal("the request decided with the dump never left, so the prefix it asks about stops being asked about")
	}
}

// RFC 8966 section 3.8.1.1 makes a request for a prefix this node knows
// nothing about draw a retraction, and the prefix comes out of the neighbor's
// own Route Request. Recording that retraction as an advertisement when its
// packet is dropped puts a prefix the neighbor chose into n.advertised, which
// advertisableKeys unions into every later dump, and nothing bounds it: each
// dropped dump rolls the phantoms back in, so the set never drains and every
// dump carries an Update for a prefix that does not exist.
func TestRetractionForUnadvertisedPrefixCostsNothing(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	blocked := make(chan struct{})
	var release sync.Once
	stuck := netstack.NewPeerReserved("peer",
		func(int) (netstack.BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { <-blocked; return nil })
	defer func() { release.Do(func() { close(blocked) }); stuck.Close() }()
	speaker.mu.Lock()
	neighbor.peer = stuck
	speaker.mu.Unlock()
	for {
		place, err := stuck.ReserveRawOrDrop([]byte("bulk"), 41)
		if errors.Is(err, netstack.ErrSendQueueFull) {
			break
		}
		place.Send()
	}

	// Prefixes this node has never heard of, asked about by the neighbor
	// while nothing it produces can leave.
	const asked = 4096
	var requests []RawTLV
	for i := range asked {
		prefix := netip.MustParsePrefix(fmt.Sprintf("fd00:dead:%x::/64", i))
		requests = append(requests, EncodeRouteRequest(RouteRequest{AE: AEIPv6, Prefix: prefix}))
	}
	speaker.handlePacket(neighbor, EncodePacket(requests))

	speaker.mu.Lock()
	phantoms := len(neighbor.advertised)
	known := len(speaker.routes.entries)
	speaker.mu.Unlock()
	if known != 0 {
		t.Fatalf("the node learned %d of the prefixes it was asked about, so this proves nothing", known)
	}
	if phantoms != 0 {
		t.Errorf("%d prefixes the neighbor named are recorded as advertised, and every later dump carries an update for each", phantoms)
	}
}

// A Hello is multicast, like the dump, so ordering a pass by destination put
// it behind every unicast request the same pass decided, and coalesce had
// already merged it into the dump's action. Three lost Hellos withdraw every
// route through the neighbor, and the only retry is the next hello interval,
// so it is the one packet of a pass that nothing else can stand in for.
func TestHelloSurvivesPassThatFillsTheBudget(t *testing.T) {
	speaker, err := New(Config{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		t.Fatal(err)
	}
	arrived := make(chan struct{})
	var once sync.Once
	blocked := make(chan struct{})
	var release sync.Once
	unblock := func() { release.Do(func() { close(blocked) }) }
	peer := netstack.NewPeerReserved("peer",
		func(int) (netstack.BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func(sealed [][]byte) error {
			<-blocked
			for _, raw := range sealed {
				tlvs, err := DecodePacket(raw[ipv6HeaderLen+udpHeaderLen:])
				if err != nil {
					return err
				}
				for _, tlv := range tlvs {
					if tlv.Type == TLVHello {
						once.Do(func() { close(arrived) })
					}
				}
			}
			return nil
		})
	defer func() { unblock(); peer.Close() }()
	handle := speaker.AddPeer(peer)
	defer handle.Close()
	neighbor := speaker.neighbors[peer.ID]
	neighbor.addr = netip.MustParseAddr("fe80::2")

	// One pass carrying more requests than the peer can hold, decided with
	// the Hello that keeps the adjacency up.
	speaker.mu.Lock()
	actions := []sendAction{speaker.helloAction(neighbor, time.Now())}
	for i := range 1 << 15 {
		prefix := netip.MustParsePrefix(fmt.Sprintf("fd00:%x::/64", i))
		actions = append(actions, sendAction{neighbor: neighbor, dest: neighbor.destination(), priority: priorityRequest, tlvs: []RawTLV{
			EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: prefix, Seqno: 9, HopCount: 8, RouterID: [8]byte{1}}),
		}})
	}
	send := speaker.emitLocked(actions)
	speaker.mu.Unlock()
	send()
	if dropped := peer.Dropped(); dropped == 0 {
		t.Fatal("the whole pass fit inside the peer's budget, so nothing had to be given up and this proves nothing")
	}
	unblock()

	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("the hello was dropped for the requests decided with it, so the adjacency goes and every route through it with it")
	}
}

// RFC 8966 section 4.6.5: "Every time a Hello is sent, the corresponding seqno
// counter MUST be incremented." A neighbor that joins between two intervals
// draws an extra Hello, which a counter incremented per interval repeats.
func TestEveryHelloCarriesItsOwnSeqno(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	now := time.Now()
	seen := map[uint16]bool{}
	for range 3 {
		action := speaker.helloAction(neighbor, now)
		hello, err := DecodeHello(action.tlvs[0].Body)
		if err != nil {
			t.Fatal(err)
		}
		if seen[hello.Seqno] {
			t.Fatalf("hello seqno %d was sent twice, so the neighbor reads a repeat as a loss", hello.Seqno)
		}
		seen[hello.Seqno] = true
	}
}

// RFC 8966 section 3.7.2: "whenever it changes the selected router-id for a
// given destination, a node MUST send an update as an urgent TLV". takeDirty
// consumes the record that one is owed, so a dropped triggered update leaves
// the change to the next periodic dump, which is sixteen seconds at the
// defaults and four expiries at a neighbor that has lost the prefix.
func TestDroppedTriggeredUpdateIsStillOwed(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	blocked := make(chan struct{})
	var release sync.Once
	stuck := netstack.NewPeerReserved("peer",
		func(int) (netstack.BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { <-blocked; return nil })
	defer func() { release.Do(func() { close(blocked) }); stuck.Close() }()
	speaker.mu.Lock()
	neighbor.peer = stuck
	speaker.mu.Unlock()
	for {
		place, err := stuck.ReserveRawOrDrop([]byte("bulk"), 41)
		if errors.Is(err, netstack.ErrSendQueueFull) {
			break
		}
		place.Send()
	}

	prefix := netip.MustParsePrefix("fd00:7::/64")
	speaker.Originate(prefix)
	speaker.mu.Lock()
	if len(speaker.routes.dirty) == 0 {
		speaker.routes.dirty[routeKey{dest: prefix}] = struct{}{}
	}
	emitLockedNow := speaker.emitLocked(speaker.triggeredActions(time.Now()))
	speaker.mu.Unlock()
	emitLockedNow()

	speaker.mu.Lock()
	owed := len(speaker.routes.dirty)
	speaker.mu.Unlock()
	if owed == 0 {
		t.Error("the urgent update was dropped and nothing still owes it, so the change waits for the next periodic dump")
	}
}
