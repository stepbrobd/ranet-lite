package babel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
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
	// A third, because every Update in this dump carries the same origin and
	// only the first spells its id out: two of them now fit in one packet.
	speaker.Originate(netip.MustParsePrefix("2001:db8::2/128"))
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
	owed := len(neighbor.owed)
	speaker.mu.Unlock()
	if owed == 0 {
		t.Error("the urgent update was dropped and nothing still owes it, so the change waits for the next periodic dump")
	}
}

// And what goes back is that neighbor's copy. A shared record put the whole
// triggered update back for every neighbor, so one congested peer made the
// speaker repeat it to every healthy one on every wake of the run loop until
// the next periodic dump, which on a neighbor loss is a full multi-packet dump
// several times a second.
func TestOneJammedNeighborDoesNotRepeatTheUpdateToTheRest(t *testing.T) {
	speaker, jammed, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(jammed)
	blocked := make(chan struct{})
	var release sync.Once
	stuck := netstack.NewPeerReserved("stuck",
		func(int) (netstack.BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { <-blocked; return nil })
	defer func() { release.Do(func() { close(blocked) }); stuck.Close() }()
	speaker.mu.Lock()
	jammed.peer = stuck
	speaker.mu.Unlock()
	for {
		place, err := stuck.ReserveRawOrDrop([]byte("bulk"), 41)
		if errors.Is(err, netstack.ErrSendQueueFull) {
			break
		}
		place.Send()
	}

	var healthy atomic.Int64
	peer := netstack.NewPeer("healthy", func(raw []byte, _ byte) ([]byte, error) { return raw, nil },
		func([]byte) error { healthy.Add(1); return nil })
	handle := speaker.AddPeer(peer)
	defer handle.Close()
	makeNeighborReachable(speaker.neighbors[peer.ID])

	prefix := netip.MustParsePrefix("fd00:7::/64")
	speaker.Originate(prefix)
	const passes = 20
	for pass := range passes {
		speaker.mu.Lock()
		// Seeded on the first pass only: Originate wakes the run loop rather
		// than leaving the key for the next pass to pick up, and what is being
		// measured is what the later passes repeat on their own.
		if pass == 0 {
			speaker.routes.dirty[routeKey{dest: prefix}] = struct{}{}
		}
		send := speaker.emitLocked(speaker.triggeredActions(time.Now()))
		speaker.mu.Unlock()
		send()
	}
	if got := healthy.Load(); got > 2 {
		t.Errorf("the healthy neighbor was sent %d copies of one triggered update across %d passes", got, passes)
	}
	speaker.mu.Lock()
	stillOwed := len(jammed.owed)
	speaker.mu.Unlock()
	if stillOwed == 0 {
		t.Error("the jammed neighbor stopped being owed the update it never got")
	}
}

// A dropped Hello is the one packet of a pass that nothing else stands in for,
// so the pass that lost it has to put the record back: Run re-emits only for a
// neighbor whose sentHello is clear or whose interval is due, and three lost
// Hellos in a row withdraw every route through the neighbor.
func TestDroppedHelloIsSentAgainOnTheNextWake(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	closed := netstack.NewPeerReserved("closed",
		func(int) (netstack.BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { return nil })
	closed.Close()
	speaker.mu.Lock()
	neighbor.peer = closed
	hello := speaker.helloAction(neighbor, time.Now())
	sent := neighbor.sentHello
	send := speaker.emitLocked([]sendAction{hello})
	speaker.mu.Unlock()
	send()

	if !sent {
		t.Fatal("helloAction did not record the hello it built, so this proves nothing")
	}
	speaker.mu.Lock()
	still := neighbor.sentHello
	speaker.mu.Unlock()
	if still {
		t.Error("a dropped hello is still recorded as sent, so the next wake does not redo it")
	}
}

// The Hello and the dump are both multicast, so coalescing on the destination
// alone merged them into one action and one priority. The priority is part of
// the key for that reason: a dump decided before its Hello would otherwise
// carry the Hello into the droppable tail, and a truncated dump would roll the
// Hello's own record back with it.
func TestHelloIsNotCoalescedIntoTheDump(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	prefix := netip.MustParsePrefix("fd00:9::/64")
	dump := sendAction{neighbor: neighbor, dest: multicastGroup, priority: priorityDump, tlvs: []RawTLV{
		EncodeRouterID([8]byte{1}),
		EncodeUpdate(Update{AE: AEIPv6, Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(),
			Interval: 6000, Seqno: 1, Metric: 64}),
	}}
	speaker.mu.Lock()
	// The dump first, which is the order that used to swallow the hello.
	merged := coalesce([]sendAction{dump, speaker.helloAction(neighbor, time.Now())})
	speaker.mu.Unlock()
	if len(merged) != 2 {
		t.Fatalf("coalesce produced %d actions, so the hello shares the dump's place in the queue", len(merged))
	}
	if merged[0].priority == merged[1].priority {
		t.Error("the two actions carry one priority, so the sort cannot tell them apart")
	}
}

// A wildcard retraction is a walk of the whole route table, and its TLV is
// twelve bytes: a hundred and twelve fit in one packet. After the first, every
// route through that neighbor is already at infinity and the walk finds
// nothing to do, so the repeats are the same work over again, under the lock
// that carries every other neighbor's receive path, the hello emitter and
// route selection. Measured at 403 ms per packet at maxRouteKeys routes.
func TestRepeatedWildcardRetractionsCostNothing(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	now := time.Now()
	const routes = 2000
	speaker.mu.Lock()
	for i := range routes {
		key := routeKey{dest: netip.MustParsePrefix(fmt.Sprintf("fd00:%x:%x::/64", i>>16, i&0xffff))}
		speaker.routes.update(neighbor, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 64},
			time.Minute, now)
	}
	if got := len(speaker.routes.entries); got != routes {
		t.Fatalf("the table holds %d routes, so this proves nothing", got)
	}

	// A packet of them. Each reselection reads every route of every entry, so
	// the first is linear in the table and the rest have to be constant.
	// Built by hand: EncodeUpdate has no AE 0 case, because this node never
	// sends one. AE, flags, plen, omitted, interval, seqno, metric.
	wildcard := EncodePacket([]RawTLV{{Type: TLVUpdate, Body: []byte{
		AEWildcard, 0, 0, 0, 0x00, 0x64, 0, 0, 0xff, 0xff,
	}}})
	first := time.Now()
	speaker.handlePacketLocked(neighbor, wildcard, now)
	one := time.Since(first)

	rest := time.Now()
	for range 111 {
		speaker.handlePacketLocked(neighbor, wildcard, now)
	}
	many := time.Since(rest)
	speaker.mu.Unlock()

	if one == 0 {
		t.Fatal("the first retraction took no measurable time, so the comparison below proves nothing")
	}
	if many > one {
		t.Errorf("111 repeated wildcard retractions took %s against %s for the first, so each one walks the table again", many, one)
	}
}

// One neighbor alternating an update and a retraction for one prefix drives a
// selection change per TLV, and sixty-six of those fit in one packet. Each was
// a synchronous log write on the goroutine holding s.mu, which is the shape
// the tenth round fixed in the hub's receive loop one level out.
func TestSelectionChangesAreNotOneLogLineEach(t *testing.T) {
	var lines atomic.Int64
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(countingWriter{&lines}, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	dest := netip.MustParsePrefix("fd00:1::/64")
	key := routeKey{dest: dest}
	now := time.Now()
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	const flaps = 66
	for i := range flaps {
		metric := uint16(64)
		if i%2 == 1 {
			metric = MetricInfinity
		}
		speaker.routes.update(neighbor, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: metric},
			time.Minute, now)
	}
	if got := lines.Load(); got != 1 {
		t.Errorf("%d selection changes produced %d log lines, want the one the interval allows", flaps, got)
	}
	if routeLogInterval > time.Second {
		t.Errorf("a selection change is said at most once every %v, which is not a log anybody can follow a flapping mesh with",
			routeLogInterval)
	}
	if speaker.routeChanges == 0 {
		t.Error("the changes were not counted, so the line that stands for them says nothing")
	}

	// The other half of the bound: the interval passes and the next change is
	// said out loud, carrying how many it stands for. A line that never comes
	// back, or one that does not count, is a selection log that says nothing.
	var said strings.Builder
	slog.SetDefault(slog.New(slog.NewTextHandler(&said, nil)))
	speaker.routeLogged = now.Add(-routeLogInterval - time.Second)
	suppressed := speaker.routeChanges
	speaker.routes.update(neighbor, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 64},
		time.Minute, now)
	if got := said.String(); !strings.Contains(got, "changes_since_last="+strconv.Itoa(suppressed+1)) {
		t.Errorf("the line after the interval reads %q, which does not stand for the %d changes before it",
			strings.TrimSpace(got), suppressed+1)
	}
}

type countingWriter struct{ n *atomic.Int64 }

func (w countingWriter) Write(b []byte) (int, error) { w.n.Add(1); return len(b), nil }

// settleRunLoop stands in for a pass that has just finished: nothing is owed,
// and the loop is asleep on the deadline this state implies.
func settleRunLoop(s *Speaker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextHello, s.nextUpdate = time.Now().Add(time.Hour), time.Now().Add(time.Hour)
	s.updatePending = false
	clear(s.routes.dirty)
	s.routes.starved = nil
	for _, n := range s.neighbors {
		n.sentHello = true
		clear(n.owed)
	}
	s.sleepUntil = s.deadlineLocked()
	select {
	case <-s.changed:
	default:
	}
}

// One pass of the run loop reselects the whole route table, tens of
// milliseconds at a full one, all of it under the lock that is every other
// neighbor's receive path. A wake for every arriving packet therefore lets one
// neighbor charge this node a sweep for a fifty-two byte Hello, as fast as the
// link carries them. The wake is owed to what a packet left behind, and a
// Hello that only pushes its own deadline further out leaves nothing.
func TestARefreshingHelloDoesNotWakeTheRunLoop(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	hello := func(seqno uint16, interval uint16) []byte {
		return EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: seqno, Interval: interval})})
	}
	speaker.handlePacket(neighbor, hello(1, 400))
	settleRunLoop(speaker)

	speaker.handlePacket(neighbor, hello(2, 400))
	if len(speaker.changed) != 0 {
		t.Error("a Hello that only moved its own deadline later woke a full selection sweep")
	}

	// A Hello promising a much shorter interval brings the neighbor's own
	// deadline forward, which the loop is asleep past, so it has to wake.
	speaker.handlePacket(neighbor, hello(3, 1))
	if len(speaker.changed) == 0 {
		t.Error("a Hello that brought the neighbor's deadline forward left the loop asleep past it")
	}

	// An Update that changes a selection owes a triggered update, RFC 8966
	// section 3.7.2, which waits for the next pass.
	settleRunLoop(speaker)
	makeNeighborReachable(neighbor)
	prefix := netip.MustParsePrefix("fd00:5::/64")
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{
		EncodeRouterID([8]byte{1}),
		EncodeUpdate(Update{AE: AEIPv6, Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(),
			Interval: 6000, Seqno: 1, Metric: 60}),
	}))
	if len(speaker.routes.entries) != 1 {
		t.Fatalf("the update installed %d routes, so this proves nothing", len(speaker.routes.entries))
	}
	if len(speaker.changed) == 0 {
		t.Error("a selection change left the triggered update waiting for whatever wakes the loop next")
	}
}

// RFC 8966 section 4.6.7 has a Router-Id TLV set the id "implied by subsequent
// Update TLVs" for the rest of its own packet, so the id belongs in a packet
// once rather than in front of every Update. It repeats most in what a
// neighbor can ask for: a Route Request for a prefix this node has no route to
// is answered with a retraction carrying this node's own id, and a packet of
// requests draws a packet of those. The state is packet-local, so a split has
// to put the id back at the head of the next one.
func TestARepeatedRouterIDIsSentOncePerPacket(t *testing.T) {
	speaker, neighbor, packets := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	mine, theirs := [8]byte{1}, [8]byte{2}
	update := func(id [8]byte, prefix string) []RawTLV {
		p := netip.MustParsePrefix(prefix)
		return []RawTLV{EncodeRouterID(id), EncodeUpdate(Update{AE: AEIPv6, Plen: p.Bits(),
			Prefix: p.Addr().AsSlice(), Interval: 6000, Seqno: 1, Metric: 60})}
	}
	var tlvs []RawTLV
	for _, spell := range []struct {
		id     [8]byte
		prefix string
	}{{mine, "fd00:1::/64"}, {mine, "fd00:2::/64"}, {theirs, "fd00:3::/64"}, {mine, "fd00:4::/64"}} {
		tlvs = append(tlvs, update(spell.id, spell.prefix)...)
	}
	speaker.mu.Lock()
	send := speaker.emitLocked([]sendAction{{neighbor: neighbor, dest: neighbor.addr, priority: priorityDump, tlvs: tlvs}})
	speaker.mu.Unlock()
	send()
	if len(*packets) != 1 {
		t.Fatalf("the batch left as %d packets", len(*packets))
	}
	sent, err := DecodePacket((*packets)[0][ipv6HeaderLen+udpHeaderLen:])
	if err != nil {
		t.Fatal(err)
	}
	var shape []TLVType
	for _, tlv := range sent {
		shape = append(shape, tlv.Type)
	}
	want := []TLVType{TLVRouterID, TLVUpdate, TLVUpdate, TLVRouterID, TLVUpdate, TLVRouterID, TLVUpdate}
	if !slices.Equal(shape, want) {
		t.Errorf("the packet carries %v, want %v", shape, want)
	}

	// A neighbor has to read it back the same way, or the saving is a wrong
	// origin on every Update that followed the one it dropped.
	reader, peer, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(peer)
	reader.handlePacket(peer, (*packets)[0][ipv6HeaderLen+udpHeaderLen:])
	reader.mu.Lock()
	defer reader.mu.Unlock()
	for prefix, want := range map[string][8]byte{
		"fd00:1::/64": mine, "fd00:2::/64": mine, "fd00:3::/64": theirs, "fd00:4::/64": mine,
	} {
		entry := reader.routes.entries[routeKey{dest: netip.MustParsePrefix(prefix)}]
		if entry == nil {
			t.Fatalf("%s was not learned at all", prefix)
		}
		if got := entry.routes[peer].routerID; got != want {
			t.Errorf("%s was learned from origin %v, want %v", prefix, got, want)
		}
	}
}

// The id in effect does not cross a packet boundary, so a run the assembler
// splits has to spell it out again at the head of the piece that follows.
func TestASplitPacketCarriesTheRouterIDAgain(t *testing.T) {
	speaker, neighbor, packets := captureSpeaker(t, Config{PacketSize: 96})
	makeNeighborReachable(neighbor)
	var tlvs []RawTLV
	for i := range 8 {
		p := netip.MustParsePrefix(fmt.Sprintf("fd00:%x::/64", i))
		tlvs = append(tlvs, EncodeRouterID([8]byte{1}), EncodeUpdate(Update{AE: AEIPv6, Plen: p.Bits(),
			Prefix: p.Addr().AsSlice(), Interval: 6000, Seqno: 1, Metric: 60}))
	}
	speaker.mu.Lock()
	send := speaker.emitLocked([]sendAction{{neighbor: neighbor, dest: neighbor.addr, priority: priorityDump, tlvs: tlvs}})
	speaker.mu.Unlock()
	send()
	if len(*packets) < 2 {
		t.Fatalf("the batch left as %d packets, so nothing was split", len(*packets))
	}
	for i, raw := range *packets {
		sent, err := DecodePacket(raw[ipv6HeaderLen+udpHeaderLen:])
		if err != nil {
			t.Fatal(err)
		}
		if len(sent) == 0 || sent[0].Type != TLVRouterID {
			t.Errorf("packet %d opens with %v, so every Update in it takes an origin from nowhere", i, sent)
		}
	}
}

// The kept minimum stands in for a walk of up to maxStarveRetries entries that
// the receive path would otherwise do per packet. It is allowed to be early,
// which costs one pass that finds nothing due, and never late: a late one is a
// seqno request that waits for whatever wakes the loop next, which on a quiet
// link is nothing. Every write of a deadline has to fold into it, and the pass
// that reads them all has to rebuild it.
func TestTheStarveRetryDeadlineIsNeverLate(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	now := time.Now()
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	truest := func() time.Time {
		var earliest time.Time
		for _, retry := range speaker.starveRetries {
			earliest = earlier(earliest, retry.nextAt)
		}
		return earliest
	}
	// Two-sided while nothing has been forgotten: the kept value is allowed to
	// be early only because a removal can leave it so, and no removal has
	// happened yet, so anything but equality here is a write that did not fold
	// in. After a pass that forgets entries the weaker rule is all that holds.
	exact := func(what string) {
		t.Helper()
		if want := truest(); !speaker.nextStarveRetry.Equal(want) {
			t.Errorf("after %s the kept deadline is %v and the earliest retry is due at %v",
				what, speaker.nextStarveRetry, want)
		}
	}
	check := func(what string) {
		t.Helper()
		want := truest()
		// Zero is not "early": earlier() reads it as no deadline at all, so a
		// kept value that collapses to zero while retries remain is the late
		// case this is named for, and After() alone never sees it.
		if speaker.nextStarveRetry.IsZero() != want.IsZero() {
			t.Errorf("after %s the kept deadline is %v and the earliest retry is due at %v",
				what, speaker.nextStarveRetry, want)
			return
		}
		if speaker.nextStarveRetry.After(want) {
			t.Errorf("after %s the kept deadline is %v, later than the %v something is due at",
				what, speaker.nextStarveRetry, want)
		}
	}
	for i := range 8 {
		key := routeKey{dest: netip.MustParsePrefix(fmt.Sprintf("fd00:%x::/64", i))}
		speaker.rememberStarved(key, [8]byte{byte(i)}, uint16(i), neighbor.peer.ID, now.Add(time.Duration(8-i)*time.Second))
		exact("remembering one")
	}
	// The same prefix again pulls its own deadline back in, which is the write
	// that reading the map afterwards would have caught for free.
	first := routeKey{dest: netip.MustParsePrefix("fd00:0::/64")}
	speaker.rememberStarved(first, [8]byte{0}, 9, neighbor.peer.ID, now.Add(-time.Hour))
	exact("bringing one forward")

	// A pass with some of them due and some not: the rebuild has to carry the
	// ones it walked past as well as the ones it rescheduled.
	speaker.retryStarvedLocked(now.Add(4 * time.Second))
	if due, waiting := 0, 0; true {
		for _, retry := range speaker.starveRetries {
			if retry.attempts > 0 {
				due++
			} else {
				waiting++
			}
		}
		if due == 0 || waiting == 0 {
			t.Fatalf("the pass found %d due and %d waiting, so it read only one kind", due, waiting)
		}
	}
	check("a pass with some due and some not")

	// And a pass in which every one of them is due, so the rebuild carries
	// only what it rescheduled: that fold is the one no other pass reaches,
	// and without it the kept value collapses to zero while retries remain.
	speaker.retryStarvedLocked(now.Add(time.Minute))
	check("a pass in which every retry was due")

	// Passes until every retry has spent its attempts, which is what empties
	// the map. A kept deadline that survives that is one the rebuild did not
	// clear, and the run loop then wakes for a retry that no longer exists.
	at := now
	for range seqnoRequestRetries + 2 {
		at = at.Add(time.Hour)
		speaker.retryStarvedLocked(at)
		check("a pass that read every one of them")
	}
	if len(speaker.starveRetries) != 0 {
		t.Fatalf("%d retries outlived their attempts, so the clear is not reached", len(speaker.starveRetries))
	}
	if !speaker.nextStarveRetry.IsZero() {
		t.Errorf("with no retries left the loop is still due to wake at %v", speaker.nextStarveRetry)
	}
}

// A peer that cannot be sent to must not make every packet from every other
// neighbor pay for a full sweep. A rollback restores the neighbor's owed set
// and its sentHello, and both stay restored for as long as that peer refuses:
// a peer whose Child SA the other end deleted refuses every reservation, and
// RFC 7296 section 1.4.1 lets it stay that way, so "a pass is owed something"
// is true from then on. The work is put on a timer instead.
func TestACongestedPeerDoesNotReopenTheWakePerPacket(t *testing.T) {
	speaker, healthy, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(healthy)
	stuck := speaker.AddPeer(netstack.NewPeerReserved("stuck",
		func(int) (netstack.BatchSealer, error) { return nil, errors.New("no child sa") },
		func([][]byte) error { return nil })).state
	stuck.addr = netip.MustParseAddr("fe80::3")
	makeNeighborReachable(stuck)

	// A pass that builds a Hello for the stuck peer and cannot send it, which
	// is what leaves sentHello false from here on.
	speaker.mu.Lock()
	send := speaker.emitLocked([]sendAction{speaker.helloAction(stuck, time.Now())})
	speaker.mu.Unlock()
	send()
	if stuck.sentHello {
		t.Fatal("the stuck peer took the hello, so this proves nothing")
	}

	// The healthy neighbor's own hello interval has to be settled first, or
	// the second Hello shortens it and wakes the loop for that instead.
	speaker.handlePacket(healthy, EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 8, Interval: 400})}))

	// Stand in for a loop that has finished that pass and is asleep on its
	// deadline, without touching the flag the pass left behind.
	speaker.mu.Lock()
	speaker.nextHello, speaker.nextUpdate = time.Now().Add(time.Hour), time.Now().Add(time.Hour)
	speaker.updatePending, speaker.retryAt = false, time.Time{}
	clear(speaker.routes.dirty)
	speaker.routes.starved = nil
	speaker.sleepUntil = speaker.deadlineLocked()
	select {
	case <-speaker.changed:
	default:
	}
	speaker.mu.Unlock()

	speaker.handlePacket(healthy, EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 9, Interval: 400})}))
	if len(speaker.changed) != 0 {
		t.Error("one peer that cannot be sent to made a refreshing Hello from another wake a full sweep")
	}

	// The Hello is not forgotten: the pass that could not send it schedules
	// its own retry, and that retry is a term of the deadline.
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	speaker.retryAt = time.Time{}
	speaker.emitLocked([]sendAction{speaker.helloAction(stuck, time.Now())})
	if speaker.retryAt.IsZero() {
		t.Fatal("a pass that could not send scheduled no retry, so the Hello waits for the hello interval")
	}
	if got := speaker.deadlineLocked(); !got.Equal(speaker.retryAt) {
		t.Errorf("the deadline is %v and the retry is due at %v, which it does not carry", got, speaker.retryAt)
	}
}

// The two request suppression tables expire on a two second window, which is
// shorter than every other deadline the run loop has. Nothing on the receive
// path sweeps them any more, so without a deadline of their own the budgets
// they hold -- maxPendingSeqnoPerNeighbor of them per neighbor -- stay held by
// entries that suppress nothing for as long as a hello interval, which
// Validate allows to be minutes.
func TestTheSuppressionWindowIsADeadlineOfItsOwn(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{HelloInterval: 10 * time.Minute, UpdateInterval: 10 * time.Minute})
	makeNeighborReachable(neighbor)
	now := time.Now()
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	speaker.nextHello, speaker.nextUpdate = now.Add(time.Hour), now.Add(time.Hour)

	index := sourceKey{route: routeKey{dest: netip.MustParsePrefix("fd00:7::/64")}, routerID: [8]byte{3}}
	if !speaker.allowSeqnoRequest(index, 1, neighbor.peer.ID, now) {
		t.Fatal("the first request was suppressed")
	}
	if speaker.pendingByAsker[neighbor.peer.ID] != 1 {
		t.Fatalf("the asker holds %d of its share", speaker.pendingByAsker[neighbor.peer.ID])
	}
	want := now.Add(seqnoRequestSuppress)
	if got := speaker.deadlineLocked(); got.After(want) {
		t.Fatalf("the loop sleeps until %v, past the %v the window expires at", got, want)
	}

	// The record of what this node asked expires on the same window and is
	// held by the same budget, so it is a deadline the same way.
	speaker.nextRequestSweep = time.Time{}
	if !speaker.allowAsk(neighbor, index.route, index.routerID, now) {
		t.Fatal("the first ask was suppressed")
	}
	if got := speaker.deadlineLocked(); got.After(want) {
		t.Errorf("after an ask the loop sleeps until %v, past the %v that window expires at", got, want)
	}

	// A sweep that leaves something behind has to carry it: the rebuild is
	// what makes the kept value exact, and an entry it walks past without
	// folding in is one the loop never wakes for again.
	// One of each table survives the sweep, so both rebuilds have something to
	// walk past and fold back in, and the ask is the earlier of the two so
	// that its fold is the one the kept deadline depends on.
	later := sourceKey{route: routeKey{dest: netip.MustParsePrefix("fd00:9::/64")}, routerID: [8]byte{4}}
	if !speaker.allowAsk(neighbor, later.route, later.routerID, want) {
		t.Fatal("the second ask was suppressed")
	}
	if !speaker.allowSeqnoRequest(later, 1, neighbor.peer.ID, want.Add(time.Second)) {
		t.Fatal("the second request was suppressed")
	}
	speaker.sweepRequestsLocked(want)
	if len(speaker.askedSeqno) != 1 || len(speaker.pendingSeqno) != 1 {
		t.Fatalf("the sweep left %d asks and %d entries, want one of each",
			len(speaker.askedSeqno), len(speaker.pendingSeqno))
	}
	if got := speaker.nextRequestSweep; got.IsZero() || got.After(want.Add(seqnoRequestSuppress)) {
		t.Errorf("the ask the sweep walked past is due at %v and the kept deadline is %v",
			want.Add(seqnoRequestSuppress), got)
	}

	// And a sweep that empties both tables leaves nothing to wake for.
	speaker.sweepRequestsLocked(want.Add(2 * seqnoRequestSuppress).Add(time.Second))
	if len(speaker.pendingSeqno) != 0 || len(speaker.pendingByAsker) != 0 || len(speaker.askedSeqno) != 0 {
		t.Errorf("the sweep left %d entries, %d shares and %d asks",
			len(speaker.pendingSeqno), len(speaker.pendingByAsker), len(speaker.askedSeqno))
	}
	if !speaker.nextRequestSweep.IsZero() {
		t.Errorf("with nothing left the sweep is still due at %v", speaker.nextRequestSweep)
	}
}

// quietPasses waits for the run loop to stop working and reports how many
// passes it has made.
func quietPasses(t *testing.T, s *Speaker) uint64 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	last := s.Passes()
	for still := 0; still < 10; still++ {
		time.Sleep(10 * time.Millisecond)
		if now := s.Passes(); now != last {
			last, still = now, 0
		}
		if time.Now().After(deadline) {
			t.Fatal("the run loop never went quiet")
		}
	}
	return last
}

// The wake decision is only worth anything if Run actually records the
// deadline it slept on: without that, sleepUntil stays zero, every packet
// takes the zero branch, and the whole mechanism is inert while every test
// that writes sleepUntil itself still passes. This one drives the real loop
// and counts what the packets cost.
func TestRefreshingHellosCostTheRunLoopNothing(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{
		HelloInterval: 10 * time.Minute, UpdateInterval: 10 * time.Minute})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); speaker.Run(ctx) }()
	defer func() { cancel(); <-done }()

	hello := func(seqno uint16) []byte {
		return EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: seqno, Interval: 400})})
	}
	quietPasses(t, speaker)
	// The first Hello sets the neighbor's interval, which moves a deadline and
	// is allowed to wake the loop.
	speaker.handlePacket(neighbor, hello(1))
	settled := quietPasses(t, speaker)

	for i := range 50 {
		speaker.handlePacket(neighbor, hello(uint16(2+i)))
	}
	if got := quietPasses(t, speaker); got != settled {
		t.Errorf("fifty Hellos that refreshed a deadline already set cost %d reselections of the whole route table", got-settled)
	}

	// Receive is the other entry, and takes the same decision.
	for i := range 50 {
		speaker.Receive(neighbor.peer, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup, hello(uint16(60+i))))
	}
	if got := quietPasses(t, speaker); got != settled {
		t.Errorf("fifty Hellos through Receive cost %d reselections of the whole route table", got-settled)
	}

	// And the loop is not merely asleep for good: something it owes still
	// wakes it.
	speaker.Originate(netip.MustParsePrefix("fd00:4::/64"))
	if got := quietPasses(t, speaker); got == settled {
		t.Error("originating a prefix woke nothing, so this test would pass with the loop stopped")
	}
}

// wildcardRetraction is the AE 0 Update of RFC 8966 section 4.6.9, built by
// hand because EncodeUpdate has no AE 0 case: this node never sends one.
func wildcardRetraction() RawTLV {
	return RawTLV{Type: TLVUpdate, Body: []byte{AEWildcard, 0, 0, 0, 0x00, 0x64, 0, 0, 0xff, 0xff}}
}

// The memo that makes a repeated wildcard retraction free has to be forgotten
// the moment the neighbor advertises a finite metric again, or its next
// wildcard retraction is a no-op and the route it should have withdrawn stays
// selected for as long as the neighbor keeps sending them.
func TestARetractionAfterANewUpdateIsNotMemoized(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	prefix := netip.MustParsePrefix("fd00:6::/64")
	announce := func(metric uint16) {
		speaker.handlePacket(neighbor, EncodePacket([]RawTLV{
			EncodeRouterID([8]byte{1}),
			EncodeUpdate(Update{AE: AEIPv6, Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(),
				Interval: 6000, Seqno: 1, Metric: metric}),
		}))
	}
	selected := func() bool {
		speaker.mu.Lock()
		defer speaker.mu.Unlock()
		entry := speaker.routes.entries[routeKey{dest: prefix}]
		return entry != nil && entry.selected.neighbor != nil
	}
	announce(60)
	if !selected() {
		t.Fatal("the route was never selected, so this proves nothing")
	}
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{wildcardRetraction()}))
	if selected() {
		t.Fatal("the first wildcard retraction did not withdraw the route")
	}
	announce(60)
	if !selected() {
		t.Fatal("the route did not come back, so the second retraction has nothing to do")
	}
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{wildcardRetraction()}))
	if selected() {
		t.Error("the second wildcard retraction was skipped as already applied")
	}
}

// A neighbor that goes away takes its memo with it. The map is keyed by the
// neighbor's state pointer, so an entry left behind pins a retired one and
// everything it held for the life of the speaker.
func TestARetiredNeighborLeavesNoRetractionMemo(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{wildcardRetraction()}))
	speaker.mu.Lock()
	held := len(speaker.routes.retracted)
	speaker.mu.Unlock()
	if held != 1 {
		t.Fatalf("the retraction was recorded against %d neighbors, so this proves nothing", held)
	}
	speaker.mu.Lock()
	speaker.routes.expireNeighbor(neighbor, time.Now())
	left := len(speaker.routes.retracted)
	speaker.mu.Unlock()
	if left != 0 {
		t.Errorf("a retired neighbor left %d memo entries, which pin it forever", left)
	}
}

// The kept expiry minimum is rebuilt by the sweep, which is the one pass that
// reads every route. Without the clear it only ever moves earlier, so the
// first route to leave the table leaves a deadline permanently in the past and
// the run loop spins on it.
func TestTheExpiryMinimumIsRebuiltByTheSweep(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	prefix := netip.MustParsePrefix("fd00:8::/64")
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{
		EncodeRouterID([8]byte{1}),
		EncodeUpdate(Update{AE: AEIPv6, Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(),
			Interval: 100, Seqno: 1, Metric: 60}),
	}))
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	if speaker.routes.nextExpiry().IsZero() {
		t.Fatal("the route carried no expiry, so this proves nothing")
	}
	// Section 3.5.3 expires a route to infinity first and flushes it on the
	// next expiry, so two sweeps empty the table.
	at := time.Now().Add(time.Hour)
	speaker.routes.sweepExpired(at)
	at = at.Add(time.Hour)
	speaker.routes.sweepExpired(at)
	for _, entry := range speaker.routes.entries {
		if len(entry.routes) != 0 {
			t.Fatal("a route survived both sweeps, so the expiry is still real")
		}
	}
	if got := speaker.routes.nextExpiry(); !got.IsZero() && !got.After(at) {
		t.Errorf("a table with no routes left is due at %v, before the %v it was just swept at: "+
			"the run loop wakes immediately, finds nothing, and does it again", got, at)
	}
}

// The loop's own two timers are terms of the deadline, or it never sends a
// periodic Hello or a periodic dump again.
func TestTheLoopsOwnTimersAreTermsOfItsDeadline(t *testing.T) {
	speaker, _, _ := captureSpeaker(t, Config{})
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	now := time.Now()
	far := func() {
		speaker.nextHello, speaker.nextUpdate = now.Add(time.Hour), now.Add(time.Hour)
		speaker.nextStarveRetry, speaker.retryAt, speaker.nextRequestSweep = time.Time{}, time.Time{}, time.Time{}
	}
	for name, set := range map[string]func(){
		"hello":  func() { far(); speaker.nextHello = now.Add(time.Second) },
		"update": func() { far(); speaker.nextUpdate = now.Add(time.Second) },
		// Each of the kept deadlines stands for work nothing else wakes for: a
		// seqno request that has to be repeated, a pass that could not send
		// what it built, and a suppression window whose budget is held until
		// it is swept.
		"starvation retry":   func() { far(); speaker.nextStarveRetry = now.Add(time.Second) },
		"refused send retry": func() { far(); speaker.retryAt = now.Add(time.Second) },
		"request sweep":      func() { far(); speaker.nextRequestSweep = now.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			set()
			if got := speaker.deadlineLocked(); !got.Equal(now.Add(time.Second)) {
				t.Errorf("the deadline is %v, which does not carry the %s timer", got, name)
			}
		})
	}
}

// A dump a reload or an origination asked for is work the next pass owes, and
// nothing else records it.
func TestAPendingDumpIsWorkTheNextPassOwes(t *testing.T) {
	speaker, _, _ := captureSpeaker(t, Config{})
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	speaker.updatePending = false
	clear(speaker.routes.dirty)
	speaker.routes.starved = nil
	if speaker.pendingWorkLocked() {
		t.Fatal("a speaker with nothing to do reports work, so this proves nothing")
	}
	for name, set := range map[string]func(){
		"a pending dump":      func() { speaker.updatePending = true },
		"a changed selection": func() { speaker.routes.dirty[routeKey{dest: netip.MustParsePrefix("fd00::/64")}] = struct{}{} },
		"a starved prefix":    func() { speaker.routes.starved = []starveRequest{{}} },
	} {
		t.Run(name, func(t *testing.T) {
			speaker.updatePending = false
			clear(speaker.routes.dirty)
			speaker.routes.starved = nil
			set()
			if !speaker.pendingWorkLocked() {
				t.Errorf("%s is not work, so it waits for whatever wakes the loop next", name)
			}
		})
	}
}

// A speaker whose loop has not run yet is asleep on no deadline at all, and
// every arriving packet has to wake it: the comparison below it is against a
// zero time, which nothing is before.
func TestAPacketWakesALoopThatHasNotRunYet(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	speaker.mu.Lock()
	speaker.updatePending = false
	clear(speaker.routes.dirty)
	speaker.routes.starved = nil
	for _, n := range speaker.neighbors {
		n.sentHello = true
	}
	if !speaker.sleepUntil.IsZero() {
		t.Fatal("the loop already recorded a deadline, so this proves nothing")
	}
	speaker.mu.Unlock()
	select {
	case <-speaker.changed:
	default:
	}
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 1, Interval: 400})}))
	if len(speaker.changed) == 0 {
		t.Error("the packet left the loop asleep on a deadline it has never set")
	}
}

// The saving has to reach the packet count, not only the wire: the suppressed
// id has to come out of the size the run is packed to, or the assembler splits
// as if it were still there and the packets stay as many as before.
func TestASuppressedRouterIDMakesRoomInThePacket(t *testing.T) {
	speaker, neighbor, packets := captureSpeaker(t, Config{PacketSize: 96})
	makeNeighborReachable(neighbor)
	var run []RawTLV
	for i := range 4 {
		p := netip.MustParsePrefix(fmt.Sprintf("fd00:a%x::/64", i))
		run = append(run, EncodeRouterID([8]byte{1}), EncodeUpdate(Update{AE: AEIPv6, Plen: p.Bits(),
			Prefix: p.Addr().AsSlice(), Interval: 6000, Seqno: 1, Metric: 60}))
	}
	speaker.mu.Lock()
	send := speaker.emitLocked([]sendAction{{neighbor: neighbor, dest: neighbor.addr,
		priority: priorityDump, tlvs: run}})
	speaker.mu.Unlock()
	send()
	// Four bytes of header, twelve for the one id and twenty an Update, which
	// is ninety-six exactly. With the id charged four times it is two packets.
	if got := len(*packets); got != 1 {
		t.Errorf("four Updates sharing one id left as %d packets, the shape they have with the id repeated", got)
	}
	for _, raw := range *packets {
		if got := len(raw) - ipv6HeaderLen - udpHeaderLen; got > speaker.cfg.PacketSize {
			t.Errorf("a packet came out %d bytes, past the %d configured", got, speaker.cfg.PacketSize)
		}
	}
}
