package babel

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

// meshFabric wires several speakers over in-memory relays, one per link, with
// the same per-peer dispatch as wireSpeakerPair. Neighbors start reachable and
// packets are delivered inline, so a test drives the protocol one exchange at a
// time instead of waiting for timers.
type meshFabric struct {
	t        *testing.T
	speakers map[string]*Speaker
	meshes   map[string]*netstack.Mesh
	handles  map[string]*PeerHandle
	sentMu   sync.Mutex
	sent     map[string][]RawTLV
}

// newMeshFabric builds the topology described by links of the form "a-b".
func newMeshFabric(t *testing.T, cfg Config, links ...string) *meshFabric {
	t.Helper()
	f := &meshFabric{
		t:        t,
		speakers: make(map[string]*Speaker),
		meshes:   make(map[string]*netstack.Mesh),
		handles:  make(map[string]*PeerHandle),
		sent:     make(map[string][]RawTLV),
	}
	for _, link := range links {
		ends := strings.Split(link, "-")
		if len(ends) != 2 {
			t.Fatalf("malformed link %q", link)
		}
		f.connect(cfg, ends[0], ends[1])
	}
	return f
}

func (f *meshFabric) node(cfg Config, name string) *Speaker {
	if s, ok := f.speakers[name]; ok {
		return s
	}
	// A router-id derived from the name keeps failures readable and keeps the
	// origin of a route distinguishable from its relay.
	copy(cfg.RouterID[:], name)
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	s, err := New(cfg, mesh)
	if err != nil {
		f.t.Fatal(err)
	}
	f.speakers[name], f.meshes[name] = s, mesh
	return s
}

func (f *meshFabric) connect(cfg Config, x, y string) {
	speakerX, speakerY := f.node(cfg, x), f.node(cfg, y)
	noopEncrypt := func(raw []byte, _ byte) ([]byte, error) { return raw, nil }
	var peerXforY, peerYforX *netstack.Peer
	deliver := func(from, to string, speaker *Speaker, peer **netstack.Peer, mesh *netstack.Mesh) func([]byte) error {
		return func(raw []byte) error {
			f.record(from, to, raw)
			if !speaker.Receive(*peer, raw) {
				mesh.DeliverInbound(raw)
			}
			return nil
		}
	}
	peerYforX = netstack.NewPeer(y, noopEncrypt, deliver(x, y, speakerY, &peerXforY, f.meshes[y]))
	peerXforY = netstack.NewPeer(x, noopEncrypt, deliver(y, x, speakerX, &peerYforX, f.meshes[x]))
	f.handles[x+"-"+y] = speakerX.AddPeer(peerYforX)
	f.handles[y+"-"+x] = speakerY.AddPeer(peerXforY)
	makeNeighborReachable(f.neighbor(x, y))
	makeNeighborReachable(f.neighbor(y, x))
}

// record, reset and tlvs take sentMu because a test that runs a real
// Speaker.Run records from that goroutine while the test body reads.
func (f *meshFabric) record(from, to string, raw []byte) {
	tlvs, err := DecodePacket(raw[ipv6HeaderLen+udpHeaderLen:])
	if err != nil {
		f.t.Errorf("%s sent %s an undecodable packet: %v", from, to, err)
		return
	}
	f.sentMu.Lock()
	defer f.sentMu.Unlock()
	f.sent[from+">"+to] = append(f.sent[from+">"+to], tlvs...)
}

func (f *meshFabric) neighbor(node, peer string) *neighborState {
	f.t.Helper()
	n := f.speakers[node].neighbors[peer]
	if n == nil {
		f.t.Fatalf("%s has no neighbor %s", node, peer)
	}
	return n
}

// cost sets the rxcost node reports for peer, which is the link cost peer's
// routes through node are computed with.
func (f *meshFabric) cost(node, peer string, cost uint16) {
	f.neighbor(node, peer).reportedCost = cost
}

// flush sends a full update dump from each named node, in order. Deliveries are
// inline, so one call carries a change as far as the named nodes reach.
func (f *meshFabric) flush(nodes ...string) {
	for _, node := range nodes {
		f.speakers[node].flushUpdates()
	}
}

func (f *meshFabric) reset() {
	f.sentMu.Lock()
	defer f.sentMu.Unlock()
	clear(f.sent)
}

func (f *meshFabric) tlvs(from, to string) []RawTLV {
	f.sentMu.Lock()
	defer f.sentMu.Unlock()
	return slices.Clone(f.sent[from+">"+to])
}

// inject hands node a packet as if peer had sent it, which is how a test
// reaches a neighbor that split horizon would otherwise keep quiet.
func (f *meshFabric) inject(node, peer string, tlvs ...RawTLV) {
	f.speakers[node].handlePacket(f.neighbor(node, peer), EncodePacket(tlvs))
}

// down drops both ends of a link, as a peer whose ESP session is gone does.
func (f *meshFabric) down(link string) {
	ends := strings.Split(link, "-")
	f.handles[link].Close()
	f.handles[ends[1]+"-"+ends[0]].Close()
}

// selected reports the route node has chosen for key, if any.
func (f *meshFabric) selected(node string, key routeKey) routeSelection {
	if entry := f.speakers[node].routes.entries[key]; entry != nil {
		return entry.selected
	}
	return routeSelection{}
}

func (f *meshFabric) nextHop(node string, key routeKey) string {
	if sel := f.selected(node, key); sel.neighbor != nil {
		return sel.neighbor.peer.ID
	}
	return ""
}

// forwards resolves an address through the node's forwarding table the way a
// routed packet does, so a prefix held unreachable and a prefix missing
// altogether can be told apart: the second falls through to a covering route.
func (f *meshFabric) forwards(node string, address netip.Addr) string {
	peer, ok := f.meshes[node].Routes.Lookup(netip.Addr{}, address)
	if !ok {
		return ""
	}
	return peer.ID
}

func routerID(name string) [8]byte {
	var id [8]byte
	copy(id[:], name)
	return id
}

// updatesFor returns every Update TLV for one prefix, oldest first.
func updatesFor(t *testing.T, tlvs []RawTLV, dest netip.Prefix) []Update {
	t.Helper()
	var out []Update
	for _, tlv := range tlvs {
		if tlv.Type != TLVUpdate {
			continue
		}
		// Nothing here compresses prefixes, so each Update decodes alone.
		update, err := (&PrefixDecoder{}).Decode(tlv.Body)
		if err != nil {
			t.Fatalf("undecodable Update: %v", err)
		}
		addr, ok := netip.AddrFromSlice(update.Prefix)
		if !ok || netip.PrefixFrom(addr.Unmap(), update.Plen).Masked() != dest {
			continue
		}
		out = append(out, update)
	}
	return out
}

func seqnoRequestsFor(t *testing.T, tlvs []RawTLV, dest netip.Prefix) []SeqnoRequest {
	t.Helper()
	var out []SeqnoRequest
	for _, tlv := range tlvs {
		if tlv.Type != TLVSeqnoRequest {
			continue
		}
		request, err := DecodeSeqnoRequest(tlv.Body)
		if err != nil {
			t.Fatalf("undecodable Seqno Request: %v", err)
		}
		if request.Prefix == dest {
			out = append(out, request)
		}
	}
	return out
}

// A relayed route is only loop free because of the feasibility condition: a
// chain converges on transit through the middle node, and when the origin goes
// away the two survivors must not select each other.
func TestThreeNodeChainRedistributesAndCannotLoop(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "b-c")
	dest := netip.MustParsePrefix("fd00:c::/64")
	key := routeKey{dest: dest}
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c", "b", "a")

	if got := fabric.nextHop("b", key); got != "c" {
		t.Fatalf("b reaches the origin via %q, want \"c\"", got)
	}
	if got := fabric.nextHop("a", key); got != "b" {
		t.Fatalf("a did not learn the relayed route, next hop %q", got)
	}
	if got := fabric.selected("a", key); got.cost != 64 || got.routerID != routerID("c") {
		t.Fatalf("relayed route = cost %d from router %v, want 64 from c", got.cost, got.routerID)
	}
	if peer, ok := fabric.meshes["a"].Routes.Lookup(netip.MustParseAddr("2001:db8::1"), dest.Addr()); !ok || peer.ID != "b" {
		t.Fatal("the relayed route was not published to the forwarding table")
	}
	// Split horizon keeps a from offering the route back to the node it came
	// from, so b hears nothing about the prefix from a.
	if got := updatesFor(t, fabric.tlvs("a", "b"), dest); len(got) != 0 {
		t.Fatalf("a advertised %d updates for its next hop's own prefix", len(got))
	}

	fabric.down("b-c")
	fabric.flush("b", "a")
	if got := fabric.nextHop("b", key); got != "" {
		t.Fatalf("b picked up a route via %q after losing the origin", got)
	}
	if got := fabric.nextHop("a", key); got != "" {
		t.Fatalf("a kept a route via %q after the origin went away", got)
	}

	// The omission above is an optimization rather than the safety property. Hand b
	// the advertisement a would have made and it must still refuse it: a's
	// metric is not better than the distance b has already advertised.
	fabric.inject("b", "a",
		EncodeRouterID(routerID("c")),
		EncodeUpdate(Update{AE: AEIPv6, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
			Interval: 6000, Seqno: 1, Metric: 64}))
	if got := fabric.nextHop("b", key); got != "" {
		t.Fatalf("b selected an unfeasible route via %q, closing a loop", got)
	}
}

// A withdrawal must reach the far side of a relay as an explicit retraction
// rather than as silence, which would leave the prefix installed until it aged
// out several update intervals later.
func TestRetractionPropagatesThroughTransit(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "b-c")
	dest := netip.MustParsePrefix("fd00:c::/64")
	key := routeKey{dest: dest}
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c", "b", "a")
	if fabric.nextHop("a", key) != "b" {
		t.Fatal("a never learned the relayed route")
	}
	fabric.reset()

	fabric.down("b-c")
	fabric.flush("b")
	updates := updatesFor(t, fabric.tlvs("b", "a"), dest)
	if len(updates) != 1 || updates[0].Metric != MetricInfinity {
		t.Fatalf("b sent %v for a prefix it lost, want a single retraction", updates)
	}
	if peer, ok := fabric.meshes["a"].Routes.Lookup(netip.MustParseAddr("2001:db8::1"), dest.Addr()); ok {
		t.Fatalf("a kept forwarding to %q after the retraction", peer.ID)
	}

	// The prefix has been withdrawn from a, so there is nothing left to
	// retract and a second dump must stay quiet.
	fabric.reset()
	fabric.flush("b")
	if got := updatesFor(t, fabric.tlvs("b", "a"), dest); len(got) != 0 {
		t.Fatalf("b repeated %d retractions for a prefix a has already dropped", len(got))
	}
}

// A seqno request that the relay cannot satisfy has to reach the origin, and a
// repeat of it must not.
func TestSeqnoRequestIsForwardedOnceTowardOrigin(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "b-c")
	dest := netip.MustParsePrefix("fd00:c::/64")
	key := routeKey{dest: dest}
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c", "b", "a")
	fabric.reset()

	// Ask for a sequence number far ahead of the origin's, so neither the
	// relay nor the reply can satisfy the repeat either.
	request := EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: dest, Seqno: 5, HopCount: 64, RouterID: routerID("c")})
	fabric.inject("b", "a", request)

	forwarded := seqnoRequestsFor(t, fabric.tlvs("b", "c"), dest)
	if len(forwarded) != 1 {
		t.Fatalf("relay forwarded %d requests, want 1", len(forwarded))
	}
	if forwarded[0].HopCount != 63 || forwarded[0].RouterID != routerID("c") || forwarded[0].Seqno != 5 {
		t.Fatalf("forwarded request = %+v", forwarded[0])
	}
	if got := fabric.speakers["c"].originSeqno; got != 2 {
		t.Fatalf("origin sequence number = %d, want a single increment to 2", got)
	}
	if got := fabric.selected("b", key).seqno; got != 2 {
		t.Fatalf("relay route sequence number = %d, want the answered 2", got)
	}

	fabric.reset()
	fabric.inject("b", "a", request)
	if got := seqnoRequestsFor(t, fabric.tlvs("b", "c"), dest); len(got) != 0 {
		t.Fatalf("relay forwarded %d duplicate requests", len(got))
	}
}

// An unfeasible update for the selected route must produce a request for a
// sequence number that would make it usable again, or the route stays
// unselectable until it expires.
func TestUnfeasibleUpdateAsksOriginForNewSeqno(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c", "b-c")
	dest := netip.MustParsePrefix("fd00:c::/64")
	key := routeKey{dest: dest}
	// a's own link to the origin is expensive, so the relayed route through b
	// is both better and feasible when it arrives.
	fabric.cost("a", "c", 1000)
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c", "b", "a")
	if got := fabric.nextHop("a", key); got != "b" {
		t.Fatalf("a reaches the origin via %q, want the cheaper relay \"b\"", got)
	}
	fabric.reset()

	// The relay's route worsens past the distance a has already advertised,
	// so a must drop it rather than keep forwarding along it.
	fabric.inject("a", "b",
		EncodeRouterID(routerID("c")),
		EncodeUpdate(Update{AE: AEIPv6, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
			Interval: 6000, Seqno: 1, Metric: 900}))
	if got := fabric.nextHop("a", key); got == "b" {
		t.Fatal("a kept an unfeasible route selected")
	}
	requests := seqnoRequestsFor(t, fabric.tlvs("a", "b"), dest)
	if len(requests) != 1 {
		t.Fatalf("a sent %d seqno requests after losing its feasible routes, want 1", len(requests))
	}
	if requests[0].RouterID != routerID("c") || !seqnoGT(requests[0].Seqno, 1) {
		t.Fatalf("starvation request = %+v, want a newer seqno for the origin", requests[0])
	}
}

// An exit announces `route ::/0 from <its prefix>`: the source prefix has to
// survive origination, the wire, and selection at the far end.
func TestSourceSpecificOriginationAndSelection(t *testing.T) {
	for _, test := range []struct {
		name   string
		dest   string
		source string
		lookup string
		match  string
		miss   string
	}{
		{"ipv6 default from an exit prefix", "::/0", "2602:f590::/36", "2001:4860::1", "2602:f590:1::7", "2001:db8::7"},
		{"ipv4 default from an announced prefix", "0.0.0.0/0", "23.161.104.0/24", "192.0.2.1", "23.161.104.7", "198.51.100.7"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fabric := newMeshFabric(t, Config{}, "a-b")
			dest, source := netip.MustParsePrefix(test.dest), netip.MustParsePrefix(test.source)
			fabric.speakers["a"].OriginateFrom(dest, source)
			fabric.flush("a")

			updates := updatesFor(t, fabric.tlvs("a", "b"), dest)
			if len(updates) != 1 {
				t.Fatalf("origination sent %d updates for %s, want 1", len(updates), dest)
			}
			if updates[0].SourcePrefix != source || updates[0].Metric != 0 {
				t.Fatalf("update = %s from %s metric %d", dest, updates[0].SourcePrefix, updates[0].Metric)
			}

			key := routeKey{source: source, dest: dest}
			if got := fabric.nextHop("b", key); got != "a" {
				t.Fatalf("the source-specific route was selected via %q, want \"a\"", got)
			}
			routes := fabric.meshes["b"].Routes
			if peer, ok := routes.Lookup(netip.MustParseAddr(test.match), netip.MustParseAddr(test.lookup)); !ok || peer.ID != "a" {
				t.Fatal("a source inside the announced prefix does not resolve")
			}
			if _, ok := routes.Lookup(netip.MustParseAddr(test.miss), netip.MustParseAddr(test.lookup)); ok {
				t.Fatal("a source outside the announced prefix resolved anyway")
			}

			// A source-specific route is an independent entry: retracting it
			// must not need the ordinary route to the same destination.
			fabric.down("a-b")
			if _, ok := routes.Lookup(netip.MustParseAddr(test.match), netip.MustParseAddr(test.lookup)); ok {
				t.Fatal("the source-specific route outlived its peer")
			}
		})
	}
}

// Requests carry a source prefix too, so an exit's default route can be asked
// for by name rather than answered with the ordinary route's state.
func TestRequestsCarrySourcePrefix(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b")
	dest, source := netip.MustParsePrefix("::/0"), netip.MustParsePrefix("2602:f590::/36")
	fabric.speakers["a"].OriginateFrom(dest, source)
	fabric.reset()

	fabric.inject("a", "b", EncodeRouteRequest(RouteRequest{AE: AEIPv6, Prefix: dest, SourcePrefix: source}))
	updates := updatesFor(t, fabric.tlvs("a", "b"), dest)
	if len(updates) != 1 || updates[0].SourcePrefix != source || updates[0].Metric != 0 {
		t.Fatalf("source-specific route request answered with %v", updates)
	}

	// The ordinary route to the same destination is a different entry, and
	// this node does not have it.
	fabric.reset()
	fabric.inject("a", "b", EncodeRouteRequest(RouteRequest{AE: AEIPv6, Prefix: dest}))
	updates = updatesFor(t, fabric.tlvs("a", "b"), dest)
	if len(updates) != 1 || updates[0].SourcePrefix.IsValid() || updates[0].Metric != MetricInfinity {
		t.Fatalf("ordinary route request answered with %v, want a retraction", updates)
	}
}

// Seqno requests reach the origin only if every hop can be trusted to stop
// forwarding them, so the hop count has to run out.
func TestSeqnoRequestStopsAtHopCount(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "b-c")
	dest := netip.MustParsePrefix("fd00:c::/64")
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c", "b", "a")
	fabric.reset()

	for _, hops := range []uint8{0, 1} {
		fabric.inject("b", "a", EncodeSeqnoRequest(SeqnoRequest{
			AE: AEIPv6, Prefix: dest, Seqno: 5, HopCount: hops, RouterID: routerID("c"),
		}))
		if got := seqnoRequestsFor(t, fabric.tlvs("b", "c"), dest); len(got) != 0 {
			t.Fatalf("a request with hop count %d was forwarded", hops)
		}
		if got := fabric.speakers["c"].originSeqno; got != 1 {
			t.Fatalf("origin sequence number = %d, want it untouched", got)
		}
	}
}

func TestSourceTableGarbageCollection(t *testing.T) {
	rt := newRouteTable(func(routeKey, routeSelection) {})
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	adv := advertisement{routerID: [8]byte{1}, seqno: 1, metric: 10}
	now := time.Now()
	rt.observe(key, adv, now)

	rt.sweepSources(now.Add(sourceGCTime - time.Second))
	if len(rt.sources) != 1 {
		t.Fatal("a feasibility distance was dropped before its timer expired")
	}
	// And goes when it expires, whether or not a route still references it.
	// RFC 8966 section 3.7.3 makes the removal unconditional, and Appendix B
	// sets the source GC time longer than the route expiry time so that it is
	// safe. Keeping a referenced entry instead makes a prefix whose only path
	// worsened unreachable for the life of the process: the route stays
	// unfeasible, so it stays referenced, so the distance that refuses it is
	// never collected.
	n := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	makeNeighborReachable(n)
	rt.update(n, key, advertisement{routerID: adv.routerID, seqno: 2, metric: 1}, time.Hour, now)
	rt.sweepSources(now.Add(2 * sourceGCTime))
	if len(rt.sources) != 0 {
		t.Fatal("a feasibility distance outlived its garbage-collection timer")
	}
}

// A wildcard route request answers with the whole table, and on a transit node
// that table is the whole mesh. RFC 8966 section 3.8.1.1 says such a dump
// SHOULD be rate-limited; without a limit one packet of four-byte requests
// draws one full dump each, which is an amplifier pointed at whoever the
// requests claim to come from and a long walk under the protocol lock.
func TestWildcardRouteRequestDumpsAtMostOncePerInterval(t *testing.T) {
	cfg := Config{}
	fabric := newMeshFabric(t, cfg, "a-b")
	for i := range 40 {
		fabric.speakers["a"].Originate(netip.MustParsePrefix(fmt.Sprintf("fd00:a:%x::/64", i)))
	}
	fabric.flush("a")
	fabric.reset()

	// One packet carrying many wildcard requests, as fits in a
	// single MTU and is the shape that amplifies.
	const requests = 64
	wildcards := make([]RawTLV, 0, requests)
	for range requests {
		wildcards = append(wildcards, EncodeRouteRequest(RouteRequest{AE: AEWildcard}))
	}
	fabric.inject("a", "b", wildcards...)

	updates := 0
	for _, tlv := range fabric.tlvs("a", "b") {
		if tlv.Type == TLVUpdate {
			updates++
		}
	}
	if updates == 0 {
		t.Fatal("a wildcard request drew no dump at all, so the reply path is broken")
	}
	// One dump is 40 prefixes plus whatever compression state each carries.
	// The limit is what matters: 64 dumps would be 64 times this.
	if updates > 2*40 {
		t.Errorf("%d wildcard requests in one packet drew %d updates, which is more than one dump", requests, updates)
	}

	// The next interval may dump again, or a neighbor that genuinely lost its
	// table could never recover it.
	n := fabric.neighbor("a", "b")
	n.lastFullDump = n.lastFullDump.Add(-2 * fabric.speakers["a"].cfg.UpdateInterval)
	fabric.reset()
	fabric.inject("a", "b", EncodeRouteRequest(RouteRequest{AE: AEWildcard}))
	again := 0
	for _, tlv := range fabric.tlvs("a", "b") {
		if tlv.Type == TLVUpdate {
			again++
		}
	}
	if again == 0 {
		t.Error("a wildcard request a full interval later drew nothing, so the limit never lifts")
	}
}

// RFC 8966 section 3.5.4: while a retracted prefix is still held, "packets
// destined to an address within P MUST NOT be forwarded by following a route
// for a shorter prefix". Transit is what makes this reachable: a node carrying
// both an exit's default and a more specific prefix would otherwise start
// sending that prefix's traffic down the default the moment it is retracted,
// and if the exit reaches it back through here the packet bounces until its
// hop limit runs out.
func TestRetractedPrefixDoesNotFallThroughToCoveringRoute(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c")
	specific := netip.MustParsePrefix("fd00:b::/64")
	covering := netip.MustParsePrefix("fd00::/16")
	fabric.speakers["b"].Originate(specific)
	fabric.speakers["c"].Originate(covering)
	fabric.flush("b", "c", "a")

	inside := netip.MustParseAddr("fd00:b::1")
	if peer, ok := fabric.meshes["a"].Routes.Lookup(inside, inside); !ok || peer.ID != "b" {
		t.Fatalf("a reaches %s via %v, want b", inside, peer)
	}

	// b retracts it explicitly, which keeps the entry while it is held rather
	// than flushing it the way a lost neighbor would. The covering route
	// through c is still there.
	fabric.inject("a", "b",
		EncodeRouterID(routerID("b")),
		EncodeUpdate(Update{AE: AEIPv6, Plen: specific.Bits(), Prefix: specific.Addr().AsSlice(),
			Interval: 6000, Seqno: 1, Metric: MetricInfinity}))

	if peer, ok := fabric.meshes["a"].Routes.Lookup(inside, inside); ok {
		t.Errorf("a followed the covering route to %q for a prefix that was just retracted", peer.ID)
	}
	// The covering prefix itself still works, so the hold is scoped to the
	// prefix that was retracted rather than blanking the table.
	outside := netip.MustParseAddr("fd00:ffff::1")
	if _, ok := fabric.meshes["a"].Routes.Lookup(outside, outside); !ok {
		t.Error("the covering route stopped working too")
	}
}

// The forwarding suppression table of RFC 8966 section 3.8.1.2 is indexed by a
// router id the requester writes into the packet, and the one case that
// forwards a request rather than answering it is a neighbor asking about a
// prefix it is itself this node's next hop for, which is the ordinary shape of
// a mesh. Nothing in the request bounds the router id and eighty of them fit
// in one packet, so the table needs a cap that is not the suppression window.
func TestForwardedSeqnoRequestsAreBounded(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "b-a", "b-c")
	dest := netip.MustParsePrefix("fd00:1::/64")
	key := routeKey{dest: dest}
	// b reaches the prefix through a and has a worse path through c. Split
	// horizon keeps b from answering a, and c is somewhere to forward to.
	fabric.inject("b", "a", EncodeRouterID(routerID("a")),
		EncodeUpdate(Update{AE: AEIPv6, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
			Interval: 6000, Seqno: 1, Metric: 64}))
	fabric.inject("b", "c", EncodeRouterID(routerID("a")),
		EncodeUpdate(Update{AE: AEIPv6, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
			Interval: 6000, Seqno: 1, Metric: 512}))
	if got := fabric.nextHop("b", key); got != "a" {
		t.Fatalf("b selected %q for the prefix, want a", got)
	}

	speaker := fabric.speakers["b"]
	for i := range maxPendingSeqno + 64 {
		var id [8]byte
		binary.BigEndian.PutUint64(id[:], uint64(i))
		fabric.inject("b", "a", EncodeSeqnoRequest(SeqnoRequest{
			AE: AEIPv6, Prefix: dest, Seqno: 9, HopCount: 8, RouterID: id,
		}))
	}
	switch got := len(speaker.pendingSeqno); {
	case got > maxPendingSeqno:
		t.Fatalf("b held %d forwarded seqno requests, past its cap of %d", got, maxPendingSeqno)
	case got < maxPendingSeqno:
		t.Fatalf("b held %d forwarded seqno requests, so the flood never reached the table", got)
	}
}

// The source table is indexed the same way, and a node records a distance for
// every finite advertisement it makes. A neighbor that names a new origin for
// one prefix on every packet therefore adds an entry on every packet, and
// RFC 8966 Appendix B keeps each one for three minutes after the last time it
// was advertised.
func TestSourceTableRefusesAnUnknownOriginWhenFull(t *testing.T) {
	rt := newRouteTable(func(routeKey, routeSelection) {})
	key := routeKey{dest: netip.MustParsePrefix("fd00:1::/64")}
	now := time.Now()
	for i := range maxSources {
		var id [8]byte
		binary.BigEndian.PutUint64(id[:], uint64(i))
		rt.observe(key, advertisement{routerID: id, seqno: 1, metric: 64}, now)
	}
	var fresh [8]byte
	binary.BigEndian.PutUint64(fresh[:], uint64(maxSources))
	if rt.feasible(key, advertisement{routerID: fresh, seqno: 1, metric: 64}) {
		t.Fatal("a full source table still admitted an origin it had never advertised")
	}
	// The cap refuses origins it has no room to record, not the ones it holds,
	// and never a retraction: neither of those can close a loop.
	if !rt.feasible(key, advertisement{routerID: [8]byte{}, seqno: 2, metric: 64}) {
		t.Error("a full source table refused a better distance for an origin it holds")
	}
	if !rt.feasible(key, advertisement{routerID: fresh, metric: MetricInfinity}) {
		t.Error("a full source table refused a retraction")
	}
}

// One seqno request is not enough. If it or its reply is lost, the prefix
// stays starved: nothing asks again, and the unfeasible route that caused the
// starvation keeps the feasibility distance alive so it never expires either.
// RFC 8966 section 3.8.2.1 says to repeat the request a small number of times.
func TestSeqnoRequestIsRepeatedWhileStarved(t *testing.T) {
	// d is a leaf with no path of its own to the origin. It exists so that a
	// has somewhere to advertise, which records the feasibility
	// distance the worsened update below has to fall foul of, without giving a
	// a second route that would make the prefix not starved at all.
	fabric := newMeshFabric(t, Config{}, "a-b", "b-c", "a-d")
	dest := netip.MustParsePrefix("fd00:c::/64")
	key := routeKey{dest: dest}
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c", "b", "a")
	if got := fabric.nextHop("a", key); got != "b" {
		t.Fatalf("a reaches the origin via %q, want \"b\"", got)
	}
	fabric.reset()

	fabric.inject("a", "b",
		EncodeRouterID(routerID("c")),
		EncodeUpdate(Update{AE: AEIPv6, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
			Interval: 6000, Seqno: 1, Metric: 900}))
	if len(seqnoRequestsFor(t, fabric.tlvs("a", "b"), dest)) != 1 {
		t.Fatal("a did not ask for a new seqno when its route became unfeasible")
	}

	// Nothing answers. The request has to come again rather than leaving the
	// prefix black-holed for as long as b keeps refreshing the bad route.
	speaker := fabric.speakers["a"]
	speaker.mu.Lock()
	pending := len(speaker.starveRetries)
	for _, retry := range speaker.starveRetries {
		retry.nextAt = time.Now().Add(-time.Second)
	}
	// The retry backoff is longer than the suppression window, so in production
	// the retry falls outside it. Backdate rather than sleep through it.
	for index := range speaker.askedSeqno {
		speaker.askedSeqno[index] = time.Now().Add(-seqnoRequestSuppress - time.Second)
	}
	retries := speaker.retryStarvedLocked(time.Now())
	speaker.mu.Unlock()
	if pending == 0 {
		t.Fatal("a kept no record of the starved prefix, so it can never ask again")
	}
	if len(retries) == 0 {
		t.Error("a never repeated the seqno request, so the prefix stays starved indefinitely")
	}
}

// A prefix removed from the originated set has to be retracted. Dropping it
// from the set alone leaves every neighbor holding it until it expires, and if
// it was withdrawn because the address moved, that is a black hole for three
// and a half update intervals.
func TestWithdrawnOriginationIsRetracted(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b")
	dest := netip.MustParsePrefix("fd00:a::/64")
	key := routeKey{dest: dest}
	fabric.speakers["a"].Originate(dest)
	fabric.flush("a")
	if got := fabric.nextHop("b", key); got != "a" {
		t.Fatalf("b reaches %s via %q, want \"a\"", dest, got)
	}

	fabric.reset()
	fabric.speakers["a"].SetOriginated(nil)
	fabric.flush("a")

	updates := updatesFor(t, fabric.tlvs("a", "b"), dest)
	if len(updates) != 1 || updates[0].Metric != MetricInfinity {
		t.Errorf("a sent %v for a prefix it stopped originating, want a single retraction", updates)
	}
	if got := fabric.nextHop("b", key); got != "" {
		t.Errorf("b still forwards %s via %q after the origin withdrew it", dest, got)
	}
}

// Starting to originate a prefix this node already learned from a neighbor
// must drop what it learned. Otherwise the learned route stays selected, split
// horizon compares its next hop against nil and never fires, and the node
// advertises the prefix at metric 0 straight back to the neighbor it is still
// forwarding to, which is a loop until the entry expires.
func TestOriginatingLearnedPrefixDoesNotLoop(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "b-c")
	dest := netip.MustParsePrefix("fd00:a::/64")
	key := routeKey{dest: dest}
	fabric.speakers["a"].Originate(dest)
	fabric.flush("a", "b", "c")
	if got := fabric.nextHop("c", key); got != "b" {
		t.Fatalf("c reaches %s via %q, want \"b\"", dest, got)
	}

	// c now originates the same prefix, as a reload adding it to
	// babel.originate does.
	fabric.reset()
	fabric.speakers["c"].SetOriginated([]OriginatedRoute{{Destination: dest}})
	fabric.flush("c", "b")

	if got := fabric.nextHop("c", key); got != "" {
		t.Errorf("c still forwards its own prefix to %q", got)
	}
	if got := fabric.nextHop("b", key); got == "c" {
		t.Error("b now forwards to c for a prefix c reaches through b, which is the loop")
	}
}

// Originate reaches the same purge through its own entry point, which is the
// one a plain originate: list in the config uses.
func TestOriginateAlsoDropsWhatThisNodeLearned(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "b-c")
	dest := netip.MustParsePrefix("fd00:a::/64")
	key := routeKey{dest: dest}
	fabric.speakers["a"].Originate(dest)
	fabric.flush("a", "b", "c")
	if got := fabric.nextHop("c", key); got != "b" {
		t.Fatalf("c reaches %s via %q, want \"b\"", dest, got)
	}

	fabric.reset()
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c", "b")

	if got := fabric.nextHop("c", key); got != "" {
		t.Errorf("c still forwards its own prefix to %q", got)
	}
	if got := fabric.nextHop("b", key); got == "c" {
		t.Error("b now forwards to c for a prefix c reaches through b, which is the loop")
	}
}

// The origin of a prefix is not a promise that every address in it is
// reachable. Dropping the forwarding entry outright lets a packet for an
// unassigned address fall through to a covering route, which on a transit node
// means back out to a neighbor that learned the prefix from this node at
// metric 0 and forwards it straight here again.
func TestOriginatedPrefixDoesNotFallThroughToCoveringRoute(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b")
	covering := netip.MustParsePrefix("fd00::/16")
	own := netip.MustParsePrefix("fd00:a::/64")
	inside := netip.MustParseAddr("fd00:a::1")

	// a is a transit node: it holds a default-ish covering route through b and
	// originates a more specific prefix of its own.
	fabric.speakers["b"].Originate(covering)
	fabric.speakers["a"].Originate(own)
	fabric.flush("b", "a")
	if got := fabric.forwards("a", inside); got != "" {
		t.Fatalf("a forwards %s to %q, want it dropped", inside, got)
	}

	// Learning the prefix from b and then originating it has to end the same
	// way, which is the path the purge takes.
	fabric.reset()
	fabric.speakers["a"].SetOriginated(nil)
	fabric.speakers["b"].Originate(own)
	fabric.flush("b", "a")
	if got := fabric.forwards("a", inside); got != "b" {
		t.Fatalf("a reaches %s via %q before originating it, want \"b\"", inside, got)
	}
	fabric.speakers["a"].Originate(own)
	if got := fabric.forwards("a", inside); got != "" {
		t.Errorf("a forwards %s to %q after taking over the prefix, want it dropped", inside, got)
	}
}

// RFC 8966 section 3.8.2.1: a starved node "MUST send the request to at least
// one of the next-hop neighbours that advertised these routes, and SHOULD send
// it to all of them". The forwarding suppression table is indexed without the
// neighbor, so consulting it here let the first neighbor in map order consume
// the allowance and silently drop every other.
func TestStarvationAsksEveryNeighborHoldingRoute(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c", "a-d", "b-e", "c-e")
	dest := netip.MustParsePrefix("fd00:e::/64")
	key := routeKey{dest: dest}
	fabric.speakers["e"].Originate(dest)
	fabric.flush("e", "b", "c", "a")
	if fabric.nextHop("a", key) == "" {
		t.Fatal("a never learned the route")
	}
	fabric.reset()

	// Both relays worsen past the distance a has already advertised, so both
	// of a's routes become unfeasible at once.
	for _, relay := range []string{"b", "c"} {
		fabric.inject("a", relay,
			EncodeRouterID(routerID("e")),
			EncodeUpdate(Update{AE: AEIPv6, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
				Interval: 6000, Seqno: 1, Metric: 900}))
	}
	for _, relay := range []string{"b", "c"} {
		if got := len(seqnoRequestsFor(t, fabric.tlvs("a", relay), dest)); got != 1 {
			t.Errorf("a sent %d seqno requests to %s, want exactly 1", got, relay)
		}
	}
}

// askedSeqno is keyed by a router id the peer chooses and by neighbor pointer,
// so entries left behind both grow without bound and pin retired neighbors.
func TestSeqnoSuppressionEntriesAreSweptAndDroppedWithTheirNeighbor(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c", "b-e", "c-e")
	dest := netip.MustParsePrefix("fd00:e::/64")
	speaker := fabric.speakers["a"]
	fabric.speakers["e"].Originate(dest)
	fabric.flush("e", "b", "c", "a")

	// Both relays worsen at once, which starves a and makes it ask each of
	// them, recording one suppression entry per neighbor.
	for _, relay := range []string{"b", "c"} {
		fabric.inject("a", relay,
			EncodeRouterID(routerID("e")),
			EncodeUpdate(Update{AE: AEIPv6, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
				Interval: 6000, Seqno: 1, Metric: 900}))
	}
	speaker.mu.Lock()
	asked := len(speaker.askedSeqno)
	speaker.mu.Unlock()
	if asked == 0 {
		t.Fatal("no seqno requests were suppressed, so this proves nothing")
	}

	// A neighbor that goes away takes its own entries with it, so a retired
	// neighborState and everything it advertised can be collected.
	retired := fabric.neighbor("a", "b")
	fabric.handles["a-b"].Close()
	speaker.mu.Lock()
	for index := range speaker.askedSeqno {
		if index.neighbor == retired {
			speaker.mu.Unlock()
			t.Fatal("a removed neighbor is still pinned by its suppression entries")
		}
	}
	left := len(speaker.askedSeqno)
	speaker.mu.Unlock()
	if left == 0 {
		t.Fatal("every entry went with one neighbor, so the sweep below proves nothing")
	}

	// The suppression window is the lifetime, the same one pendingSeqno uses.
	speaker.mu.Lock()
	speaker.sweepRequestsLocked(time.Now().Add(seqnoRequestSuppress + time.Second))
	swept := len(speaker.askedSeqno)
	speaker.mu.Unlock()
	if swept != 0 {
		t.Errorf("%d of %d suppression entries survived their window", swept, left)
	}
}

// Starvation recovery is what stops a lost seqno becoming a permanent black
// hole, and the retry is reached only from Run. Deleting that one call left
// the retry itself covered and unreachable.
func TestRunRetriesStarvedSeqnoRequest(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c", "b-e", "c-e")
	dest := netip.MustParsePrefix("fd00:e::/64")
	speaker := fabric.speakers["a"]
	fabric.speakers["e"].Originate(dest)
	fabric.flush("e", "b", "c", "a")
	if fabric.nextHop("a", routeKey{dest: dest}) == "" {
		t.Fatal("a never learned the route")
	}

	// Both relays worsen past the distance a has already advertised, so every
	// route a holds for the prefix becomes unfeasible at once.
	fabric.reset()
	for _, relay := range []string{"b", "c"} {
		fabric.inject("a", relay,
			EncodeRouterID(routerID("e")),
			EncodeUpdate(Update{AE: AEIPv6, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(),
				Interval: 6000, Seqno: 1, Metric: 900}))
	}
	if got := len(seqnoRequestsFor(t, fabric.tlvs("a", "b"), dest)); got != 1 {
		t.Fatalf("a sent %d seqno requests when it starved, want 1", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- speaker.Run(ctx) }()

	// Bring the retry forward rather than waiting out its backoff, and clear
	// the suppression window the first request opened, as the
	// passage of time would have done.
	fabric.reset()
	speaker.mu.Lock()
	if len(speaker.starveRetries) == 0 {
		speaker.mu.Unlock()
		cancel()
		t.Fatal("starving recorded no retry at all, so there is nothing for Run to reach")
	}
	past := time.Now().Add(-time.Hour)
	for _, retry := range speaker.starveRetries {
		retry.nextAt = past
	}
	for index := range speaker.askedSeqno {
		speaker.askedSeqno[index] = past
	}
	speaker.wake()
	speaker.mu.Unlock()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if len(seqnoRequestsFor(t, fabric.tlvs("a", "b"), dest)) > 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("Run never repeated the seqno request, so a lost one is a permanent black hole")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

// A peer chooses how many Seqno Requests to put in one packet, and eighty fit.
// RFC 8966 section 3.2.2 asks a node not to raise its own sequence number
// spontaneously, and every raise re-dirties everything it originates.
func TestOriginSeqnoRisesAtMostOncePerPacket(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b")
	speaker := fabric.speakers["a"]
	dest := netip.MustParsePrefix("fd00:a::/64")
	speaker.Originate(dest)
	speaker.mu.Lock()
	before := speaker.originSeqno
	speaker.mu.Unlock()

	requests := make([]RawTLV, 0, 80)
	for i := range 80 {
		requests = append(requests, EncodeSeqnoRequest(SeqnoRequest{
			AE: AEIPv6, Prefix: dest, RouterID: routerID("a"),
			Seqno: before + uint16(i) + 1, HopCount: 3,
		}))
	}
	fabric.inject("a", "b", requests...)

	speaker.mu.Lock()
	raised := speaker.originSeqno - before
	speaker.mu.Unlock()
	if raised != 1 {
		t.Errorf("one packet of %d requests raised the origin sequence number by %d, want 1", len(requests), raised)
	}

	// A later packet can still raise it, or a genuine request goes unanswered.
	fabric.inject("a", "b", EncodeSeqnoRequest(SeqnoRequest{
		AE: AEIPv6, Prefix: dest, RouterID: routerID("a"),
		Seqno: speaker.originSeqno + 1, HopCount: 3,
	}))
	speaker.mu.Lock()
	total := speaker.originSeqno - before
	speaker.mu.Unlock()
	if total != 2 {
		t.Errorf("a second packet raised the origin sequence number to %d above the start, want 2", total)
	}
}
