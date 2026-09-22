package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/NickCao/ranet-lite/schema"
	"github.com/NickCao/ranet-lite/srv6"
)

func segAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func segPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// plainV6 is a minimal IPv6 packet, enough for the header reading the
// dataplane does.
func plainV6(src, dst netip.Addr, payload string) []byte {
	raw := make([]byte, 40+len(payload))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(len(payload)))
	raw[6] = 59
	raw[7] = 64
	copy(raw[8:], src.AsSlice())
	copy(raw[24:], dst.AsSlice())
	copy(raw[40:], payload)
	return raw
}

// recordingPeer collects what the mesh sent through it, sealing inline so a
// test sees the bytes the caller handed over.
type recordingPeer struct {
	mu   sync.Mutex
	sent [][]byte
}

func (r *recordingPeer) peer(id string) *Peer {
	return NewPeer(id,
		func(raw []byte, _ byte) ([]byte, error) { return bytes.Clone(raw), nil },
		func(sealed []byte) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.sent = append(r.sent, bytes.Clone(sealed))
			return nil
		})
}

func (r *recordingPeer) packets() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.sent...)
}

// A node that configures no segments returns the batch it was given, with no
// copy and no allocation, because that is every node on this mesh today.
func TestBatchWithoutSegmentsIsUntouched(t *testing.T) {
	mesh := &Mesh{Routes: NewRouteTable()}
	batch := [][]byte{plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::2"), "one")}
	got := mesh.applySegments(batch)
	if &got[0] != &batch[0] || len(got) != len(batch) {
		t.Fatal("a batch with no segments configured was rebuilt")
	}
	if counters := mesh.SegmentCounters(); counters != (SegmentCounters{}) {
		t.Errorf("a node with no segments counted %+v", counters)
	}
}

// An exit takes the outer header off and what was inside goes to the tun in
// place of it, so the batch that comes back carries the inner packet.
func TestExitDeliversWhatWasInside(t *testing.T) {
	exit := segAddr("3fff:1:69c:8c6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46}})
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)

	inner := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload")
	outer, err := srv6.Encapsulate(inner, segAddr("3fff:1:69c:98d0::1"), []netip.Addr{exit})
	if err != nil {
		t.Fatal(err)
	}
	passer := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::2"), "not ours")

	got := mesh.applySegments([][]byte{passer, outer})
	if len(got) != 2 {
		t.Fatalf("the batch came back with %d packets", len(got))
	}
	if !bytes.Equal(got[0], passer) {
		t.Error("a packet that was not ours was changed")
	}
	if !bytes.Equal(got[1], inner) {
		t.Error("the exit delivered something other than the inner packet")
	}
	if counters := mesh.SegmentCounters(); counters.Delivered != 1 || counters.Forwarded != 0 || counters.Dropped != 0 {
		t.Errorf("the exit counted %+v", counters)
	}
}

// A waypoint forwards to the peer the next segment routes to, and the packet
// leaves the batch: writing it to the tun would deliver a packet addressed to
// somebody else's segment to this node's own stack.
func TestWaypointForwardsInsteadOfDelivering(t *testing.T) {
	waypoint := segAddr("3fff:1:69c:8c6::2")
	exit := segAddr("3fff:1:69c:98d6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}})
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)
	recorder := &recordingPeer{}
	mesh.Routes.Set(netip.Prefix{}, segPrefix("3fff:1:69c:98d6::/64"), recorder.peer("exit"))

	inner := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload")
	outer, err := srv6.Encapsulate(inner, segAddr("3fff:1:69c:8c0::1"), []netip.Addr{waypoint, exit})
	if err != nil {
		t.Fatal(err)
	}

	got := mesh.applySegments([][]byte{outer})
	if len(got) != 0 {
		t.Fatalf("a forwarded packet was also delivered to the tun: %v", got)
	}
	sent := recorder.packets()
	if len(sent) != 1 {
		t.Fatalf("the waypoint sent %d packets", len(sent))
	}
	if got := netip.AddrFrom16([16]byte(sent[0][24:40])); got != exit {
		t.Errorf("the forwarded packet is addressed to %s, want the next segment %s", got, exit)
	}
	if counters := mesh.SegmentCounters(); counters.Forwarded != 1 || counters.Delivered != 0 {
		t.Errorf("the waypoint counted %+v", counters)
	}
}

// A segment of ours the node cannot act on, and one whose next segment nothing
// routes to, are both counted and dropped rather than written to the tun,
// where they would arrive as undeliverable packets addressed to us.
func TestSegmentsThatCannotBeActedOnAreDropped(t *testing.T) {
	waypoint := segAddr("3fff:1:69c:8c6::2")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}})
	if err != nil {
		t.Fatal(err)
	}

	// Addressed to our waypoint with no routing header.
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)
	if got := mesh.applySegments([][]byte{plainV6(segAddr("2001:db8::1"), waypoint, "payload")}); len(got) != 0 {
		t.Fatalf("a refused segment reached the tun: %v", got)
	}
	if counters := mesh.SegmentCounters(); counters.Dropped != 1 {
		t.Errorf("a refused segment counted %+v", counters)
	}

	// Well formed, and the mesh has no route to the segment after this one.
	unrouted := &Mesh{Routes: NewRouteTable()}
	unrouted.SetSegments(table)
	outer, err := srv6.Encapsulate(
		plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"),
		segAddr("3fff:1:69c:8c0::1"),
		[]netip.Addr{waypoint, segAddr("3fff:1:69c:98d6::1")})
	if err != nil {
		t.Fatal(err)
	}
	if got := unrouted.applySegments([][]byte{outer}); len(got) != 0 {
		t.Fatalf("a segment with nowhere to go reached the tun: %v", got)
	}
	if counters := unrouted.SegmentCounters(); counters.Dropped != 1 || counters.Forwarded != 0 {
		t.Errorf("a segment with nowhere to go counted %+v", counters)
	}
}

// The replacement slice is built from the first packet that is ours, so the
// ones before it have to survive in order. A batch that is all passers keeps
// its own backing array.
func TestPacketsBeforeAndAfterASegmentKeepTheirOrder(t *testing.T) {
	exit := segAddr("3fff:1:69c:8c6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46}})
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)

	first := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::a"), "first")
	second := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::b"), "second")
	last := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::c"), "last")
	inner := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "inner")
	outer, err := srv6.Encapsulate(inner, segAddr("3fff:1:69c:98d0::1"), []netip.Addr{exit})
	if err != nil {
		t.Fatal(err)
	}

	got := mesh.applySegments([][]byte{first, second, outer, last})
	if len(got) != 4 {
		t.Fatalf("the batch came back with %d packets", len(got))
	}
	for i, want := range [][]byte{first, second, inner, last} {
		if !bytes.Equal(got[i], want) {
			t.Errorf("packet %d is not the one that belongs there", i)
		}
	}
}

// A packet a policy claims leaves encapsulated and is routed by its first
// segment rather than by the address it was addressed to, which is the whole
// point of steering it and the thing a route lookup done first would undo.
func TestSteeredPacketIsRoutedByItsFirstSegment(t *testing.T) {
	exit := segAddr("3fff:1:69c:98d6::1")
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.AddrFrom(exit)},
	}}, schema.MustAddr("3fff:1:69c:8c0::1"))
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSteering(table)

	buf := make([]byte, tunOffset+2048)
	inner := plainV6(segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888"), "payload")
	copy(buf[tunOffset:], inner)

	size, action := mesh.steer(buf, len(inner), segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888"))
	if action != steerSent {
		t.Fatal("a packet the policy names was not steered")
	}
	if size != len(inner)+srv6.Overhead(1) {
		t.Fatalf("the steered packet is %d bytes, want %d", size, len(inner)+srv6.Overhead(1))
	}
	if got := netip.AddrFrom16([16]byte(buf[tunOffset+24 : tunOffset+40])); got != exit {
		t.Errorf("the steered packet is addressed to %s, want the first segment %s", got, exit)
	}
	if counters := mesh.SegmentCounters(); counters.Steered != 1 || counters.Unsteered != 0 {
		t.Errorf("steering counted %+v", counters)
	}

	// A packet from another address is left exactly as it was.
	other := len(inner)
	if size, action := mesh.steer(buf, other, segAddr("3fff:a::18"), segAddr("2001:4860:4860::8888")); action != steerPass || size != other {
		t.Errorf("a packet no policy names was steered, size %d", size)
	}
}

// A packet a policy claims and cannot encapsulate goes out as it was rather
// than being dropped, which is the more conservative of the two failures, and
// the counter says it happened.
func TestPacketThatCannotBeSteeredGoesOutUnchanged(t *testing.T) {
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.MustAddr("3fff:1:69c:98d6::1")},
	}}, schema.MustAddr("3fff:1:69c:8c0::1"))
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSteering(table)

	inner := plainV6(segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888"), "payload")
	// A buffer with no room for the header at all.
	buf := make([]byte, tunOffset+len(inner))
	copy(buf[tunOffset:], inner)
	size, action := mesh.steer(buf, len(inner), segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888"))
	// Dropped rather than sent as it was: the policy selects an exit, so the
	// route this packet would otherwise take puts it out of a different node
	// under a source that node does not announce.
	if action != steerDrop || size != len(inner) {
		t.Fatalf("a packet that could not be encapsulated reported action=%d size=%d", action, size)
	}
	if !bytes.Equal(buf[tunOffset:], inner) {
		t.Error("a packet that could not be steered was changed anyway")
	}
	if counters := mesh.SegmentCounters(); counters.Unsteered != 1 || counters.Steered != 0 {
		t.Errorf("a refused encapsulation counted %+v", counters)
	}
}

// A whole inbound batch of waypointed packets takes one place on the peer's
// budget, as a tun read does. One per packet is the same accounting at a
// 128th of the batch size, so most of a forwarded burst is dropped on an idle
// machine and a peer can spend this node's whole allowance to a third peer.
func TestWaypointBatchTakesOnePlacePerPeer(t *testing.T) {
	waypoint := segAddr("3fff:1:69c:8c6::2")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}})
	if err != nil {
		t.Fatal(err)
	}
	exit := segAddr("3fff:1:69c:98d6::1")

	// The peer is asked to reserve for a number of packets, and seals once per
	// reserved batch, so the two together say how the batch was split.
	var batches, reserved, forwarded atomic.Int64
	peer := NewPeerReserved("next", func(n int) (BatchSealer, error) {
		reserved.Add(int64(n))
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			batches.Add(1)
			forwarded.Add(int64(len(raw)))
			return out[:0], nil
		}, nil
	}, func([][]byte) error { return nil })
	defer peer.Close()

	m := &Mesh{Routes: NewRouteTable()}
	m.startSegmentReports()
	m.SetSegments(table)
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("3fff:1:69c:98d6::1/128"), peer)

	const count = 64
	batch := make([][]byte, 0, count)
	for range count {
		outer, err := srv6.Encapsulate(
			plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"),
			segAddr("3fff:1:69c:8c0::1"), []netip.Addr{waypoint, exit})
		if err != nil {
			t.Fatal(err)
		}
		batch = append(batch, outer)
	}
	if left := m.applySegments(batch); len(left) != 0 {
		t.Fatalf("%d waypointed packets reached the tun", len(left))
	}
	if got := batches.Load(); got != 1 {
		t.Errorf("a batch of %d waypointed packets was split into %d, want one for the peer", count, got)
	}
	// Reserving for fewer than are appended is the same accounting at a 128th
	// of the batch size, which drops most of a forwarded burst and lets a peer
	// spend this node's whole allowance to a third peer.
	if got := reserved.Load(); got != count {
		t.Errorf("the peer reserved for %d packets and was handed %d", got, count)
	}
	if got := forwarded.Load(); got != count {
		t.Errorf("the peer was handed %d of %d packets", got, count)
	}
	if got := m.SegmentCounters(); got.Forwarded != count || got.Dropped != 0 {
		t.Errorf("the batch forwarded %d and dropped %d of %d", got.Forwarded, got.Dropped, count)
	}
}

// An ICMP error is a packet a peer's packet made this node send, which is the
// shape of every amplification this tree has had. RFC 4443 section 2.4 (f)
// requires a limit for that reason, so a peer sending refused headers in a
// loop gets the refill rate and no more, while the counters keep the whole
// record.
func TestRefusedPacketsAreAnsweredAtABoundedRate(t *testing.T) {
	waypoint := segAddr("3fff:1:69c:8c6::2")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingPeer{}
	m := &Mesh{Routes: NewRouteTable()}
	m.startSegmentReports()
	m.SetSegments(table)
	// The error goes back to the node that encapsulated the packet, so the
	// route that has to exist is the one to its tunnel source.
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:1:69c::/48"), recorder.peer("sender"))

	// A segment list this node will not act on, which is the refusal RFC 8986
	// section 4.1 S10 answers with a Parameter Problem.
	const flood = 500
	batch := make([][]byte, 0, flood)
	for range flood {
		outer, err := srv6.Encapsulate(
			plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"),
			segAddr("3fff:1:69c:8c0::1"), []netip.Addr{waypoint, segAddr("3fff:1:69c:98d6::1")})
		if err != nil {
			t.Fatal(err)
		}
		outer[ipv6HeaderOffsetSegmentsLeft] = 9 // past the last entry
		batch = append(batch, outer)
	}
	m.applySegments(batch)

	counters := m.SegmentCounters()
	if counters.Dropped != flood {
		t.Errorf("%d of %d refused packets were counted", counters.Dropped, flood)
	}
	if counters.Answered > icmpBurst {
		t.Errorf("%d answers went out for %d refused packets, over the burst of %d",
			counters.Answered, flood, icmpBurst)
	}
	if counters.Answered == 0 {
		t.Error("nothing was answered, so a traceroute through this node sees nothing")
	}
	if sent := len(recorder.packets()); uint64(sent) != counters.Answered {
		t.Errorf("%d packets went to the peer against %d counted", sent, counters.Answered)
	}
}

// ipv6HeaderOffsetSegmentsLeft is where Segments Left sits in a packet whose
// routing header follows the fixed header.
const ipv6HeaderOffsetSegmentsLeft = 40 + 3

// A segment list may name two segments of one node, which the fleet's own
// addressing makes spellable: an End and an End.DT46 sit on the same node.
// A kernel repeats its FIB lookup after a waypoint rewrites the destination
// and acts on the second, and a node that only consulted its mesh routes would
// drop the packet one hop short, because a node has no route to itself.
func TestTwoSegmentsOfThisNodeInOneListAreBothActedOn(t *testing.T) {
	waypoint, exit := segAddr("3fff:1:69c:8c6::2"), segAddr("3fff:1:69c:8c6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{
		{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd},
		{SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46},
	})
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.startSegmentReports()
	mesh.SetSegments(table)

	inner := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload")
	outer, err := srv6.Encapsulate(inner, segAddr("3fff:1:69c:8c0::1"), []netip.Addr{waypoint, exit})
	if err != nil {
		t.Fatal(err)
	}
	got := mesh.applySegments([][]byte{outer})
	if len(got) != 1 || !bytes.Equal(got[0], inner) {
		t.Fatalf("the exit on this node did not deliver the inner packet: %v", got)
	}
	if counters := mesh.SegmentCounters(); counters.Delivered != 1 || counters.Dropped != 0 {
		t.Errorf("a list naming two of this node's segments counted %+v", counters)
	}
}

// The report interval is measured on the monotonic clock, which needs a start.
// time.Since of a zero time saturates, so a counter set that was never started
// would report once and then suppress everything for 292 years, which is the
// failure a rate limit exists to prevent rather than to cause.
func TestDropReportsSurviveACounterSetThatWasNeverStarted(t *testing.T) {
	lines := countRecords(t)

	started := &Mesh{Routes: NewRouteTable()}
	started.startSegmentReports()
	for range 3 {
		started.reportSegmentDrop("spaced")
	}
	if got := *lines; got != 1 {
		t.Errorf("a started set wrote %d lines for three drops, want one", got)
	}

	*lines = 0
	var unstarted Mesh
	if !unstarted.segmentsStarted.IsZero() {
		t.Fatal("the unstarted case is no longer reachable, so this is not testing it")
	}
	for range 3 {
		unstarted.reportSegmentDrop("still speaking")
	}
	if got := *lines; got != 3 {
		t.Errorf("an unstarted set wrote %d lines for three drops, want every one", got)
	}
}

// countRecords points the default logger at a counter for the test's duration.
func countRecords(t *testing.T) *int {
	t.Helper()
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	counter := new(int)
	slog.SetDefault(slog.New(countingHandler{n: counter}))
	return counter
}

type countingHandler struct{ n *int }

func (h countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h countingHandler) Handle(context.Context, slog.Record) error {
	*h.n++
	return nil
}
func (h countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingHandler) WithGroup(string) slog.Handler      { return h }
