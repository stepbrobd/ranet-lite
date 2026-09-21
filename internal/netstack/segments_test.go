package netstack

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"

	"github.com/NickCao/ranet-lite/internal/srv6"
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
	exit := segAddr("2a0c:b641:69c:8c6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: exit, Behavior: srv6.BehaviorEndDT46}})
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)

	inner := plainV6(segAddr("2602:f590::1"), segAddr("2602:f590::2"), "payload")
	outer, err := srv6.Encapsulate(inner, segAddr("2a0c:b641:69c:98d0::1"), []netip.Addr{exit}, 0)
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
	waypoint := segAddr("2a0c:b641:69c:8c6::2")
	exit := segAddr("2a0c:b641:69c:98d6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: waypoint, Behavior: srv6.BehaviorEnd}})
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)
	recorder := &recordingPeer{}
	mesh.Routes.Set(netip.Prefix{}, segPrefix("2a0c:b641:69c:98d6::/64"), recorder.peer("exit"))

	inner := plainV6(segAddr("2602:f590::1"), segAddr("2602:f590::2"), "payload")
	outer, err := srv6.Encapsulate(inner, segAddr("2a0c:b641:69c:8c0::1"), []netip.Addr{waypoint, exit}, 0)
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
	waypoint := segAddr("2a0c:b641:69c:8c6::2")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: waypoint, Behavior: srv6.BehaviorEnd}})
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
		plainV6(segAddr("2602:f590::1"), segAddr("2602:f590::2"), "payload"),
		segAddr("2a0c:b641:69c:8c0::1"),
		[]netip.Addr{waypoint, segAddr("2a0c:b641:69c:98d6::1")}, 0)
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
	exit := segAddr("2a0c:b641:69c:8c6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: exit, Behavior: srv6.BehaviorEndDT46}})
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)

	first := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::a"), "first")
	second := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::b"), "second")
	last := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::c"), "last")
	inner := plainV6(segAddr("2602:f590::1"), segAddr("2602:f590::2"), "inner")
	outer, err := srv6.Encapsulate(inner, segAddr("2a0c:b641:69c:98d0::1"), []netip.Addr{exit}, 0)
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
	exit := segAddr("2a0c:b641:69c:98d6::1")
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From:   segPrefix("2602:f590::17/128"),
		Policy: srv6.Policy{Source: segAddr("2a0c:b641:69c:8c0::1"), Path: []netip.Addr{exit}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSteering(table)

	buf := make([]byte, tunOffset+2048)
	inner := plainV6(segAddr("2602:f590::17"), segAddr("2001:4860:4860::8888"), "payload")
	copy(buf[tunOffset:], inner)

	size, steered := mesh.steer(buf, len(inner), segAddr("2602:f590::17"), segAddr("2001:4860:4860::8888"))
	if !steered {
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
	if size, steered := mesh.steer(buf, other, segAddr("2602:f590::18"), segAddr("2001:4860:4860::8888")); steered || size != other {
		t.Errorf("a packet no policy names was steered, size %d", size)
	}
}

// A packet a policy claims and cannot encapsulate goes out as it was rather
// than being dropped, which is the more conservative of the two failures, and
// the counter says it happened.
func TestPacketThatCannotBeSteeredGoesOutUnchanged(t *testing.T) {
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From:   segPrefix("2602:f590::17/128"),
		Policy: srv6.Policy{Source: segAddr("2a0c:b641:69c:8c0::1"), Path: []netip.Addr{segAddr("2a0c:b641:69c:98d6::1")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSteering(table)

	inner := plainV6(segAddr("2602:f590::17"), segAddr("2001:4860:4860::8888"), "payload")
	// A buffer with no room for the header at all.
	buf := make([]byte, tunOffset+len(inner))
	copy(buf[tunOffset:], inner)
	size, steered := mesh.steer(buf, len(inner), segAddr("2602:f590::17"), segAddr("2001:4860:4860::8888"))
	if steered || size != len(inner) {
		t.Fatalf("a packet that could not be encapsulated reported steered=%v size=%d", steered, size)
	}
	if !bytes.Equal(buf[tunOffset:], inner) {
		t.Error("a packet that could not be steered was changed anyway")
	}
	if counters := mesh.SegmentCounters(); counters.Unsteered != 1 || counters.Steered != 0 {
		t.Errorf("a refused encapsulation counted %+v", counters)
	}
}
