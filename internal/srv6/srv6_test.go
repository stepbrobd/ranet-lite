package srv6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// innerV6 and innerV4 are minimal well-formed packets, enough for the header
// reading this package does and no more.
func innerV6(payload string) []byte {
	raw := make([]byte, 40+len(payload))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(len(payload)))
	raw[6] = 59 // no next header
	raw[7] = 64
	copy(raw[8:], addr16(addr("2602:f590::1")))
	copy(raw[24:], addr16(addr("2602:f590::2")))
	copy(raw[40:], payload)
	return raw
}

func innerV4(payload string) []byte {
	raw := make([]byte, 20+len(payload))
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
	raw[8] = 64
	copy(raw[12:], addr("23.161.104.117").AsSlice())
	copy(raw[16:], addr("23.161.104.118").AsSlice())
	copy(raw[20:], payload)
	return raw
}

// The wire order is the reverse of the path, and the outer destination is the
// first segment the packet visits. Getting the reversal wrong sends the packet
// to the exit first and the waypoints afterwards, which still forwards and
// still arrives, so nothing but this test would report it.
func TestEncapsulationPutsTheFirstSegmentOnTheOuterHeader(t *testing.T) {
	path := []netip.Addr{addr("2a0c:b641:69c:98d6::2"), addr("2a0c:b641:69c:6c46::2"), addr("2a0c:b641:69c:29a6::1")}
	source := addr("2a0c:b641:69c:8c0::1")
	inner := innerV6("payload")

	out, err := Encapsulate(inner, source, path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := netip.AddrFrom16([16]byte(out[24:40])); got != path[0] {
		t.Errorf("the outer destination is %s, want the first segment %s", got, path[0])
	}
	if got := netip.AddrFrom16([16]byte(out[8:24])); got != source {
		t.Errorf("the outer source is %s", got)
	}
	if out[7] != DefaultHopLimit {
		t.Errorf("hop limit is %d, want the default when none was given", out[7])
	}

	header, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(header.Path(), path) {
		t.Errorf("the path read back as %v, want %v", header.Path(), path)
	}
	if int(header.SegmentsLeft) != len(path)-1 {
		t.Errorf("segments left is %d, want %d", header.SegmentsLeft, len(path)-1)
	}
	if active, ok := header.Active(); !ok || active != path[0] {
		t.Errorf("the active segment is %s (%v), want the outer destination", active, ok)
	}
	if header.NextHeader != NextHeaderIPv6 {
		t.Errorf("next header is %d, want the encapsulated family", header.NextHeader)
	}
	// The payload length has to describe the routing header and the inner
	// packet together, or every receiver truncates one or the other.
	want := len(out) - 40
	if got := int(binary.BigEndian.Uint16(out[4:])); got != want {
		t.Errorf("payload length is %d, want %d", got, want)
	}
}

// A path of one is an exit with no waypoints, which selecting an exit node
// and nothing else produces, and the one length a reversal bug cannot show up
// in.
func TestEncapsulationHandlesASingleSegment(t *testing.T) {
	exit := addr("2a0c:b641:69c:98d6::1")
	out, err := Encapsulate(innerV4("payload"), addr("2a0c:b641:69c:8c0::1"), []netip.Addr{exit}, 0)
	if err != nil {
		t.Fatal(err)
	}
	header, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if header.SegmentsLeft != 0 || len(header.Segments) != 1 || header.Segments[0] != exit {
		t.Fatalf("a single segment read back as %+v", header)
	}
	if header.NextHeader != NextHeaderIPv4 {
		t.Errorf("next header is %d, want IPv4 for an encapsulated v4 packet", header.NextHeader)
	}
	inner, family, err := Decap(out)
	if err != nil {
		t.Fatal(err)
	}
	if family != NextHeaderIPv4 {
		t.Errorf("the exit reported family %d", family)
	}
	if !bytes.Equal(inner, innerV4("payload")) {
		t.Error("the inner packet did not survive the round trip")
	}
}

// Every waypoint moves the packet along by one and leaves the rest alone, so a
// three-segment path arrives at its exit with the inner packet untouched.
func TestWaypointsWalkThePathInOrder(t *testing.T) {
	path := []netip.Addr{addr("2a0c:b641:69c:98d6::2"), addr("2a0c:b641:69c:6c46::2"), addr("2a0c:b641:69c:29a6::1")}
	inner := innerV6("payload")
	out, err := Encapsulate(inner, addr("2a0c:b641:69c:8c0::1"), path, 10)
	if err != nil {
		t.Fatal(err)
	}

	for step, want := range path[1:] {
		next, err := End(out)
		if err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		if next != want {
			t.Fatalf("step %d moved to %s, want %s", step, next, want)
		}
		if got := netip.AddrFrom16([16]byte(out[24:40])); got != want {
			t.Fatalf("step %d left the outer destination at %s", step, got)
		}
		if out[7] != uint8(9-step) {
			t.Errorf("step %d left the hop limit at %d", step, out[7])
		}
	}

	if _, err := End(out); !errors.Is(err, ErrExhausted) {
		t.Errorf("a fourth waypoint on a three-segment path returned %v", err)
	}
	delivered, family, err := Decap(out)
	if err != nil {
		t.Fatal(err)
	}
	if family != NextHeaderIPv6 || !bytes.Equal(delivered, inner) {
		t.Error("the packet that arrived is not the one that was sent")
	}
}

// A packet with no routing header is the ordinary case on this mesh, so it is
// reported as such rather than as a malformed one: the caller asks every
// packet and acts on the few that answer.
func TestPlainPacketsAreNotSegmentRouted(t *testing.T) {
	for name, raw := range map[string][]byte{
		"an ipv6 packet": innerV6("payload"),
		"an ipv4 packet": innerV4("payload"),
		"a short buffer": {0x60, 0, 0, 0},
		"an empty one":   {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); !errors.Is(err, ErrNotSegmentRouted) {
				t.Errorf("Parse returned %v, want ErrNotSegmentRouted", err)
			}
		})
	}
	// Another routing type is somebody else's header, not a broken one.
	routed := segmentRouted(t)
	routed[ipv6HeaderLen+2] = 0
	if _, err := Parse(routed); !errors.Is(err, ErrNotSegmentRouted) {
		t.Errorf("routing type 0 returned %v, want ErrNotSegmentRouted", err)
	}
}

// A header that does not describe itself is refused rather than clamped. Each
// of these is a packet whose intent this node cannot know, and acting on a
// guess is how a forwarding loop starts.
func TestMalformedHeadersAreRefusedByName(t *testing.T) {
	for name, damage := range map[string]func([]byte){
		"a length that is not whole segments": func(raw []byte) { raw[ipv6HeaderLen+1] = 3 },
		"a length past the buffer":            func(raw []byte) { raw[ipv6HeaderLen+1] = 40 },
		"a last entry past the segments":      func(raw []byte) { raw[ipv6HeaderLen+4] = 9 },
		"segments left past the last entry":   func(raw []byte) { raw[ipv6HeaderLen+3] = 9 },
		"a zero length":                       func(raw []byte) { raw[ipv6HeaderLen+1] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			raw := segmentRouted(t)
			damage(raw)
			header, err := Parse(raw)
			if err == nil {
				t.Fatalf("%s was accepted as %+v", name, header)
			}
			if errors.Is(err, ErrNotSegmentRouted) {
				t.Errorf("%s was reported as an ordinary packet", name)
			}
		})
	}
}

// An exit delivers what was addressed to it and refuses everything else: a
// packet with segments still to go was addressed to an exit in the middle of
// its own path, and one carrying something that is not an IP packet is not
// something an exit can hand to a stack.
func TestExitRefusesWhatItCannotDeliver(t *testing.T) {
	path := []netip.Addr{addr("2a0c:b641:69c:98d6::2"), addr("2a0c:b641:69c:29a6::1")}
	midPath, err := Encapsulate(innerV6("payload"), addr("2a0c:b641:69c:8c0::1"), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decap(midPath); err == nil {
		t.Error("an exit delivered a packet that still had a waypoint to visit")
	}

	arrived := segmentRouted(t)
	arrived[ipv6HeaderLen] = 59 // no next header, which is not an inner packet
	if _, _, err := Decap(arrived); err == nil {
		t.Error("an exit delivered a payload that is not an IP packet")
	}
}

// Both halves refuse an address of the wrong family and a list longer than
// this node will carry, because every segment is sixteen bytes in front of
// every packet and the length is a cost somebody else would otherwise choose.
func TestEncapsulationRefusesWhatItWillNotCarry(t *testing.T) {
	source, exit := addr("2a0c:b641:69c:8c0::1"), addr("2a0c:b641:69c:98d6::1")
	long := make([]netip.Addr, MaxSegments+1)
	for i := range long {
		long[i] = exit
	}
	for name, test := range map[string]struct {
		source netip.Addr
		path   []netip.Addr
		inner  []byte
	}{
		"no segments":       {source: source, path: nil, inner: innerV6("x")},
		"too many segments": {source: source, path: long, inner: innerV6("x")},
		"a v4 source":       {source: addr("23.161.104.117"), path: []netip.Addr{exit}, inner: innerV6("x")},
		"a v4 segment":      {source: source, path: []netip.Addr{addr("23.161.104.117")}, inner: innerV6("x")},
		"nothing inside":    {source: source, path: []netip.Addr{exit}, inner: nil},
		"not an ip packet":  {source: source, path: []netip.Addr{exit}, inner: []byte{0x10, 0, 0, 0}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Encapsulate(test.inner, test.source, test.path, 0); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

// A waypoint decrements the hop limit, so a segment list that points back at a
// node it has already visited dies at the same count anything else does rather
// than running until something else notices.
func TestWaypointRefusesToForwardAtTheLastHop(t *testing.T) {
	path := []netip.Addr{addr("2a0c:b641:69c:98d6::2"), addr("2a0c:b641:69c:29a6::1")}
	out, err := Encapsulate(innerV6("payload"), addr("2a0c:b641:69c:8c0::1"), path, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := End(out); err == nil {
		t.Error("a waypoint forwarded a packet whose hop limit had run out")
	}
}

func segmentRouted(t *testing.T) []byte {
	t.Helper()
	path := []netip.Addr{addr("2a0c:b641:69c:98d6::2"), addr("2a0c:b641:69c:29a6::1")}
	out, err := Encapsulate(innerV6("payload"), addr("2a0c:b641:69c:8c0::1"), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Walked to its exit, which is the state an End.DT46 sees.
	if _, err := End(out); err != nil {
		t.Fatal(err)
	}
	return out
}
