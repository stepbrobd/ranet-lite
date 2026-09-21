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
func innerV6(payload string) []byte { return innerV6Hops(payload, 64) }

// innerV6Hops names the hop limit, because H.Encaps copies it onto the outer
// header, so a test about the outer budget sets it on the inner packet.
func innerV6Hops(payload string, hops uint8) []byte {
	raw := make([]byte, 40+len(payload))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(len(payload)))
	raw[6] = 59 // no next header
	raw[7] = hops
	copy(raw[8:], addr16(addr("3fff:a::1")))
	copy(raw[24:], addr16(addr("3fff:a::2")))
	copy(raw[40:], payload)
	return raw
}

func innerV4(payload string) []byte {
	raw := make([]byte, 20+len(payload))
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
	raw[8] = 64
	copy(raw[12:], addr("198.18.104.117").AsSlice())
	copy(raw[16:], addr("198.18.104.118").AsSlice())
	copy(raw[20:], payload)
	return raw
}

// The wire order is the reverse of the path, and the outer destination is the
// first segment the packet visits. Getting the reversal wrong sends the packet
// to the exit first and the waypoints afterwards, which still forwards and
// still arrives, so nothing but this test would report it.
func TestEncapsulationPutsTheFirstSegmentOnTheOuterHeader(t *testing.T) {
	path := []netip.Addr{addr("3fff:1:69c:98d6::2"), addr("3fff:1:69c:6c46::2"), addr("3fff:1:69c:29a6::1")}
	source := addr("3fff:1:69c:8c0::1")
	inner := innerV6("payload")

	out, err := Encapsulate(inner, source, path)
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
	exit := addr("3fff:1:69c:98d6::1")
	out, err := Encapsulate(innerV4("payload"), addr("3fff:1:69c:8c0::1"), []netip.Addr{exit})
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
	path := []netip.Addr{addr("3fff:1:69c:98d6::2"), addr("3fff:1:69c:6c46::2"), addr("3fff:1:69c:29a6::1")}
	inner := innerV6Hops("payload", 10)
	out, err := Encapsulate(inner, addr("3fff:1:69c:8c0::1"), path)
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
		"a length too short for its segments": func(raw []byte) { raw[ipv6HeaderLen+1] = 2 },
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
	path := []netip.Addr{addr("3fff:1:69c:98d6::2"), addr("3fff:1:69c:29a6::1")}
	midPath, err := Encapsulate(innerV6("payload"), addr("3fff:1:69c:8c0::1"), path)
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
	source, exit := addr("3fff:1:69c:8c0::1"), addr("3fff:1:69c:98d6::1")
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
		"a v4 source":       {source: addr("198.18.104.117"), path: []netip.Addr{exit}, inner: innerV6("x")},
		"a v4 segment":      {source: source, path: []netip.Addr{addr("198.18.104.117")}, inner: innerV6("x")},
		"nothing inside":    {source: source, path: []netip.Addr{exit}, inner: nil},
		"not an ip packet":  {source: source, path: []netip.Addr{exit}, inner: []byte{0x10, 0, 0, 0}},
		// A zone never reaches the wire, and neither the unspecified address
		// nor a multicast group is somewhere a packet can be forwarded to.
		"a zoned source":       {source: addr("fe80::1%eth0"), path: []netip.Addr{exit}, inner: innerV6("x")},
		"a zoned segment":      {source: source, path: []netip.Addr{addr("fe80::1%eth0")}, inner: innerV6("x")},
		"the unspecified exit": {source: source, path: []netip.Addr{addr("::")}, inner: innerV6("x")},
		"a multicast exit":     {source: source, path: []netip.Addr{addr("ff02::1")}, inner: innerV6("x")},
		// writeOuter reads the inner header's traffic class and hop limit, so
		// a packet shorter than the header it claims is refused before it can.
		"shorter than its own header": {source: source, path: []netip.Addr{exit}, inner: []byte{0x60, 0}},
		// The outer payload length is 16 bits and counts the routing header.
		"more than a payload length holds": {source: source, path: []netip.Addr{exit}, inner: oversizedV6()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Encapsulate(test.inner, test.source, test.path); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

// A waypoint decrements the hop limit, so a segment list that points back at a
// node it has already visited dies at the same count anything else does rather
// than running until something else notices.
func TestWaypointRefusesToForwardAtTheLastHop(t *testing.T) {
	path := []netip.Addr{addr("3fff:1:69c:98d6::2"), addr("3fff:1:69c:29a6::1")}
	out, err := Encapsulate(innerV6Hops("payload", 1), addr("3fff:1:69c:8c0::1"), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := End(out); err == nil {
		t.Error("a waypoint forwarded a packet whose hop limit had run out")
	}
}

func segmentRouted(t *testing.T) []byte {
	t.Helper()
	path := []netip.Addr{addr("3fff:1:69c:98d6::2"), addr("3fff:1:69c:29a6::1")}
	out, err := Encapsulate(innerV6("payload"), addr("3fff:1:69c:8c0::1"), path)
	if err != nil {
		t.Fatal(err)
	}
	// Walked to its exit, which is the state an End.DT46 sees.
	if _, err := End(out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A reduced header of RFC 8754 section 4.1.1 leaves out the segment the
// destination address already carries, so its Segments Left is one past its
// Last Entry. RFC 8986 section 4.1 S09 permits exactly that, and `ip route ...
// encap seg6 mode encap.red` writes it, so refusing one black-holes a path
// rather than rejecting a malformed packet.
func TestReducedHeaderIsForwarded(t *testing.T) {
	// Policy S1,S2,S3 with S1 in the destination, so the list is S3,S2.
	s2, s3 := addr("3fff:1:69c:6c46::2"), addr("3fff:1:69c:29a6::1")
	raw := reducedHeader(t, addr("3fff:1:69c:98d6::2"), []netip.Addr{s3, s2})

	header, err := Parse(raw)
	if err != nil {
		t.Fatalf("a reduced header was refused: %v", err)
	}
	if int(header.SegmentsLeft) != len(header.Segments) {
		t.Fatalf("segments left is %d against %d segments", header.SegmentsLeft, len(header.Segments))
	}
	next, err := End(raw)
	if err != nil {
		t.Fatal(err)
	}
	if next != s2 {
		t.Errorf("a reduced header moved to %s, want %s", next, s2)
	}
}

// RFC 8754 section 2.1 puts TLVs after the segment list and requires a type
// this node does not recognize to be ignored. An 8-octet padding TLV makes Hdr
// Ext Len odd, which is legal, and moves where the payload starts.
func TestTLVAfterTheSegmentsIsIgnored(t *testing.T) {
	exit := addr("3fff:1:69c:98d6::1")
	inner := innerV6("payload")
	raw, err := Encapsulate(inner, addr("3fff:1:69c:8c0::1"), []netip.Addr{exit})
	if err != nil {
		t.Fatal(err)
	}
	cut := ipv6HeaderLen + srhFixedLen + addrLen
	withTLV := slices.Concat(raw[:cut], []byte{4, 6, 0, 0, 0, 0, 0, 0}, raw[cut:])
	withTLV[ipv6HeaderLen+1]++
	binary.BigEndian.PutUint16(withTLV[4:], uint16(len(withTLV)-ipv6HeaderLen))

	header, err := Parse(withTLV)
	if err != nil {
		t.Fatalf("a header carrying a padding TLV was refused: %v", err)
	}
	if len(header.Segments) != 1 || header.Segments[0] != exit {
		t.Fatalf("the segment list read back as %v", header.Segments)
	}
	delivered, family, err := Decap(withTLV)
	if err != nil {
		t.Fatal(err)
	}
	if family != NextHeaderIPv6 || !bytes.Equal(delivered, inner) {
		t.Error("an exit did not skip the TLV to reach the inner packet")
	}
}

// An exit is keyed on the upper-layer header, RFC 8986 section 4.8, so a
// reduced encapsulation of a one-segment policy, which carries no routing
// header at all, is delivered rather than refused.
func TestExitDeliversAnEncapsulationWithNoRoutingHeader(t *testing.T) {
	inner := innerV6("payload")
	raw := make([]byte, ipv6HeaderLen+len(inner))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(len(inner)))
	raw[6] = NextHeaderIPv6
	raw[7] = 64
	copy(raw[8:], addr16(addr("3fff:1:69c:8c0::1")))
	copy(raw[24:], addr16(addr("3fff:1:69c:98d6::1")))
	copy(raw[ipv6HeaderLen:], inner)

	delivered, family, err := Decap(raw)
	if err != nil {
		t.Fatalf("an exit refused a reduced encapsulation: %v", err)
	}
	if family != NextHeaderIPv6 || !bytes.Equal(delivered, inner) {
		t.Error("the inner packet did not come back")
	}
}

// H.Encaps copies the traffic class, the flow label and the hop limit off an
// IPv6 inner packet the way __seg6_do_srh_encap does under the seg6_flowlabel
// default. Every class is swept, because reading one back with the inverse of
// the expression that wrote it cannot see a nibble in the wrong place. A fixed
// outer hop limit would launder a packet past the budget its own header had
// already spent.
func TestEncapsulationCopiesTheInnerTrafficClassAndHopLimit(t *testing.T) {
	exit := []netip.Addr{addr("3fff:1:69c:98d6::1")}
	for class := range 256 {
		inner := innerV6Hops("payload", 7)
		inner[0] = 0x60 | byte(class)>>4
		inner[1] = byte(class)<<4 | 0x0c
		inner[2], inner[3] = 0xde, 0xf0 // the rest of the flow label
		out, err := Encapsulate(inner, addr("3fff:1:69c:8c0::1"), exit)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out[:4], inner[:4]) {
			t.Fatalf("class %#x: the outer first word is %x, want the inner %x", class, out[:4], inner[:4])
		}
		if out[7] != 7 {
			t.Fatalf("class %#x: the outer hop limit is %d, want the inner 7", class, out[7])
		}
	}
	// An IPv4 inner has no class or label to copy, so the outer gets neither.
	out, err := Encapsulate(innerV4("payload"), addr("3fff:1:69c:8c0::1"), exit)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != 0x60 || out[1] != 0 || out[2] != 0 || out[3] != 0 || out[7] != DefaultHopLimit {
		t.Errorf("an encapsulated v4 packet got outer %x hop limit %d", out[:4], out[7])
	}
}

// A routing header longer than the packet holding it is refused. Without the
// length check the segment loop reads past the buffer, which is a panic a peer
// chooses, so this names the shape rather than relying on another check
// happening to fire first.
func TestRoutingHeaderLongerThanItsPacketIsRefused(t *testing.T) {
	raw := segmentRouted(t)
	raw[ipv6HeaderLen+1] = 40 // 328 bytes of header in a packet that has far less
	raw[ipv6HeaderLen+4] = 15 // a last entry the header would have room for
	raw[ipv6HeaderLen+3] = 15
	if _, err := Parse(raw); err == nil {
		t.Fatal("a routing header running past its packet was accepted")
	}
}

// A segment list longer than this node will act on is refused, so the work a
// peer can ask for stays bounded by a number this node chose.
func TestSegmentListPastTheCapIsRefused(t *testing.T) {
	segments := make([]netip.Addr, MaxSegments+1)
	for i := range segments {
		segments[i] = addr("3fff:1:69c:29a6::1")
	}
	raw := reducedHeader(t, addr("3fff:1:69c:98d6::2"), segments)
	if _, err := Parse(raw); err == nil {
		t.Fatalf("a %d segment header was accepted", len(segments))
	}
}

// reducedHeader writes what a `mode encap.red` sender produces: the segment in
// the destination address is left out of the list, so Segments Left is one
// past Last Entry. Segments are in wire order.
func reducedHeader(t *testing.T, destination netip.Addr, segments []netip.Addr) []byte {
	t.Helper()
	inner := innerV6("payload")
	srhLen := srhFixedLen + addrLen*len(segments)
	raw := make([]byte, ipv6HeaderLen+srhLen+len(inner))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(srhLen+len(inner)))
	raw[6] = nextHeaderRouting
	raw[7] = 64
	copy(raw[8:], addr16(addr("3fff:1:69c:8c0::1")))
	copy(raw[24:], addr16(destination))
	srh := raw[ipv6HeaderLen:]
	srh[0] = NextHeaderIPv6
	srh[1] = uint8(2 * len(segments))
	srh[2] = routingTypeSegment
	srh[3] = uint8(len(segments))
	srh[4] = uint8(len(segments) - 1)
	for i, segment := range segments {
		copy(srh[srhFixedLen+addrLen*i:], addr16(segment))
	}
	copy(raw[ipv6HeaderLen+srhLen:], inner)
	return raw
}

// oversizedV6 is a well-formed IPv6 packet too long for an outer payload
// length to describe once a routing header is in front of it.
func oversizedV6() []byte {
	raw := innerV6("payload")
	return append(raw, make([]byte, 0xffff-len(raw))...)
}

// RFC 8200 section 4.1 puts a hop-by-hop header ahead of the routing header
// and allows destination options there too, and ipv6_find_hdr walks to it. A
// parser that reads only the byte after the fixed header sees no segment list
// in a packet a kernel acts on, and refuses it as addressed to one of this
// node's own segments with nothing in it.
func TestRoutingHeaderIsFoundBehindAnotherExtensionHeader(t *testing.T) {
	exit := addr("3fff:1:69c:98d6::1")
	inner := innerV6("payload")
	plain, err := Encapsulate(inner, addr("3fff:1:69c:8c0::1"), []netip.Addr{exit})
	if err != nil {
		t.Fatal(err)
	}
	// One eight-octet hop-by-hop header with a PadN filling it, between the
	// fixed header and the routing header.
	hopByHop := []byte{plain[6], 0, 1, 4, 0, 0, 0, 0}
	behind := slices.Concat(plain[:ipv6HeaderLen], hopByHop, plain[ipv6HeaderLen:])
	behind[6] = nextHeaderHopByHop
	binary.BigEndian.PutUint16(behind[4:], uint16(len(behind)-ipv6HeaderLen))

	header, err := Parse(behind)
	if err != nil {
		t.Fatalf("a routing header behind a hop-by-hop header was not found: %v", err)
	}
	if header.Offset != ipv6HeaderLen+len(hopByHop) {
		t.Errorf("the routing header was found at %d", header.Offset)
	}
	if len(header.Segments) != 1 || header.Segments[0] != exit {
		t.Fatalf("the segment list read back as %v", header.Segments)
	}
	delivered, family, err := Decap(behind)
	if err != nil {
		t.Fatal(err)
	}
	if family != NextHeaderIPv6 || !bytes.Equal(delivered, inner) {
		t.Error("an exit did not reach the inner packet past the hop-by-hop header")
	}
}

// The chain is walked on bytes a peer chooses, so every shape that could read
// past the packet or spend this node's time is refused rather than followed.
func TestExtensionHeaderWalkRefusesWhatAPeerCanChoose(t *testing.T) {
	for name, build := range map[string]func() []byte{
		"a header that runs past the packet": func() []byte {
			raw := segmentRouted(t)
			out := slices.Concat(raw[:ipv6HeaderLen], []byte{nextHeaderRouting, 40, 0, 0, 0, 0, 0, 0}, raw[ipv6HeaderLen:])
			out[6] = nextHeaderHopByHop
			return out
		},
		"a header the packet ends inside": func() []byte {
			raw := segmentRouted(t)[:ipv6HeaderLen+4]
			raw[6] = nextHeaderHopByHop
			return raw
		},
		"a chain longer than this node walks": func() []byte {
			raw := segmentRouted(t)
			chain := []byte(nil)
			for range maxExtensionHeaders + 2 {
				chain = append(chain, nextHeaderDestOpts, 0, 1, 4, 0, 0, 0, 0)
			}
			out := slices.Concat(raw[:ipv6HeaderLen], chain, raw[ipv6HeaderLen:])
			out[6] = nextHeaderDestOpts
			return out
		},
		"a fragment": func() []byte {
			raw := segmentRouted(t)
			out := slices.Concat(raw[:ipv6HeaderLen], []byte{nextHeaderRouting, 0, 0, 1, 0, 0, 0, 0}, raw[ipv6HeaderLen:])
			out[6] = nextHeaderFragment
			return out
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw := build()
			binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-ipv6HeaderLen))
			if header, err := Parse(raw); err == nil {
				t.Errorf("%s was accepted as %+v", name, header)
			}
		})
	}
}

// Every byte Parse, End and Decap read comes from a peer, and the bounds are
// arithmetic on fields the peer chose, so the one thing none of them may do is
// panic. The corpus holds well formed packets, so the mutations start near the
// shapes that reach the interesting code.
func FuzzParseNeverPanics(f *testing.F) {
	f.Add(innerV6("payload"))
	f.Add(innerV4("payload"))
	raw, err := Encapsulate(innerV6("payload"), addr("3fff:1:69c:8c0::1"),
		[]netip.Addr{addr("3fff:1:69c:98d6::2"), addr("3fff:1:69c:29a6::1")})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add(reducedHeader(&testing.T{}, addr("3fff:1:69c:98d6::2"), []netip.Addr{addr("3fff:1:69c:29a6::1")}))

	f.Fuzz(func(t *testing.T, raw []byte) {
		header, err := Parse(raw)
		if err == nil && int(header.SegmentsLeft) > len(header.Segments) {
			t.Fatalf("segments left %d past %d segments was accepted", header.SegmentsLeft, len(header.Segments))
		}
		End(bytes.Clone(raw))
		Decap(bytes.Clone(raw))
		TimeExceeded(raw, addr("3fff:1:69c:8c6::2"))
		ParameterProblem(raw, addr("3fff:1:69c:8c6::2"))
	})
}
