// Package srv6 is segment routing over IPv6 done in this process rather than
// by a kernel.
//
// # Why here
//
// The fleet's SRv6 today is `ip route ... encap seg6local`, which is a linux
// facility and only a linux facility: darwin has no segment routing, and a
// NEPacketTunnelProvider or a VpnService is handed a tun and a list of routes
// and never sees a forwarding table at all. Waiting for each platform's kernel
// would mean segment routing on one of the four.
//
// It does not have to be the kernel's, because this process is already the
// dataplane. A packet leaving a node is read off the tun here, routed here and
// sealed into ESP here, so pushing an outer IPv6 header and a routing header
// in front of it is one more step on a path that already copies. A packet
// arriving is decrypted here before anything else sees it, so a segment
// addressed to this node can be acted on before it is written to the tun. The
// same code then runs on every platform, and a converted fleet needs no
// seg6local routes at all.
//
// # What it implements
//
// [RFC 8754] for the header and [RFC 8986] for the two behaviors this mesh
// uses: End, a waypoint that forwards to the next segment, and End.DT46, an
// exit that strips the outer header and delivers what was inside. The fleet
// spells those as `<base>6::2` and `<base>6::1`, with `<base>6::3` a second
// End.DT46 into the egress VRF, and the encapsulation this package performs is
// H.Encaps of RFC 8986 section 5.1.
//
// Nothing here touches a socket or a route table. It takes bytes and returns
// bytes, so it is testable without a kernel and identical on every platform.
//
// [RFC 8754]: https://www.rfc-editor.org/rfc/rfc8754
// [RFC 8986]: https://www.rfc-editor.org/rfc/rfc8986
package srv6

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	// ipv6HeaderLen is the fixed IPv6 header, RFC 8200 section 3.
	ipv6HeaderLen = 40
	// srhFixedLen is the routing header before its first segment.
	srhFixedLen = 8
	// addrLen is one segment.
	addrLen = 16

	// Next Header values, from the IANA protocol registry. Routing is the
	// SRH's own, and the two below it announce an encapsulated inner packet.
	nextHeaderRouting = 43
	// NextHeaderIPv4 and NextHeaderIPv6 name what H.Encaps put inside, which
	// an End.DT46 has to read to know which stack to deliver to.
	NextHeaderIPv4 = 4
	NextHeaderIPv6 = 41

	// routingTypeSegment is Routing Type 4, the SRH, RFC 8754 section 2.
	routingTypeSegment = 4

	// MaxSegments bounds a segment list this node will build or act on. The
	// fleet's longest path is a handful of waypoints, and the cap exists so
	// the number is ours rather than a peer's: every segment is 16 bytes in
	// front of every packet, and a list long enough to matter is a list
	// somebody else chose the cost of.
	MaxSegments = 16
)

var (
	// ErrNotSegmentRouted is returned for a packet with no SRH, which is the
	// ordinary case on a mesh where most traffic is not steered.
	ErrNotSegmentRouted = errors.New("srv6: packet carries no segment routing header")
	// ErrExhausted is an End reached with no segment left to move to. RFC 8986
	// section 4.1 has the node drop it; there is nowhere else to send it.
	ErrExhausted = errors.New("srv6: End reached the last segment, so there is nowhere to forward to")
)

// Header is one segment routing header as this package reads and writes it.
//
// Segments are held in wire order, which is the reverse of the path: the first
// segment a packet visits is the last element. That is the order RFC 8754
// section 2 defines and the order the kernel and every other implementation
// puts on the wire, so keeping it here means a decode and an encode are
// inverses rather than two places that each flip it.
type Header struct {
	// SegmentsLeft indexes Segments for the destination the packet is
	// currently heading to, so Segments[SegmentsLeft] and the outer
	// destination address agree while the packet is in flight.
	SegmentsLeft uint8
	Segments     []netip.Addr
	Flags        uint8
	Tag          uint16
	// NextHeader names whatever follows the SRH, which for an encapsulated
	// packet is NextHeaderIPv4 or NextHeaderIPv6.
	NextHeader uint8
}

// Path is the segment list in the order a packet visits it, which is how an
// operator writes one and the reverse of how it goes on the wire.
func (h Header) Path() []netip.Addr {
	path := make([]netip.Addr, 0, len(h.Segments))
	for i := len(h.Segments) - 1; i >= 0; i-- {
		path = append(path, h.Segments[i])
	}
	return path
}

// Active is the segment this packet is on its way to, which is also the outer
// destination address of a well-formed packet in flight.
func (h Header) Active() (netip.Addr, bool) {
	if int(h.SegmentsLeft) >= len(h.Segments) {
		return netip.Addr{}, false
	}
	return h.Segments[h.SegmentsLeft], true
}

// Encapsulate is H.Encaps, RFC 8986 section 5.1: it puts inner inside a new
// IPv6 packet whose destination is the first segment of path and whose routing
// header carries the rest.
//
// path is in the order the packet visits, so a caller writes the waypoints and
// then the exit, and this reverses them for the wire. source is the address
// the outer header is sent from, which the fleet sets with `ip sr tunsrc` and
// which here is an argument because nothing global decides it.
//
// The inner packet is not modified and its hop limit is not touched: an
// encapsulated packet is carried, not forwarded, so the hop count it is
// spending is the outer one.
func Encapsulate(inner []byte, source netip.Addr, path []netip.Addr, hopLimit uint8) ([]byte, error) {
	if len(path) == 0 {
		return nil, errors.New("srv6: a segment list needs at least one segment")
	}
	if len(path) > MaxSegments {
		return nil, fmt.Errorf("srv6: %d segments is more than the %d this node will build", len(path), MaxSegments)
	}
	if !source.Is6() || source.Is4In6() {
		return nil, fmt.Errorf("srv6: tunnel source %s is not an IPv6 address", source)
	}
	for _, segment := range path {
		if !segment.Is6() || segment.Is4In6() {
			return nil, fmt.Errorf("srv6: segment %s is not an IPv6 address", segment)
		}
	}
	innerNext, err := innerNextHeader(inner)
	if err != nil {
		return nil, err
	}
	if hopLimit == 0 {
		hopLimit = DefaultHopLimit
	}

	segments := reversed(path)
	last := uint8(len(segments) - 1)
	srhLen := srhFixedLen + addrLen*len(segments)
	out := make([]byte, ipv6HeaderLen+srhLen+len(inner))

	out[0] = 0x60 // version 6, traffic class and flow label left at zero
	binary.BigEndian.PutUint16(out[4:], uint16(srhLen+len(inner)))
	out[6] = nextHeaderRouting
	out[7] = hopLimit
	copy(out[8:], addr16(source))
	// The outer destination is the first segment of the path, which after the
	// reversal above is the last element and is also Segments[SegmentsLeft].
	copy(out[24:], addr16(segments[last]))

	srh := out[ipv6HeaderLen:]
	srh[0] = innerNext
	// Hdr Ext Len counts 8-octet units after the first eight octets, so a list
	// of n segments is 2n.
	srh[1] = uint8(2 * len(segments))
	srh[2] = routingTypeSegment
	srh[3] = last // Segments Left starts at the last index
	srh[4] = last // Last Entry is that index too
	for i, segment := range segments {
		copy(srh[srhFixedLen+addrLen*i:], addr16(segment))
	}
	copy(out[ipv6HeaderLen+srhLen:], inner)
	return out, nil
}

// DefaultHopLimit applies when a caller names none. It takes the RFC 8200
// recommended default rather than a mesh-sized number, so a segment list that
// loops dies at the same count anything else does.
const DefaultHopLimit = 64

// Parse reads the routing header of an IPv6 packet, and reports
// ErrNotSegmentRouted for one that has none, which is most of them.
//
// Everything it accepts is something this node is willing to act on. A routing
// type it does not implement, a length that disagrees with the segment count,
// and a Segments Left past the end of the list are each refused by name rather
// than clamped: a packet whose header does not describe itself is one this
// node cannot know the intent of, and guessing at it is how a forwarding loop
// starts.
func Parse(raw []byte) (Header, error) {
	if len(raw) < ipv6HeaderLen {
		return Header{}, ErrNotSegmentRouted
	}
	if raw[0]>>4 != 6 || raw[6] != nextHeaderRouting {
		return Header{}, ErrNotSegmentRouted
	}
	srh := raw[ipv6HeaderLen:]
	if len(srh) < srhFixedLen {
		return Header{}, errors.New("srv6: the routing header is shorter than its fixed part")
	}
	if srh[2] != routingTypeSegment {
		return Header{}, ErrNotSegmentRouted
	}
	// Hdr Ext Len is in 8-octet units after the first eight, so the header is
	// 8*(1+len) bytes and an odd value would not be a whole number of
	// segments.
	extLen := int(srh[1])
	if extLen == 0 || extLen%2 != 0 {
		return Header{}, fmt.Errorf("srv6: header length %d is not a whole number of segments", extLen)
	}
	total := srhFixedLen + 8*extLen
	if len(srh) < total {
		return Header{}, fmt.Errorf("srv6: the routing header claims %d bytes and %d are present", total, len(srh))
	}
	count := extLen / 2
	if count > MaxSegments {
		return Header{}, fmt.Errorf("srv6: %d segments is more than the %d this node will act on", count, MaxSegments)
	}
	// Last Entry indexes the list, so it has to name an element of it. A
	// header with TLVs after the segments is well-formed and its Last Entry is
	// smaller than the count; one larger than the count describes segments
	// that are not there.
	if int(srh[4]) >= count {
		return Header{}, fmt.Errorf("srv6: last entry %d is past the %d segments present", srh[4], count)
	}
	header := Header{
		NextHeader:   srh[0],
		SegmentsLeft: srh[3],
		Flags:        srh[5],
		Tag:          binary.BigEndian.Uint16(srh[6:]),
	}
	last := int(srh[4])
	header.Segments = make([]netip.Addr, 0, last+1)
	for i := 0; i <= last; i++ {
		var segment [16]byte
		copy(segment[:], srh[srhFixedLen+addrLen*i:])
		header.Segments = append(header.Segments, netip.AddrFrom16(segment))
	}
	if int(header.SegmentsLeft) > last {
		return Header{}, fmt.Errorf("srv6: segments left %d is past the last entry %d", header.SegmentsLeft, last)
	}
	return header, nil
}

// End is the waypoint behavior of RFC 8986 section 4.1: the packet is not
// changed except that it moves on to the next segment. It returns the address
// the packet now goes to, having rewritten the destination and the counter in
// place.
//
// The hop limit is decremented here, which forwarding does and which the RFC's
// pseudocode leaves to the "Send" step it shares with ordinary forwarding. A
// waypoint that did not would let a segment list that points back at an
// earlier node run until something else noticed.
func End(raw []byte) (netip.Addr, error) {
	header, err := Parse(raw)
	if err != nil {
		return netip.Addr{}, err
	}
	if header.SegmentsLeft == 0 {
		return netip.Addr{}, ErrExhausted
	}
	if raw[7] <= 1 {
		return netip.Addr{}, errors.New("srv6: the hop limit reached zero at this waypoint")
	}
	raw[7]--
	srh := raw[ipv6HeaderLen:]
	srh[3] = header.SegmentsLeft - 1
	next := header.Segments[srh[3]]
	copy(raw[24:], addr16(next))
	return next, nil
}

// Decap is the exit behavior of RFC 8986 section 4.10, End.DT46: the outer
// IPv6 header and the routing header are removed and what was inside is
// returned, with the next-header value that says which family it is.
//
// It returns a slice of raw rather than a copy, because the caller is the
// dataplane and the buffer is already its own. The two-table half of the RFC's
// End.DT46, choosing a lookup table per family, is the caller's: this package
// takes bytes and returns bytes.
func Decap(raw []byte) (inner []byte, family uint8, err error) {
	header, err := Parse(raw)
	if err != nil {
		return nil, 0, err
	}
	if header.SegmentsLeft != 0 {
		// RFC 8986 section 4.10 runs End.DT46 on the last segment. Reaching it
		// with segments still to go means the packet was addressed to an exit
		// in the middle of its own path, which is a segment list that does not
		// describe what it wants.
		return nil, 0, fmt.Errorf("srv6: an exit was reached with %d segments still to go", header.SegmentsLeft)
	}
	if header.NextHeader != NextHeaderIPv4 && header.NextHeader != NextHeaderIPv6 {
		return nil, 0, fmt.Errorf("srv6: an exit cannot deliver next header %d, only an encapsulated IPv4 or IPv6 packet", header.NextHeader)
	}
	offset := ipv6HeaderLen + srhFixedLen + 8*int(raw[ipv6HeaderLen+1])
	if len(raw) <= offset {
		return nil, 0, errors.New("srv6: the packet ends where its payload should start")
	}
	return raw[offset:], header.NextHeader, nil
}

// innerNextHeader is the protocol number announcing what an encapsulation is
// carrying, read from the packet itself rather than taken on trust from the
// caller: the two disagreeing is a packet an exit refuses to deliver, found
// one hop too late to say anything useful about it.
func innerNextHeader(inner []byte) (uint8, error) {
	if len(inner) == 0 {
		return 0, errors.New("srv6: nothing to encapsulate")
	}
	switch inner[0] >> 4 {
	case 4:
		return NextHeaderIPv4, nil
	case 6:
		return NextHeaderIPv6, nil
	}
	return 0, fmt.Errorf("srv6: the packet to encapsulate is IP version %d", inner[0]>>4)
}

func reversed(path []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, len(path))
	for i, segment := range path {
		out[len(path)-1-i] = segment
	}
	return out
}

func addr16(address netip.Addr) []byte {
	raw := address.As16()
	return raw[:]
}
