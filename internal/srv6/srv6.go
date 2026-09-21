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
// bytes, which makes it testable without a kernel and identical on every
// platform.
//
// # What it does not read
//
// A routing header is found only where it is the first extension header, which
// is where H.Encaps puts it and where every encapsulation on this mesh has it.
// A packet that reached a segment of this node's behind a hop-by-hop or
// destination options header is refused rather than acted on, where
// ipv6_find_hdr would have walked to it.
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
	// ipv6HeaderLen is the fixed IPv6 header, RFC 8200 section 3, and
	// ipv4HeaderLen the shortest IPv4 one, RFC 791 section 3.1.
	ipv6HeaderLen = 40
	ipv4HeaderLen = 20
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

	// MinimumIPv6MTU is RFC 8200 section 5: "IPv6 requires that every link in
	// the Internet have an MTU of 1280 octets or greater." A device steering
	// through a list is refused below it, and an ICMP error stays inside it so
	// it reaches the sender without fragmenting.
	MinimumIPv6MTU = 1280

	// MaxSegments bounds a segment list this node will build or act on. The
	// fleet's longest path is a handful of waypoints, and the cap exists so
	// the number is ours rather than a peer's: every segment is 16 bytes in
	// front of every packet, and a list long enough to matter is a list
	// somebody else chose the cost of. A list this node builds is bounded
	// tighter than this by the MTU, which refuses a fifth segment.
	MaxSegments = 16
)

var (
	// ErrNotSegmentRouted is returned for a packet with no SRH, which is the
	// ordinary case on a mesh where most traffic is not steered.
	ErrNotSegmentRouted = errors.New("srv6: packet carries no segment routing header")
	// ErrExhausted is an End reached with no segment left to move to. RFC 8986
	// section 4.1 S03 hands the packet to whatever the next header names; this
	// drops it, as get_and_validate_srh does, because a waypoint SID is not
	// an address this node terminates traffic on.
	ErrExhausted = errors.New("srv6: End reached the last segment and there is nowhere to forward to")
	// ErrHopLimit and ErrHeaderInvalid name the two refusals RFC 8986 section
	// 4.1 answers with an ICMP message rather than with silence, S06 and S10.
	// A caller that can reach the sender tells them apart with errors.Is and
	// builds the answer with TimeExceeded or ParameterProblem.
	ErrHopLimit      = errors.New("srv6: the hop limit reached zero at this waypoint")
	ErrHeaderInvalid = errors.New("srv6: the routing header does not describe itself")
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
	// destination address agree while the packet is in flight. A reduced
	// header of RFC 8754 section 4.1.1 leaves the segment it is heading to
	// out of the list, since the destination already carries it, and there
	// SegmentsLeft is len(Segments).
	SegmentsLeft uint8
	Segments     []netip.Addr
	Flags        uint8
	Tag          uint16
	// NextHeader names whatever follows the SRH, which for an encapsulated
	// packet is NextHeaderIPv4 or NextHeaderIPv6.
	NextHeader uint8
}

// Path is the segment list in the order a packet visits it, which is how an
// operator writes one and the reverse of how it goes on the wire. A reduced
// header carries every segment but the first, so its path starts one hop in.
func (h Header) Path() []netip.Addr {
	path := make([]netip.Addr, 0, len(h.Segments))
	for i := len(h.Segments) - 1; i >= 0; i-- {
		path = append(path, h.Segments[i])
	}
	return path
}

// Active is the segment this packet is on its way to, which is also the outer
// destination address of a well-formed packet in flight. A reduced header does
// not carry it, so this reports false and the caller reads the destination.
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
// The inner packet is not modified. RFC 8986 section 5.1 S05 decrements its
// hop limit and this does not, matching __seg6_do_srh_encap: a
// packet read off the tun was either originated here, where a host must not
// decrement, or already forwarded into the tun by the kernel, where it
// already was. Decrementing again would charge it twice for one hop.
func Encapsulate(inner []byte, source netip.Addr, path []netip.Addr) ([]byte, error) {
	overhead, err := checkEncapsulation(inner, source, path)
	if err != nil {
		return nil, err
	}
	out := make([]byte, overhead+len(inner))
	copy(out[overhead:], inner)
	writeOuter(out[:overhead], inner, source, path)
	return out, nil
}

// Overhead is the bytes an encapsulation puts in front of a packet for a path
// of n segments, which a tunnel takes off its own MTU so the dataplane keeps
// being handed packets that still fit once the header is there.
func Overhead(segments int) int {
	return ipv6HeaderLen + srhFixedLen + addrLen*segments
}

// EncapsulateInPlace is Encapsulate for a dataplane that already owns the
// buffer. The packet at buf[offset:offset+size] is moved along to make room
// and the outer header is written in front of it, so an encapsulation costs a
// copy of the packet rather than an allocation per packet.
//
// It returns the new size, with the encapsulated packet at buf[offset:] as
// before. A buffer too short to hold the result is refused rather than
// truncated. The tun's MTU keeps that from happening, so a packet reaching
// here anyway belongs to a deployment that has the MTU wrong.
func EncapsulateInPlace(buf []byte, offset, size int, source netip.Addr, path []netip.Addr) (int, error) {
	if offset < 0 || size < 0 || offset+size > len(buf) {
		return 0, fmt.Errorf("srv6: a packet at %d+%d is not inside a %d byte buffer", offset, size, len(buf))
	}
	inner := buf[offset : offset+size]
	overhead, err := checkEncapsulation(inner, source, path)
	if err != nil {
		return 0, err
	}
	if offset+overhead+size > len(buf) {
		return 0, fmt.Errorf("srv6: encapsulating %d bytes needs %d more and the buffer has %d",
			size, overhead, len(buf)-offset-size)
	}
	copy(buf[offset+overhead:], inner)
	writeOuter(buf[offset:offset+overhead], buf[offset+overhead:offset+overhead+size], source, path)
	return overhead + size, nil
}

// CheckPath refuses a segment list and a tunnel source this node will not
// encapsulate with, so a configuration is rejected when it is read rather than
// when the first packet matches it.
func CheckPath(source netip.Addr, path []netip.Addr) error {
	if len(path) == 0 {
		return errors.New("srv6: a segment list needs at least one segment")
	}
	if len(path) > MaxSegments {
		return fmt.Errorf("srv6: %d segments is more than the %d this node will build", len(path), MaxSegments)
	}
	if !Usable(source) {
		return fmt.Errorf("srv6: tunnel source %s cannot address a segment routed packet", source)
	}
	for _, segment := range path {
		if !Usable(segment) {
			return fmt.Errorf("srv6: segment %s cannot address a segment routed packet", segment)
		}
	}
	return nil
}

// checkEncapsulation refuses what this node will not encapsulate and returns
// the bytes the header will take. Both entry points run it, so the two cannot
// come to disagree about what is acceptable.
func checkEncapsulation(inner []byte, source netip.Addr, path []netip.Addr) (int, error) {
	if err := CheckPath(source, path); err != nil {
		return 0, err
	}
	if _, err := innerNextHeader(inner); err != nil {
		return 0, err
	}
	// The outer payload length is 16 bits and counts the routing header as
	// well, so a packet that would overflow it is refused rather than sent
	// with a length that has wrapped.
	payload := srhFixedLen + addrLen*len(path) + len(inner)
	if payload > 0xffff {
		return 0, fmt.Errorf("srv6: %d bytes behind %d segments is more than an IPv6 payload length can carry", len(inner), len(path))
	}
	return Overhead(len(path)), nil
}

// Usable reports whether an address can be a segment or a tunnel source. A
// zone is local to one host and never reaches the wire, a v4-mapped address
// cannot appear in an IPv6 destination, and neither the unspecified address
// nor a multicast group is somewhere a packet can be forwarded to.
func Usable(address netip.Addr) bool {
	return address.Is6() && !address.Is4In6() && address.Zone() == "" &&
		!address.IsUnspecified() && !address.IsMulticast()
}

// writeOuter fills a header of exactly Overhead(len(path)) bytes. Its caller
// has already checked everything, so it cannot fail and never reports.
//
// Every byte of the header is assigned rather than left as it was found:
// EncapsulateInPlace hands this the bytes the packet it is encapsulating used
// to occupy, so anything skipped here would go on the wire as a fragment of
// the inner header.
func writeOuter(out, inner []byte, source netip.Addr, path []netip.Addr) {
	innerNext, _ := innerNextHeader(inner)
	// __seg6_do_srh_encap copies the traffic class and the hop limit out of an
	// IPv6 inner packet and leaves the flow label at zero, the default the
	// seg6_flowlabel sysctl asks for. Matching it keeps a packet
	// this node steers and one a kernel headend steers the same bytes, and
	// stops an encapsulation handing a packet a hop budget its own header had
	// already spent.
	traffic, hopLimit := uint8(0), uint8(DefaultHopLimit)
	if innerNext == NextHeaderIPv6 {
		traffic, hopLimit = inner[0]<<4|inner[1]>>4, inner[7]
	}
	segments := reversed(path)
	last := uint8(len(segments) - 1)
	srhLen := srhFixedLen + addrLen*len(segments)

	out[0] = 0x60 | traffic>>4
	out[1] = traffic << 4
	binary.BigEndian.PutUint16(out[2:], 0) // flow label, see above
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
	srh[5], srh[6], srh[7] = 0, 0, 0
	for i, segment := range segments {
		copy(srh[srhFixedLen+addrLen*i:], addr16(segment))
	}
}

// DefaultHopLimit is the outer budget an IPv4 inner packet gets, since its TTL
// is not an IPv6 hop limit to copy. It takes the RFC 8200 recommended default
// rather than a mesh-sized number, so a segment list that loops dies at the
// same count anything else does.
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
	// 8*(1+len) bytes.
	extLen := int(srh[1])
	total := srhFixedLen + 8*extLen
	if len(srh) < total {
		return Header{}, fmt.Errorf("srv6: the routing header claims %d bytes and %d are present", total, len(srh))
	}
	// Last Entry gives the segment count, and RFC 8754 section 2.1 puts any
	// TLVs after the list: they are present exactly when Hdr Ext Len is
	// greater than (Last Entry+1)*2, and the same section requires a type this
	// node does not recognize to be ignored rather than refused. So the
	// segments have to fit and everything past them is somebody else's.
	count := int(srh[4]) + 1
	if 2*count > extLen {
		return Header{}, fmt.Errorf("%w: last entry %d needs %d bytes of segments and the header carries %d", ErrHeaderInvalid, srh[4], addrLen*count, 8*extLen)
	}
	if count > MaxSegments {
		return Header{}, fmt.Errorf("srv6: %d segments is more than the %d this node will act on", count, MaxSegments)
	}
	header := Header{
		NextHeader:   srh[0],
		SegmentsLeft: srh[3],
		Flags:        srh[5],
		Tag:          binary.BigEndian.Uint16(srh[6:]),
	}
	header.Segments = make([]netip.Addr, 0, count)
	for i := range count {
		var segment [16]byte
		copy(segment[:], srh[srhFixedLen+addrLen*i:])
		header.Segments = append(header.Segments, netip.AddrFrom16(segment))
	}
	// RFC 8986 section 4.1 S09 makes only a Segments Left past Last Entry+1 an
	// error, because RFC 8754 section 4.1.1 lets a source leave out the
	// segment the destination address already carries. That reduced header is
	// what a kernel writes for `encap.red`, so refusing it black-holes a path
	// rather than rejecting a malformed packet.
	if int(header.SegmentsLeft) > count {
		return Header{}, fmt.Errorf("%w: segments left %d is past the last entry %d", ErrHeaderInvalid, header.SegmentsLeft, count-1)
	}
	return header, nil
}

// End is the waypoint behavior of RFC 8986 section 4.1: the packet is not
// changed except that it moves on to the next segment. It returns the address
// the packet now goes to, having rewritten the destination and the counter in
// place.
//
// The hop limit is decremented, RFC 8986 section 4.1 S12, which bounds a
// segment list that points back at an earlier node.
func End(raw []byte) (netip.Addr, error) {
	header, err := Parse(raw)
	if err != nil {
		return netip.Addr{}, err
	}
	if header.SegmentsLeft == 0 {
		return netip.Addr{}, ErrExhausted
	}
	if raw[7] <= 1 {
		return netip.Addr{}, ErrHopLimit
	}
	raw[7]--
	srh := raw[ipv6HeaderLen:]
	srh[3] = header.SegmentsLeft - 1
	next := header.Segments[srh[3]]
	copy(raw[24:], addr16(next))
	return next, nil
}

// Decap is the exit behavior of RFC 8986 section 4.8, End.DT46: the outer IPv6
// header and the routing header are removed and what was inside is returned,
// with the next-header value that says which family it is.
//
// An exit is keyed on the upper-layer header rather than on a routing header,
// which is why a packet carrying none is delivered rather than refused: a
// reduced encapsulation of a one-segment policy puts that segment in the
// destination address and writes no SRH at all, and the kernel's own
// decap_and_validate accepts it the same way.
//
// It returns a slice of raw rather than a copy, because the caller is the
// dataplane and the buffer is already its own. The two-table half of the RFC's
// End.DT46, choosing a lookup table per family, is the caller's: this package
// takes bytes and returns bytes.
func Decap(raw []byte) (inner []byte, family uint8, err error) {
	if len(raw) < ipv6HeaderLen || raw[0]>>4 != 6 {
		return nil, 0, ErrNotSegmentRouted
	}
	offset, upper := ipv6HeaderLen, raw[6]
	if upper == nextHeaderRouting {
		header, err := Parse(raw)
		if err != nil {
			return nil, 0, err
		}
		if header.SegmentsLeft != 0 {
			// RFC 8986 section 4.8 runs End.DT46 on the last segment. Reaching
			// it with segments still to go means the packet was addressed to
			// an exit in the middle of its own path, which is a segment list
			// that does not describe what it wants.
			return nil, 0, fmt.Errorf("srv6: an exit was reached with %d segments still to go", header.SegmentsLeft)
		}
		offset, upper = ipv6HeaderLen+srhFixedLen+8*int(raw[ipv6HeaderLen+1]), header.NextHeader
	}
	if upper != NextHeaderIPv4 && upper != NextHeaderIPv6 {
		return nil, 0, fmt.Errorf("srv6: an exit cannot deliver next header %d, only an encapsulated IPv4 or IPv6 packet", upper)
	}
	if len(raw) <= offset {
		return nil, 0, errors.New("srv6: the packet ends where its payload should start")
	}
	return raw[offset:], upper, nil
}

// innerNextHeader is the protocol number announcing what an encapsulation is
// carrying, read from the packet itself rather than taken on trust from the
// caller: the two disagreeing is a packet an exit refuses to deliver, found
// one hop too late to say anything useful about it.
//
// A packet too short to hold the header its version claims is refused here,
// which lets writeOuter read the fields it copies.
func innerNextHeader(inner []byte) (uint8, error) {
	if len(inner) == 0 {
		return 0, errors.New("srv6: nothing to encapsulate")
	}
	switch version := inner[0] >> 4; version {
	case 4:
		if len(inner) < ipv4HeaderLen {
			return 0, fmt.Errorf("srv6: %d bytes is shorter than the IPv4 header it claims to be", len(inner))
		}
		return NextHeaderIPv4, nil
	case 6:
		if len(inner) < ipv6HeaderLen {
			return 0, fmt.Errorf("srv6: %d bytes is shorter than the IPv6 header it claims to be", len(inner))
		}
		return NextHeaderIPv6, nil
	default:
		return 0, fmt.Errorf("srv6: the packet to encapsulate is IP version %d", version)
	}
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
