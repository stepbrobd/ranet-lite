package srv6

import (
	"encoding/binary"
	"net/netip"
)

// This file builds the ICMPv6 errors RFC 8986's pseudocode answers a refused
// packet with, rather than dropping it in silence. It takes bytes and returns
// bytes like the rest of the package: whether an answer is sent at all, and
// how often, is the dataplane's to decide.
//
// Without these a converted waypoint is invisible to traceroute, where a node
// still running seg6local answers through ip6_forward, so a fleet migrating
// node by node loses the tool it debugs paths with one node at a time.

const (
	// icmpv6Next is the protocol number of the header these messages carry.
	icmpv6Next = 58
	// The two messages RFC 8986 calls for, RFC 4443 sections 3.3 and 3.4, each
	// with the one code this node uses.
	icmpTimeExceeded     = 3
	icmpHopLimitInTranst = 0
	icmpParameterProblem = 4
	icmpErroneousHeader  = 0
	// icmpHeaderLen is the type, the code, the checksum and the four octets
	// the two messages use differently.
	icmpHeaderLen = 8
	// segmentsLeftOffset is where Segments Left sits in a packet whose routing
	// header follows the fixed header, which is the only shape Parse reads.
	segmentsLeftOffset = ipv6HeaderLen + 3
)

// TimeExceeded answers a packet whose hop limit ran out at this node, RFC 4443
// section 3.3. source is the segment the packet was addressed to, which is the
// address a router answers an expired packet from.
func TimeExceeded(offending []byte, source netip.Addr) ([]byte, bool) {
	return icmpError(offending, source, icmpTimeExceeded, icmpHopLimitInTranst, 0)
}

// ParameterProblem answers a routing header this node will not act on, RFC
// 4443 section 3.4, pointing at the Segments Left field that RFC 8986 section
// 4.1 S10 names.
func ParameterProblem(offending []byte, source netip.Addr) ([]byte, bool) {
	return icmpError(offending, source, icmpParameterProblem, icmpErroneousHeader, segmentsLeftOffset)
}

// icmpError builds one message carrying as much of the offending packet as
// fits, RFC 4443 section 3.3: enough that the whole reply stays inside the
// IPv6 minimum MTU, so it reaches the sender without fragmenting.
//
// It reports false for a packet no error may answer, which keeps one message
// from becoming many.
func icmpError(offending []byte, source netip.Addr, kind, code uint8, pointer uint32) ([]byte, bool) {
	if !Usable(source) || !answerable(offending) {
		return nil, false
	}
	destination := netip.AddrFrom16([16]byte(offending[8:24]))
	quoted := min(len(offending), MinimumIPv6MTU-ipv6HeaderLen-icmpHeaderLen)
	body := make([]byte, icmpHeaderLen+quoted)
	body[0], body[1] = kind, code
	binary.BigEndian.PutUint32(body[4:], pointer)
	copy(body[icmpHeaderLen:], offending[:quoted])

	out := make([]byte, ipv6HeaderLen+len(body))
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:], uint16(len(body)))
	out[6] = icmpv6Next
	out[7] = DefaultHopLimit
	copy(out[8:], addr16(source))
	copy(out[24:], addr16(destination))
	copy(out[ipv6HeaderLen:], body)
	binary.BigEndian.PutUint16(out[ipv6HeaderLen+2:], icmpChecksum(source, destination, body))
	return out, true
}

// answerable is RFC 4443 section 2.4 (e): the rules that stop one refused
// packet turning into many. An ICMPv6 error may not answer another, and it may
// not answer anything addressed to or sent from more than one interface, since
// every receiver would answer the same packet.
//
// The link-layer cases of (e.3) and (e.4) cannot arise, because every packet
// reaching here was decrypted out of a unicast ESP session with one peer.
func answerable(offending []byte) bool {
	if len(offending) < ipv6HeaderLen || offending[0]>>4 != 6 {
		return false
	}
	from := netip.AddrFrom16([16]byte(offending[8:24]))
	to := netip.AddrFrom16([16]byte(offending[24:40]))
	if from.IsUnspecified() || from.IsMulticast() || to.IsMulticast() {
		return false
	}
	return !carriesICMPError(offending)
}

// carriesICMPError reads past the one extension header this node acts on, so
// that an error refused at a segment is not answered with another error.
func carriesICMPError(offending []byte) bool {
	next, payload := offending[6], ipv6HeaderLen
	if next == nextHeaderRouting {
		if len(offending) < ipv6HeaderLen+srhFixedLen {
			return false
		}
		next = offending[ipv6HeaderLen]
		payload = ipv6HeaderLen + srhFixedLen + 8*int(offending[ipv6HeaderLen+1])
	}
	// An ICMPv6 type below 128 is an error message, RFC 4443 section 2.1.
	return next == icmpv6Next && len(offending) > payload && offending[payload] < 128
}

// icmpChecksum is the RFC 4443 section 2.3 checksum over the pseudo-header of
// RFC 8200 section 8.1 and the message.
func icmpChecksum(source, destination netip.Addr, body []byte) uint16 {
	var pseudo [40]byte
	copy(pseudo[0:], addr16(source))
	copy(pseudo[16:], addr16(destination))
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(body)))
	pseudo[39] = icmpv6Next

	sum := ones(0, pseudo[:])
	sum = ones(sum, body)
	return ^uint16(sum)
}

// ones accumulates the one's complement sum of b into carrying, folding the
// carries in as it goes.
func ones(carrying uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		carrying += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		carrying += uint32(b[len(b)-1]) << 8
	}
	for carrying>>16 != 0 {
		carrying = carrying&0xffff + carrying>>16
	}
	return carrying
}
