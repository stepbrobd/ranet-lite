package srv6

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// The checksum is the one field a receiver drops the packet over, and it is
// computed here by hand. This sums the finished message the way a receiver
// does, over the same pseudo-header: a correct message sums to zero, which is
// the check RFC 4443 section 2.3 has the receiver make.
func TestTimeExceededChecksumsAsAReceiverVerifiesIt(t *testing.T) {
	sid := addr("3fff:1:69c:8c6::2")
	offending := segmentRouted(t)
	answer, ok := TimeExceeded(offending, sid)
	if !ok {
		t.Fatal("a packet that expired here was not answered")
	}
	if answer[6] != icmpv6Next || answer[ipv6HeaderLen] != icmpTimeExceeded || answer[ipv6HeaderLen+1] != 0 {
		t.Fatalf("the answer is next header %d type %d code %d", answer[6], answer[ipv6HeaderLen], answer[ipv6HeaderLen+1])
	}
	if got := netip.AddrFrom16([16]byte(answer[8:24])); got != sid {
		t.Errorf("the answer is sent from %s, want the segment it was addressed to", got)
	}
	if got := netip.AddrFrom16([16]byte(answer[24:40])); got != netip.AddrFrom16([16]byte(offending[8:24])) {
		t.Errorf("the answer is addressed to %s", got)
	}
	body := answer[ipv6HeaderLen:]
	if got := verify(sid, netip.AddrFrom16([16]byte(answer[24:40])), body); got != 0 {
		t.Errorf("a receiver sums the message to %#04x, want zero", got)
	}
	// The sender matches the error to its own packet by the quoted bytes, and
	// the whole message has to reach it without fragmenting.
	if len(answer) > MinimumIPv6MTU {
		t.Errorf("the answer is %d bytes, over the %d byte minimum", len(answer), MinimumIPv6MTU)
	}
	if string(body[icmpHeaderLen:]) != string(offending) {
		t.Error("the answer does not quote the packet it is about")
	}
}

// A packet quoted at the minimum MTU is truncated rather than dropped, and the
// message still verifies, which is the odd-length path through the checksum.
func TestLargeOffendingPacketIsQuotedUpToTheMinimumMTU(t *testing.T) {
	sid := addr("3fff:1:69c:8c6::2")
	offending := append(segmentRouted(t), make([]byte, 2000)...)
	binary.BigEndian.PutUint16(offending[4:], uint16(len(offending)-ipv6HeaderLen))
	answer, ok := ParameterProblem(offending, sid)
	if !ok {
		t.Fatal("a header this node refused was not answered")
	}
	if len(answer) != MinimumIPv6MTU {
		t.Errorf("the answer is %d bytes, want it filled to %d", len(answer), MinimumIPv6MTU)
	}
	if got := verify(sid, netip.AddrFrom16([16]byte(answer[24:40])), answer[ipv6HeaderLen:]); got != 0 {
		t.Errorf("a receiver sums the message to %#04x, want zero", got)
	}
	if pointer := binary.BigEndian.Uint32(answer[ipv6HeaderLen+4:]); pointer != ipv6HeaderLen+segmentsLeftInHeader {
		t.Errorf("the pointer is %d, want the segments left field at %d", pointer, ipv6HeaderLen+segmentsLeftInHeader)
	}
}

// RFC 4443 section 2.4 (e) names what an error may not answer. Every one of
// these turns one refused packet into many, which is the reason the rule
// exists and the reason a segment routing node is a good place to break it.
func TestNoErrorAnswersWhatWouldMultiply(t *testing.T) {
	sid := addr("3fff:1:69c:8c6::2")
	for name, damage := range map[string]func([]byte) []byte{
		"a source that is no single node": func(raw []byte) []byte {
			copy(raw[8:], addr16(addr("::")))
			return raw
		},
		"a multicast source": func(raw []byte) []byte {
			copy(raw[8:], addr16(addr("ff02::1")))
			return raw
		},
		"a multicast destination": func(raw []byte) []byte {
			copy(raw[24:], addr16(addr("ff02::1")))
			return raw
		},
		"another icmp error": func(raw []byte) []byte {
			raw[ipv6HeaderLen] = icmpv6Next
			raw[ipv6HeaderLen+srhFixedLen+addrLen*2] = icmpTimeExceeded
			return raw
		},
		"a packet shorter than a header": func([]byte) []byte { return []byte{0x60} },
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := TimeExceeded(damage(segmentRouted(t)), sid); ok {
				t.Errorf("%s was answered", name)
			}
		})
	}
	// An informational ICMP message is not an error, so it is answerable.
	raw := segmentRouted(t)
	raw[ipv6HeaderLen] = icmpv6Next
	raw[ipv6HeaderLen+srhFixedLen+addrLen*2] = 128 // echo request
	if _, ok := TimeExceeded(raw, sid); !ok {
		t.Error("an echo request was treated as an error message")
	}
}

// verify sums a finished message the way a receiver does, with the checksum
// field in place rather than zeroed. A correct message comes back zero,
// whatever the length parity, which is the test RFC 4443 section 2.3 has the
// receiver make.
func verify(source, destination netip.Addr, body []byte) uint16 {
	return icmpChecksum(source, destination, body)
}
