package packet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func ipv4(total int, payload int) []byte {
	raw := make([]byte, 20+payload)
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(total))
	return raw
}

func ipv6(length int, payload int) []byte {
	raw := make([]byte, 40+payload)
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:6], uint16(length))
	return raw
}

// Payload trims to the length the header declares, and the ESP path hands
// that trim to the TUN. A packet claiming more than it carries must be
// refused rather than trimmed to something longer than itself: the buffer it
// arrived in is a decrypt buffer with other peers' plaintext behind it, and
// where the claim runs past the capacity it is not a buffer at all.
func TestPayloadRefusesWhatIsShorterThanItClaims(t *testing.T) {
	for name, raw := range map[string][]byte{
		"IPv4 claiming more than it carries": ipv4(40, 4),
		"IPv4 claiming less than its header": ipv4(19, 0),
		"IPv6 claiming more than it carries": ipv6(64, 8),
	} {
		t.Run(name, func(t *testing.T) {
			if payload, version := Payload(raw); payload != nil || version != 0 {
				t.Errorf("a packet shorter than it claims decoded as %d bytes of version %d", len(payload), version)
			}
		})
	}

	// A packet whose header is honest is returned trimmed, with whatever
	// follows it left to the caller. That is the TFC padding of RFC 4303
	// section 2.7 on the ESP path.
	for name, test := range map[string]struct {
		raw  []byte
		want int
		ver  byte
	}{
		"IPv4 exact":       {ipv4(24, 4), 24, 4},
		"IPv4 with tail":   {ipv4(24, 40), 24, 4},
		"IPv6 exact":       {ipv6(8, 8), 48, 6},
		"IPv6 with tail":   {ipv6(8, 40), 48, 6},
		"IPv6 header only": {ipv6(0, 0), 40, 6},
	} {
		t.Run(name, func(t *testing.T) {
			payload, version := Payload(test.raw)
			if len(payload) != test.want || version != test.ver {
				t.Errorf("got %d bytes of version %d, want %d of %d", len(payload), version, test.want, test.ver)
			}
		})
	}

	// A payload length of zero with anything behind it is the jumbogram
	// encoding, which this tunnel does not carry, and trimming it to the
	// header would deliver an empty packet instead of refusing one.
	if payload, version := Payload(ipv6(0, 8)); payload != nil || version != 0 {
		t.Errorf("a jumbogram decoded as %d bytes of version %d", len(payload), version)
	}
}

// Version is the TUN intake's rule: a frame the kernel hands over is exactly
// one packet, so anything after it is malformed rather than padding.
func TestVersionRefusesAnythingAfterThePacket(t *testing.T) {
	for name, test := range map[string]struct {
		raw  []byte
		want byte
	}{
		"IPv4 exact":     {ipv4(24, 4), 4},
		"IPv4 with tail": {ipv4(24, 40), 0},
		"IPv6 exact":     {ipv6(8, 8), 6},
		"IPv6 with tail": {ipv6(8, 40), 0},
		"empty":          {nil, 0},
		"not IP":         {bytes.Repeat([]byte{0x30}, 64), 0},
	} {
		t.Run(name, func(t *testing.T) {
			if got := Version(test.raw); got != test.want {
				t.Errorf("Version = %d, want %d", got, test.want)
			}
		})
	}
}
