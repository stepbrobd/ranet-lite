// Package packet validates the IP envelope shared by TUN intake and ESP
// decapsulation. Transport checksums and extension headers remain the kernel's
// responsibility, and neither path accepts a packet shorter than its own
// header claims. They differ on what may follow one: a TUN frame is exactly
// one packet, while an ESP payload may carry Traffic Flow Confidentiality
// padding after it.
package packet

import (
	"encoding/binary"
	"net/netip"
)

// Payload returns the IP packet at the front of raw, trimmed to the length its
// own header declares, together with its version, and nil for malformed data.
// IPv6 jumbograms are outside the tunnel's supported packet size and are
// refused rather than truncated to their header.
//
// Trailing bytes are the caller's to interpret. RFC 4303 section 2.7 lets a
// sender append Traffic Flow Confidentiality padding after the payload in
// tunnel mode, and ESP cannot tell that padding from the payload: "This length
// information will enable the receiver to discard the TFC padding."
func Payload(raw []byte) ([]byte, byte) {
	if len(raw) == 0 {
		return nil, 0
	}
	switch raw[0] >> 4 {
	case 4:
		if len(raw) < 20 {
			return nil, 0
		}
		headerLen := int(raw[0]&0xf) * 4
		total := int(binary.BigEndian.Uint16(raw[2:4]))
		if headerLen < 20 || total < headerLen || total > len(raw) {
			return nil, 0
		}
		return raw[:total], 4
	case 6:
		if len(raw) < 40 {
			return nil, 0
		}
		length := int(binary.BigEndian.Uint16(raw[4:6]))
		if length == 0 && len(raw) > 40 || 40+length > len(raw) {
			return nil, 0
		}
		return raw[:40+length], 6
	default:
		return nil, 0
	}
}

// Version returns 4 or 6 for a complete IP packet with nothing after it, and
// zero for anything else. It is the TUN intake's rule: a frame the kernel
// hands over is exactly one packet.
func Version(raw []byte) byte {
	payload, version := Payload(raw)
	if len(payload) != len(raw) {
		return 0
	}
	return version
}

// Addrs returns addresses only after validating the complete IP envelope.
func Addrs(raw []byte) (src, dst netip.Addr, version byte) {
	version = Version(raw)
	switch version {
	case 4:
		src = netip.AddrFrom4([4]byte(raw[12:16]))
		dst = netip.AddrFrom4([4]byte(raw[16:20]))
	case 6:
		src = netip.AddrFrom16([16]byte(raw[8:24]))
		dst = netip.AddrFrom16([16]byte(raw[24:40]))
	}
	return
}
