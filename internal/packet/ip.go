// Package packet validates the IP envelope shared by TUN intake and ESP
// decapsulation. Transport checksums and extension headers remain the kernel's
// responsibility; neither path accepts truncated packets or trailing bytes.
package packet

import (
	"encoding/binary"
	"net/netip"
)

// Version returns 4 or 6 for a complete IP packet, and zero for malformed data.
// IPv6 jumbograms are outside the tunnel's supported packet size.
func Version(raw []byte) byte {
	if len(raw) == 0 {
		return 0
	}
	switch raw[0] >> 4 {
	case 4:
		if len(raw) < 20 {
			return 0
		}
		headerLen := int(raw[0]&0xf) * 4
		if headerLen < 20 || headerLen > len(raw) || int(binary.BigEndian.Uint16(raw[2:4])) != len(raw) {
			return 0
		}
		return 4
	case 6:
		if len(raw) < 40 || 40+int(binary.BigEndian.Uint16(raw[4:6])) != len(raw) {
			return 0
		}
		return 6
	default:
		return 0
	}
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
