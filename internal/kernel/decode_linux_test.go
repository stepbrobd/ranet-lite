//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// The ownership filter stands between this reconciler and another
// daemon's routes, and on linux it is a pure function over a dump message.
// darwin's equivalent has been tested against a synthetic RIB since the backend
// landed; this is the same test for the platform the fleet actually runs, where
// the only other coverage needs root and /dev/net/tun and so never runs in the
// nix sandbox.
func TestLinuxDumpKeepsOnlyRoutesItOwns(t *testing.T) {
	const ourIndex, ourTable, ourProtocol = 7, 200, DefaultProtocol
	plat := &netlinkPlatform{
		cfg:      Config{Interface: "ranet0", Table: ourTable, Protocol: ourProtocol},
		index:    ourIndex,
		occupied: map[Route]bool{}, refused: map[Route]bool{},
	}
	ours := netip.MustParsePrefix("10.99.0.0/24")

	for _, test := range []struct {
		name    string
		message nlMessage
		want    bool
	}{
		{"ours", routeDump(ourTable, ourProtocol, unix.RTN_UNICAST, ourIndex, ours), true},
		{"another protocol", routeDump(ourTable, 12, unix.RTN_UNICAST, ourIndex, ours), false},
		{"the kernel's own", routeDump(ourTable, unix.RTPROT_KERNEL, unix.RTN_UNICAST, ourIndex, ours), false},
		{"another table", routeDump(unix.RT_TABLE_MAIN, ourProtocol, unix.RTN_UNICAST, ourIndex, ours), false},
		{"another device", routeDump(ourTable, ourProtocol, unix.RTN_UNICAST, ourIndex+1, ours), false},
		{"a blackhole of ours", routeDump(ourTable, ourProtocol, unix.RTN_BLACKHOLE, ourIndex, ours), false},
		{"a local entry", routeDump(ourTable, ourProtocol, unix.RTN_LOCAL, ourIndex, ours), false},
		// A retracted prefix is held as an unreachable route, and a hold this
		// reconciler installed and cannot read back is one it re-adds on every
		// pass, forever.
		{"a hold of ours", routeDump(ourTable, ourProtocol, unix.RTN_UNREACHABLE, ourIndex, ours), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			decoded, ok := plat.decodeRoute(test.message)
			if ok != test.want {
				t.Fatalf("claimed = %v, want %v (decoded %v)", ok, test.want, decoded)
			}
			if !ok {
				return
			}
			if decoded.Destination != ours {
				t.Errorf("decoded %s, want %s", decoded.Destination, ours)
			}
			// The hold has to come back as a hold, or the diff sees a path
			// where there is a hold and replaces it every pass.
			if want := test.message.Data[7] == unix.RTN_UNREACHABLE; decoded.Unreachable != want {
				t.Errorf("a hold came back as a path, so the diff replaces it on every pass")
			}
		})
	}
}

// routeDump builds the RTM_NEWROUTE the kernel emits for one route.
func routeDump(table uint32, protocol, kind uint8, oif int, destination netip.Prefix) nlMessage {
	body := make([]byte, unix.SizeofRtMsg)
	family := uint8(unix.AF_INET)
	if !destination.Addr().Is4() {
		family = unix.AF_INET6
	}
	body[0] = family
	body[1] = uint8(destination.Bits())
	body[4] = uint8(table)
	body[5] = protocol
	body[6] = unix.RT_SCOPE_UNIVERSE
	body[7] = kind
	body = append(body, attribute(unix.RTA_DST, destination.Addr().AsSlice())...)
	oifValue := make([]byte, 4)
	binary.NativeEndian.PutUint32(oifValue, uint32(oif))
	body = append(body, attribute(unix.RTA_OIF, oifValue)...)
	tableValue := make([]byte, 4)
	binary.NativeEndian.PutUint32(tableValue, table)
	body = append(body, attribute(unix.RTA_TABLE, tableValue)...)
	return nlMessage{Kind: unix.RTM_NEWROUTE, Data: body}
}

func attribute(kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	out := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint16(out[0:], uint16(length))
	binary.NativeEndian.PutUint16(out[2:], kind)
	copy(out[unix.SizeofRtAttr:], value)
	return out
}
