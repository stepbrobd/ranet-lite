//go:build linux && !android

package kernel

import (
	"maps"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// routeReply builds one RTM_NEWROUTE the way a dump delivers it. The table
// goes in the byte when it fits and in RTA_TABLE when it does not, which is
// the same split the kernel makes.
func routeReply(table uint32, protocol, kind uint8) nlMessage {
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_INET
	if table <= 255 {
		body[4] = uint8(table)
	}
	body[5] = protocol
	body[7] = kind
	body = putAttrU32(body, unix.RTA_TABLE, table)
	return nlMessage{Kind: unix.RTM_NEWROUTE, Data: body}
}

// The report exists because an install takes over a same-key route rather than
// failing, so a second writer in one table loses routes silently. Everything
// else on a host keeps to its own table, and BIRD on a fleet node uses 200,
// which is exactly the table this reconciler is pointed at during a migration.
func TestForeignWritersReportsOnlyOurOwnTable(t *testing.T) {
	const ours = DefaultProtocol
	for name, test := range map[string]struct {
		table   uint32
		replies []nlMessage
		want    []uint8
	}{
		"another protocol in our table": {
			table:   200,
			replies: []nlMessage{routeReply(200, unix.RTPROT_BIRD, unix.RTN_UNICAST)},
			want:    []uint8{unix.RTPROT_BIRD},
		},
		"our own routes are not foreign": {
			table:   200,
			replies: []nlMessage{routeReply(200, ours, unix.RTN_UNICAST)},
		},
		"another table is not ours to report": {
			table:   200,
			replies: []nlMessage{routeReply(52, unix.RTPROT_STATIC, unix.RTN_UNICAST)},
		},
		"a route that is not unicast is not a writer": {
			table:   200,
			replies: []nlMessage{routeReply(200, unix.RTPROT_BIRD, unix.RTN_LOCAL)},
		},
		// The kernel's own plumbing for the machine's addresses, which is not
		// somebody else sharing the table.
		"kernel routes in the main table are the kernel's own": {
			table:   unix.RT_TABLE_MAIN,
			replies: []nlMessage{routeReply(unix.RT_TABLE_MAIN, unix.RTPROT_KERNEL, unix.RTN_UNICAST)},
		},
		// In a VRF table those same entries belong to whoever enslaved the
		// interface, and an install must not take them over.
		"kernel routes in a vrf table belong to somebody": {
			table:   200,
			replies: []nlMessage{routeReply(200, unix.RTPROT_KERNEL, unix.RTN_UNICAST)},
			want:    []uint8{unix.RTPROT_KERNEL},
		},
	} {
		t.Run(name, func(t *testing.T) {
			seen := map[uint8]bool{}
			collectForeignWriters(test.replies, test.table, ours, seen)
			got := slices.Sorted(maps.Keys(seen))
			if !slices.Equal(got, test.want) {
				t.Errorf("reported %v, want %v", got, test.want)
			}
		})
	}
}
