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

// The report exists because an install asks for its key exclusively, so a
// second writer in one table leaves the routes it holds uninstalled, and
// nothing else says so before the first refusal. Everything else on a host
// keeps to its own table, and BIRD on a fleet node uses 200, which is exactly
// the table this reconciler is pointed at during a migration.
func TestForeignWritersReportsOnlyOurOwnTable(t *testing.T) {
	const ours = DefaultProtocol
	for name, test := range map[string]struct {
		table   uint32
		ownVRF  bool
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
		// The connected routes of the links enslaved to the VRF this reconciler
		// is configured with, present on every node of that profile.
		"kernel routes in our own vrf's table are the kernel's own": {
			table:   200,
			ownVRF:  true,
			replies: []nlMessage{routeReply(200, unix.RTPROT_KERNEL, unix.RTN_UNICAST)},
		},
		// Another VRF bound to this table put them there, and an install must
		// not share its keys with it.
		"kernel routes in another vrf's table belong to somebody": {
			table:   200,
			replies: []nlMessage{routeReply(200, unix.RTPROT_KERNEL, unix.RTN_UNICAST)},
			want:    []uint8{unix.RTPROT_KERNEL},
		},
		// Only the kernel's entries are excused in our own VRF's table.
		"another daemon in our own vrf's table is still reported": {
			table:   200,
			ownVRF:  true,
			replies: []nlMessage{routeReply(200, unix.RTPROT_BIRD, unix.RTN_UNICAST)},
			want:    []uint8{unix.RTPROT_BIRD},
		},
	} {
		t.Run(name, func(t *testing.T) {
			seen := map[uint8]bool{}
			collectForeignWriters(test.replies, test.table, ours, test.ownVRF, seen)
			got := slices.Sorted(maps.Keys(seen))
			if !slices.Equal(got, test.want) {
				t.Errorf("reported %v, want %v", got, test.want)
			}
		})
	}
}

// linkReply builds one RTM_NEWLINK of a given kind whose IFLA_INFO_DATA opens
// with a 32-bit attribute 1, nested the way EnsureVRF writes a VRF and the
// kernel reports it back. For a VRF that attribute is IFLA_VRF_TABLE; for
// vxlan the same number and width carry the VNI.
func linkReply(kind string, value uint32) nlMessage {
	info := putAttrString(nil, unix.IFLA_INFO_KIND, kind)
	info = putAttr(info, unix.IFLA_INFO_DATA, putAttrU32(nil, unix.IFLA_VRF_TABLE, value))
	body := putAttr(make([]byte, unix.SizeofIfInfomsg), unix.IFLA_LINKINFO, info)
	return nlMessage{Kind: unix.RTM_NEWLINK, Data: body}
}

// The binding sits two levels down, and only a VRF has one. A vxlan device
// carries its VNI under the same attribute number and width, so a parser that
// skipped the kind check would read VNI 200 as a VRF bound to table 200.
func TestLinkVRFTableReadsTheNestedBinding(t *testing.T) {
	if table, ok := linkVRFTable(linkReply("vrf", 200)); !ok || table != 200 {
		t.Errorf("a vrf bound to 200 read as %d, %v", table, ok)
	}
	if table, ok := linkVRFTable(linkReply("vrf", 51820)); !ok || table != 51820 {
		t.Errorf("a vrf bound to 51820 read as %d, %v", table, ok)
	}
	if table, ok := linkVRFTable(linkReply("vxlan", 200)); ok {
		t.Errorf("a vxlan device with VNI 200 read as a vrf bound to %d", table)
	}
	bare := nlMessage{Kind: unix.RTM_NEWLINK, Data: make([]byte, unix.SizeofIfInfomsg)}
	if _, ok := linkVRFTable(bare); ok {
		t.Error("a link with no linkinfo read as a vrf")
	}
}
