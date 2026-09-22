//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"maps"
	"slices"
	"testing"

	"github.com/NickCao/ranet-lite/schema"
	"golang.org/x/sys/unix"
)

// ruleAttrs reads back the attributes of a rule message the backend wrote, so
// a test asserts on what reaches the kernel rather than on the struct it came
// from.
func ruleAttrs(t *testing.T, body []byte) (hdr []byte, attrs map[uint16][]byte) {
	t.Helper()
	if len(body) < sizeofFibRuleHdr {
		t.Fatalf("a rule message is %d bytes, shorter than its header", len(body))
	}
	message := nlMessage{Data: body}
	attrs = maps.Collect(message.attributes(sizeofFibRuleHdr))
	return body[:sizeofFibRuleHdr], attrs
}

// Every rule carries the reconciler's protocol, the table goes in FRA_TABLE
// rather than in the header's one byte, and the action is the only one this
// backend writes. The first is the ownership marker, the second is how a table
// above 255 reaches the kernel at all, and the third keeps a mistaken rule a
// lookup in the wrong table rather than a black hole.
func TestRuleMessageCarriesTheOwnershipMarker(t *testing.T) {
	plat, _ := writePlatform(t)
	rule := Rule{Family: FamilyIPv6, From: schema.MustPrefix("3fff:a::/36"), Table: 200, Priority: 150}
	hdr, attrs := ruleAttrs(t, plat.ruleMessage(rule))

	if hdr[0] != afInet6 {
		t.Errorf("family byte is %d", hdr[0])
	}
	if hdr[2] != 36 {
		t.Errorf("src_len is %d, want the source prefix length", hdr[2])
	}
	if hdr[4] != 0 {
		t.Errorf("the legacy table byte is %d, want RT_TABLE_UNSPEC so FRA_TABLE decides", hdr[4])
	}
	if hdr[7] != unix.FR_ACT_TO_TBL {
		t.Errorf("action is %d, want the only one this backend writes", hdr[7])
	}
	protocol, ok := attrs[unix.FRA_PROTOCOL]
	if !ok || len(protocol) != 1 || protocol[0] != DefaultProtocol {
		t.Errorf("FRA_PROTOCOL is %v, want the reconciler's own protocol", protocol)
	}
	if table := attrs[unix.FRA_TABLE]; len(table) != 4 || binary.NativeEndian.Uint32(table) != 200 {
		t.Errorf("FRA_TABLE is %v", table)
	}
	if priority := attrs[unix.FRA_PRIORITY]; len(priority) != 4 || binary.NativeEndian.Uint32(priority) != 150 {
		t.Errorf("FRA_PRIORITY is %v", priority)
	}
	if _, ok := attrs[unix.FRA_DST]; ok {
		t.Error("a rule with no destination carried FRA_DST")
	}
}

// A mark rule names no address, so the family comes from the rule rather than
// from a prefix, and the mask is sent only when there is one.
func TestRuleMessageCarriesTheMarkAndItsMask(t *testing.T) {
	plat, _ := writePlatform(t)
	_, attrs := ruleAttrs(t, plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x726c, Table: 254, Priority: 40}))
	if mark := attrs[unix.FRA_FWMARK]; len(mark) != 4 || binary.NativeEndian.Uint32(mark) != 0x726c {
		t.Errorf("FRA_FWMARK is %v", mark)
	}
	if _, ok := attrs[unix.FRA_FWMASK]; ok {
		t.Error("a rule with no mask carried FRA_FWMASK, which the kernel reads as an exact match anyway")
	}

	_, attrs = ruleAttrs(t, plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x726c, FWMask: 0xffff, Table: 254, Priority: 40}))
	if mask := attrs[unix.FRA_FWMASK]; len(mask) != 4 || binary.NativeEndian.Uint32(mask) != 0xffff {
		t.Errorf("FRA_FWMASK is %v", mask)
	}
}

// What the backend writes has to read back as the same value, or the diff
// installs a duplicate on every pass and the rule list grows without bound.
func TestRuleRoundTripsThroughItsOwnEncoding(t *testing.T) {
	plat, conn := writePlatform(t)
	for name, rule := range map[string]Rule{
		"a destination rule": {Family: FamilyIPv4, To: schema.MustPrefix("198.18.104.0/24"), Table: 200, Priority: 100},
		"a source rule":      {Family: FamilyIPv6, From: schema.MustPrefix("3fff:1:69c::/48"), Table: 200, Priority: 150},
		"a mark rule":        {Family: FamilyIPv6, FWMark: 0x726c, Table: 254, Priority: 40},
		"both selectors":     {Family: FamilyIPv4, To: schema.MustPrefix("10.0.0.0/8"), From: schema.MustPrefix("10.1.0.0/16"), Table: 7, Priority: 90},
	} {
		t.Run(name, func(t *testing.T) {
			conn.replies = []nlMessage{{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(rule)}}
			got, err := plat.Rules()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("the dump read back %v, want the one rule that was written", got)
			}
			if got[0] != rule {
				t.Errorf("read back %s, want %s", got[0], rule)
			}
		})
	}
}

// The kernel reports an absent FRA_FWMASK as a mask of all ones, so the two
// spellings have to compare equal or every pass deletes and reinstalls the
// same rule.
func TestExactMarkReadsBackAsTheRuleThatWasWritten(t *testing.T) {
	plat, conn := writePlatform(t)
	rule := Rule{Family: FamilyIPv4, FWMark: 0x726c, Table: 254, Priority: 40}
	body := plat.ruleMessage(rule)
	body = putAttrU32(body, unix.FRA_FWMASK, ^uint32(0))
	conn.replies = []nlMessage{{Kind: unix.RTM_NEWRULE, Data: body}}
	got, err := plat.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != rule {
		t.Fatalf("read back %v, want %s", got, rule)
	}
}

// A dump holds every rule on the box. Anything without this reconciler's
// protocol, and anything whose action is not the one this backend writes, is
// somebody else's: a delete list that contained one would be a delete list
// that takes the machine's own routing apart.
func TestRuleDumpKeepsOnlyWhatThisReconcilerOwns(t *testing.T) {
	plat, conn := writePlatform(t)
	ours := Rule{Family: FamilyIPv6, From: schema.MustPrefix("2001:db8::/32"), Table: 200, Priority: 150}

	other := plat.ruleMessage(Rule{Family: FamilyIPv4, To: schema.MustPrefix("10.0.0.0/8"), Table: 200, Priority: 100})
	// networkd stamps RTPROT_STATIC on the rules it installs, so this is the
	// marker the fleet's own rules carry today.
	other = replaceProtocol(t, other, unix.RTPROT_STATIC)

	blackhole := plat.ruleMessage(Rule{Family: FamilyIPv4, To: schema.MustPrefix("10.0.0.0/8"), Table: 200, Priority: 101})
	blackhole[7] = unix.FR_ACT_BLACKHOLE

	unmarked := plat.ruleMessage(Rule{Family: FamilyIPv4, To: schema.MustPrefix("192.0.2.0/24"), Table: 200, Priority: 102})
	unmarked = stripProtocol(t, unmarked)

	conn.replies = []nlMessage{
		{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(ours)},
		{Kind: unix.RTM_NEWRULE, Data: other},
		{Kind: unix.RTM_NEWRULE, Data: blackhole},
		{Kind: unix.RTM_NEWRULE, Data: unmarked},
	}
	got, err := plat.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []Rule{ours}) {
		t.Fatalf("the dump kept %v, want only this reconciler's own rule", got)
	}
}

// replaceProtocol and stripProtocol rewrite one attribute of an encoded rule,
// so a test can build the messages another writer would have produced without
// a second encoder to keep in step with the first.
func replaceProtocol(t *testing.T, body []byte, protocol uint8) []byte {
	t.Helper()
	out := rebuildRule(t, body, func(kind uint16, value []byte) ([]byte, bool) {
		if kind == unix.FRA_PROTOCOL {
			return []byte{protocol}, true
		}
		return value, true
	})
	return out
}

func stripProtocol(t *testing.T, body []byte) []byte {
	t.Helper()
	return rebuildRule(t, body, func(kind uint16, value []byte) ([]byte, bool) {
		return value, kind != unix.FRA_PROTOCOL
	})
}

func rebuildRule(t *testing.T, body []byte, edit func(uint16, []byte) ([]byte, bool)) []byte {
	t.Helper()
	out := slices.Clone(body[:sizeofFibRuleHdr])
	message := nlMessage{Data: body}
	for kind, value := range message.attributes(sizeofFibRuleHdr) {
		replacement, keep := edit(kind, value)
		if keep {
			out = putAttr(out, kind, replacement)
		}
	}
	return out
}
