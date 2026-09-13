package sadr

import (
	"net/netip"
	"testing"
)

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }

func TestTableLPMAndSADRSelection(t *testing.T) {
	var table Table[string]
	table.Set(netip.Prefix{}, prefix("2001:db8::/32"), "broad")
	table.Set(prefix("2001:db8:1::/48"), prefix("2001:db8::/32"), "source-specific")
	table.Set(netip.Prefix{}, prefix("2001:db8::/48"), "narrow")

	if got, ok := table.Lookup(addr("2001:db8:1::1"), addr("2001:db8::1")); !ok || got != "narrow" {
		t.Fatalf("got %q, %v; want narrow, true", got, ok)
	}
	if got, ok := table.Lookup(addr("2001:db8:1::1"), addr("2001:db8:2::1")); !ok || got != "source-specific" {
		t.Fatalf("got %q, %v; want source-specific, true", got, ok)
	}
	if got, ok := table.Lookup(addr("2001:db8:3::1"), addr("2001:db8:2::1")); !ok || got != "broad" {
		t.Fatalf("got %q, %v; want broad, true", got, ok)
	}
}

func TestTableRemoveValue(t *testing.T) {
	var table Table[string]
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), "remove")
	table.Set(prefix("192.0.2.0/24"), prefix("10.1.0.0/16"), "remove")
	table.Set(netip.Prefix{}, prefix("10.2.0.0/16"), "keep")

	table.RemoveValue("remove")
	if _, ok := table.Lookup(addr("192.0.2.1"), addr("10.1.0.1")); ok {
		t.Fatal("removed value still resolves")
	}
	if got, ok := table.Lookup(addr("192.0.2.1"), addr("10.2.0.1")); !ok || got != "keep" {
		t.Fatalf("got %q, %v; want keep, true", got, ok)
	}
}

func TestTableIPv4AndIPv6(t *testing.T) {
	var table Table[int]
	table.Set(netip.Prefix{}, prefix("192.0.2.0/24"), 4)
	table.Set(netip.Prefix{}, prefix("2001:db8::/32"), 6)

	if got, ok := table.Lookup(addr("198.51.100.1"), addr("192.0.2.1")); !ok || got != 4 {
		t.Fatalf("IPv4 lookup got %d, %v; want 4, true", got, ok)
	}
	if got, ok := table.Lookup(addr("2001:db8::2"), addr("2001:db8::1")); !ok || got != 6 {
		t.Fatalf("IPv6 lookup got %d, %v; want 6, true", got, ok)
	}
	if _, ok := table.Lookup(addr("198.51.100.1"), addr("2001:db9::1")); ok {
		t.Fatal("unexpected cross-family route")
	}
}

func TestTableFallsBackPastInapplicableDestination(t *testing.T) {
	var table Table[string]
	table.Set(netip.Prefix{}, prefix("2001:db8::/32"), "fallback")
	table.Set(prefix("fd00:1::/64"), prefix("2001:db8:1::/64"), "specific")

	if got, ok := table.Lookup(addr("fd00:2::1"), addr("2001:db8:1::1")); !ok || got != "fallback" {
		t.Fatalf("got %q, %v; want fallback, true", got, ok)
	}
	if got, ok := table.Lookup(addr("fd00:1::1"), addr("2001:db8:1::1")); !ok || got != "specific" {
		t.Fatalf("got %q, %v; want specific, true", got, ok)
	}
}

// The index is one map per distinct source prefix length, not one per entry.
// That is the whole basis of the bound: a lookup costs a map lookup per
// length, which the address width caps at 129 however many sources one
// destination carries. A group per entry is the linear scan again, with the
// map overhead on top.
func TestSourcesAreGroupedByLengthNotByEntry(t *testing.T) {
	var table Table[int]
	dst := prefix("fd00::/16")
	for i := range 64 {
		table.Set(netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0, byte(i)}), 48), dst, i+1)
	}
	table.Set(prefix("fd00:1::/32"), dst, 1000)
	table.Set(netip.Prefix{}, dst, 2000)

	root := table.roots.Load().ipv6
	if root == nil {
		t.Fatal("the table holds no IPv6 root")
	}
	node := root
	for node != nil && int(node.prefixLen) != dst.Bits() {
		node = node.child[0]
	}
	if node == nil {
		t.Fatalf("no node for %v", dst)
	}
	if got := len(node.byLen); got != 2 {
		t.Errorf("66 sources of two distinct lengths built %d groups, want 2", got)
	}
	if !node.haveAny {
		t.Error("the match-all source is not held apart from the groups")
	}
}
