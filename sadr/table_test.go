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
	if got := len(node.index()); got != 2 {
		t.Errorf("66 sources of two distinct lengths built %d groups, want 2", got)
	}
	if !node.haveAny {
		t.Error("the match-all source is not held apart from the groups")
	}
	// The same lookup BenchmarkLookupBySourceCount is built around, asserted
	// here because `go test` never runs a benchmark: a source no specific
	// entry contains falls through every group to the match-all one.
	if got, ok := table.Lookup(addr("fd7f:ffff::1"), addr("fd00::1")); !ok || got != 2000 {
		t.Errorf("a source no group contains looked up %v, %v, want the match-all entry", got, ok)
	}
	if got, ok := table.Lookup(addr("fd00:1::5"), addr("fd00::1")); !ok || got != 1000 {
		t.Errorf("a source one group contains looked up %v, %v, want the longest match", got, ok)
	}
}

// The index is built only where it pays. Many sources at one length is the
// shape a neighbor can force and the one the maps exist for; the same number
// spread one to a length is slower indexed than scanned, and the edit path
// would pay to build it either way.
func TestTheSourceIndexIsBuiltOnlyWhereItPays(t *testing.T) {
	dst := prefix("fd00::/16")
	nodeFor := func(table *Table[int]) *trieNode[int] {
		root := table.roots.Load().ipv6
		for node := root; node != nil; node = node.child[0] {
			if int(node.prefixLen) == dst.Bits() {
				return node
			}
		}
		t.Fatalf("no node for %v", dst)
		return nil
	}

	var grouped Table[int]
	for i := range 64 {
		grouped.Set(netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0, byte(i)}), 48), dst, i+1)
	}
	if got := len(nodeFor(&grouped).index()); got != 1 {
		t.Errorf("sixty-four sources at one length built %d groups, want the one map they belong in", got)
	}

	var spread Table[int]
	for i := range 64 {
		spread.Set(netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0, byte(i)}), 17+i).Masked(), dst, i+1)
	}
	if node := nodeFor(&spread); node.index() != nil {
		t.Errorf("sixty-four sources at sixty-four lengths built %d groups, which costs more to build and to read than the scan", len(node.index()))
	}
	// And the answer is the same either way, which the linear model
	// test covers across every shape; this is the pair that motivated it.
	spread.Set(netip.Prefix{}, dst, 999)
	if got, ok := spread.Lookup(addr("fd7f:ffff::1"), addr("fd00::1")); !ok || got != 999 {
		t.Errorf("the unindexed node answered %v, %v, want the match-all entry", got, ok)
	}
	node := nodeFor(&spread)
	for _, probe := range []netip.Addr{addr("fd00::1"), addr("fd00:400::1"), addr("fd7f::1")} {
		want, found := 0, false
		best := -1
		for _, entry := range node.srcs {
			if entry.src.IsValid() && entry.src.Contains(probe) && entry.src.Bits() > best {
				want, found, best = entry.value, true, entry.src.Bits()
			}
		}
		if !found {
			want, found = 999, true // the match-all entry
		}
		if got, ok := spread.Lookup(probe, addr("fd00::1")); !ok || got != want {
			t.Errorf("the unindexed node answered %v, %v for %v, want %v", got, ok, probe, want)
		}
	}
}
