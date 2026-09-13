package sadr

import (
	"fmt"
	"net/netip"
	"testing"
)

func benchmarkPrefixes(count int) ([]netip.Prefix, []netip.Addr) {
	prefixes := make([]netip.Prefix, count)
	addresses := make([]netip.Addr, count)
	for i := range prefixes {
		ip := [16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 8), byte(i)}
		prefixes[i] = netip.PrefixFrom(netip.AddrFrom16(ip), 64)
		ip[15] = 1
		addresses[i] = netip.AddrFrom16(ip)
	}
	return prefixes, addresses
}

func BenchmarkLookup(b *testing.B) {
	for _, count := range []int{16, 1024, 16384} {
		b.Run(fmt.Sprintf("routes=%d", count), func(b *testing.B) {
			var table Table[int]
			prefixes, addresses := benchmarkPrefixes(count)
			for i, p := range prefixes {
				table.Set(netip.Prefix{}, p, i)
			}
			source := netip.MustParseAddr("fd00::1")
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					if got, ok := table.Lookup(source, addresses[i]); !ok || got != i {
						b.Errorf("lookup = %d, %v; want %d", got, ok, i)
						return
					}
					i = (i + 1) % count
				}
			})
		})
	}
}

func BenchmarkRouteChange(b *testing.B) {
	var table Table[int]
	prefixes, _ := benchmarkPrefixes(1024)
	for i, p := range prefixes {
		table.Set(netip.Prefix{}, p, i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table.Set(netip.Prefix{}, prefixes[i%len(prefixes)], i)
	}
}

// One packet's classification runs inline on every TUN reader, and the number
// of source prefixes on one destination is a number a neighbor chooses: babel
// holds one entry per source and destination pair and nothing makes the
// destinations distinct, so a single short prefix can carry a neighbor's whole
// share. The cost of a lookup must not follow that number.
func BenchmarkLookupBySourceCount(b *testing.B) {
	dst := netip.MustParsePrefix("fd00::/16")
	source := netip.MustParseAddr("fd7f:ffff::1")
	target := netip.MustParseAddr("fd00::1")
	for _, sources := range []int{1, 64, 1024, 16384} {
		b.Run(fmt.Sprint(sources), func(b *testing.B) {
			var table Table[int]
			for i := range sources {
				// Distinct /48s under a common /16, none of which contains the
				// source looked up, plus the match-all entry that answers it.
				src := netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0,
					byte(i >> 8), byte(i), byte(i >> 16)}), 48)
				table.Set(src, dst, i+1)
			}
			table.Set(netip.Prefix{}, dst, 0)
			if got, ok := table.Lookup(source, target); !ok || got != 0 {
				b.Fatalf("the lookup answered %v, %v, so it is not reaching the match-all entry", got, ok)
			}
			b.ResetTimer()
			for b.Loop() {
				table.Lookup(source, target)
			}
		})
	}
}

// The shape the index is not for: many sources spread thinly over many
// distinct prefix lengths, none of them matching. A map probe costs about
// twice what Prefix.Contains does, so an index over one-entry groups is slower
// than the scan, and indexSrcs declines to build one.
func BenchmarkLookupByDistinctLengths(b *testing.B) {
	dst := netip.MustParsePrefix("fd00::/16")
	source := netip.MustParseAddr("fd7f:ffff::1")
	target := netip.MustParseAddr("fd00::1")
	for _, lengths := range []int{1, 16, 128} {
		b.Run(fmt.Sprint(lengths), func(b *testing.B) {
			var table Table[int]
			for i := range lengths {
				// One source at each of `lengths` distinct prefix lengths,
				// none containing the source looked up.
				bits := 17 + i
				table.Set(netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0, byte(i)}), bits).Masked(), dst, i+1)
			}
			table.Set(netip.Prefix{}, dst, 0)
			if got, ok := table.Lookup(source, target); !ok || got != 0 {
				b.Fatalf("the lookup answered %v, %v", got, ok)
			}
			b.ResetTimer()
			for b.Loop() {
				table.Lookup(source, target)
			}
		})
	}
}

// The edit path is what pays for the index, and the shape the index exists for
// is the one a neighbor can force: a whole share of sources on one short
// destination prefix.
func BenchmarkRouteChangeOnOneDestination(b *testing.B) {
	dst := netip.MustParsePrefix("fd00::/16")
	for _, sources := range []int{64, 1024, 16384} {
		b.Run(fmt.Sprint(sources), func(b *testing.B) {
			var table Table[int]
			for i := range sources {
				table.Set(netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0,
					byte(i >> 8), byte(i), byte(i >> 16)}), 48), dst, i+1)
			}
			churn := netip.MustParsePrefix("fd00:ffff::/48")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				table.Set(churn, dst, i)
			}
		})
	}
}

// Filling one destination through the public API, the way
// routeTable.selectRoute does it, one route at a time, under the babel speaker
// lock. The per-edit benchmark above measures one Set against a table that is
// already full; this measures the n of them it takes to get there, which is
// the number a neighbor actually drives and the one that was quadratic in map
// operations until the index stopped being rebuilt on every edit.
func BenchmarkFillOneDestination(b *testing.B) {
	dst := netip.MustParsePrefix("2001:db8::/32")
	for _, sources := range []int{128, 1024, 4096} {
		for _, shape := range []string{"one length", "many lengths"} {
			b.Run(fmt.Sprintf("%s/%d", shape, sources), func(b *testing.B) {
				srcs := make([]netip.Prefix, sources)
				for i := range srcs {
					addr := netip.AddrFrom16([16]byte{0x20, 0x02, byte(i >> 8), byte(i), byte(i >> 16)})
					bits := 64
					if shape == "many lengths" {
						bits = 17 + i%112
					}
					srcs[i] = netip.PrefixFrom(addr, bits).Masked()
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					var table Table[int]
					for i, src := range srcs {
						table.Set(src, dst, i)
					}
				}
			})
		}
	}
}

// A lookup walks every destination node on the path, and pays that node's
// source cost at each one. Both the depth and the sources are chosen by a
// neighbor, so this is the product rather than either figure alone, and it is
// inline on the TUN reader. The per-node figures beside byLen are for one
// node; this is the cost of one packet.
func BenchmarkLookupDownADestinationChain(b *testing.B) {
	for _, depth := range []int{1, 8, 32} {
		for _, shape := range []string{"one length", "many lengths"} {
			b.Run(fmt.Sprintf("%s/depth=%d", shape, depth), func(b *testing.B) {
				var table Table[int]
				const perNode = 448
				for d := range depth {
					dst := netip.PrefixFrom(netip.MustParseAddr("2001:db8::"), 32+d*2).Masked()
					for i := range perNode {
						addr := netip.AddrFrom16([16]byte{0x20, 0x02, byte(i >> 8), byte(i), byte(d)})
						bits := 64
						if shape == "many lengths" {
							bits = 17 + i%112
						}
						table.Set(netip.PrefixFrom(addr, bits).Masked(), dst, d*perNode+i+1)
					}
					// The match-all entry at the deepest node, so the walk
					// reaches the bottom and every node above it is probed.
					table.Set(netip.Prefix{}, dst, -d-1)
				}
				source := netip.MustParseAddr("2001:db8:1::1")
				target := netip.MustParseAddr("2001:db8::1")
				table.Lookup(source, target)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					table.Lookup(source, target)
				}
			})
		}
	}
}
