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
