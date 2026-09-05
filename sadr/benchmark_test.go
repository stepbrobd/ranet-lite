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
