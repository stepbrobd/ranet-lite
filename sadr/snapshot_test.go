package sadr

import (
	"math/rand/v2"
	"net/netip"
	"sync"
	"testing"
)

func TestCanonicalPrefixesAndSnapshotIsolation(t *testing.T) {
	var table Table[int]
	src, dst := prefix("192.0.2.123/24"), prefix("10.2.3.4/16")
	table.Set(src, dst, 1)
	snapshot := table.All()
	table.Set(src.Masked(), dst.Masked(), 2)
	for entry := range snapshot {
		if entry.Value != 1 || entry.Source != src.Masked() || entry.Destination != dst.Masked() {
			t.Fatalf("snapshot changed after update: %+v", entry)
		}
	}
	count := 0
	for entry := range table.All() {
		count++
		if entry.Value != 2 {
			t.Fatalf("canonical update did not replace route: %+v", entry)
		}
		table.Remove(src, dst) // iteration must not retain the writer lock
	}
	if count != 1 {
		t.Fatalf("canonical update left %d entries", count)
	}
	if _, ok := table.Lookup(addr("192.0.2.1"), addr("10.2.0.1")); ok {
		t.Fatal("unmasked removal did not remove the canonical entry")
	}
}

func TestInvalidTableInputs(t *testing.T) {
	var table Table[int]
	table.Set(netip.Prefix{}, netip.Prefix{}, 1)
	table.Remove(netip.Prefix{}, netip.Prefix{})
	table.Set(prefix("192.0.2.0/24"), prefix("2001:db8::/32"), 2)
	table.Set(netip.Prefix{}, prefix("::/0"), 3)
	if _, ok := table.Lookup(netip.Addr{}, netip.Addr{}); ok {
		t.Fatal("invalid destination matched a route")
	}
	count := 0
	for range table.All() {
		count++
	}
	if count != 1 {
		t.Fatalf("invalid insertions left %d entries", count)
	}
}

// Compare the trie against an independent linear route table through random
// insertions, replacements, removals, peer removal, and overlapping SADR keys.
func TestTableAgainstLinearModel(t *testing.T) {
	for _, ipv4 := range []bool{true, false} {
		var table Table[int]
		type key struct{ src, dst netip.Prefix }
		model := make(map[key]int)
		rng := rand.New(rand.NewPCG(123, 456))
		randomAddr := func() netip.Addr {
			if ipv4 {
				return netip.AddrFrom4([4]byte{10, byte(rng.UintN(16)), byte(rng.UintN(256)), byte(rng.UintN(256))})
			}
			return netip.AddrFrom16([16]byte{0xfd, byte(rng.UintN(16)), byte(rng.UintN(256)), byte(rng.UintN(256))})
		}
		keys := make([]key, 256)
		for i := range keys {
			dst := randomAddr()
			keys[i].dst = netip.PrefixFrom(dst, rng.IntN(dst.BitLen()+1)).Masked()
			if i%3 != 0 {
				src := randomAddr()
				keys[i].src = netip.PrefixFrom(src, rng.IntN(src.BitLen()+1)).Masked()
			}
		}
		for step := range 3000 {
			k, value := keys[rng.IntN(len(keys))], rng.IntN(16)
			switch rng.IntN(10) {
			case 0:
				table.RemoveValue(value)
				for k, v := range model {
					if v == value {
						delete(model, k)
					}
				}
			case 1, 2, 3:
				table.Remove(k.src, k.dst)
				delete(model, k)
			default:
				table.Set(k.src, k.dst, value)
				model[k] = value
			}
			for range 10 {
				src, dst := randomAddr(), randomAddr()
				bestDest, bestSource, want, found := -2, -2, 0, false
				for k, value := range model {
					if !k.dst.Contains(dst) || (k.src.IsValid() && !k.src.Contains(src)) {
						continue
					}
					if k.dst.Bits() > bestDest || (k.dst.Bits() == bestDest && k.src.Bits() > bestSource) {
						bestDest, bestSource, want, found = k.dst.Bits(), k.src.Bits(), value, true
					}
				}
				if got, ok := table.Lookup(src, dst); got != want || ok != found {
					t.Fatalf("step %d: %s -> %s = %d, %v; model = %d, %v", step, src, dst, got, ok, want, found)
				}
			}
			if step%100 == 0 {
				count := 0
				for entry := range table.All() {
					value, ok := model[key{entry.Source, entry.Destination}]
					if !ok || value != entry.Value {
						t.Fatalf("iteration disagrees with model: %+v", entry)
					}
					count++
				}
				if count != len(model) {
					t.Fatalf("iteration has %d entries, model has %d", count, len(model))
				}
			}
		}
	}
}

func TestConcurrentReadersAndWriters(t *testing.T) {
	var table Table[int]
	dst := prefix("2001:db8::/32")
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for i := range 1000 {
				table.Set(netip.Prefix{}, dst, i)
				table.Lookup(addr("fd00::1"), addr("2001:db8::1"))
				for entry := range table.All() {
					if entry.Destination != dst {
						t.Errorf("corrupt snapshot: %+v", entry)
					}
				}
				table.RemoveValue(i)
			}
		})
	}
	wg.Wait()
}

// The per-length index is built on the first lookup that reads it, so the
// build races every other lookup of the same node, and an edit publishes a new
// node whose index is unbuilt again. The test above never reaches it: its only
// source matches everything, and indexSrcs declines to index that. This one
// holds enough sources at one length to be indexed, and churns them while
// readers look up.
func TestConcurrentLookupsBuildTheIndexOnce(t *testing.T) {
	var table Table[int]
	dst := prefix("2001:db8::/32")
	const sources = 64
	for i := range sources {
		table.Set(netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0, byte(i >> 8), byte(i)}), 64).Masked(), dst, i+1)
	}
	// Inside the prefix built for i == 1, which is fd00:1::/64.
	source, target := addr("fd00:1::5"), addr("2001:db8::1")

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 500 {
				table.Lookup(source, target)
			}
		})
	}
	for range 2 {
		wg.Go(func() {
			for i := range 200 {
				table.Set(netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0, 0xff, byte(i)}), 64).Masked(), dst, i)
			}
		})
	}
	wg.Wait()

	// Every source is still reachable: a lookup that raced a build must not
	// have seen a half-built index.
	if got, ok := table.Lookup(source, target); !ok || got == 0 {
		t.Errorf("lookup after the churn returned %v, %v", got, ok)
	}
}
