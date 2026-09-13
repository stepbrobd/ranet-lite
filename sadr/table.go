// Package sadr implements source-address-dependent routing tables.
package sadr

import (
	"encoding/binary"
	"iter"
	"math/bits"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
)

// Table resolves destination first, over (source, destination) pairs: the
// longest destination that has an entry matching the source wins, so a lookup
// whose longest matching destination has no matching source falls back to a
// shorter destination that does, rather than failing. Its zero value is ready
// to use.
//
// Writers copy only the changed trie path and publish a new immutable root.
// Lookups and iteration use one snapshot without locks or shared counters.
type Table[V comparable] struct {
	mu    sync.Mutex
	roots atomic.Pointer[roots[V]]
}

type roots[V comparable] struct {
	ipv4 *trieNode[V]
	ipv6 *trieNode[V]
}

type srcEntry[V comparable] struct {
	src   netip.Prefix
	value V
}

type trieNode[V comparable] struct {
	// Only the first prefixLen bits of address are significant. IPv4 uses
	// its mapped 128-bit representation, with lengths from 96 through 128.
	address   [16]byte
	prefixLen uint8
	byteIndex uint8 // cached branch position; fits in the node's padding
	bitShift  uint8
	srcs      []srcEntry[V]
	// byLen is srcs as one map per distinct source prefix length, longest
	// first, and anySrc is the entry whose source matches everything. Both are
	// derived from srcs, which stays the record. A walk of srcs was linear in
	// a number a neighbor chooses -- babel holds one entry per source and
	// destination pair, up to maxSourcesPerNeighbor of them from one neighbor,
	// and nothing makes the destinations distinct, so one short prefix can
	// carry the lot -- and that walk is inline on every TUN reader. This makes
	// it one masked map lookup per distinct length, which the address width
	// bounds at 129 however many entries there are. Measured per lookup, with
	// every entry on one destination and the answer the match-all one, before
	// and after: 10.7 ns and 13.4 ns at one source, 84 us and 13.4 ns at
	// 16384. The edit path pays for the maps, 357 ns and 452 ns per route
	// change, which is a route install against a packet. See
	// BenchmarkLookupBySourceCount and BenchmarkRouteChange.
	byLen   []srcIndex[V]
	anySrc  V
	haveAny bool
	child   [2]*trieNode[V]
}

// srcIndex is every source prefix of one length at one destination node.
type srcIndex[V comparable] struct {
	bits uint8
	m    map[netip.Prefix]V
}

// indexSrcs derives byLen and anySrc. srcs is ordered longest first, so the
// groups come out in the same order and the first that answers is the longest
// match.
func indexSrcs[V comparable](srcs []srcEntry[V]) ([]srcIndex[V], V, bool) {
	var byLen []srcIndex[V]
	var anySrc V
	haveAny := false
	for _, entry := range srcs {
		if !entry.src.IsValid() {
			anySrc, haveAny = entry.value, true
			continue
		}
		bits := uint8(entry.src.Bits())
		if len(byLen) == 0 || byLen[len(byLen)-1].bits != bits {
			byLen = append(byLen, srcIndex[V]{bits: bits, m: make(map[netip.Prefix]V, 1)})
		}
		byLen[len(byLen)-1].m[entry.src] = entry.value
	}
	return byLen, anySrc, haveAny
}

// Route is one canonical source/destination entry. An invalid Source matches
// every source address.
type Route[V comparable] struct {
	Source      netip.Prefix
	Destination netip.Prefix
	Value       V
}

func branch(address [16]byte, bit uint8) int {
	return int(address[bit/8] >> (7 - bit%8) & 1)
}

func newTrieNode[V comparable](address [16]byte, prefixLen uint8, srcs []srcEntry[V]) *trieNode[V] {
	n := &trieNode[V]{address: address, prefixLen: prefixLen,
		byteIndex: prefixLen / 8, bitShift: 7 - prefixLen%8}
	n.setSrcs(srcs)
	return n
}

// setSrcs replaces a node's sources and the index derived from them. Nodes are
// copied rather than mutated once published, so this only ever runs on a node
// the caller still owns.
func (n *trieNode[V]) setSrcs(srcs []srcEntry[V]) {
	n.srcs = srcs
	n.byLen, n.anySrc, n.haveAny = indexSrcs(srcs)
}

func commonBits(a, b [16]byte) uint8 {
	common := bits.LeadingZeros64(binary.BigEndian.Uint64(a[:8]) ^ binary.BigEndian.Uint64(b[:8]))
	if common == 64 {
		common += bits.LeadingZeros64(binary.BigEndian.Uint64(a[8:]) ^ binary.BigEndian.Uint64(b[8:]))
	}
	return uint8(common)
}

// Lookup needs only a prefix comparison, not the full common-prefix length
// used by insertion. Convert the packet address to words once per lookup.
func (n *trieNode[V]) matches(hi, lo uint64) bool {
	highDiff := binary.BigEndian.Uint64(n.address[:8]) ^ hi
	if n.prefixLen <= 64 {
		return highDiff>>(64-n.prefixLen) == 0
	}
	return highDiff == 0 && (binary.BigEndian.Uint64(n.address[8:])^lo)>>(128-n.prefixLen) == 0
}

// edit returns a new path; published nodes and source slices are never mutated.
func edit[V comparable](n *trieNode[V], address [16]byte, prefixLen uint8, change func([]srcEntry[V]) []srcEntry[V]) *trieNode[V] {
	if n == nil {
		srcs := change(nil)
		if len(srcs) == 0 {
			return nil
		}
		return newTrieNode(address, prefixLen, srcs)
	}
	common := min(commonBits(n.address, address), n.prefixLen, prefixLen)
	if common < n.prefixLen {
		srcs := change(nil)
		if len(srcs) == 0 {
			return n // removing an absent destination
		}
		parent := newTrieNode[V](address, common, nil)
		parent.child[branch(n.address, common)] = n
		if common == prefixLen {
			parent.setSrcs(srcs)
		} else {
			parent.child[branch(address, common)] = newTrieNode(address, prefixLen, srcs)
		}
		return parent
	}
	copy := *n
	if n.prefixLen == prefixLen {
		copy.setSrcs(change(n.srcs))
	} else {
		bit := branch(address, n.prefixLen)
		copy.child[bit] = edit(n.child[bit], address, prefixLen, change)
	}
	return compact(&copy)
}

func compact[V comparable](n *trieNode[V]) *trieNode[V] {
	if len(n.srcs) == 0 {
		if n.child[0] == nil {
			return n.child[1]
		}
		if n.child[1] == nil {
			return n.child[0]
		}
	}
	return n
}

func validPrefixes(src, dst netip.Prefix) bool {
	return dst.IsValid() && (!src.IsValid() || src.Addr().BitLen() == dst.Addr().BitLen())
}

func (t *Table[V]) change(src, dst netip.Prefix, fn func([]srcEntry[V]) []srcEntry[V]) {
	if !validPrefixes(src, dst) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var next roots[V]
	if current := t.roots.Load(); current != nil {
		next = *current
	}
	root := &next.ipv6
	prefixLen := uint8(dst.Bits())
	if dst.Addr().Is4() {
		root = &next.ipv4
		prefixLen += 96
	}
	*root = edit(*root, dst.Addr().As16(), prefixLen, fn)
	t.roots.Store(&next)
}

// Set installs or replaces an entry. Prefixes are masked before comparison.
// Invalid destinations or source/destination family mismatches are ignored.
func (t *Table[V]) Set(src, dst netip.Prefix, value V) {
	src = src.Masked()
	t.change(src, dst, func(entries []srcEntry[V]) []srcEntry[V] {
		next := slices.Clone(entries)
		for i := range next {
			if next[i].src == src {
				next[i].value = value
				return next
			}
		}
		// Inserted in order rather than appended: srcs is sorted by prefix
		// length, longest first, which is what lets Lookup stop at the first
		// entry that contains the source instead of scoring every one of
		// them. An invalid source matches everything and has Bits() -1, so
		// the same rule puts it last. Remove and removeValue keep the order
		// by construction.
		at, _ := slices.BinarySearchFunc(next, src, func(entry srcEntry[V], want netip.Prefix) int {
			return want.Bits() - entry.src.Bits()
		})
		return slices.Insert(next, at, srcEntry[V]{src: src, value: value})
	})
}

// Remove deletes an entry, accepting canonical or unmasked prefixes.
func (t *Table[V]) Remove(src, dst netip.Prefix) {
	src = src.Masked()
	t.change(src, dst, func(entries []srcEntry[V]) []srcEntry[V] {
		for i, entry := range entries {
			if entry.src == src {
				next := make([]srcEntry[V], 0, len(entries)-1)
				next = append(next, entries[:i]...)
				return append(next, entries[i+1:]...)
			}
		}
		return entries
	})
}

// RemoveValue atomically removes all routes with the given value.
func (t *Table[V]) RemoveValue(value V) {
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.roots.Load()
	if current == nil {
		return
	}
	t.roots.Store(&roots[V]{
		ipv4: removeValue(current.ipv4, value),
		ipv6: removeValue(current.ipv6, value),
	})
}

func removeValue[V comparable](n *trieNode[V], value V) *trieNode[V] {
	if n == nil {
		return nil
	}
	left, right := removeValue(n.child[0], value), removeValue(n.child[1], value)
	match := slices.ContainsFunc(n.srcs, func(entry srcEntry[V]) bool { return entry.value == value })
	if !match && left == n.child[0] && right == n.child[1] {
		return n
	}
	copy := *n
	copy.child = [2]*trieNode[V]{left, right}
	if match {
		kept := make([]srcEntry[V], 0, len(n.srcs))
		for _, entry := range n.srcs {
			if entry.value != value {
				kept = append(kept, entry)
			}
		}
		copy.setSrcs(kept)
	}
	return compact(&copy)
}

func (t *Table[V]) Lookup(src, dst netip.Addr) (V, bool) {
	var result V
	current := t.roots.Load()
	if current == nil || !dst.IsValid() {
		return result, false
	}
	n := current.ipv6
	if dst.Is4() {
		n = current.ipv4
	}
	found := false
	address := dst.As16()
	hi, lo := binary.BigEndian.Uint64(address[:8]), binary.BigEndian.Uint64(address[8:])
	for n != nil && n.matches(hi, lo) {
		// One masked map lookup per distinct source prefix length, longest
		// first, so the first that answers is the longest match and the rest
		// cannot beat it. See trieNode.byLen for what walking every entry
		// instead cost. A deeper node still overwrites this, which is
		// destination specificity beating source specificity, as before.
		matched := false
		for _, group := range n.byLen {
			if value, ok := group.m[netip.PrefixFrom(src, int(group.bits)).Masked()]; ok {
				result, found, matched = value, true, true
				break
			}
		}
		if !matched && n.haveAny {
			result, found = n.anySrc, true
		}
		if n.prefixLen == 128 {
			break
		}
		n = n.child[(address[n.byteIndex]>>n.bitShift)&1]
	}
	return result, found
}

// All captures a consistent snapshot at the call. The caller may modify the
// table while iterating; those modifications do not change the snapshot.
func (t *Table[V]) All() iter.Seq[Route[V]] {
	snapshot := t.roots.Load()
	return func(yield func(Route[V]) bool) {
		if snapshot == nil {
			return
		}
		var walk func(*trieNode[V], bool) bool
		walk = func(n *trieNode[V], ipv4 bool) bool {
			if n == nil {
				return true
			}
			address, prefixLen := netip.AddrFrom16(n.address), int(n.prefixLen)
			if ipv4 {
				address, prefixLen = address.Unmap(), prefixLen-96
			}
			prefix := netip.PrefixFrom(address, prefixLen).Masked()
			for _, entry := range n.srcs {
				if !yield(Route[V]{Source: entry.src, Destination: prefix, Value: entry.value}) {
					return false
				}
			}
			return walk(n.child[0], ipv4) && walk(n.child[1], ipv4)
		}
		if walk(snapshot.ipv4, true) {
			walk(snapshot.ipv6, false)
		}
	}
}
