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
	// bounds at 129 per destination node however many entries there are; a
	// packet pays that at every node on its path, not once.
	//
	// Measured per lookup on one node with every entry on one destination and
	// the answer the match-all one, scanning against indexed: 9.6 ns at one
	// source, 68 us against 13.6 ns at 16384 all at one length. indexSrcs
	// declines to build one where it would not pay, which is the other half of
	// the trade.
	//
	// Those are one node. A packet pays at every node on its path, and the
	// path is as deep as the destination prefixes a neighbor announces, so the
	// figure a forwarding decision actually costs is the product: 16.7 ns at
	// one node holding 448 sources at one length, 510 ns down a chain of 32
	// such nodes, and 1.7 us and 54 us for the same two with those 448 spread
	// over 112 lengths. The last is a shape a neighbor can build with the
	// source prefix sub-TLV of RFC 9079, and 54 us inline on the TUN reader is
	// about 18,000 forwarding decisions a second on one core. Bounding it
	// needs a different structure for the sources rather than a better
	// threshold, so it is measured here rather than claimed away. See
	// BenchmarkLookupBySourceCount, BenchmarkLookupByDistinctLengths,
	// BenchmarkLookupDownADestinationChain, BenchmarkRouteChangeOnOneDestination
	// and BenchmarkFillOneDestination.
	byLen     []srcIndex[V]
	indexOnce sync.Once
	anySrc    V
	haveAny   bool
	child     [2]*trieNode[V]
}

// srcIndex is every source prefix of one length at one destination node.
type srcIndex[V comparable] struct {
	bits uint8
	m    map[netip.Prefix]V
}

// indexThreshold is how many sources one length has to carry, on average,
// before maps beat scanning them. A map probe is about twice what
// Prefix.Contains costs, so an index over lengths that carry one prefix each
// is slower than the ordered scan it replaces -- measured at 471 ns against
// about 1.2 us for 128 sources at 128 distinct lengths -- and it is the edit
// path that pays to build it.
const indexThreshold = 4

// indexSrcs derives byLen and anySrc. srcs is ordered longest first, so the
// runs of one length are contiguous, the groups come out in the same order,
// and the first that answers is the longest match.
//
// It returns no index at all when one would not pay: few sources, or many
// spread thinly over many lengths, which is the shape where the scan wins on
// both the lookup and the rebuild. Lookup falls back to the ordered scan, so
// the answer is the same either way.
func indexSrcs[V comparable](srcs []srcEntry[V]) []srcIndex[V] {
	specific := 0
	runs := 0
	for i, entry := range srcs {
		if !entry.src.IsValid() {
			continue
		}
		specific++
		if i == 0 || srcs[i-1].src.Bits() != entry.src.Bits() {
			runs++
		}
	}
	if runs == 0 || specific < runs*indexThreshold {
		return nil
	}
	// Sized per run rather than grown from one, which is what made a rebuild
	// walk log2(n) growth rounds for every length it held.
	byLen := make([]srcIndex[V], 0, runs)
	for i := 0; i < len(srcs); {
		if !srcs[i].src.IsValid() {
			i++
			continue
		}
		bits := srcs[i].src.Bits()
		end := i
		for end < len(srcs) && srcs[end].src.IsValid() && srcs[end].src.Bits() == bits {
			end++
		}
		group := srcIndex[V]{bits: uint8(bits), m: make(map[netip.Prefix]V, end-i)}
		for _, entry := range srcs[i:end] {
			group.m[entry.src] = entry.value
		}
		byLen = append(byLen, group)
		i = end
	}
	return byLen
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

// setSrcs replaces a node's sources and the match-all entry derived from them.
// Nodes are copied rather than mutated once published, so this only ever runs
// on a node the caller still owns.
//
// The per-length index is deliberately not built here. Building it on every
// edit made filling one destination quadratic in map operations rather than in
// the slice copies the copy-on-write discipline already costs: each Set
// rebuilt every map from scratch, so n sources cost n rebuilds of up to n
// entries, measured at 267 ms and about a gigabyte of allocator traffic for
// 4096 sources on one destination, all of it under the babel speaker lock.
// The index is worth its cost to a lookup and nothing to an edit, so index
// builds it on the first lookup that needs it instead.
func (n *trieNode[V]) setSrcs(srcs []srcEntry[V]) {
	n.srcs = srcs
	n.anySrc, n.haveAny = matchAllSource(srcs)
}

// index is the per-length index, built once. A node is immutable from the
// moment it is published, so one build serves every lookup that ever reads it,
// and sync.Once makes concurrent readers agree on which build that is.
func (n *trieNode[V]) index() []srcIndex[V] {
	n.indexOnce.Do(func() { n.byLen = indexSrcs(n.srcs) })
	return n.byLen
}

// matchAllSource finds the entry whose source matches every address. srcs is
// ordered longest first and an invalid source has Bits() -1, so it is last,
// but the scan does not depend on that.
func matchAllSource[V comparable](srcs []srcEntry[V]) (anySrc V, haveAny bool) {
	for _, entry := range srcs {
		if !entry.src.IsValid() {
			return entry.value, true
		}
	}
	return anySrc, haveAny
}

// clone is a copy of the node with a fresh index. A plain value copy would
// carry the sync.Once with it, which vet refuses and which would leave the
// copy sharing the original's decision about whether the index is built.
func (n *trieNode[V]) clone() *trieNode[V] {
	return &trieNode[V]{
		address: n.address, prefixLen: n.prefixLen,
		byteIndex: n.byteIndex, bitShift: n.bitShift,
		srcs: n.srcs, anySrc: n.anySrc, haveAny: n.haveAny,
		child: n.child,
	}
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
	copy := n.clone()
	if n.prefixLen == prefixLen {
		copy.setSrcs(change(n.srcs))
	} else {
		bit := branch(address, n.prefixLen)
		copy.child[bit] = edit(n.child[bit], address, prefixLen, change)
	}
	return compact(copy)
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
	copy := n.clone()
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
	return compact(copy)
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
		// instead cost, and indexSrcs for when the walk is the cheaper of the
		// two and there is no index to use. A deeper node still overwrites
		// this, which is destination specificity beating source specificity,
		// as before.
		matched := false
		if byLen := n.index(); byLen != nil {
			for _, group := range byLen {
				if value, ok := group.m[netip.PrefixFrom(src, int(group.bits)).Masked()]; ok {
					result, found, matched = value, true, true
					break
				}
			}
		} else {
			for _, entry := range n.srcs {
				if !entry.src.IsValid() {
					continue // the match-all entry is held apart, below
				}
				if entry.src.Contains(src) {
					result, found, matched = entry.value, true, true
					break
				}
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
