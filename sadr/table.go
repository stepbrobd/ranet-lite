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

// Table resolves the longest matching destination, then the longest matching
// source at that destination. Its zero value is ready to use.
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
	child     [2]*trieNode[V]
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
	return &trieNode[V]{address: address, prefixLen: prefixLen,
		byteIndex: prefixLen / 8, bitShift: 7 - prefixLen%8, srcs: srcs}
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
			parent.srcs = srcs
		} else {
			parent.child[branch(address, common)] = newTrieNode(address, prefixLen, srcs)
		}
		return parent
	}
	copy := *n
	if n.prefixLen == prefixLen {
		copy.srcs = change(n.srcs)
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
		return append(next, srcEntry[V]{src: src, value: value})
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
		copy.srcs = make([]srcEntry[V], 0, len(n.srcs))
		for _, entry := range n.srcs {
			if entry.value != value {
				copy.srcs = append(copy.srcs, entry)
			}
		}
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
		bestBits := -2
		for _, entry := range n.srcs {
			if entry.src.IsValid() && !entry.src.Contains(src) {
				continue
			}
			if entry.src.Bits() > bestBits {
				result, found, bestBits = entry.value, true, entry.src.Bits()
			}
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
