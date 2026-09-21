package srv6

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"github.com/NickCao/ranet-lite/internal/schema"
)

// The file spellings of the two, for an entry of the capability itself.
func sprefix(s string) schema.Prefix { return schema.MustPrefix(s) }
func saddr(s string) schema.Addr     { return schema.MustAddr(s) }

// steering is one entry as the file spells it: the selector, the outer source
// and the segments it visits.
func steering(from, to string, source string, path ...string) Steer {
	entry := Steer{Source: saddr(source)}
	if from != "" {
		entry.From = sprefix(from)
	}
	if to != "" {
		entry.To = sprefix(to)
	}
	for _, hop := range path {
		entry.Via = append(entry.Via, saddr(hop))
	}
	return entry
}

func policy(source string, path ...string) Policy {
	segments := make([]netip.Addr, 0, len(path))
	for _, hop := range path {
		segments = append(segments, addr(hop))
	}
	return Policy{Source: addr(source), Path: segments}
}

// A nil table steers nothing and answers every question without a caller
// having to ask whether it exists, because most nodes configure none.
func TestNoSteeringTableClaimsNothing(t *testing.T) {
	var absent *SteerTable
	if absent.Lookup(addr("2001:db8::1"), addr("2001:db8::2")) != nil {
		t.Error("a nil table claimed a packet")
	}
	if absent.Overhead() != 0 || absent.Entries() != nil {
		t.Error("a nil table reported entries")
	}
	table, err := NewSteerTable(nil, schema.Addr{})
	if err != nil || table != nil {
		t.Errorf("an empty configuration produced %v (%v), want no table at all", table, err)
	}
}

// The table is keyed the way the forwarding table is keyed, so the selector
// such a tool uses, everything sourced from this node's announced address, reaches
// exactly the packets it reaches there.
func TestSourceSelectorClaimsOnlyItsOwnTraffic(t *testing.T) {
	announced := policy("3fff:1:69c:8c0::1", "3fff:1:69c:98d6::1")
	table, err := NewSteerTable([]Steer{
		steering("3fff:a::198:18:104:117/128", "", "3fff:1:69c:8c0::1", "3fff:1:69c:98d6::1"),
	}, schema.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if got := table.Lookup(addr("3fff:a::198:18:104:117"), addr("2001:4860:4860::8888")); got == nil {
		t.Fatal("the announced address was not claimed")
	} else if !slices.Equal(got.Path, announced.Path) {
		t.Errorf("the claimed policy is %v", got.Path)
	}
	if got := table.Lookup(addr("3fff:a::198:18:104:118"), addr("2001:4860:4860::8888")); got != nil {
		t.Errorf("another node's address was claimed by %s", got)
	}
	if table.Overhead() != Overhead(1) || len(table.Entries()) != 1 {
		t.Errorf("the table reports overhead %d over %d entries", table.Overhead(), len(table.Entries()))
	}
	if entries := table.Entries(); len(entries) != 1 || entries[0] != "from 3fff:a::198:18:104:117/128 via 3fff:1:69c:98d6::1" {
		t.Errorf("the table reads as %v", entries)
	}
}

// An entry that selects on nothing would claim the encapsulated packets this
// node has just produced, which would then be encapsulated again.
func TestSteeringRefusesWhatWouldClaimItsOwnEncapsulation(t *testing.T) {
	const source, exit = "3fff:1:69c:8c0::1", "3fff:1:69c:98d6::1"
	for name, entry := range map[string]Steer{
		"no selector":    steering("", "", source, exit),
		"no segments":    steering("2001:db8::/32", "", source),
		"a v4 source":    steering("10.0.0.0/8", "", "198.18.104.117", exit),
		"a v4 segment":   steering("2001:db8::/32", "", source, "198.18.104.117"),
		"mixed families": steering("2001:db8::/32", "10.0.0.0/8", source, exit),
		// A v4-mapped prefix goes into the IPv6 half of the trie while a v4
		// packet is looked up in the v4 half, so it would never match.
		"a v4-mapped selector": steering("", "::ffff:10.0.0.0/104", source, exit),
		// A selector carrying bits below its length steers a whole prefix
		// where one address was meant, and says nothing.
		"host bits under a length": steering("2001:db8::1/32", "", source, exit),
		// Neither the entry nor the block names an outer source, so there is
		// nothing to send the encapsulation from.
		"no source at all": {From: sprefix("2001:db8::/32"), Via: []schema.Addr{saddr(exit)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSteerTable([]Steer{entry}, schema.Addr{}); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

// An entry naming no source of its own takes the block's, which is how the
// fleet's one `ip sr tunsrc` per node carries over.
func TestSteeringEntryInheritsTheBlockSource(t *testing.T) {
	entry := Steer{From: sprefix("2001:db8::/32"), Via: []schema.Addr{saddr("3fff:1:69c:98d6::1")}}
	table, err := NewSteerTable([]Steer{entry}, saddr("3fff:1:69c:8c0::1"))
	if err != nil {
		t.Fatal(err)
	}
	got := table.Lookup(addr("2001:db8::5"), addr("2001:4860:4860::8888"))
	if got == nil || got.Source != addr("3fff:1:69c:8c0::1") {
		t.Errorf("the entry was steered from %v", got)
	}
}

// Two entries selecting the same packets are a configuration whose halves
// disagree, and the trie keeps one of them while a diagnostic prints both. The
// local segment table and the rule list both refuse the same shape.
func TestSteeringRefusesTwoEntriesWithOneSelector(t *testing.T) {
	const source = "3fff:1:69c:8c0::1"
	first := steering("2001:db8::/32", "", source, "3fff:1:69c:98d6::1")
	second := steering("2001:db8::/32", "", source, "3fff:1:69c:6c46::1")
	for name, entries := range map[string][]Steer{
		"written the same way": {first, second},
		// An omitted destination and one written out as the zero-length
		// prefix are two spellings of one trie key, so keying the check on
		// what was written rather than on what the trie stores lets the
		// second entry quietly replace the first.
		"an omitted destination against an explicit one": {
			first,
			steering("2001:db8::/32", "::/0", source, "3fff:1:69c:6c46::1"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSteerTable(entries, schema.Addr{}); err == nil {
				t.Error("two entries selecting the same packets were accepted")
			}
		})
	}
}

// The in-place encapsulation has to produce the same bytes the allocating one
// does, or a dataplane and a test would be exercising two different encoders.
//
// The inner packet carries a traffic class and a flow label, and the buffer
// starts full of a byte neither encoder writes, because the two ways this can
// go wrong are both invisible against a zeroed buffer and a zeroed header: the
// allocating encoder gets its zeros from make, and the in-place one is handed
// the bytes of the very packet it is moving out of the way.
func TestInPlaceEncapsulationMatchesTheAllocatingOne(t *testing.T) {
	source := addr("3fff:1:69c:8c0::1")
	path := []netip.Addr{addr("3fff:1:69c:98d6::2"), addr("3fff:1:69c:29a6::1")}
	inner := innerV6("payload")
	inner[0], inner[1], inner[2], inner[3] = 0x6a, 0xbc, 0xde, 0xf0

	want, err := Encapsulate(inner, source, path)
	if err != nil {
		t.Fatal(err)
	}

	const offset = 16
	buf := bytes.Repeat([]byte{0xff}, offset+len(want)+64)
	copy(buf[offset:], inner)
	size, err := EncapsulateInPlace(buf, offset, len(inner), source, path)
	if err != nil {
		t.Fatal(err)
	}
	if size != len(want) {
		t.Fatalf("in place produced %d bytes, want %d", size, len(want))
	}
	if !bytes.Equal(buf[offset:offset+size], want) {
		t.Error("the two encoders disagree")
	}
	if Overhead(len(path)) != len(want)-len(inner) {
		t.Errorf("Overhead(%d) is %d, want %d", len(path), Overhead(len(path)), len(want)-len(inner))
	}
}

// A buffer that cannot hold the result is refused rather than truncated. The
// MTU keeps that from happening, so a packet arriving anyway means the
// deployment has the MTU wrong, which is worth reporting rather than
// corrupting.
func TestInPlaceEncapsulationRefusesABufferTooShort(t *testing.T) {
	source := addr("3fff:1:69c:8c0::1")
	path := []netip.Addr{addr("3fff:1:69c:98d6::1")}
	inner := innerV6("payload")
	buf := make([]byte, 16+len(inner)+8)
	copy(buf[16:], inner)
	if _, err := EncapsulateInPlace(buf, 16, len(inner), source, path); err == nil {
		t.Error("a buffer with no room was accepted")
	}
	if _, err := EncapsulateInPlace(buf, 16, len(buf), source, path); err == nil {
		t.Error("a packet running past the end of its buffer was accepted")
	}
}
