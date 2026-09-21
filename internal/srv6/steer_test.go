package srv6

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"
)

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

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
	if absent.Overhead() != 0 || absent.Len() != 0 || absent.Entries() != nil {
		t.Error("a nil table reported entries")
	}
	table, err := NewSteerTable(nil)
	if err != nil || table != nil {
		t.Errorf("an empty configuration produced %v (%v), want no table at all", table, err)
	}
}

// The table is keyed the way the forwarding table is keyed, so the selector
// `gv` uses, everything sourced from this node's announced address, reaches
// exactly the packets it reaches there.
func TestSourceSelectorClaimsOnlyItsOwnTraffic(t *testing.T) {
	announced := policy("2a0c:b641:69c:8c0::1", "2a0c:b641:69c:98d6::1")
	table, err := NewSteerTable([]Steer{{From: prefix("2602:f590::23:161:104:117/128"), Policy: announced}})
	if err != nil {
		t.Fatal(err)
	}
	if got := table.Lookup(addr("2602:f590::23:161:104:117"), addr("2001:4860:4860::8888")); got == nil {
		t.Fatal("the announced address was not claimed")
	} else if !slices.Equal(got.Path, announced.Path) {
		t.Errorf("the claimed policy is %v", got.Path)
	}
	if got := table.Lookup(addr("2602:f590::23:161:104:118"), addr("2001:4860:4860::8888")); got != nil {
		t.Errorf("another node's address was claimed by %s", got)
	}
	if table.Overhead() != Overhead(1) || table.Len() != 1 {
		t.Errorf("the table reports overhead %d over %d entries", table.Overhead(), table.Len())
	}
	if entries := table.Entries(); len(entries) != 1 || entries[0] != "from 2602:f590::23:161:104:117/128 via 2a0c:b641:69c:98d6::1" {
		t.Errorf("the table reads as %v", entries)
	}
}

// An entry that selects on nothing would claim the encapsulated packets this
// node has just produced, which would then be encapsulated again.
func TestSteeringRefusesWhatWouldClaimItsOwnEncapsulation(t *testing.T) {
	via := policy("2a0c:b641:69c:8c0::1", "2a0c:b641:69c:98d6::1")
	for name, entry := range map[string]Steer{
		"no selector":    {Policy: via},
		"no segments":    {From: prefix("2001:db8::/32"), Policy: Policy{Source: addr("2a0c:b641:69c:8c0::1")}},
		"a v4 source":    {From: prefix("10.0.0.0/8"), Policy: policy("23.161.104.117", "2a0c:b641:69c:98d6::1")},
		"a v4 segment":   {From: prefix("2001:db8::/32"), Policy: policy("2a0c:b641:69c:8c0::1", "23.161.104.117")},
		"mixed families": {From: prefix("2001:db8::/32"), To: prefix("10.0.0.0/8"), Policy: via},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSteerTable([]Steer{entry}); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

// The in-place encapsulation has to produce the same bytes the allocating one
// does, or a dataplane and a test would be exercising two different encoders.
func TestInPlaceEncapsulationMatchesTheAllocatingOne(t *testing.T) {
	source := addr("2a0c:b641:69c:8c0::1")
	path := []netip.Addr{addr("2a0c:b641:69c:98d6::2"), addr("2a0c:b641:69c:29a6::1")}
	inner := innerV6("payload")

	want, err := Encapsulate(inner, source, path, 0)
	if err != nil {
		t.Fatal(err)
	}

	const offset = 16
	buf := make([]byte, offset+len(want)+64)
	copy(buf[offset:], inner)
	size, err := EncapsulateInPlace(buf, offset, len(inner), source, path, 0)
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
	source := addr("2a0c:b641:69c:8c0::1")
	path := []netip.Addr{addr("2a0c:b641:69c:98d6::1")}
	inner := innerV6("payload")
	buf := make([]byte, 16+len(inner)+8)
	copy(buf[16:], inner)
	if _, err := EncapsulateInPlace(buf, 16, len(inner), source, path, 0); err == nil {
		t.Error("a buffer with no room was accepted")
	}
	if _, err := EncapsulateInPlace(buf, 16, len(buf), source, path, 0); err == nil {
		t.Error("a packet running past the end of its buffer was accepted")
	}
}
