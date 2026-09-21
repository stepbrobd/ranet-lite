package srv6

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

// A packet not addressed to one of this node's segments costs a map lookup and
// goes where it was going, which is almost every packet on the mesh.
func TestPacketsForSomebodyElsePassThrough(t *testing.T) {
	table, err := NewLocalTable([]Segment{{SID: addr("3fff:1:69c:8c6::1"), Behavior: BehaviorEndDT46}})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"an ordinary v6 packet":    innerV6("payload"),
		"an ordinary v4 packet":    innerV4("payload"),
		"a short buffer":           {0x60},
		"an empty one":             {},
		"a segment list elsewhere": segmentRouted(t),
	} {
		t.Run(name, func(t *testing.T) {
			if result := table.Handle(raw); result.Action != ActionPass {
				t.Errorf("Handle returned %v, want ActionPass", result.Action)
			}
		})
	}
	// A nil table answers for nothing without a caller having to ask.
	var absent *LocalTable
	if result := absent.Handle(segmentRouted(t)); result.Action != ActionPass {
		t.Errorf("a nil table returned %v", result.Action)
	}
	if absent.Segments() != nil {
		t.Error("a nil table reported segments")
	}
}

// A waypoint moves the packet to the next segment and says where it now goes.
// An exit hands back what was inside. Both are reached only by a packet whose
// current segment is this node's.
func TestWaypointAndExitActOnTheirOwnSegments(t *testing.T) {
	waypoint := addr("3fff:1:69c:8c6::2")
	exit := addr("3fff:1:69c:98d6::1")
	table, err := NewLocalTable([]Segment{
		{SID: waypoint, Behavior: BehaviorEnd},
		{SID: exit, Behavior: BehaviorEndDT46},
	})
	if err != nil {
		t.Fatal(err)
	}
	inner := innerV6("payload")
	raw, err := Encapsulate(inner, addr("3fff:1:69c:8c0::1"), []netip.Addr{waypoint, exit})
	if err != nil {
		t.Fatal(err)
	}

	forwarded := table.Handle(raw)
	if forwarded.Action != ActionForward {
		t.Fatalf("the waypoint returned %v (%v)", forwarded.Action, forwarded.Err)
	}
	if forwarded.Next != exit {
		t.Fatalf("the waypoint forwarded to %s, want the next segment %s", forwarded.Next, exit)
	}
	if got := netip.AddrFrom16([16]byte(raw[24:40])); got != exit {
		t.Errorf("the packet's destination is %s, so it was not rewritten in place", got)
	}

	// The same table now sees the same packet as the exit, which happens when
	// one node holds both segments.
	delivered := table.Handle(raw)
	if delivered.Action != ActionDeliver {
		t.Fatalf("the exit returned %v (%v)", delivered.Action, delivered.Err)
	}
	if delivered.Family != NextHeaderIPv6 || !bytes.Equal(delivered.Inner, inner) {
		t.Error("the exit delivered something other than the packet that was sent")
	}
}

// A packet addressed to one of this node's segments that cannot be acted on is
// dropped with a reason rather than written to the tun, where it would arrive
// as an undeliverable IPv6 packet addressed to an address of ours.
func TestSegmentsOfOursThatCannotBeActedOnAreDropped(t *testing.T) {
	sid := addr("3fff:1:69c:8c6::2")
	waypoint, err := NewLocalTable([]Segment{{SID: sid, Behavior: BehaviorEnd}})
	if err != nil {
		t.Fatal(err)
	}
	// Addressed to our waypoint with no routing header at all.
	plain := innerV6("payload")
	copy(plain[24:], addr16(sid))
	result := waypoint.Handle(plain)
	if result.Action != ActionDrop || !errors.Is(result.Err, ErrNotSegmentRouted) {
		t.Errorf("a plain packet to a waypoint returned %v (%v)", result.Action, result.Err)
	}

	// Addressed to our waypoint having already reached its last segment.
	arrived := segmentRouted(t)
	copy(arrived[24:], addr16(sid))
	if result := waypoint.Handle(arrived); result.Action != ActionDrop || !errors.Is(result.Err, ErrExhausted) {
		t.Errorf("a finished path at a waypoint returned %v (%v)", result.Action, result.Err)
	}

	// An exit reached with segments still to go.
	exitSID := addr("3fff:1:69c:98d6::1")
	exit, err := NewLocalTable([]Segment{{SID: exitSID, Behavior: BehaviorEndDT46}})
	if err != nil {
		t.Fatal(err)
	}
	midPath, err := Encapsulate(innerV6("payload"), addr("3fff:1:69c:8c0::1"),
		[]netip.Addr{exitSID, addr("3fff:1:69c:29a6::1")})
	if err != nil {
		t.Fatal(err)
	}
	if result := exit.Handle(midPath); result.Action != ActionDrop {
		t.Errorf("an exit in the middle of a path returned %v", result.Action)
	}
}

// A configuration whose two halves disagree about what this node does, or that
// names something not implemented, is refused at startup rather than skipped.
func TestLocalTableRefusesWhatItCannotAnswerFor(t *testing.T) {
	for name, segments := range map[string][]Segment{
		"a v4 segment":     {{SID: addr("198.18.104.117"), Behavior: BehaviorEnd}},
		"a duplicate":      {{SID: addr("2001:db8::1"), Behavior: BehaviorEnd}, {SID: addr("2001:db8::1"), Behavior: BehaviorEndDT46}},
		"a behavior of no": {{SID: addr("2001:db8::1"), Behavior: 0}},
		"one not written":  {{SID: addr("2001:db8::1"), Behavior: Behavior(99)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewLocalTable(segments); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
	table, err := NewLocalTable(nil)
	if err != nil || table != nil {
		t.Errorf("an empty configuration produced %v (%v), want no table at all", table, err)
	}
}

// The spelling is RFC 8986's and `ip route ... encap seg6local action`'s, so a
// configuration converted from the fleet's own reads the same.
func TestBehaviorSpellsItselfTheWayTheFleetWritesIt(t *testing.T) {
	for name, want := range map[string]Behavior{
		"End":      BehaviorEnd,
		"end":      BehaviorEnd,
		"End.DT46": BehaviorEndDT46,
		"end.dt46": BehaviorEndDT46,
		" End ":    BehaviorEnd,
	} {
		got, err := ParseBehavior(name)
		if err != nil || got != want {
			t.Errorf("ParseBehavior(%q) = %v (%v), want %v", name, got, err, want)
		}
	}
	for _, name := range []string{"", "End.DT4", "End.X", "uN"} {
		if _, err := ParseBehavior(name); err == nil {
			t.Errorf("ParseBehavior(%q) was accepted", name)
		}
	}
	if got := BehaviorEnd.String(); got != "End" {
		t.Errorf("BehaviorEnd prints as %q", got)
	}
	if got := BehaviorEndDT46.String(); got != "End.DT46" {
		t.Errorf("BehaviorEndDT46 prints as %q", got)
	}
}

// A table reports itself in a stable order, because a diagnostic that shuffles
// between two reads is one an operator cannot diff.
func TestSegmentsReportInAStableOrder(t *testing.T) {
	table, err := NewLocalTable([]Segment{
		{SID: addr("3fff:1:69c:8c6::2"), Behavior: BehaviorEnd},
		{SID: addr("3fff:1:69c:8c6::1"), Behavior: BehaviorEndDT46},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Segments()) != 2 {
		t.Fatalf("the table holds %d segments", len(table.Segments()))
	}
	for range 4 {
		got := table.Segments()
		if len(got) != 2 || got[0].SID.String() != "3fff:1:69c:8c6::1" || got[1].Behavior != BehaviorEnd {
			t.Fatalf("the table reported %v", got)
		}
	}
}
