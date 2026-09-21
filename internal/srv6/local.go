package srv6

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// This file is the receiving half: the segments this node answers for, and
// what it does with a packet that arrives addressed to one. The sending half
// is Encapsulate in srv6.go.
//
// On linux the fleet spells these as seg6local routes in a table of their own,
// reached by a policy rule, and the kernel acts on them after strongSwan has
// decrypted the packet. Here the same decision is made one step earlier, on
// the decrypted packet before it reaches the tun, which is the only place the
// other three platforms have. The two interoperate: a packet this node
// encapsulates is the same bytes the kernel would have produced, and one the
// kernel acts on is one this table would have acted on the same way.

// Behavior names the action a node takes on a packet addressed to one of its
// own segments, RFC 8986. Only the two this mesh uses are implemented, and a
// configuration naming another is refused rather than accepted and skipped.
type Behavior uint8

const (
	// BehaviorEnd is the waypoint of RFC 8986 section 4.1: move the packet to
	// the next segment and send it on, changing nothing else.
	BehaviorEnd Behavior = iota + 1
	// BehaviorEndDT46 is the exit of section 4.10: strip the outer header and
	// deliver what was inside, whichever family it is.
	BehaviorEndDT46
)

func (b Behavior) String() string {
	switch b {
	case BehaviorEnd:
		return "End"
	case BehaviorEndDT46:
		return "End.DT46"
	}
	return fmt.Sprintf("behavior(%d)", uint8(b))
}

// ParseBehavior reads the spelling an operator writes, which is the one RFC
// 8986 uses and the one `ip route ... encap seg6local action` takes, so a
// configuration converted from the fleet's own reads the same.
func ParseBehavior(name string) (Behavior, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "end":
		return BehaviorEnd, nil
	case "end.dt46":
		return BehaviorEndDT46, nil
	}
	return 0, fmt.Errorf("srv6: behavior %q is not End or End.DT46", name)
}

// Segment is one local SID and what this node does with it.
type Segment struct {
	SID      netip.Addr
	Behavior Behavior
}

func (s Segment) String() string { return s.SID.String() + " " + s.Behavior.String() }

// LocalTable is the set of segments this node answers for. A nil table answers
// for none, which is every node that configures no segment routing, and every
// method below works on one so a caller never has to ask first.
type LocalTable struct {
	entries map[netip.Addr]Behavior
}

// NewLocalTable builds the table, refusing a SID that is not an address this
// node could be reached at. A v4 SID has no meaning, since a segment list is
// carried in an IPv6 routing header, and a duplicate is a configuration whose
// two halves disagree about what this node does.
func NewLocalTable(segments []Segment) (*LocalTable, error) {
	if len(segments) == 0 {
		return nil, nil
	}
	entries := make(map[netip.Addr]Behavior, len(segments))
	for _, segment := range segments {
		if !segment.SID.Is6() || segment.SID.Is4In6() {
			return nil, fmt.Errorf("srv6: local segment %s is not an IPv6 address", segment.SID)
		}
		if segment.SID.Zone() != "" {
			return nil, fmt.Errorf("srv6: local segment %s carries a zone", segment.SID)
		}
		if segment.Behavior != BehaviorEnd && segment.Behavior != BehaviorEndDT46 {
			return nil, fmt.Errorf("srv6: local segment %s: %s is not implemented", segment.SID, segment.Behavior)
		}
		if existing, dup := entries[segment.SID]; dup {
			return nil, fmt.Errorf("srv6: local segment %s is configured as both %s and %s", segment.SID, existing, segment.Behavior)
		}
		entries[segment.SID] = segment.Behavior
	}
	return &LocalTable{entries: entries}, nil
}

// Segments is the table in a stable order, for a diagnostic to print.
func (t *LocalTable) Segments() []Segment {
	if t == nil {
		return nil
	}
	out := make([]Segment, 0, len(t.entries))
	for sid, behavior := range t.entries {
		out = append(out, Segment{SID: sid, Behavior: behavior})
	}
	slices.SortFunc(out, func(a, b Segment) int { return a.SID.Compare(b.SID) })
	return out
}

func (t *LocalTable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.entries)
}

// Action tells the caller how to treat a packet Handle has looked at.
type Action uint8

const (
	// ActionPass is a packet this table has nothing to say about, which is
	// almost all of them: it goes where it was going.
	ActionPass Action = iota
	// ActionForward is a waypoint's result. The packet was rewritten in place
	// and goes to Result.Next.
	ActionForward
	// ActionDeliver is an exit's result. Result.Inner is the packet that was
	// inside and Result.Family says which stack it belongs to.
	ActionDeliver
	// ActionDrop is a packet addressed to one of this node's segments that it
	// will not act on, with Result.Err saying why.
	ActionDrop
)

// Result carries Handle's decision.
type Result struct {
	Action Action
	Next   netip.Addr
	Inner  []byte
	Family uint8
	Err    error
}

// Handle decides what this node does with one decrypted packet.
//
// It answers ActionPass for anything not addressed to a segment this node
// holds, which is the common case and costs one map lookup on the IPv6
// packets alone. Only a packet this node is the current segment of is parsed
// any further, so a peer cannot make this node do work by sending it segment
// routing headers addressed elsewhere.
//
// The packet is rewritten in place for a waypoint, as the RFC's own
// pseudocode does, which keeps a forwarded packet off a second buffer.
func (t *LocalTable) Handle(raw []byte) Result {
	if t == nil || len(raw) < ipv6HeaderLen || raw[0]>>4 != 6 {
		return Result{Action: ActionPass}
	}
	destination := netip.AddrFrom16([16]byte(raw[24:40]))
	behavior, ours := t.entries[destination]
	if !ours {
		return Result{Action: ActionPass}
	}
	switch behavior {
	case BehaviorEnd:
		next, err := End(raw)
		if err != nil {
			return Result{Action: ActionDrop, Err: err}
		}
		return Result{Action: ActionForward, Next: next}
	case BehaviorEndDT46:
		inner, family, err := Decap(raw)
		if err != nil {
			return Result{Action: ActionDrop, Err: err}
		}
		return Result{Action: ActionDeliver, Inner: inner, Family: family}
	}
	// NewLocalTable refuses anything else, so this is unreachable rather than
	// a case left to fall through into silence.
	return Result{Action: ActionDrop, Err: fmt.Errorf("srv6: %s carries an unimplemented behavior", destination)}
}
