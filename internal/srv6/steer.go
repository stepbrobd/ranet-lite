package srv6

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/NickCao/ranet-lite/internal/schema"
	"github.com/NickCao/ranet-lite/sadr"
)

// This file is the sending half of steering: which of this node's own packets
// go through a segment list, and which list.
//
// It is keyed the way the forwarding table is keyed, by source and destination
// prefix together, because that is the selector the fleet's own steering uses:
// A steering tool sends the traffic sourced from this node's announced address through a
// list and leaves everything else alone. Reusing the same trie means the two
// tables answer the same question the same way rather than nearly the same
// way.

// Policy is one steering decision: the outer source an encapsulation is sent
// from, and the segments the packet visits in order.
type Policy struct {
	// Source is the outer header's source address, which the fleet sets once
	// per node with `ip sr tunsrc` and which is per policy here because
	// nothing global decides it.
	Source netip.Addr
	// Path is in the order the packet visits, so an operator writes the
	// waypoints and then the exit.
	Path []netip.Addr
	// name is the line a diagnostic prints, built once so a report costs no
	// formatting per read.
	name string
}

func (p *Policy) String() string {
	if p == nil {
		return "none"
	}
	return p.name
}

// Overhead is the bytes this policy adds in front of every packet it steers.
func (p *Policy) Overhead() int {
	if p == nil {
		return 0
	}
	return Overhead(len(p.Path))
}

// Steer is one entry of the cap.segment capability, parsed straight out of the
// file: which of this node's own packets go through a segment list, and which
// list.
type Steer struct {
	// From and To select the packets. An omitted prefix matches every address
	// of the family the other one names, and an entry naming neither would
	// steer this node's own underlay into its own tunnel, so it is refused.
	From schema.Prefix `yaml:"from,omitempty" json:"from,omitempty" toml:"from,omitempty"`
	To   schema.Prefix `yaml:"to,omitempty" json:"to,omitempty" toml:"to,omitempty"`
	// Source overrides the block's own outer source for this entry alone.
	Source schema.Addr `yaml:"source,omitempty" json:"source,omitempty" toml:"source,omitempty"`
	// Via is the segments the packet visits, in that order, so an operator
	// writes the waypoints and then the exit.
	Via []schema.Addr `yaml:"via" json:"via" toml:"via"`
}

// policy is the entry as the dataplane takes it, the block's source filled in
// where the entry names none.
func (s Steer) policy(fallback schema.Addr) Policy {
	source := s.Source
	if !source.IsValid() {
		source = fallback
	}
	path := make([]netip.Addr, 0, len(s.Via))
	for _, hop := range s.Via {
		path = append(path, hop.Addr)
	}
	return Policy{Source: source.Addr, Path: path}
}

// SteerTable answers which policy applies to one packet. A nil table steers
// nothing, which is every node that configures none, and Lookup works on one.
type SteerTable struct {
	table sadr.Table[*Policy]
	// policies is every entry in the order it was configured, for a
	// diagnostic: each carries the line that describes it.
	policies []*Policy
	// overhead is the largest any policy here adds, which a tunnel takes off
	// its MTU so the dataplane is never handed a packet that will not fit
	// once encapsulated.
	overhead int
}

// NewSteerTable builds the table, refusing an entry that cannot mean what it
// says. source is the block's own outer source, which an entry naming none
// inherits.
func NewSteerTable(entries []Steer, source schema.Addr) (*SteerTable, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := &SteerTable{}
	seen := make(map[[2]netip.Prefix]bool, len(entries))
	for _, entry := range entries {
		from, to := entry.From.Prefix, entry.To.Prefix
		policy := entry.policy(source)
		if !policy.Source.IsValid() {
			return nil, fmt.Errorf("srv6: steering entry %s needs a source, its own or the block's", steerName(entry, &policy))
		}
		if err := CheckPath(policy.Source, policy.Path); err != nil {
			return nil, err
		}
		if !from.IsValid() && !to.IsValid() {
			// Every packet this node sends is matched, the babel traffic that
			// carries the mesh's own routing included, so the steering would
			// take out the adjacency that makes its own segments reachable.
			return nil, fmt.Errorf("srv6: a steering entry selecting neither a source nor a destination would steer every packet this node sends")
		}
		if from.IsValid() && to.IsValid() && from.Addr().Is4() != to.Addr().Is4() {
			return nil, fmt.Errorf("srv6: steering entry from %s to %s names two address families", from, to)
		}
		for _, prefix := range [2]netip.Prefix{from, to} {
			if !prefix.IsValid() {
				continue
			}
			if prefix.Addr().Is4In6() {
				return nil, fmt.Errorf("srv6: steering entry selector %s is a v4-mapped prefix, which no packet is looked up under", prefix)
			}
			// Refused rather than masked, as kernel.Rule.validate refuses the
			// same typo. Masking a host address written with the wrong length
			// steers a whole prefix where one address was meant, and says
			// nothing.
			if prefix.Masked() != prefix {
				return nil, fmt.Errorf("srv6: steering entry selector %s has bits set below its prefix length", prefix)
			}
		}
		// The trie is keyed by destination first and has no entry for "any
		// destination", so an entry that names only a source takes the
		// zero-length prefix of the family its source is in. An invalid
		// source needs no such treatment: the trie already reads one as
		// matching every address.
		destination := to
		if !destination.IsValid() {
			destination = anyDestination(from)
		}
		// Keyed on what the trie is keyed on rather than on what was written,
		// because those differ: an omitted destination and one written out as
		// the zero-length prefix are two spellings the trie stores under one
		// key, so keying on the spelling lets the second entry overwrite the
		// first while a diagnostic goes on reporting both.
		selector := [2]netip.Prefix{from, destination}
		if seen[selector] {
			return nil, fmt.Errorf("srv6: two steering entries select %s", steerName(entry, &policy))
		}
		seen[selector] = true
		policy.name = steerName(entry, &policy)
		stored := &policy
		out.policies = append(out.policies, stored)
		out.overhead = max(out.overhead, stored.Overhead())
		out.table.Set(from, destination, stored)
	}
	return out, nil
}

// steerName is the line a diagnostic prints for one entry, in the order an
// operator wrote it.
func steerName(entry Steer, policy *Policy) string {
	selector := "any"
	switch {
	case entry.From.IsValid() && entry.To.IsValid():
		selector = fmt.Sprintf("from %s to %s", entry.From, entry.To)
	case entry.From.IsValid():
		selector = "from " + entry.From.String()
	case entry.To.IsValid():
		selector = "to " + entry.To.String()
	}
	hops := make([]string, 0, len(policy.Path))
	for _, segment := range policy.Path {
		hops = append(hops, segment.String())
	}
	return fmt.Sprintf("%s via %s", selector, strings.Join(hops, ","))
}

// anyDestination is the zero-length prefix of one address family, which is
// how the trie spells "every destination".
func anyDestination(source netip.Prefix) netip.Prefix {
	if source.Addr().Is4() {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0)
	}
	return netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0)
}

// Lookup is the policy for one packet, or nil for one this node does not
// steer. It reads the same immutable trie snapshot the forwarding table reads,
// without locking.
func (t *SteerTable) Lookup(source, destination netip.Addr) *Policy {
	if t == nil {
		return nil
	}
	policy, ok := t.table.Lookup(source, destination)
	if !ok {
		return nil
	}
	return policy
}

// Overhead is the most any entry here adds in front of a packet.
func (t *SteerTable) Overhead() int {
	if t == nil {
		return 0
	}
	return t.overhead
}

// Entries is the table as it was configured, for a diagnostic to print.
func (t *SteerTable) Entries() []string {
	if t == nil {
		return nil
	}
	out := make([]string, 0, len(t.policies))
	for _, policy := range t.policies {
		out = append(out, policy.name)
	}
	return out
}
