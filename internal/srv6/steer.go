package srv6

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

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

// Steer is one configured entry: which packets, and through what.
type Steer struct {
	// From and To select the packets. An invalid prefix matches every address
	// of the family the other one names, and a policy naming neither would
	// steer this node's own underlay into its own tunnel, so it is refused.
	From netip.Prefix
	To   netip.Prefix
	Policy
}

// SteerTable answers which policy applies to one packet. A nil table steers
// nothing, which is every node that configures none, and Lookup works on one.
type SteerTable struct {
	table   sadr.Table[*Policy]
	entries []Steer
	// overhead is the largest any policy here adds, which a tunnel takes off
	// its MTU so the dataplane is never handed a packet that will not fit
	// once encapsulated.
	overhead int
}

// NewSteerTable builds the table, refusing an entry that cannot mean what it
// says.
func NewSteerTable(entries []Steer) (*SteerTable, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := &SteerTable{entries: slices.Clone(entries)}
	seen := make(map[[2]netip.Prefix]bool, len(out.entries))
	for i := range out.entries {
		entry := &out.entries[i]
		if err := CheckPath(entry.Source, entry.Path); err != nil {
			return nil, err
		}
		if !entry.From.IsValid() && !entry.To.IsValid() {
			// Every packet this node sends is matched, the babel traffic that
			// carries the mesh's own routing included, so the steering would
			// take out the adjacency that makes its own segments reachable.
			return nil, fmt.Errorf("srv6: a steering entry selecting neither a source nor a destination would steer every packet this node sends")
		}
		if entry.From.IsValid() && entry.To.IsValid() && entry.From.Addr().Is4() != entry.To.Addr().Is4() {
			return nil, fmt.Errorf("srv6: steering entry from %s to %s names two address families", entry.From, entry.To)
		}
		for _, prefix := range [2]netip.Prefix{entry.From, entry.To} {
			if prefix.IsValid() && prefix.Addr().Is4In6() {
				return nil, fmt.Errorf("srv6: steering entry selector %s is a v4-mapped prefix, which no packet is looked up under", prefix)
			}
		}
		// The trie is keyed by destination first and has no entry for "any
		// destination", so an entry that names only a source takes the
		// zero-length prefix of the family its source is in. An invalid
		// source needs no such treatment: the trie already reads one as
		// matching every address.
		destination := entry.To
		if !destination.IsValid() {
			destination = anyDestination(entry.From)
		}
		// Keyed on what the trie is keyed on rather than on what was written,
		// because those differ: an omitted destination and one written out as
		// the zero-length prefix are two spellings the trie stores under one
		// key, so keying on the spelling lets the second entry overwrite the
		// first while a diagnostic goes on reporting both.
		selector := [2]netip.Prefix{entry.From, destination}
		if seen[selector] {
			return nil, fmt.Errorf("srv6: two steering entries select %s", steerName(*entry))
		}
		seen[selector] = true
		entry.name = steerName(*entry)
		out.overhead = max(out.overhead, entry.Policy.Overhead())
		out.table.Set(entry.From, destination, &entry.Policy)
	}
	return out, nil
}

// steerName is the line a diagnostic prints for one entry, in the order an
// operator wrote it.
func steerName(entry Steer) string {
	selector := "any"
	switch {
	case entry.From.IsValid() && entry.To.IsValid():
		selector = fmt.Sprintf("from %s to %s", entry.From, entry.To)
	case entry.From.IsValid():
		selector = "from " + entry.From.String()
	case entry.To.IsValid():
		selector = "to " + entry.To.String()
	}
	hops := make([]string, 0, len(entry.Path))
	for _, segment := range entry.Path {
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
	out := make([]string, 0, len(t.entries))
	for _, entry := range t.entries {
		out = append(out, entry.name)
	}
	return out
}
