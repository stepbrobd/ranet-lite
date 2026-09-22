package srv6

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/NickCao/ranet-lite/schema"
	"go.yaml.in/yaml/v3"
)

// Segments is the cap.segment capability, parsed straight out of the file: the
// segments this node answers for and the ones it sends its own packets
// through. This tree acts on a routing header in the dataplane rather than
// asking a kernel to, so the same block works on every platform: darwin has no
// segment routing and a mobile tunnel provider has no forwarding table at all,
// and neither needs one when the process carrying the packet is the one acting
// on the header.
type Segments struct {
	// Source is the outer source address an encapsulation is sent from, which
	// the fleet sets once per node with `ip sr tunsrc`. A steering entry
	// inherits it unless it names its own.
	Source schema.Addr `yaml:"source,omitempty" json:"source,omitzero" toml:"source,omitempty"`
	// Local is the segments this node answers for.
	Local []Segment `yaml:"local,omitempty" json:"local,omitempty" toml:"local,omitempty"`
	// Steer decides which of this node's own packets go through a segment
	// list: the traffic sourced from this node's announced address, through
	// the waypoints and out at a chosen exit.
	Steer []Steer `yaml:"steer,omitempty" json:"steer,omitempty" toml:"steer,omitempty"`
}

// Normalized is the capability as the dataplane runs it: an omitted list and
// an empty one the same, both lists in one order, and every steering entry
// carrying the outer source it will be sent from, the block's own where the
// entry named none. Two configurations are compared through this rather than
// as they were written, so neither a source repeated on the entry that
// inherits it nor the order the entries were listed in is a change, and
// neither costs a restart.
//
// Both lists are read as sets: the local segments become a map keyed by SID
// and the steering entries a trie keyed by their selector, and a duplicate key
// in either is refused rather than resolved by position. The segments inside
// one steering entry are the exception and are left alone, because Via is the
// order a packet visits its waypoints.
func (s Segments) Normalized() Segments {
	if len(s.Local) == 0 {
		s.Local = nil
	} else {
		s.Local = slices.SortedFunc(slices.Values(s.Local), func(a, b Segment) int {
			return cmp.Or(schema.CompareAddr(a.SID, b.SID), cmp.Compare(a.Behavior, b.Behavior))
		})
	}
	if len(s.Steer) == 0 {
		s.Steer = nil
		return s
	}
	// Cloned before the entries are touched: the struct is a shallow copy, so
	// writing through it would reach the configuration this only reads.
	s.Steer = slices.Clone(s.Steer)
	for i := range s.Steer {
		if len(s.Steer[i].Via) == 0 {
			s.Steer[i].Via = nil
		}
		if !s.Steer[i].Source.IsValid() {
			s.Steer[i].Source = s.Source
		}
	}
	slices.SortFunc(s.Steer, func(a, b Steer) int {
		return cmp.Or(
			schema.ComparePrefix(a.From, b.From),
			schema.ComparePrefix(a.To, b.To),
			schema.CompareAddr(a.Source, b.Source),
			slices.CompareFunc(a.Via, b.Via, schema.CompareAddr),
		)
	})
	return s
}

// Validate refuses a capability this node could not act on, by building the
// two tables and throwing them away. Everything it can say is said by the
// constructors, so there is one set of rules rather than two.
//
// deviceMTU is the device the steering runs on, a node fact rather than part
// of the block, and zero asks for no device check. A caller that has one
// passes it: a segment list long enough to take that device under the 1280
// RFC 8200 requires of every link is refused here rather than at startup, so
// a file this accepts is a file the daemon will run.
func (s Segments) Validate(deviceMTU int) error {
	if s.Source.IsValid() && !Usable(s.Source.Addr) {
		// Checked here rather than where the first steering entry needs it,
		// because nothing else reads the field and a node that steers nothing
		// yet would otherwise carry a source it can never send from.
		return fmt.Errorf("srv6: cap.segment source %s cannot address a segment routed packet", s.Source)
	}
	_, steering, err := s.Tables()
	if err != nil {
		return err
	}
	if deviceMTU == 0 {
		return nil
	}
	_, err = steering.CheckMTU(deviceMTU)
	return err
}

// Tables is the pair the dataplane runs on: what this node answers for and
// what it steers. Either is nil where the capability configures none of it,
// and every method on both works on a nil table.
func (s Segments) Tables() (*LocalTable, *SteerTable, error) {
	local, err := NewLocalTable(s.Local)
	if err != nil {
		return nil, nil, err
	}
	steering, err := NewSteerTable(s.Steer, s.Source)
	if err != nil {
		return nil, nil, err
	}
	return local, steering, nil
}

func (b *Behavior) UnmarshalText(text []byte) error {
	parsed, err := ParseBehavior(string(text))
	if err != nil {
		return err
	}
	*b = parsed
	return nil
}

func (b Behavior) MarshalText() ([]byte, error) {
	if b != BehaviorEnd && b != BehaviorEndDT46 {
		return nil, fmt.Errorf("srv6: %s has no spelling", b)
	}
	return []byte(b.String()), nil
}

func (b *Behavior) UnmarshalYAML(value *yaml.Node) error {
	return schema.Scalar(value, "a behavior, End or End.DT46", b)
}

func (b Behavior) MarshalYAML() (any, error) { return b.String(), nil }
