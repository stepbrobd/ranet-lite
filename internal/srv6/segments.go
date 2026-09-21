package srv6

import (
	"fmt"

	"github.com/NickCao/ranet-lite/internal/schema"
	"gopkg.in/yaml.v3"
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
	Source schema.Addr `yaml:"source,omitempty" json:"source,omitempty" toml:"source,omitempty"`
	// Local is the segments this node answers for.
	Local []Segment `yaml:"local,omitempty" json:"local,omitempty" toml:"local,omitempty"`
	// Steer decides which of this node's own packets go through a segment
	// list: the traffic sourced from this node's announced address, through
	// the waypoints and out at a chosen exit.
	Steer []Steer `yaml:"steer,omitempty" json:"steer,omitempty" toml:"steer,omitempty"`
}

// Validate refuses a capability this node could not act on, by building the
// two tables and throwing them away. Everything it can say is said by the
// constructors, so there is one set of rules rather than two.
func (s Segments) Validate() error {
	if s.Source.IsValid() && !Usable(s.Source.Addr) {
		// Checked here rather than where the first steering entry needs it,
		// because nothing else reads the field and a node that steers nothing
		// yet would otherwise carry a source it can never send from.
		return fmt.Errorf("srv6: cap.segment source %s cannot address a segment routed packet", s.Source)
	}
	_, _, err := s.Tables()
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
