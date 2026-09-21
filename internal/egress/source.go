package egress

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"gopkg.in/yaml.v3"
)

// Source is the address a translated packet leaves under, written either as
// an address or as "auto".
//
// "auto" is the address this node's own routes would have used for the packet,
// which is the only answer a deployment owning no address block has: on the way
// out of the mesh that is the address of the link the packet leaves by, and on
// the way into the mesh it is this node's own mesh address, which is unique per
// node and routable within the mesh. Leaving the field out asks for the same
// thing; the flag is kept so that a capability read from a file and written
// back out reads as it was written.
//
// An address written out is used unchanged in both directions. That is the
// arrangement a fleet with its own address block has, where one announced
// address is both globally routable and returned to through the mesh, and it is
// the only way to make return traffic land on a chosen node rather than on
// whichever one a reply happens to reach.
type Source struct {
	Auto bool
	Addr netip.Addr
}

// IsZero reports a source nothing was written for. yaml.v3 and encoding/json
// both consult it, so an absent source stays absent through a round trip
// rather than coming back as an empty string.
func (s Source) IsZero() bool { return !s.Auto && !s.Addr.IsValid() }

func (s Source) String() string {
	if s.Addr.IsValid() {
		return s.Addr.String()
	}
	return "auto"
}

func (s *Source) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: a source is auto or an address, not %s", value.Line, nodeKindName(value.Kind))
	}
	return s.parse(value.Value)
}

func (s Source) MarshalYAML() (any, error) { return s.String(), nil }

func (s *Source) UnmarshalJSON(b []byte) error {
	var text string
	if err := json.Unmarshal(b, &text); err != nil {
		return err
	}
	return s.parse(text)
}

func (s Source) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Source) parse(text string) error {
	if text == "auto" {
		*s = Source{Auto: true}
		return nil
	}
	address, err := netip.ParseAddr(text)
	if err != nil {
		return fmt.Errorf("a source is auto or an address: %w", err)
	}
	if address.Zone() != "" {
		// A zone names a link on this host, and the address goes into a
		// translation rule the kernel matches on its own, so there is nothing
		// for one to select.
		return fmt.Errorf("source %s carries a zone, which a translated address cannot", address)
	}
	*s = Source{Addr: address.Unmap()}
	return nil
}

// Duration is a Go duration string in YAML and in JSON alike, so the file and
// the wire carry one spelling. A bare zero is taken as well, which is how
// every other interval in this tree spells "leave the default alone".
type Duration time.Duration

func (d Duration) String() string { return time.Duration(d).String() }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: a duration is a scalar such as 30s, not %s", value.Line, nodeKindName(value.Kind))
	}
	return d.parse(value.Value, value.Tag == "!!int")
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var text string
	if err := json.Unmarshal(b, &text); err != nil {
		return err
	}
	return d.parse(text, false)
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) parse(text string, integer bool) error {
	if integer && text == "0" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// nodeKindName names what was written where a scalar was wanted, so a refusal
// points at the shape of the mistake rather than at an empty value.
func nodeKindName(kind yaml.Kind) string {
	switch kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a sequence"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "a document"
	}
}
