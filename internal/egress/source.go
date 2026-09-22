package egress

import (
	"fmt"
	"net/netip"

	"gopkg.in/yaml.v3"

	"github.com/NickCao/ranet-lite/schema"
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

// IsZero reports a source nothing was written for. yaml.v3 and the toml
// encoder both consult it, so an absent source stays absent through a round
// trip rather than coming back as an empty string.
func (s Source) IsZero() bool { return !s.Auto && !s.Addr.IsValid() }

// normalized is the source the translator reads: one naming no address is
// auto, whether the file left the field out or wrote the word.
func (s Source) normalized() Source {
	if !s.Addr.IsValid() {
		return Source{Auto: true}
	}
	return s
}

func (s Source) String() string {
	if s.Addr.IsValid() {
		return s.Addr.String()
	}
	return "auto"
}

func (s *Source) UnmarshalText(text []byte) error {
	if string(text) == "auto" {
		*s = Source{Auto: true}
		return nil
	}
	address, err := netip.ParseAddr(string(text))
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

func (s Source) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Source) UnmarshalYAML(value *yaml.Node) error {
	return schema.Scalar(value, "a source, auto or an address", s)
}

func (s Source) MarshalYAML() (any, error) { return s.String(), nil }
