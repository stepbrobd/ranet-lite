package babel

import (
	"fmt"
	"net/netip"

	"github.com/NickCao/ranet-lite/internal/schema"
)

// Routes is the cap.route capability: what this node puts into the mesh, and
// whether it carries anybody else's traffic. It lives here rather than beside
// the reconciler because an announcement is a babel origination first, and the
// addresses cap.table assigns follow from it rather than the other way round.
type Routes struct {
	// Announce is every prefix this node claims to reach, each either bare or
	// carrying the source prefix it is reachable from. The second spelling is
	// how an exit announces a default from its own transit prefix.
	Announce []schema.Announce `yaml:"announce,omitempty" json:"announce,omitempty" toml:"announce,omitempty"`
	// Transit relays the routes this node learns, so it is offering to carry
	// the mesh. It is on unless the file says otherwise, because a converted
	// fleet needs the relaying and turning it off silently would break the
	// mesh it is replacing. A leaf on a laptop or a cellular uplink writes
	// "transit = false": measured on one, the community started forwarding
	// third-party traffic through it within minutes.
	//
	// A pointer because absent and false differ here: absent is the default,
	// which is on.
	Transit *bool `yaml:"transit,omitempty" json:"transit,omitempty" toml:"transit,omitempty"`
}

// Transits is the setting in force, on for a node that left it out.
func (r Routes) Transits() bool { return r.Transit == nil || *r.Transit }

// Originated is the announcements as the speaker takes them.
func (r Routes) Originated() []OriginatedRoute {
	out := make([]OriginatedRoute, 0, len(r.Announce))
	for _, entry := range r.Announce {
		out = append(out, OriginatedRoute{Destination: entry.Prefix.Prefix, Source: entry.From.Prefix})
	}
	return out
}

// Announced is the destination prefixes alone, which is the set the route
// reconciler assigns to the device when cap.table asks it to.
func (r Routes) Announced() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(r.Announce))
	for _, entry := range r.Announce {
		out = append(out, entry.Prefix.Prefix)
	}
	return out
}

// Validate refuses an announcement that cannot mean what it looks like. Each
// of these loads into a node that announces something other than what its file
// says, and nothing downstream says so.
func (r Routes) Validate() error {
	for _, entry := range r.Announce {
		// In this order, so an entry whose prefix and from are both wrong
		// names the same one every time it is loaded.
		for _, field := range []struct {
			name   string
			prefix netip.Prefix
		}{{"prefix", entry.Prefix.Prefix}, {"from", entry.From.Prefix}} {
			if !field.prefix.IsValid() {
				continue
			}
			if err := maskedDefault(field.prefix); err != nil {
				return fmt.Errorf("cap.route announce %s %s %w", field.name, field.prefix, err)
			}
		}
		switch source := entry.From.Prefix; {
		case !source.IsValid():
		case source.Bits() == 0:
			// originatedKey keeps a source only while it is shorter than the
			// whole address space, so this one is dropped and the entry
			// silently becomes an ordinary announcement of its destination.
			return fmt.Errorf("cap.route announce %s: a source covering every address is not a source-specific route, drop the from", entry)
		case source.Addr().Is4() != entry.Prefix.Addr().Is4():
			// The source prefix is encoded under the destination's address
			// encoding, so the pair has no representation on the wire.
			return fmt.Errorf("cap.route announce %s: mismatched address families", entry)
		case entry.Prefix.Addr().Is4():
			// Nothing consumes an IPv4 source-specific route. BIRD's
			// babel_read_source_prefix drops the whole Update unless the
			// channel is NET_IP6_SADR, and it has no IPv4 SADR channel; the
			// Linux IPv4 FIB has no source-address-dependent lookup either, so
			// internal/kernel refuses to install one. Announcing it would be a
			// prefix that reaches nobody.
			return fmt.Errorf("cap.route announce %s: source-specific routes are IPv6 only", entry)
		}
	}
	return nil
}

// maskedDefault refuses a prefix announcing the default route while carrying
// host bits, which is always a typo: originatedKey masks it, so the node
// announces "::/0" to the whole mesh and claims to be its exit. A real default
// is written "::/0" and is refused nothing.
func maskedDefault(prefix netip.Prefix) error {
	if prefix.Bits() != 0 || prefix.Addr().IsUnspecified() {
		return nil
	}
	unspecified := "::"
	if prefix.Addr().Is4() {
		unspecified = "0.0.0.0"
	}
	return fmt.Errorf("announces a default route, write %s/0 to mean that", unspecified)
}
