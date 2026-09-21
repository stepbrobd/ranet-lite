// Package schema holds the scalar spellings a configuration file uses: a
// duration, a prefix, an address, a routing table and one announcement. Every
// capability takes its fields from here, so a duration is written the same way
// wherever it appears and a later generator or DSL has one definition of each
// to target.
//
// Each type carries two decoders, because the two this tree reads dispatch
// differently. yaml.v3 asks a type for [yaml.Unmarshaler] and never for
// [encoding.TextUnmarshaler]; BurntSushi/toml asks for the text one and never
// for the yaml one. A type carrying one and not the other is a field that
// parses under one file extension and is refused under the other, which is the
// worst of the failures a second decoder can introduce.
//
// Nothing here imports the rest of this tree, so a capability package can take
// it whatever else that package holds.
package schema

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is an interval as Go spells one, "4s" or "1h30m". A bare zero is
// taken too, so a disabled timer reads as "0" rather than as "0s".
type Duration time.Duration

// Duration is the interval itself, for a caller doing arithmetic on it.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

func (d *Duration) UnmarshalText(text []byte) error {
	// ParseDuration takes a bare "0" and nothing else without a unit, which is
	// the spelling an operator writes for a disabled timer.
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	// Value is empty for a mapping or a sequence, so without the check the
	// error is `invalid duration ""` with nothing pointing at the line.
	return Scalar(value, "a duration such as 4s", d)
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// Prefix is a CIDR prefix, "10.66.0.5/32" or "2001:db8::/48".
type Prefix struct{ netip.Prefix }

// PrefixFrom carries a parsed prefix into the file's spelling of one.
func PrefixFrom(prefix netip.Prefix) Prefix { return Prefix{prefix} }

func ParsePrefix(s string) (Prefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return Prefix{}, err
	}
	return Prefix{prefix}, nil
}

// MustPrefix is ParsePrefix for a literal written in this tree.
func MustPrefix(s string) Prefix { return Prefix{netip.MustParsePrefix(s)} }

// IsZero decides whether an omitempty field is written out. It is spelled out
// because yaml.v3 judges emptiness by walking a struct's exported fields, and
// every field of a netip.Prefix is private, so without this every prefix in the
// tree reads as empty and is dropped on the way out.
func (p Prefix) IsZero() bool { return !p.IsValid() }

func (p *Prefix) UnmarshalText(text []byte) error {
	parsed, err := ParsePrefix(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

func (p Prefix) MarshalText() ([]byte, error) {
	if !p.IsValid() {
		return nil, fmt.Errorf("schema: a prefix carrying no address has no spelling")
	}
	return []byte(p.String()), nil
}

func (p *Prefix) UnmarshalYAML(value *yaml.Node) error {
	return Scalar(value, "a prefix such as 2001:db8::/48", p)
}

func (p Prefix) MarshalYAML() (any, error) { return p.String(), nil }

// Addr is one address, with no prefix length and no zone.
type Addr struct{ netip.Addr }

// AddrFrom carries a parsed address into the file's spelling of one.
func AddrFrom(address netip.Addr) Addr { return Addr{address} }

func ParseAddr(s string) (Addr, error) {
	address, err := netip.ParseAddr(s)
	if err != nil {
		return Addr{}, err
	}
	return Addr{address}, nil
}

// MustAddr is ParseAddr for a literal written in this tree.
func MustAddr(s string) Addr { return Addr{netip.MustParseAddr(s)} }

// IsZero is Prefix.IsZero for an address, and is there for the same reason.
func (a Addr) IsZero() bool { return !a.IsValid() }

func (a *Addr) UnmarshalText(text []byte) error {
	parsed, err := ParseAddr(string(text))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

func (a Addr) MarshalText() ([]byte, error) {
	if !a.IsValid() {
		return nil, fmt.Errorf("schema: an address carrying no value has no spelling")
	}
	return []byte(a.String()), nil
}

func (a *Addr) UnmarshalYAML(value *yaml.Node) error {
	return Scalar(value, "an address such as 2001:db8::1", a)
}

func (a Addr) MarshalYAML() (any, error) { return a.String(), nil }

// TableID is a routing table, as a number or as one of the names the kernel
// reserves, so a rule sending the underlay to the main table reads as
// "table: main" rather than as "table: 254".
type TableID uint32

// Reserved table numbers, from linux/rtnetlink.h. Named here rather than taken
// from x/sys so this package still builds on every platform.
const (
	TableDefault TableID = 253
	TableMain    TableID = 254
	TableLocal   TableID = 255
)

func (t TableID) String() string {
	switch t {
	case TableMain:
		return "main"
	case TableLocal:
		return "local"
	case TableDefault:
		return "default"
	}
	return strconv.FormatUint(uint64(t), 10)
}

func (t *TableID) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "main":
		*t = TableMain
		return nil
	case "local":
		*t = TableLocal
		return nil
	case "default":
		*t = TableDefault
		return nil
	}
	number, err := strconv.ParseUint(string(text), 0, 32)
	if err != nil {
		return fmt.Errorf("table %q is neither a number nor one of main, local and default", text)
	}
	*t = TableID(number)
	return nil
}

func (t TableID) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

func (t *TableID) UnmarshalYAML(value *yaml.Node) error {
	return Scalar(value, "a table as a number or a name such as main", t)
}

func (t TableID) MarshalYAML() (any, error) { return t.String(), nil }

// Announce is one prefix a node puts into the mesh, either bare or carrying
// the source prefix it is reachable from:
//
//	announce:
//	  - 2001:db8::/48
//	  - { prefix: "::/0", from: 2001:db8::/48 }
//
// What the pair may say is decided where the announcement is made rather than
// here, so this package stays a spelling and the routing rules stay with the
// protocol carrying them.
type Announce struct {
	Prefix Prefix `yaml:"prefix" json:"prefix" toml:"prefix"`
	From   Prefix `yaml:"from,omitempty" json:"from,omitempty" toml:"from,omitempty"`
}

func (a Announce) String() string {
	if !a.From.IsValid() {
		return a.Prefix.String()
	}
	return a.Prefix.String() + " from " + a.From.String()
}

func (a *Announce) UnmarshalText(text []byte) error {
	// The bare spelling alone. A mapping reaches whichever decoder can carry
	// one, UnmarshalYAML under yaml.v3 and UnmarshalTOML under toml.
	return a.Prefix.UnmarshalText(text)
}

func (a *Announce) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		return Scalar(value, "an announcement", a)
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: an announcement is a prefix or a prefix and from mapping, not %s", value.Line, nodeKind(value.Kind))
	}
	// Walked by hand rather than decoded into a helper struct: a nested
	// decoder does not inherit the outer one's rejection of unknown fields.
	for i := 0; i+1 < len(value.Content); i += 2 {
		key, item := value.Content[i], value.Content[i+1]
		target, err := a.field(key.Value)
		if err != nil {
			return fmt.Errorf("line %d: %w", key.Line, err)
		}
		if err := target.UnmarshalYAML(item); err != nil {
			return err
		}
	}
	return a.complete()
}

// UnmarshalTOML takes the same two spellings under the other decoder, which
// hands over the value it decoded rather than a node. A type implementing this
// is told nothing about unknown keys either, so the walk below refuses them the
// way the yaml walk does.
func (a *Announce) UnmarshalTOML(data any) error {
	switch value := data.(type) {
	case string:
		return a.UnmarshalText([]byte(value))
	case map[string]any:
		// Sorted, so an entry whose prefix and from are both wrong names the
		// same one on every load.
		for _, key := range slices.Sorted(maps.Keys(value)) {
			target, err := a.field(key)
			if err != nil {
				return err
			}
			text, ok := value[key].(string)
			if !ok {
				return fmt.Errorf("announce %s is %T, and a prefix is written as a string", key, value[key])
			}
			if err := target.UnmarshalText([]byte(text)); err != nil {
				return err
			}
		}
		return a.complete()
	}
	return fmt.Errorf("an announcement is a prefix or a prefix and from table, not %T", data)
}

func (a *Announce) field(name string) (*Prefix, error) {
	switch name {
	case "prefix":
		return &a.Prefix, nil
	case "from":
		return &a.From, nil
	}
	return nil, fmt.Errorf("announce: unknown field %q", name)
}

func (a *Announce) complete() error {
	if !a.Prefix.IsValid() {
		return fmt.Errorf("announce: prefix is required")
	}
	return nil
}

// MarshalYAML writes the shorter of the two spellings, so a rendered
// announcement reads the way an operator writes one.
//
// There is deliberately no MarshalText beside it: the toml encoder takes a text
// marshaler ahead of a struct's own fields, and an announcement carrying a
// source has no text form, so the source would be dropped on the way out.
func (a Announce) MarshalYAML() (any, error) {
	if !a.From.IsValid() {
		return a.Prefix.String(), nil
	}
	return struct {
		Prefix Prefix `yaml:"prefix"`
		From   Prefix `yaml:"from"`
	}{a.Prefix, a.From}, nil
}

// Scalar decodes one yaml scalar through the text half, so both decoders read
// the same spellings and only the wrapping differs. It is exported because a
// capability package with a scalar of its own, a behavior or a link quality,
// needs the same dispatch and the same refusal for a mapping written where a
// word belongs.
func Scalar(value *yaml.Node, want string, target interface{ UnmarshalText([]byte) error }) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: %s is a scalar, not %s", value.Line, want, nodeKind(value.Kind))
	}
	if err := target.UnmarshalText([]byte(value.Value)); err != nil {
		return fmt.Errorf("line %d: %w", value.Line, err)
	}
	return nil
}

func nodeKind(kind yaml.Kind) string {
	switch kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a sequence"
	case yaml.AliasNode:
		return "an alias"
	}
	return "a document"
}
