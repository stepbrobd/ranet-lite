// Package schema holds the scalar spellings a configuration file is written
// in: a duration, a prefix, an address, a routing table and one announcement.
// Every capability takes its fields from here, which fixes one spelling per
// scalar wherever it appears and gives a later generator or DSL one definition
// of each to target. A configuration file commits to these spellings, and
// changing one changes what an operator may already have written down.
//
// # What a caller uses
//
// [Duration], [Prefix], [Addr], [TableID] and [Announce] are the vocabulary
// itself. A capability declares them by value in its own struct, beside the
// yaml, json and toml tags that name the key. [ParsePrefix], [ParseAddr] and
// the Must forms build one from a literal, [PrefixFrom] and [AddrFrom] carry
// in a value [net/netip] already parsed, and [ComparePrefix] and [CompareAddr]
// put a list whose order the subsystem does not read into one order, which is
// how two files writing the same set compare equal across a reload.
//
// This package imports nothing else in this repository, so a capability
// package takes it without taking the daemon.
//
// # Adding a scalar
//
// A capability with a scalar of its own, a behavior or a link quality, writes
// five methods on it. The three encoders this tree reads and writes dispatch
// differently, and a method left out is found by an operator rather than by
// the compiler.
//
//   - UnmarshalText and UnmarshalYAML. yaml.v3 asks a type for
//     [yaml.Unmarshaler] and never for [encoding.TextUnmarshaler];
//     BurntSushi/toml asks for the text one and never for the yaml one. A type
//     carrying one alone parses under one file extension and is refused under
//     the other. [Scalar] routes the yaml half into the text half, which
//     leaves both decoders reading the same spellings and only the wrapping
//     differing.
//   - MarshalText and MarshalYAML, for the same split going the other way. A
//     type whose written form is a mapping rather than a word takes the yaml
//     one alone, and [Announce] records why.
//   - IsZero, when the type wraps a struct. yaml.v3 decides omitempty for a
//     struct by asking for IsZero and otherwise walking the exported fields,
//     and a [net/netip] value exports none, so a prefix holding 10.0.0.0/8 is
//     dropped on the way out rather than written. encoding/json fails the
//     other way around: omitempty never drops a struct at all, so a struct
//     field here spells its json tag omitzero rather than omitempty, the one
//     option under which json asks for IsZero.
//
// Each of those three has cost this tree a round of debugging already.
package schema

import (
	"cmp"
	"encoding/json"
	"fmt"
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

// MarshalYAML makes the refusal MarshalText makes, rather than writing the
// "invalid Prefix" that String answers for a prefix carrying no address: that
// literal renders without complaint and no decoder reads it back, so a
// rendered configuration would be one nothing can load.
func (p Prefix) MarshalYAML() (any, error) {
	text, err := p.MarshalText()
	if err != nil {
		return nil, err
	}
	return string(text), nil
}

// ComparePrefix orders two prefixes, by address and then by length. It is a
// total order over every value the type takes, the zero one included, since
// netip orders an invalid address before every valid one.
//
// It is here rather than in each capability because a capability needs it for
// one reason only: to put a list whose order the subsystem does not read into
// one order, so that two files writing the same set compare equal and a reload
// is not refused over the order somebody happened to write them in.
func ComparePrefix(a, b Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
}

// CompareAddr orders two addresses, and is there for the same reason.
func CompareAddr(a, b Addr) int { return a.Addr.Compare(b.Addr) }

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

// MarshalYAML is Prefix.MarshalYAML for an address, and is there for the same
// reason.
func (a Addr) MarshalYAML() (any, error) {
	text, err := a.MarshalText()
	if err != nil {
		return nil, err
	}
	return string(text), nil
}

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
	From   Prefix `yaml:"from,omitempty" json:"from,omitzero" toml:"from,omitempty"`
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
func (a *Announce) UnmarshalTOML(data any) error { return a.decoded(data, "table") }

// UnmarshalJSON takes the two spellings under encoding/json, which is how the
// control plane reads an announcement. Without it json takes the bare form
// through UnmarshalText and refuses the mapping outright, so the file and the
// wire form would be two schemas rather than one. The decoded value is the
// same pair of shapes the toml decoder hands over, so the walk is shared.
func (a *Announce) UnmarshalJSON(data []byte) error {
	var written any
	if err := json.Unmarshal(data, &written); err != nil {
		return err
	}
	return a.decoded(written, "object")
}

// decoded walks the mapping form for a decoder that hands over a value rather
// than a node. shape names a mapping the way that decoder's own documentation
// does, so a refusal names the thing the operator was writing.
func (a *Announce) decoded(data any, shape string) error {
	switch value := data.(type) {
	case string:
		return a.UnmarshalText([]byte(value))
	case map[string]any:
		// prefix first, which is the order the yaml walk takes and the order
		// Routes.Validate checks in, so an entry whose prefix and from are
		// both wrong names the same half whichever decoder read it. The rest
		// is sorted, so an entry with two typos names the same one every time.
		for _, key := range append([]string{"prefix", "from"}, otherKeys(value)...) {
			written, present := value[key]
			if !present {
				continue
			}
			target, err := a.field(key)
			if err != nil {
				return err
			}
			text, ok := written.(string)
			if !ok {
				return fmt.Errorf("announce %s is %T, and a prefix is written as a string", key, written)
			}
			if err := target.UnmarshalText([]byte(text)); err != nil {
				return err
			}
		}
		return a.complete()
	}
	return fmt.Errorf("an announcement is a prefix or a prefix and from %s, not %T", shape, data)
}

// otherKeys is every key an announcement does not name, in one order.
func otherKeys(value map[string]any) []string {
	out := make([]string, 0, len(value))
	for key := range value {
		if key != "prefix" && key != "from" {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out
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
