package schema

import (
	"encoding"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// holder carries one of each scalar, so a case can be written once and read by
// both decoders. The keys are the same under all three tags, which is the
// property that lets one file and one wire form describe one schema.
type holder struct {
	Interval Duration   `yaml:"interval" json:"interval" toml:"interval"`
	Prefix   Prefix     `yaml:"prefix" json:"prefix" toml:"prefix"`
	Address  Addr       `yaml:"address" json:"address" toml:"address"`
	Table    TableID    `yaml:"table" json:"table" toml:"table"`
	Announce []Announce `yaml:"announce" json:"announce" toml:"announce"`
}

func decodeYAML(t *testing.T, body string) (holder, error) {
	t.Helper()
	var out holder
	decoder := yaml.NewDecoder(strings.NewReader(body))
	decoder.KnownFields(true)
	return out, decoder.Decode(&out)
}

func decodeTOML(t *testing.T, body string) (holder, error) {
	t.Helper()
	var out holder
	md, err := toml.Decode(body, &out)
	if err != nil {
		return out, err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return out, &unknownKey{undecoded[0].String()}
	}
	return out, nil
}

type unknownKey struct{ key string }

func (u *unknownKey) Error() string { return "unknown field " + u.key }

// One configuration written twice reaches the same struct. This is the
// property the two decoders exist for: a fleet that writes toml and a control
// plane that speaks json describe one node, not two.
func TestBothDecodersReadOneConfiguration(t *testing.T) {
	const asYAML = `
interval: 4s
prefix: 2001:db8::/48
address: 2001:db8::1
table: main
announce:
  - 10.66.0.5/32
  - { prefix: "::/0", from: 2001:db8::/48 }
`
	const asTOML = `
interval = "4s"
prefix = "2001:db8::/48"
address = "2001:db8::1"
table = "main"
announce = ["10.66.0.5/32", { prefix = "::/0", from = "2001:db8::/48" }]
`
	fromYAML, err := decodeYAML(t, asYAML)
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	fromTOML, err := decodeTOML(t, asTOML)
	if err != nil {
		t.Fatalf("toml: %v", err)
	}
	if fromYAML.Interval != Duration(4*time.Second) || fromYAML.Table != TableMain {
		t.Fatalf("yaml read %+v", fromYAML)
	}
	if len(fromYAML.Announce) != 2 || fromYAML.Announce[0].From.IsValid() || !fromYAML.Announce[1].From.IsValid() {
		t.Fatalf("the two announcement spellings read as %v", fromYAML.Announce)
	}
	if !equal(fromYAML, fromTOML) {
		t.Errorf("yaml read %+v and toml read %+v", fromYAML, fromTOML)
	}
}

// parse(render(x)) is x under both decoders, so a generated configuration and
// a hand written one describe one node rather than two.
func TestRenderedScalarsParseBackToThemselves(t *testing.T) {
	cases := map[string]holder{
		"an ordinary node": {
			Interval: Duration(90 * time.Second),
			Prefix:   MustPrefix("10.66.0.5/32"),
			Address:  MustAddr("10.66.0.5"),
			Table:    200,
			Announce: []Announce{{Prefix: MustPrefix("10.66.0.5/32")}},
		},
		"a disabled timer and a named table": {
			Interval: 0,
			Prefix:   MustPrefix("::/0"),
			Address:  MustAddr("2001:db8::1"),
			Table:    TableMain,
			Announce: []Announce{
				{Prefix: MustPrefix("2001:db8::/48")},
				{Prefix: MustPrefix("::/0"), From: MustPrefix("2001:db8::/48")},
			},
		},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			rendered, err := yaml.Marshal(want)
			if err != nil {
				t.Fatalf("render as yaml: %v", err)
			}
			got, err := decodeYAML(t, string(rendered))
			if err != nil {
				t.Fatalf("parse %s: %v", rendered, err)
			}
			if !equal(got, want) {
				t.Errorf("yaml round trip gave %+v from %s", got, rendered)
			}
			var buf strings.Builder
			if err := toml.NewEncoder(&buf).Encode(want); err != nil {
				t.Fatalf("render as toml: %v", err)
			}
			got, err = decodeTOML(t, buf.String())
			if err != nil {
				t.Fatalf("parse %s: %v", buf.String(), err)
			}
			if !equal(got, want) {
				t.Errorf("toml round trip gave %+v from %s", got, buf.String())
			}
		})
	}
}

// Every spelling below is refused by both decoders, rather than by the one
// whose extension the writer happened to pick.
func TestBothDecodersRefuseTheSameSpellings(t *testing.T) {
	for name, pair := range map[string]struct{ asYAML, asTOML string }{
		"an unknown field": {
			asYAML: "unknown: true\n",
			asTOML: "unknown = true\n",
		},
		"a duration with no unit": {
			asYAML: "interval: 4\n",
			asTOML: "interval = 4\n",
		},
		"an address carrying a prefix length": {
			asYAML: "address: 2001:db8::1/128\n",
			asTOML: "address = \"2001:db8::1/128\"\n",
		},
		"a prefix carrying no length": {
			asYAML: "prefix: 2001:db8::1\n",
			asTOML: "prefix = \"2001:db8::1\"\n",
		},
		"a table that is neither a number nor a name": {
			asYAML: "table: mane\n",
			asTOML: "table = \"mane\"\n",
		},
		"an announcement with an unknown field": {
			asYAML: "announce: [{ prefix: \"::/0\", form: 2001:db8::/48 }]\n",
			asTOML: "announce = [{ prefix = \"::/0\", form = \"2001:db8::/48\" }]\n",
		},
		"an announcement with no prefix": {
			asYAML: "announce: [{ from: 2001:db8::/48 }]\n",
			asTOML: "announce = [{ from = \"2001:db8::/48\" }]\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeYAML(t, pair.asYAML); err == nil {
				t.Errorf("yaml took %q", pair.asYAML)
			}
			if _, err := decodeTOML(t, pair.asTOML); err == nil {
				t.Errorf("toml took %q", pair.asTOML)
			}
		})
	}
}

// A duration is a scalar. Reading Value off a mapping or a sequence gives the
// empty string, and `invalid duration ""` names neither the line nor what was
// written there.
func TestDurationRefusalNamesWhatWasWritten(t *testing.T) {
	_, err := decodeYAML(t, "interval: [4s]\n")
	if err == nil {
		t.Fatal("a sequence was taken as a duration")
	}
	if !strings.Contains(err.Error(), "a sequence") {
		t.Errorf("the error reads %q, which does not say what was written instead", err)
	}
}

// A bare zero disables a timer, and every other spelling in this file takes
// one, so the two decoders have to agree about it as well.
func TestZeroIntervalIsTakenByBothDecoders(t *testing.T) {
	for name, body := range map[string]func(*testing.T) (holder, error){
		"yaml": func(t *testing.T) (holder, error) { return decodeYAML(t, "interval: 0\n") },
		"toml": func(t *testing.T) (holder, error) { return decodeTOML(t, "interval = 0\n") },
	} {
		t.Run(name, func(t *testing.T) {
			got, err := body(t)
			if err != nil {
				t.Fatalf("a zero interval was refused: %v", err)
			}
			if got.Interval != 0 {
				t.Errorf("a zero interval parsed as %s", got.Interval)
			}
		})
	}
}

func TestTableNamesSurviveARoundTrip(t *testing.T) {
	for _, table := range []TableID{TableMain, TableLocal, TableDefault, 200, 51820} {
		text, err := table.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var got TableID
		if err := got.UnmarshalText(text); err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if got != table {
			t.Errorf("table %d was written as %q and read back as %d", table, text, got)
		}
	}
}

// A value with no spelling is refused by every marshaller, not only by the
// text one. MarshalYAML used to answer the "invalid Prefix" String gives for a
// zero prefix, which renders without complaint and which no decoder reads
// back, so a rendered configuration would be one nothing can load.
func TestEveryMarshallerRefusesAValueWithNoSpelling(t *testing.T) {
	for name, empty := range map[string]any{
		"a prefix carrying no address": Prefix{},
		"an address carrying no value": Addr{},
	} {
		t.Run(name, func(t *testing.T) {
			rendered, err := yaml.Marshal(empty)
			if err == nil {
				t.Errorf("yaml wrote %q, which nothing reads back", strings.TrimSpace(string(rendered)))
			}
			if _, err := empty.(encoding.TextMarshaler).MarshalText(); err == nil {
				t.Error("the text half wrote it too")
			}
		})
	}
}

// encoding/json is the control plane's decoder, and rule 5 of the capability
// plan says the file and the wire form are one schema. Without UnmarshalJSON
// the bare spelling went through the text half and the mapping one was refused
// outright, so an exit's announcement could be written in a file and not sent
// over the wire.
func TestJSONReadsBothAnnouncementSpellings(t *testing.T) {
	want := []Announce{
		{Prefix: MustPrefix("10.66.0.5/32")},
		{Prefix: MustPrefix("::/0"), From: MustPrefix("2001:db8::/48")},
	}
	var got []Announce
	if err := json.Unmarshal([]byte(`["10.66.0.5/32", {"prefix": "::/0", "from": "2001:db8::/48"}]`), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("json read %v, want %v", got, want)
	}
	// And it reads back what it rendered, so a capability sent to a daemon and
	// one written in a file describe the same node.
	rendered, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := json.Unmarshal(rendered, &got); err != nil {
		t.Fatalf("parse %s: %v", rendered, err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("the json round trip gave %v from %s", got, rendered)
	}
	// The same refusals the other two decoders make. A nested decoder is told
	// nothing about unknown keys, so the walk has to refuse them itself.
	for name, body := range map[string]string{
		"an unknown field":              `[{"prefix": "::/0", "form": "2001:db8::/48"}]`,
		"no prefix":                     `[{"from": "2001:db8::/48"}]`,
		"a prefix that is not a string": `[{"prefix": 5}]`,
		"neither spelling":              `[["10.66.0.5/32"]]`,
	} {
		t.Run(name, func(t *testing.T) {
			var refused []Announce
			if err := json.Unmarshal([]byte(body), &refused); err == nil {
				t.Errorf("json took %s as %v", body, refused)
			}
		})
	}
}

// An entry whose prefix and from are both wrong names the same half under
// every decoder. The toml walk sorted its keys, which puts from first, while
// the yaml walk and Routes.Validate both take prefix first, so the three
// disagreed about which half to name.
func TestEveryDecoderNamesTheSameHalfOfABadAnnouncement(t *testing.T) {
	// Each half is spelled wrong differently, so the refusal says which one it
	// reached rather than only that something was wrong.
	const badPrefix, badFrom = "xn--prefix", "xn--from"
	named := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("an announcement with two bad halves was taken")
		}
		if !strings.Contains(err.Error(), badPrefix) {
			t.Errorf("the refusal reads %q, and prefix is the half the yaml walk and Routes.Validate name first", err)
		}
	}
	var fromYAML Announce
	named(t, yaml.Unmarshal([]byte("{ prefix: "+badPrefix+", from: "+badFrom+" }"), &fromYAML))
	var fromTOML Announce
	named(t, fromTOML.UnmarshalTOML(map[string]any{"prefix": badPrefix, "from": badFrom}))
	var fromJSON Announce
	named(t, json.Unmarshal([]byte(`{"prefix": "`+badPrefix+`", "from": "`+badFrom+`"}`), &fromJSON))
}

func equal(a, b holder) bool {
	if a.Interval != b.Interval || a.Prefix != b.Prefix || a.Address != b.Address || a.Table != b.Table {
		return false
	}
	if len(a.Announce) != len(b.Announce) {
		return false
	}
	for i := range a.Announce {
		if a.Announce[i] != b.Announce[i] {
			return false
		}
	}
	return true
}
