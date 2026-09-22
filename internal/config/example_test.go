package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The three shipped examples, one per extension a configuration may carry. An
// operator copies one of them, so a change to how a field is spelled is
// checked against the file they will copy rather than against a fixture
// written next to the change.
var examples = map[string]struct {
	path string
	// commented matches the optional lines the file documents, so the test can
	// enable all of them at once. Removing the marker and nothing else has to
	// leave a configuration that still loads, or the documentation is wrong
	// about what it says an operator may turn on. It is nil where the format
	// has no comment syntax and so documents nothing.
	commented *regexp.Regexp
	enabled   string
}{
	"toml": {
		path:      filepath.Join("..", "..", "examples", "config.toml"),
		commented: regexp.MustCompile(`(?m)^# ((?:\[|\]|[a-z_][a-z0-9_]* = |  ).*)$`),
		enabled:   `${1}`,
	},
	"yaml": {
		path:      filepath.Join("..", "..", "examples", "config.yaml"),
		commented: regexp.MustCompile(`(?m)^([ ]*)# ([ ]*(?:[a-z_][a-z0-9_]*:|-[ ]).*)$`),
		enabled:   `${1}${2}`,
	},
	"json": {path: filepath.Join("..", "..", "examples", "config.json")},
}

// The extensions whose format carries no comment, so their example documents
// no optional line and the half of TestShippedExamplesParse that enables one
// has nothing to work on. Named here rather than read off a nil commented
// pattern, because a yaml entry that lost its pattern would then skip that
// half without saying so.
var uncommentable = map[string]bool{"json": true}

// Both the shipped defaults and the optional lines get copied into real
// configurations, so neither may hide an invalid field or a duplicate block.
func TestShippedExamplesParse(t *testing.T) {
	for name, example := range examples {
		body, err := os.ReadFile(example.path)
		if err != nil {
			t.Fatalf("read the example: %v", err)
		}
		variants := map[string][]byte{"shipped": body}
		if !uncommentable[name] {
			variants["all options enabled"] = example.commented.ReplaceAll(body, []byte(example.enabled))
		}
		for which, variant := range variants {
			t.Run(name+" "+which, func(t *testing.T) {
				if _, err := loadExample(t, name, variant); err != nil {
					t.Fatalf("the example no longer loads: %v", err)
				}
			})
		}
		if uncommentable[name] {
			continue
		}
		if enabled := example.commented.ReplaceAll(body, []byte(example.enabled)); string(enabled) == string(body) {
			t.Errorf("%s documents no optional line, so half of this test proves nothing", name)
		}
	}
}

// All three examples describe one node, so an operator picking any extension
// gets the same daemon. Only the files' own contents differ: the toml one
// carries the documentation and the other two are the short form, so the
// comparison is on what all of them write.
func TestShippedExamplesAgreeOnTheNode(t *testing.T) {
	loaded := make(map[string]*Config, len(examples))
	for name, example := range examples {
		body, err := os.ReadFile(example.path)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := loadExample(t, name, body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		loaded[name] = cfg
	}
	// Compared whole rather than field by field. Counting two slices let the
	// toml example ship a live "::/0 from 2001:db8:1::/48" while the yaml one
	// announced a single address, so copying the annotated reference started a
	// node claiming to be an exit.
	//
	// The toml file is the reference because it is the annotated one, so a
	// mismatch reads as the shorter file having drifted from it.
	reference := loaded["toml"]
	for name, cfg := range loaded {
		if name == "toml" {
			continue
		}
		if !reflect.DeepEqual(reference, cfg) {
			t.Errorf("the toml and %s examples describe different nodes:\ntoml %s\n%s %s",
				name, rendered(t, reference), name, rendered(t, cfg))
		}
	}
	// Neither of them is an exit. The reference is the ordinary case, and an
	// exit is described in prose beside the line it would change.
	for name, cfg := range loaded {
		for _, announced := range cfg.Routes().Announce {
			if announced.From.IsValid() {
				t.Errorf("the %s example announces %s, so copying it starts an exit node", name, announced)
			}
		}
	}
}

// A .json file goes to the YAML decoder, which accepts a great deal that JSON
// does not. So every other check in this file would pass on an examples
// config.json holding plain YAML, while jq, a control plane and anything else
// an operator points at the file would refuse it.
func TestShippedJSONExampleIsJSONAndNotOnlyYAML(t *testing.T) {
	body, err := os.ReadFile(examples["json"].path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		t.Errorf("the json example is not valid json: %v", err)
	}
	// The same document in the spelling this test exists to refuse, so a
	// change that made the check vacuous fails here rather than passing.
	if err := json.Unmarshal([]byte("node:\n  org: example\n"), &document); err == nil {
		t.Error("json.Unmarshal took a yaml mapping, so this test would pass on a yaml file")
	}
}

// rendered puts a configuration back into the file's own spelling, so a
// mismatch above reads as the two files rather than as two struct dumps full
// of pointers.
func rendered(t *testing.T, cfg *Config) string {
	t.Helper()
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return "\n" + string(body)
}

// The integration harness writes sub-second intervals, which is the one
// spelling this file accepts that the examples do not use, so it is checked
// against the example rather than against a fixture of its own.
func TestExampleTakesTheIntervalsTheHarnessWrites(t *testing.T) {
	body, err := os.ReadFile(examples["yaml"].path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.NewReplacer("hello: 4s", "hello: 500ms", "update: 16s", "update: 1s").Replace(string(body))
	if rewritten == string(body) {
		t.Fatal("the example no longer spells the intervals the way this test rewrites")
	}
	cfg, err := loadExample(t, "yaml", []byte(rewritten))
	if err != nil {
		t.Fatalf("the sub-second spelling the integration test uses was refused: %v", err)
	}
	if cfg.Babel().HelloInterval() != 500*time.Millisecond {
		t.Errorf("hello parsed as %v", cfg.Babel().HelloInterval())
	}

	// Every other duration in this file takes a bare zero for "leave the
	// default alone", and the two decoders have to agree about that too.
	zeroed := strings.Replace(string(body), "hello: 4s", "hello: 0", 1)
	cfg, err = loadExample(t, "yaml", []byte(zeroed))
	if err != nil {
		t.Fatalf("a zero interval was refused: %v", err)
	}
	if cfg.Babel().Hello != 0 {
		t.Errorf("a zero interval parsed as %v", cfg.Babel().Hello)
	}

	// A duration is a scalar. Reading Value off a mapping or a sequence gives
	// the empty string, and `invalid duration ""` names neither the line nor
	// what was written there.
	sequence := strings.Replace(string(body), "hello: 4s", "hello: [4s]", 1)
	_, err = loadExample(t, "yaml", []byte(sequence))
	if err == nil {
		t.Fatal("a sequence was accepted as a duration")
	}
	if !strings.Contains(err.Error(), "a sequence") {
		t.Errorf("the error reads %q, which does not say what was written instead", err)
	}
}

func loadExample(t *testing.T, extension string, body []byte) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config."+extension)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}
