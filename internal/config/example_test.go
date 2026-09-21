package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The two shipped examples, one per decoder. An operator copies one of them,
// so a change to how a field is spelled is checked against the file they will
// copy rather than against a fixture written next to the change.
var examples = map[string]struct {
	path string
	// commented matches the optional lines the file documents, so the test can
	// enable all of them at once. Removing the marker and nothing else has to
	// leave a configuration that still loads, or the documentation is wrong
	// about what it says an operator may turn on.
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
}

// Both the shipped defaults and the optional lines get copied into real
// configurations, so neither may hide an invalid field or a duplicate block.
func TestShippedExamplesParse(t *testing.T) {
	for name, example := range examples {
		body, err := os.ReadFile(example.path)
		if err != nil {
			t.Fatalf("read the example: %v", err)
		}
		for which, variant := range map[string][]byte{
			"shipped":             body,
			"all options enabled": example.commented.ReplaceAll(body, []byte(example.enabled)),
		} {
			t.Run(name+" "+which, func(t *testing.T) {
				if _, err := loadExample(t, name, variant); err != nil {
					t.Fatalf("the example no longer loads: %v", err)
				}
			})
		}
		if enabled := example.commented.ReplaceAll(body, []byte(example.enabled)); string(enabled) == string(body) {
			t.Errorf("%s documents no optional line, so half of this test proves nothing", name)
		}
	}
}

// Both examples describe one node, so an operator picking either extension
// gets the same daemon. Only the two files' own contents differ: the yaml one
// is the short form, so the comparison is on what both of them write.
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
	fromTOML, fromYAML := loaded["toml"], loaded["yaml"]
	if fromTOML.Node != fromYAML.Node || fromTOML.Auth != fromYAML.Auth {
		t.Errorf("the two examples describe different nodes: %+v and %+v", fromTOML.Node, fromYAML.Node)
	}
	if fromTOML.Link.Port != fromYAML.Link.Port || len(fromTOML.Link.Endpoints) != len(fromYAML.Link.Endpoints) {
		t.Errorf("the two examples bind differently: %+v and %+v", fromTOML.Link, fromYAML.Link)
	}
	if len(fromTOML.Dial.To) != len(fromYAML.Dial.To) {
		t.Errorf("the two examples dial differently: %+v and %+v", fromTOML.Dial, fromYAML.Dial)
	}
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
