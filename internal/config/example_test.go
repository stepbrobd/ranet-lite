package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The shipped example is what an operator copies, so a change to how a field
// is spelled is checked against it rather than against a fixture written next
// to the change. The integration test's own spelling, which is sub-second, is
// checked the same way: both are durations written as Go duration strings,
// which is the one spelling this file accepts.
func TestTheShippedExampleParses(t *testing.T) {
	const example = "../../examples/config.yaml"
	cfg, err := Load(example)
	if err != nil {
		t.Fatalf("%s: %v", example, err)
	}
	if got := time.Duration(cfg.Babel.HelloInterval); got != 4*time.Second {
		t.Errorf("hello_interval parsed as %v", got)
	}
	if got := time.Duration(cfg.Babel.UpdateInterval); got != 16*time.Second {
		t.Errorf("update_interval parsed as %v", got)
	}

	raw, err := os.ReadFile(example)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.NewReplacer("hello_interval: 4s", "hello_interval: 500ms",
		"update_interval: 16s", "update_interval: 1s").Replace(string(raw))
	if body == string(raw) {
		t.Fatal("the example no longer spells the intervals the way this test rewrites")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("the sub-second spelling the integration test uses was refused: %v", err)
	}
	if got := time.Duration(cfg.Babel.HelloInterval); got != 500*time.Millisecond {
		t.Errorf("hello_interval parsed as %v", got)
	}

	// Zero is what every other duration in this file takes for "leave the
	// default alone", and yaml.v3 decodes a bare time.Duration from a duration
	// string and from nothing else, so this one spelling was a parse error in
	// the middle of a block that accepts it two lines below.
	body = strings.Replace(string(raw), "hello_interval: 4s", "hello_interval: 0", 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("a zero interval was refused: %v", err)
	}
	if cfg.Babel.HelloInterval != 0 {
		t.Errorf("a zero interval parsed as %v", time.Duration(cfg.Babel.HelloInterval))
	}

	// A duration is a scalar. Reading Value off a mapping or a sequence gives
	// the empty string, and `invalid duration ""` names neither the line nor
	// what was written there.
	body = strings.Replace(string(raw), "hello_interval: 4s", "hello_interval: [4s]", 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Load(path)
	if err == nil {
		t.Fatal("a sequence was accepted as a duration")
	}
	if !strings.Contains(err.Error(), "a sequence") {
		t.Errorf("the error reads %q, which does not say what was written instead", err)
	}
}
