//go:build !linux && !darwin

package transport

import (
	"strings"
	"testing"
)

// Both spellings of keeping the underlay out are platform facilities: SO_MARK
// is linux, IP_BOUND_IF is darwin. A platform with neither must refuse the
// configuration rather than ignore it, because what asked for it was written
// to keep the underlay out of a table, and a setting that never takes effect
// is worse than an error at startup.
func TestUnderlayIsolationIsRefusedWhereItCannotBeSet(t *testing.T) {
	for name, underlay := range map[string]Underlay{
		"a socket mark":                {Mark: 0x5115},
		"an interface binding":         {Bind: true},
		"a mark and a binding at once": {Mark: 0x5115, Bind: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewHub(":0", underlay, Runtime{})
			if err == nil {
				t.Fatal("a setting this platform cannot apply was accepted")
			}
			// Wrapped once by NewHub, so the reason has to survive without
			// repeating the package name an operator already sees.
			if got := err.Error(); strings.Count(got, "transport:") != 1 {
				t.Errorf("the refusal reads %q", got)
			}
		})
	}
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatalf("a hub asking for neither was refused: %v", err)
	}
	_ = hub.Close()
}
