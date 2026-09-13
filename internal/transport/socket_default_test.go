//go:build !linux

package transport

import (
	"strings"
	"testing"
)

// SO_MARK is a linux facility. A platform without it must refuse a mark rather
// than ignore one, because the configuration that asked for it was written to
// keep the underlay out of a table, and a rule that never matches is worse
// than an error at startup. darwin needs no mark: an announced default is
// installed interface-scoped there, so an unbound socket never sees it.
func TestFWMarkIsRefusedWhereItCannotBeSet(t *testing.T) {
	_, err := NewHub(":0", 0x5115)
	if err == nil {
		t.Fatal("a mark this platform cannot set was accepted")
	}
	// Wrapped once by NewHub, so the reason has to survive without repeating
	// the package name an operator already sees.
	if got := err.Error(); !strings.Contains(got, "fwmark") || strings.Count(got, "transport:") != 1 {
		t.Errorf("the refusal reads %q", got)
	}
	hub, err := NewHub(":0", 0)
	if err != nil {
		t.Fatalf("an unmarked hub was refused: %v", err)
	}
	_ = hub.Close()
}
