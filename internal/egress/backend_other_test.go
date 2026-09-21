//go:build !linux

package egress

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// The capability is refused by name where there is no packet filter to write
// into, rather than accepted and quietly doing nothing. A node that came up as
// an exit and translated nothing would advertise itself and then drop every
// flow that took it, which is the failure internal/kernel refuses a policy
// rule on darwin to avoid.
func TestUnsupportedPlatformRefusesTheCapabilityByName(t *testing.T) {
	cfg := Config{Enable: true, Advertise: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	_, err := New(cfg, Runtime{Interface: "ranet0", Forwarding: func() (bool, bool) { return true, true }})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("New returned %v, want the unsupported sentinel", err)
	}
	if !strings.Contains(err.Error(), "egress.enable") {
		t.Errorf("the refusal %q does not name the field that asked for it", err)
	}
	if !strings.Contains(err.Error(), "nftables") {
		t.Errorf("the refusal %q does not say what is missing", err)
	}
}
