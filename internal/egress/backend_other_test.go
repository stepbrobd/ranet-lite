//go:build !linux

package egress

import (
	"errors"
	"strings"
	"testing"

	"github.com/NickCao/ranet-lite/schema"
)

// The capability is refused by name where there is no packet filter to write
// into, rather than accepted and quietly doing nothing. A node that came up as
// an exit and translated nothing would advertise itself and then drop every
// flow that took it, which is the failure internal/kernel refuses a policy
// rule on darwin to avoid.
func TestUnsupportedPlatformRefusesTheCapabilityByName(t *testing.T) {
	cfg := Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0")}}
	_, err := New(cfg, Runtime{Interface: "ranet0", Forwarding: func() (bool, bool) { return true, true }})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("New returned %v, want the unsupported sentinel", err)
	}
	if !strings.Contains(err.Error(), "cap.egress") {
		t.Errorf("the refusal %q does not name the capability that asked for it", err)
	}
	if !strings.Contains(err.Error(), "nftables") {
		t.Errorf("the refusal %q does not say what is missing", err)
	}
}
