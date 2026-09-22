package ike

import (
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/schema"
)

// A node that writes no cap.crypto runs these, and a fleet mid-migration has
// to agree with the strongSwan it is replacing about every one of them.
func TestCryptoDefaultsAreTheOnesDocumented(t *testing.T) {
	var absent Crypto
	for name, got := range map[string]struct{ have, want time.Duration }{
		"rekey child":       {absent.ChildInterval(), time.Hour},
		"rekey ike":         {absent.IKEInterval(), 3 * time.Hour},
		"rekey margin":      {absent.Margin(), 5 * time.Minute},
		"rekey jitter":      {absent.Jitter(), time.Minute},
		"rekey retry first": {absent.RetryFirst(), 5 * time.Second},
		"rekey retry max":   {absent.RetryMax(), 5 * time.Minute},
	} {
		if got.have != got.want {
			t.Errorf("default %s is %s, want %s", name, got.have, got.want)
		}
	}
	if absent.ReplayWindow() != DefaultReplayWindow {
		t.Errorf("default replay window is %d, want %d", absent.ReplayWindow(), DefaultReplayWindow)
	}
	if err := absent.Validate(); err != nil {
		t.Errorf("the defaults do not validate: %v", err)
	}
	// An explicit zero is a window turned off rather than an absent field.
	for _, want := range []uint32{0, 64, 8192} {
		configured := want
		if got := (Crypto{Replay: &configured}).ReplayWindow(); got != want {
			t.Errorf("configured replay window = %d, want %d", got, want)
		}
	}
}

// Everything a session captures when it is created reaches it from here, so a
// value written in the file and dropped on the way through would leave a node
// running the default while its operator reads otherwise.
func TestConfiguredCryptoReachesEveryTimer(t *testing.T) {
	interval := func(d time.Duration) *schema.Duration {
		value := schema.Duration(d)
		return &value
	}
	crypto := Crypto{Rekey: Rekey{
		Child:  interval(2 * time.Hour),
		IKE:    interval(8 * time.Hour),
		Margin: interval(10 * time.Minute),
		Jitter: interval(2 * time.Minute),
		Retry:  Retry{First: interval(3 * time.Second), Max: interval(30 * time.Second)},
	}}
	if err := crypto.Validate(); err != nil {
		t.Fatalf("a configuration a session could run was refused: %v", err)
	}
	for name, got := range map[string]struct{ have, want time.Duration }{
		"rekey child":       {crypto.ChildInterval(), 2 * time.Hour},
		"rekey ike":         {crypto.IKEInterval(), 8 * time.Hour},
		"rekey margin":      {crypto.Margin(), 10 * time.Minute},
		"rekey jitter":      {crypto.Jitter(), 2 * time.Minute},
		"rekey retry first": {crypto.RetryFirst(), 3 * time.Second},
		"rekey retry max":   {crypto.RetryMax(), 30 * time.Second},
	} {
		if got.have != got.want {
			t.Errorf("%s is %s, want %s", name, got.have, got.want)
		}
	}
	// A rekey runs interval minus margin minus jitter, so a disabled interval
	// has no schedule for either to fit inside and neither is contradictory.
	disabled := Crypto{Rekey: Rekey{
		Child:  interval(0),
		IKE:    interval(0),
		Margin: interval(time.Hour),
		Jitter: interval(time.Hour),
	}}
	if err := disabled.Validate(); err != nil {
		t.Errorf("a margin beside two disabled rekeys was refused: %v", err)
	}
}

// Each of these is a session that could not run the timers it was handed, and
// the refusal names the field as the operator wrote it.
func TestCryptoRefusesTimingsASessionCannotRun(t *testing.T) {
	interval := func(d time.Duration) *schema.Duration {
		value := schema.Duration(d)
		return &value
	}
	oversized := uint32(1<<20 + 1)
	for name, crypto := range map[string]Crypto{
		"a replay window past the cap": {Replay: &oversized},
		"a negative child rekey":       {Rekey: Rekey{Child: interval(-time.Second)}},
		"a negative ike rekey":         {Rekey: Rekey{IKE: interval(-time.Second)}},
		"a negative margin":            {Rekey: Rekey{Margin: interval(-time.Second)}},
		"a negative jitter":            {Rekey: Rekey{Jitter: interval(-time.Second)}},
		"a zero first retry":           {Rekey: Rekey{Retry: Retry{First: interval(0)}}},
		"a zero retry maximum":         {Rekey: Rekey{Retry: Retry{Max: interval(0)}}},
		"a negative first retry":       {Rekey: Rekey{Retry: Retry{First: interval(-time.Second)}}},
		"a first retry past the max": {Rekey: Rekey{Retry: Retry{
			First: interval(time.Minute), Max: interval(5 * time.Second),
		}}},
		"a child rekey shorter than its margin": {Rekey: Rekey{Child: interval(5 * time.Minute)}},
		"an ike rekey shorter than its margin":  {Rekey: Rekey{IKE: interval(6 * time.Minute)}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := crypto.Validate(); err == nil {
				t.Error("a session that could not run these timers was accepted")
			}
		})
	}
}
