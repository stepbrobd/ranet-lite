package ike

import (
	"fmt"
	"time"

	"github.com/NickCao/ranet-lite/schema"
)

// Crypto is the cap.crypto capability, parsed straight out of the file: how
// long a key lives and how far out of order a packet may arrive. It lives here
// rather than beside the ESP code because every one of these values is handed
// to a session this package builds, the replay window included: the window is
// captured when the Child SA is set up, and the initiator and the responder
// have to agree about it.
//
// Every field is a pointer, because an explicit zero and an absent field ask
// for different things: zero disables a rekey, absent takes the default.
type Crypto struct {
	// Replay is the ESP receive window in packets. Omitted uses 4096, which is
	// wider than the interoperable minimum on purpose: a multicore sender
	// reorders bursts by more than 32 before they reach userspace. An explicit
	// 0 turns replay checking off.
	Replay *uint32 `yaml:"replay,omitempty" json:"replay,omitempty" toml:"replay,omitempty"`
	Rekey  Rekey   `yaml:"rekey,omitempty" json:"rekey,omitzero" toml:"rekey,omitempty"`
}

// Rekey is when a key is replaced. A rekey runs before its interval expires:
// Margin is always subtracted and Jitter is independently randomized from zero
// through its value, so a fleet does not rekey in lockstep.
type Rekey struct {
	Child  *schema.Duration `yaml:"child,omitempty" json:"child,omitempty" toml:"child,omitempty"`
	IKE    *schema.Duration `yaml:"ike,omitempty" json:"ike,omitempty" toml:"ike,omitempty"`
	Margin *schema.Duration `yaml:"margin,omitempty" json:"margin,omitempty" toml:"margin,omitempty"`
	Jitter *schema.Duration `yaml:"jitter,omitempty" json:"jitter,omitempty" toml:"jitter,omitempty"`
	Retry  Retry            `yaml:"retry,omitempty" json:"retry,omitzero" toml:"retry,omitempty"`
}

// Retry is the capped exponential backoff after a scheduled rekey fails.
type Retry struct {
	First *schema.Duration `yaml:"first,omitempty" json:"first,omitempty" toml:"first,omitempty"`
	Max   *schema.Duration `yaml:"max,omitempty" json:"max,omitempty" toml:"max,omitempty"`
}

// The defaults every accessor below fills in. They are the values a node runs
// with when cap.crypto is absent entirely.
const (
	DefaultReplayWindow = 4096
	DefaultChildRekey   = time.Hour
	DefaultIKERekey     = 3 * time.Hour
	DefaultRekeyMargin  = 5 * time.Minute
	DefaultRekeyJitter  = time.Minute
	DefaultRetryFirst   = 5 * time.Second
	DefaultRetryMax     = 5 * time.Minute
	maxReplayWindow     = 1 << 20
)

func (c Crypto) ReplayWindow() uint32 {
	if c.Replay == nil {
		return DefaultReplayWindow
	}
	return *c.Replay
}

func (c Crypto) ChildInterval() time.Duration { return interval(c.Rekey.Child, DefaultChildRekey) }
func (c Crypto) IKEInterval() time.Duration   { return interval(c.Rekey.IKE, DefaultIKERekey) }
func (c Crypto) Margin() time.Duration        { return interval(c.Rekey.Margin, DefaultRekeyMargin) }
func (c Crypto) Jitter() time.Duration        { return interval(c.Rekey.Jitter, DefaultRekeyJitter) }
func (c Crypto) RetryFirst() time.Duration    { return interval(c.Rekey.Retry.First, DefaultRetryFirst) }
func (c Crypto) RetryMax() time.Duration      { return interval(c.Rekey.Retry.Max, DefaultRetryMax) }

func interval(configured *schema.Duration, fallback time.Duration) time.Duration {
	if configured == nil {
		return fallback
	}
	return configured.Duration()
}

// Validate refuses timings a session could not run, naming the field as the
// operator wrote it.
func (c Crypto) Validate() error {
	if c.Replay != nil && *c.Replay > maxReplayWindow {
		return fmt.Errorf("ike: cap.crypto replay must not exceed %d", uint32(maxReplayWindow))
	}
	for _, named := range []struct {
		name     string
		value    *schema.Duration
		positive bool
	}{
		{name: "rekey child", value: c.Rekey.Child},
		{name: "rekey ike", value: c.Rekey.IKE},
		{name: "rekey margin", value: c.Rekey.Margin},
		{name: "rekey jitter", value: c.Rekey.Jitter},
		{name: "rekey retry first", value: c.Rekey.Retry.First, positive: true},
		{name: "rekey retry max", value: c.Rekey.Retry.Max, positive: true},
	} {
		if named.value == nil {
			continue
		}
		if named.positive && named.value.Duration() <= 0 {
			return fmt.Errorf("ike: cap.crypto %s must be positive when set", named.name)
		}
		if named.value.Duration() < 0 {
			return fmt.Errorf("ike: cap.crypto %s must be nonnegative when set", named.name)
		}
	}
	if c.RetryFirst() > c.RetryMax() {
		return fmt.Errorf("ike: cap.crypto rekey retry first must not exceed retry max")
	}
	// A rekey runs at interval minus margin minus jitter, so both together
	// have to leave something. A disabled interval has no schedule to fit in.
	for _, named := range []struct {
		name     string
		interval time.Duration
	}{{"child", c.ChildInterval()}, {"ike", c.IKEInterval()}} {
		if interval := named.interval; interval != 0 && !(c.Margin() < interval && c.Jitter() < interval-c.Margin()) {
			return fmt.Errorf("ike: cap.crypto rekey margin plus jitter must be less than rekey %s", named.name)
		}
	}
	return nil
}
