package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/babel"
)

const testConfig = `
organization: example
common_name: laptop
port: 13000
endpoints:
  - serial_number: "0"
    address_family: ip4
private_key: key.pem
registry: registry.json
peers:
  - common_name: gateway
`

func TestRekeyIntervals(t *testing.T) {
	tests := []struct {
		name             string
		yaml             string
		wantChild        time.Duration
		wantIKE          time.Duration
		wantMargin       time.Duration
		wantJitter       time.Duration
		wantRetryInitial time.Duration
		wantRetryMax     time.Duration
		wantErr          bool
	}{
		{name: "defaults", yaml: testConfig, wantChild: time.Hour, wantIKE: 3 * time.Hour, wantMargin: 5 * time.Minute, wantJitter: time.Minute, wantRetryInitial: 5 * time.Second, wantRetryMax: 5 * time.Minute},
		{name: "explicitly disabled", yaml: testConfig + "child_rekey_interval: 0\nike_rekey_interval: 0\n", wantMargin: 5 * time.Minute, wantJitter: time.Minute, wantRetryInitial: 5 * time.Second, wantRetryMax: 5 * time.Minute},
		{name: "configured", yaml: testConfig + "child_rekey_interval: 2h\nike_rekey_interval: 8h\nrekey_margin: 10m\nrekey_jitter: 2m\nrekey_retry_initial: 3s\nrekey_retry_max: 30s\n", wantChild: 2 * time.Hour, wantIKE: 8 * time.Hour, wantMargin: 10 * time.Minute, wantJitter: 2 * time.Minute, wantRetryInitial: 3 * time.Second, wantRetryMax: 30 * time.Second},
		{name: "negative child", yaml: testConfig + "child_rekey_interval: -1s\n", wantErr: true},
		{name: "negative IKE", yaml: testConfig + "ike_rekey_interval: -1s\n", wantErr: true},
		{name: "negative margin", yaml: testConfig + "rekey_margin: -1s\n", wantErr: true},
		{name: "negative jitter", yaml: testConfig + "rekey_jitter: -1s\n", wantErr: true},
		{name: "zero retry initial", yaml: testConfig + "rekey_retry_initial: 0\n", wantErr: true},
		{name: "zero retry max", yaml: testConfig + "rekey_retry_max: 0\n", wantErr: true},
		{name: "negative retry initial", yaml: testConfig + "rekey_retry_initial: -1s\n", wantErr: true},
		{name: "retry initial exceeds max", yaml: testConfig + "rekey_retry_initial: 1m\nrekey_retry_max: 5s\n", wantErr: true},
		{name: "child timing too short", yaml: testConfig + "child_rekey_interval: 5m\n", wantErr: true},
		{name: "IKE timing too short", yaml: testConfig + "ike_rekey_interval: 6m\n", wantErr: true},
		{name: "disabled interval ignores timing", yaml: testConfig + "child_rekey_interval: 0\nrekey_margin: 1h\nrekey_jitter: 1h\n", wantIKE: 3 * time.Hour, wantMargin: time.Hour, wantJitter: time.Hour, wantRetryInitial: 5 * time.Second, wantRetryMax: 5 * time.Minute},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(test.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if test.wantErr {
				if err == nil {
					t.Fatal("Load succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ChildRekeyIntervalValue() != test.wantChild || cfg.IKERekeyIntervalValue() != test.wantIKE || cfg.RekeyMarginValue() != test.wantMargin || cfg.RekeyJitterValue() != test.wantJitter || cfg.RekeyRetryInitialValue() != test.wantRetryInitial || cfg.RekeyRetryMaxValue() != test.wantRetryMax {
				t.Fatalf("rekey timings = %s, %s, %s, %s, %s, %s; want %s, %s, %s, %s, %s, %s", cfg.ChildRekeyIntervalValue(), cfg.IKERekeyIntervalValue(), cfg.RekeyMarginValue(), cfg.RekeyJitterValue(), cfg.RekeyRetryInitialValue(), cfg.RekeyRetryMaxValue(), test.wantChild, test.wantIKE, test.wantMargin, test.wantJitter, test.wantRetryInitial, test.wantRetryMax)
			}
		})
	}
}

func TestReplayWindow(t *testing.T) {
	if got := (&Config{}).ReplayWindowSize(); got != 4096 {
		t.Fatalf("default replay window = %d, want 4096", got)
	}

	for _, want := range []uint32{0, 64, 8192} {
		configured := want
		if got := (&Config{ReplayWindow: &configured}).ReplayWindowSize(); got != want {
			t.Fatalf("configured replay window = %d, want %d", got, want)
		}
	}
}

func TestLoadRejectsInvalidOperationalConfiguration(t *testing.T) {
	for name, addition := range map[string]string{
		"unknown field":         "unknown: true\n",
		"negative babel":        "babel:\n  hello_interval: -1s\n",
		"oversized replay":      "replay_window: 1048577\n",
		"invalid originate":     "originate: [not-a-prefix]\n",
		"missing peer name":     "peers:\n  - organization: example\n",
		"duplicate endpoint":    "endpoints:\n  - serial_number: \"0\"\n    address_family: ip4\n  - serial_number: \"0\"\n    address_family: ip4\n",
		"duplicate peer":        "peers:\n  - common_name: gateway\n  - common_name: gateway\n",
		"unrepresentable babel": "babel:\n  update_interval: 11m\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(testConfig+addition), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load succeeded, want error")
			}
		})
	}
}

func TestResponderConfigNeedsNoPeers(t *testing.T) {
	base := `
organization: example
common_name: laptop
port: 13000
endpoints:
  - serial_number: "0"
    address_family: ip4
private_key: key.pem
registry: registry.json
`
	load := func(t *testing.T, yaml string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		return err
	}
	if err := load(t, base); err == nil {
		t.Fatal("a config that neither dials nor answers was accepted")
	}
	if err := load(t, base+"responder: true\n"); err != nil {
		t.Fatalf("a responder with no peers was rejected: %v", err)
	}
}

// Both the shipped defaults and the optional YAML get copied into real
// configurations, so neither may hide invalid fields or duplicate blocks.
func TestExampleConfigParses(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "examples", "config.yaml"))
	if err != nil {
		t.Fatalf("read the example: %v", err)
	}
	// Match the example's commented lowercase keys and list items, not prose
	// or shell commands. Removing only "# " preserves YAML nesting.
	commentedYAML := regexp.MustCompile(`(?m)^([ ]*)# ([ ]*(?:[a-z_][a-z0-9_]*:|-[ ]).*)$`)
	for name, body := range map[string][]byte{
		"shipped":             example,
		"all options enabled": commentedYAML.ReplaceAll(example, []byte(`${1}${2}`)),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err != nil {
				t.Fatalf("the example no longer loads: %v", err)
			}
		})
	}
}

// An IPv4 source-specific announcement is accepted by nothing: BIRD drops the
// Update whole because it has no IPv4 SADR channel, and the IPv4 FIB has no
// source-specific lookup for internal/kernel to install into. Refusing it at
// load is the only place it can be said out loud.
func TestOriginateRefusesIPv4SourceSpecific(t *testing.T) {
	load := func(t *testing.T, addition string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(testConfig+addition), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		return err
	}
	err := load(t, "babel:\n  originate:\n    - {prefix: 0.0.0.0/0, from: 198.51.100.0/24}\n")
	if err == nil {
		t.Fatal("an IPv4 source-specific origination was accepted, and it reaches nobody")
	}
	if err := load(t, "babel:\n  originate:\n    - {prefix: \"::/0\", from: \"2001:db8::/48\"}\n"); err != nil {
		t.Errorf("the IPv6 form was refused: %v", err)
	}
}

func TestOriginateRefusesUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// A valid prefix value isolates unknown-field rejection from parsing.
	body := testConfig + "babel:\n  originate:\n    - {prefix: \"::/0\", form: \"2001:db8::/48\"}\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("an unknown originate field was accepted")
	}
}

func TestOriginateRefusesMismatchedFamilies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// An IPv6 destination keeps the IPv4 source-specific guard from masking
	// a missing address-family check.
	body := testConfig + "babel:\n  originate:\n    - {prefix: \"::/0\", from: 198.51.100.0/24}\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("originate prefixes with mismatched address families were accepted")
	}
}

// Every IKE datagram here carries the non-ESP marker, and RFC 7296 section
// 2.23 forbids UDP encapsulation on port 500, so a config naming it would
// build a node no conformant peer can talk to.
func TestConfigRejectsPort500(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := strings.Replace(testConfig, "port: 13000", "port: 500", 1)
	if body == testConfig {
		t.Fatal("the fixture no longer names a port, so this test proves nothing")
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("port 500 was accepted")
	}
}

// The link cost surface is what a node uses to look as expensive as the BIRD
// speaker it replaces. Nothing else reads these four fields, so without this
// they could all be dropped from SpeakerConfig with every check still green,
// and a node configured to match its peers would silently run on defaults.
func TestBabelCostFieldsReachSpeaker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := testConfig + `babel:
  rxcost: 42
  rtt_cost: 4242
  rtt_min: 7ms
  rtt_max: 77ms
  hello_interval: 3s
  update_interval: 9s
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	speaker := cfg.Babel.SpeakerConfig()
	if speaker.Cost.RxCost != 42 {
		t.Errorf("rxcost reached the speaker as %d, want 42", speaker.Cost.RxCost)
	}
	if speaker.Cost.RTTCost != 4242 {
		t.Errorf("rtt_cost reached the speaker as %d, want 4242", speaker.Cost.RTTCost)
	}
	if speaker.Cost.RTTMin != 7*time.Millisecond {
		t.Errorf("rtt_min reached the speaker as %s, want 7ms", speaker.Cost.RTTMin)
	}
	if speaker.Cost.RTTMax != 77*time.Millisecond {
		t.Errorf("rtt_max reached the speaker as %s, want 77ms", speaker.Cost.RTTMax)
	}
	if speaker.HelloInterval != 3*time.Second || speaker.UpdateInterval != 9*time.Second {
		t.Errorf("intervals reached the speaker as %s/%s, want 3s/9s",
			speaker.HelloInterval, speaker.UpdateInterval)
	}

	// Omitted, the speaker's own defaults stand, matching BIRD.
	bare := Babel{}.SpeakerConfig()
	if bare.Cost != babel.DefaultCostParams() {
		t.Errorf("an empty block changed the defaults to %+v", bare.Cost)
	}
}

// Both refusals below are written by hand, because the nested decoder does not
// inherit KnownFields from the outer one.
func TestOriginateMappingRefusesWhatItCannotMean(t *testing.T) {
	load := func(t *testing.T, entry string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		body := fmt.Sprintf(`organization: example
common_name: node
port: 13000
endpoints:
  - serial_number: "0"
    address_family: ip4
private_key: /dev/null
registry: /dev/null
responder: true
babel:
  originate:
    - %s
`, entry)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		return err
	}
	if err := load(t, `{ prefix: "::/0", from: "2001:db8::/48" }`); err != nil {
		t.Fatalf("a well-formed source-specific announcement was refused: %v", err)
	}
	for name, entry := range map[string]string{
		// A key nobody reads is a prefix nobody announces, and the operator
		// has no way to tell from the outside.
		"unknown field": `{ prefix: "::/0", form: "2001:db8::/48" }`,
		// Neither family has a lookup that could express this, and installing
		// it as an ordinary route would steal traffic from every other source.
		"mismatched families": `{ prefix: "::/0", from: "10.0.0.0/8" }`,
		// originatedKey masks, so this announces "::/0" and claims the exit.
		// The mapping spelling is the one an exit actually uses, so refusing
		// it only in the top-level list refuses it where nobody writes it.
		"masked default":        `{ prefix: "2001:db8::1/0", from: "2602:f590::/36" }`,
		"masked default, bare":  `2001:db8::1/0`,
		"masked default, v4":    `198.51.100.1/0`,
		"masked source default": `{ prefix: "2001:db8::/48", from: "2001:db8::1/0" }`,
		// A source covering every address is kept by nothing: originatedKey
		// drops it and the entry becomes an ordinary announcement.
		"source covering everything": `{ prefix: "2001:db8::/48", from: "::/0" }`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := load(t, entry); err == nil {
				t.Error("the config loaded, so nothing says this cannot mean what it looks like")
			}
		})
	}
}

// An exit originates a default from its transit prefix, so assign_originated
// must not try to put that default on the tun: AddAddr would be called with
// "::/0" on every pass and fail on every one.
func TestAssignOriginatedSkipsADefault(t *testing.T) {
	cfg := &Config{
		Originate: []string{"0.0.0.0/0", "10.66.0.5/32"},
		Babel: Babel{Originate: []OriginatePrefix{
			{Prefix: netip.MustParsePrefix("::/0"), From: netip.MustParsePrefix("2001:db8::/48")},
			{Prefix: netip.MustParsePrefix("2001:db8::5/128")},
		}},
		Kernel: Kernel{AssignOriginated: true},
	}
	got, err := cfg.KernelAddresses()
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range got {
		if prefix.Bits() == 0 {
			t.Errorf("a default reached the addresses assigned to the tun: %v", got)
		}
	}
	if len(got) != 2 {
		t.Errorf("assigned %v, want only the two host prefixes", got)
	}
}

// The top-level list is the other spelling of the same announcement, and what
// an operator writes for a prefix with no source. Both entries below load into
// a node that announces something other than what it says, and the second is
// an address the reconciler retries on every pass for the life of the process.
func TestTopLevelListsRefuseWhatTheyCannotMean(t *testing.T) {
	load := func(t *testing.T, addition string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(testConfig+addition), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		return err
	}
	for name, addition := range map[string]string{
		"originate masked default":    "originate:\n  - 2001:db8::1/0\n",
		"originate masked default v4": "originate:\n  - 198.51.100.1/0\n",
		"kernel address unspecified":  "kernel:\n  enabled: true\n  addresses:\n    - \"::/0\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := load(t, addition); err == nil {
				t.Error("the config loaded, so nothing says this cannot mean what it looks like")
			}
		})
	}
	// The spellings that do mean what they say stay accepted.
	for name, addition := range map[string]string{
		"a real default":   "originate:\n  - \"::/0\"\n",
		"a real address":   "kernel:\n  enabled: true\n  addresses:\n    - 2001:db8::1/128\n",
		"a plain announce": "originate:\n  - 2001:db8::/48\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := load(t, addition); err != nil {
				t.Errorf("a well-formed entry was refused: %v", err)
			}
		})
	}
}
