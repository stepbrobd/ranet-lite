package egress

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// fakeBackend stands in for a kernel. Everything above the backend seam is
// portable, so the diff, the readiness rule and the withdrawal are all
// reachable without a packet filter to write into.
type fakeBackend struct {
	mu        sync.Mutex
	held      []Installed
	conflicts []string
	applied   int
	withdrawn int
	// failApply makes a host that will not take the rules, which is the
	// condition an exit has to refuse to advertise over.
	failApply bool
	// flows is added to each rule's counter on every readback, so a test can
	// tell a rule the pass rewrote from one it left alone.
	flows uint64
}

func (f *fakeBackend) Rules() ([]Installed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.held)
	for i := range out {
		out[i].Packets += f.flows
	}
	return out, nil
}

// Apply stores the rules grouped by family, as the nftables backend does: each
// family is a table of its own, written and read back one at a time. A fake
// that kept the order it was handed would hide a desired list ordered any other
// way, which never compares equal to its own readback.
func (f *fakeBackend) Apply(rules []Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failApply {
		return errors.New("no")
	}
	f.applied++
	f.held = nil
	for _, family := range []uint8{FamilyIPv4, FamilyIPv6} {
		for _, rule := range rules {
			if rule.Family == family {
				f.held = append(f.held, Installed{Spec: rule.String()})
			}
		}
	}
	return nil
}

func (f *fakeBackend) Conflicts() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.conflicts), nil
}

func (f *fakeBackend) Withdraw() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdrawn++
	f.held = nil
	return nil
}

func (f *fakeBackend) Close() error { return nil }

func (f *fakeBackend) where(Config) string { return "a fake host" }

func (f *fakeBackend) specs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.held))
	for _, rule := range f.held {
		out = append(out, rule.Spec)
	}
	return out
}

// translator builds one around a fake backend, bypassing New so that a test
// does not need a packet filter to reach the portable half.
func translator(t *testing.T, cfg Config, rt Runtime, be backend) *Translator {
	t.Helper()
	if rt.Forwarding == nil {
		rt.Forwarding = func() (bool, bool) { return true, true }
	}
	if rt.Interface == "" {
		rt.Interface = "ranet0"
	}
	return &Translator{cfg: cfg, rt: rt, be: be}
}

func prefixes(t *testing.T, raw ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(raw))
	for _, one := range raw {
		prefix, err := netip.ParsePrefix(one)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, prefix)
	}
	return out
}

// An exit node translates the mesh's traffic on the way out and never on the
// way through: a packet that arrives on the mesh device and leaves by it again
// is somebody else's transit, and rewriting its source would put this node's
// address on a packet it is only relaying.
func TestRulesMatchBothInterfacesSoTransitIsNotTranslated(t *testing.T) {
	cfg := Config{Enable: true, Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	be := &fakeBackend{}
	tr := translator(t, cfg, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"out via ranet0 ipv6 masquerade",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// A configured source is used unchanged, which is how a deployment that owns
// an address block pins the address return traffic comes back to.
func TestConfiguredSourceReplacesTheHostsOwnChoice(t *testing.T) {
	cfg := Config{
		Enable:    true,
		Source4:   Source{Addr: netip.MustParseAddr("198.51.100.7")},
		Advertise: prefixes(t, "0.0.0.0/0"),
	}
	be := &fakeBackend{}
	if err := translator(t, cfg, Runtime{}, be).reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{"out via ranet0 ipv4 source 198.51.100.7"}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// A subnet router also translates the other way, under the one mesh address
// this node holds, and narrows that rule to the prefixes it claimed rather
// than to every packet that happens to reach the mesh device.
func TestReturnDirectionTranslatesUnderTheMeshAddress(t *testing.T) {
	cfg := Config{Enable: true, Return: true, Advertise: prefixes(t, "198.51.100.0/24", "192.0.2.5/32")}
	rt := Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("10.88.0.2")}}
	be := &fakeBackend{}
	if err := translator(t, cfg, rt, be).reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"in via ranet0 ipv4 from 198.51.100.0/24 source 10.88.0.2",
		"in via ranet0 ipv4 from 192.0.2.5/32 source 10.88.0.2",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// A prefix covering every address narrows nothing, so the rule that would
// carry it selects on the direction alone rather than on a mask no packet
// fails.
func TestReturnRuleForADefaultCarriesNoPrefixMatch(t *testing.T) {
	cfg := Config{Enable: true, Return: true, Advertise: prefixes(t, "0.0.0.0/0")}
	rt := Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("10.88.0.2")}}
	be := &fakeBackend{}
	if err := translator(t, cfg, rt, be).reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"in via ranet0 ipv4 source 10.88.0.2",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
}

// Each family is a table of its own, written and read back one at a time, so
// the rules a pass asks for have to be grouped by family. A list ordered any
// other way never compares equal to its own readback, and the ruleset is
// rewritten on every pass for the life of the node.
func TestRulesAreGroupedByFamilyAsTheyAreReadBack(t *testing.T) {
	cfg := Config{Enable: true, Return: true, Advertise: prefixes(t, "198.51.100.0/24", "2001:db8:1::/48")}
	rt := Runtime{MeshAddresses: []netip.Addr{
		netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("2001:db8::2"),
	}}
	be := &fakeBackend{}
	tr := translator(t, cfg, rt, be)
	want := []string{
		"out via ranet0 ipv4 masquerade",
		"in via ranet0 ipv4 from 198.51.100.0/24 source 10.88.0.2",
		"out via ranet0 ipv6 masquerade",
		"in via ranet0 ipv6 from 2001:db8:1::/48 source 2001:db8::2",
	}
	for range 3 {
		if err := tr.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
	if be.applied != 1 {
		t.Errorf("wrote the ruleset %d times over three passes, want once", be.applied)
	}
}

// A pass whose rules are already there writes nothing. The counters move on
// every packet, so a diff that read them would rewrite the ruleset whenever
// the node was carrying traffic, and each rewrite would drop the counters it
// had just read.
func TestUnchangedRulesAreNotRewritten(t *testing.T) {
	cfg := Config{Enable: true, Advertise: prefixes(t, "0.0.0.0/0")}
	be := &fakeBackend{flows: 11}
	tr := translator(t, cfg, Runtime{}, be)
	for range 3 {
		if err := tr.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if be.applied != 1 {
		t.Errorf("wrote the ruleset %d times, want once", be.applied)
	}
	if got := tr.Stats().Flows; got != 11 {
		t.Errorf("reported %d flows, want the counter the host holds", got)
	}
}

// An exit that cannot install its rule must not advertise. Babel gives a peer
// no way to learn that a node it selected will drop the traffic, so the only
// end that can act on it is this one.
func TestNothingIsAnnouncedWhileTheRuleWillNotInstall(t *testing.T) {
	cfg := Config{Enable: true, Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	be := &fakeBackend{failApply: true}
	var announced [][]netip.Prefix
	rt := Runtime{Announce: func(p []netip.Prefix) { announced = append(announced, p) }}
	tr := translator(t, cfg, rt, be)
	if err := tr.reconcile(); err == nil {
		t.Fatal("a pass that could not install reported success")
	}
	if got := tr.Announce(); len(got) != 0 {
		t.Errorf("announced %v with no rule installed", got)
	}
	if len(announced) != 1 || len(announced[0]) != 0 {
		t.Errorf("published %v, want one empty announcement", announced)
	}

	// And it comes back by itself once the host takes the rules, without a
	// restart and without anything else asking.
	be.mu.Lock()
	be.failApply = false
	be.mu.Unlock()
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := tr.Announce(); !slices.Equal(got, cfg.Advertise) {
		t.Errorf("announced %v after the rules installed, want %v", got, cfg.Advertise)
	}
}

// Readiness is per family, because a host can forward one and not the other
// and an exit that withheld both would take away a working half.
func TestOnlyTheForwardableFamilyIsAnnounced(t *testing.T) {
	cfg := Config{Enable: true, Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	rt := Runtime{Forwarding: func() (bool, bool) { return false, true }}
	tr := translator(t, cfg, rt, &fakeBackend{})
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := prefixes(t, "::/0")
	if got := tr.Announce(); !slices.Equal(got, want) {
		t.Errorf("announced %v, want %v", got, want)
	}
}

// A rule somebody removed under a running node is reinstalled by the next
// sweep, and the advertisement is withheld for as long as it is missing.
func TestRemovedRuleIsReinstalledAndTheAdvertisementWaits(t *testing.T) {
	cfg := Config{Enable: true, Advertise: prefixes(t, "0.0.0.0/0")}
	be := &fakeBackend{}
	tr := translator(t, cfg, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	be.mu.Lock()
	be.held = nil
	be.failApply = true
	be.mu.Unlock()
	if err := tr.reconcile(); err == nil {
		t.Fatal("a pass that could not reinstall reported success")
	}
	if got := tr.Announce(); len(got) != 0 {
		t.Errorf("kept announcing %v after the rule went away", got)
	}
}

// A translator that stops retracts before it withdraws. A peer still selecting
// this node while the table comes down is a peer whose traffic leaves
// untranslated, and the retraction is the only thing that tells it otherwise.
func TestShutdownRetractsBeforeItWithdraws(t *testing.T) {
	cfg := Config{Enable: true, Advertise: prefixes(t, "0.0.0.0/0")}
	be := &fakeBackend{}
	tr := translator(t, cfg, Runtime{}, be)
	withdrawnWhenRetracted := -1
	tr.rt.Announce = func(p []netip.Prefix) {
		if len(p) == 0 {
			withdrawnWhenRetracted = be.withdrawn
		}
	}
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(tr.Announce()) != 1 {
		t.Fatal("the first pass announced nothing to retract")
	}
	// Canceled before Run is entered, so the loop body never runs and the
	// order under test is the shutdown's alone.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tr.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := tr.Announce(); len(got) != 0 {
		t.Errorf("the advertisement survived shutdown as %v", got)
	}
	if be.withdrawn != 1 {
		t.Errorf("withdrew %d times, want once", be.withdrawn)
	}
	if withdrawnWhenRetracted != 0 {
		t.Errorf("the tables were already down when the advertisement was retracted, after %d withdrawals", withdrawnWhenRetracted)
	}
}

// Another writer's translation is named rather than removed. Several chains
// coexist at the same hook and the first to claim a connection keeps it, so a
// tool that deleted its neighbours' rules would break whatever installed them.
func TestConflictsAreReportedRatherThanRemoved(t *testing.T) {
	cfg := Config{Enable: true, Advertise: prefixes(t, "0.0.0.0/0")}
	be := &fakeBackend{conflicts: []string{"ip table nat chain POSTROUTING at priority 100"}}
	tr := translator(t, cfg, Runtime{}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := tr.Stats().Conflicts; !slices.Equal(got, be.conflicts) {
		t.Errorf("reported %q, want %q", got, be.conflicts)
	}
	if got := tr.Announce(); len(got) != 1 {
		t.Errorf("a conflict withheld the advertisement: %v", got)
	}
}

// A capability the file switched off but went on describing is refused by the
// field that was written, because nothing below enable is read and a node that
// meant to be an exit would come up as an ordinary leaf with no message.
func TestDisabledCapabilityRefusesTheFieldsItWouldIgnore(t *testing.T) {
	for _, one := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"advertise", Config{Advertise: prefixes(t, "0.0.0.0/0")}, "egress.advertise"},
		{"source4", Config{Source4: Source{Auto: true}}, "egress.source4"},
		{"source6", Config{Source6: Source{Addr: netip.MustParseAddr("2001:db8::1")}}, "egress.source6"},
		{"return", Config{Return: true}, "egress.return"},
		{"interval", Config{Interval: Duration(time.Second)}, "egress.interval"},
		{"nothing at all", Config{}, ""},
	} {
		t.Run(one.name, func(t *testing.T) {
			err := one.cfg.Validate()
			if one.want == "" {
				if err != nil {
					t.Fatalf("an empty block was refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("refused with %v, want a message naming %s", err, one.want)
			}
		})
	}
}

// Validation runs in this package rather than in internal/config, so a
// capability that arrived from a control plane is judged by the same rules a
// written one is.
func TestValidateRefusesWhatCannotBeTranslated(t *testing.T) {
	for _, one := range []struct {
		name string
		cfg  Config
		want string
	}{
		{
			"an exit that advertises nothing",
			Config{Enable: true},
			"advertise is empty",
		},
		{
			"a prefix with bits under its length",
			Config{Enable: true, Advertise: []netip.Prefix{netip.MustParsePrefix("198.51.100.7/24")}},
			"bits set below its prefix length",
		},
		{
			"the same prefix twice",
			Config{Enable: true, Advertise: prefixes(t, "::/0", "::/0")},
			"written twice",
		},
		{
			// The two spellings reach different tables here, so the mapped one
			// would be translated by an IPv6 rule matching an address family
			// no packet on the wire carries.
			"an IPv4 prefix written as IPv6",
			Config{Enable: true, Advertise: prefixes(t, "::ffff:198.51.100.0/120")},
			"written as IPv6, so write it as 198.51.100.0/24",
		},
		{
			"a source of the other family",
			Config{Enable: true, Advertise: prefixes(t, "0.0.0.0/0"), Source4: Source{Addr: netip.MustParseAddr("2001:db8::1")}},
			"is not of that family",
		},
		{
			"a source nothing can reply to",
			Config{Enable: true, Advertise: prefixes(t, "0.0.0.0/0"), Source4: Source{Addr: netip.MustParseAddr("127.0.0.1")}},
			"not an address a reply can be sent to",
		},
		{
			"a negative sweep",
			Config{Enable: true, Advertise: prefixes(t, "0.0.0.0/0"), Interval: Duration(-time.Second)},
			"is negative",
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			err := one.cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("refused with %v, want a message containing %q", err, one.want)
			}
		})
	}
}

// The return direction translates to one address, so a node that cannot say
// which is refused rather than picked from: the choice decides the address
// every flow out of this node's LAN appears as, and guessing it would change
// under an unrelated edit to the address list.
func TestReturnWithoutOneMeshAddressIsRefusedByName(t *testing.T) {
	cfg := Config{Enable: true, Return: true, Advertise: prefixes(t, "198.51.100.0/24")}
	for _, one := range []struct {
		name      string
		addresses []netip.Addr
		want      string
	}{
		{"none at all", nil, "carries no ipv4 mesh address"},
		{
			"two of the family",
			[]netip.Addr{netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("10.88.0.3")},
			"carries 2 ipv4 mesh addresses",
		},
		{
			"one of the other family",
			[]netip.Addr{netip.MustParseAddr("2001:db8::1")},
			"carries no ipv4 mesh address",
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			_, err := returnSource(cfg, Runtime{MeshAddresses: one.addresses}, FamilyIPv4)
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("refused with %v, want a message containing %q", err, one.want)
			}
			if err != nil && !strings.Contains(err.Error(), "egress.source4") {
				t.Errorf("the refusal %q does not name the field that settles it", err)
			}
		})
	}
}

// A capability written in a file and one sent as JSON are the same capability,
// so a control plane and an operator cannot disagree about a field's spelling.
func TestCapabilityRoundTripsThroughBothSerializations(t *testing.T) {
	want := Config{
		Enable:    true,
		Source4:   Source{Auto: true},
		Source6:   Source{Addr: netip.MustParseAddr("2001:db8::1")},
		Advertise: prefixes(t, "0.0.0.0/0", "2001:db8:1::/48"),
		Return:    true,
		Interval:  Duration(90 * time.Second),
	}
	for _, one := range []struct {
		name    string
		encode  func(any) ([]byte, error)
		decode  func([]byte, any) error
		written string
	}{
		{"yaml", yaml.Marshal, yaml.Unmarshal, "source4: auto"},
		{"json", json.Marshal, json.Unmarshal, `"source4":"auto"`},
	} {
		t.Run(one.name, func(t *testing.T) {
			raw, err := one.encode(want)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), one.written) {
				t.Errorf("wrote %s, which does not carry %s", raw, one.written)
			}
			var got Config
			if err := one.decode(raw, &got); err != nil {
				t.Fatalf("%s: %v", raw, err)
			}
			if !sameConfig(got, want) {
				t.Errorf("came back as %+v, want %+v", got, want)
			}
		})
	}
}

// sameConfig compares two capabilities field by field, since a prefix slice
// does not compare with ==.
func sameConfig(a, b Config) bool {
	return a.Enable == b.Enable && a.Source4 == b.Source4 && a.Source6 == b.Source6 &&
		a.Return == b.Return && a.Interval == b.Interval && slices.Equal(a.Advertise, b.Advertise)
}

// An absent source and one written as auto ask for the same thing, and neither
// reads back as an address the operator did not write.
func TestAbsentSourceStaysAbsent(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("enable: true\nadvertise: [\"::/0\"]\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Source4.IsZero() || !cfg.Source6.IsZero() {
		t.Errorf("an absent source parsed as %v and %v", cfg.Source4, cfg.Source6)
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "source4") {
		t.Errorf("wrote %s, which invents a source nobody configured", raw)
	}
}

// A duration is a scalar in both spellings. Reading the value off a mapping
// gives the empty string, and `invalid duration ""` names neither the line nor
// what was written there.
func TestDurationRefusesWhatIsNotAScalar(t *testing.T) {
	var cfg Config
	err := yaml.Unmarshal([]byte("enable: true\ninterval: [30s]\n"), &cfg)
	if err == nil || !strings.Contains(err.Error(), "a sequence") {
		t.Fatalf("refused with %v, want a message saying what was written instead", err)
	}
}

// A source is auto or an address and nothing else, said in those words rather
// than as a parse error nobody can act on.
func TestSourceRefusesWhatIsNeitherAutoNorAnAddress(t *testing.T) {
	var cfg Config
	err := yaml.Unmarshal([]byte("enable: true\nsource4: eth0\n"), &cfg)
	if err == nil || !strings.Contains(err.Error(), "auto or an address") {
		t.Fatalf("refused with %v, want a message naming both spellings", err)
	}
}

// New refuses before it opens anything, so a capability that names a source
// the return direction cannot resolve fails with nothing to clean up.
func TestNewRefusesAnUnresolvableReturnBeforeOpeningTheBackend(t *testing.T) {
	cfg := Config{Enable: true, Return: true, Advertise: prefixes(t, "198.51.100.0/24")}
	_, err := New(cfg, Runtime{Interface: "ranet0", Forwarding: func() (bool, bool) { return true, true }})
	if err == nil || !strings.Contains(err.Error(), "egress.source4") {
		t.Fatalf("New returned %v, want a refusal naming the field that settles it", err)
	}
	if errors.Is(err, ErrUnsupported) {
		t.Error("the platform was consulted before the capability was judged")
	}
}
