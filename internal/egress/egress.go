// Package egress translates the source address of a packet the mesh hands to
// this node and lets the host forward it by its ordinary routes. It is the one
// action behind an exit node and a subnet router: an exit advertises a default
// and a subnet router advertises the prefixes behind it, and both end at the
// same translation.
//
// # Ownership
//
// On linux the translation is an nftables table named after this tool, one per
// address family, holding one nat postrouting chain. That name is the ownership
// marker, the way Table.Proto is the reconciler's in internal/kernel. This
// package creates the table, writes only inside it, withdraws it whole at
// shutdown and never reads, replaces or deletes a table, a chain or a rule it
// did not create. Other source translation already on the host is reported
// rather than fought over: several nat postrouting chains coexist at the same
// hook, the first to translate a connection wins it, and taking somebody else's
// rule away to win that race would break whatever put it there.
//
// A table a previous instance left behind carries the same name and is
// therefore adopted, then brought to the rules the configuration now asks for,
// exactly as a route carrying the reconciler's protocol is.
//
// Nothing here writes iptables. The two are separate registries on a modern
// host, an iptables-nft rule is visible here as an ordinary nftables table, and
// the conflicts everybody remembers between firewall managers are an iptables
// problem this package declines to join.
//
// # Refusing to advertise
//
// Babel carries no capability signal, so a node that advertises a prefix is
// promising to carry it and the only thing a peer learns is the advertisement.
// An exit whose rule will not install, or whose kernel will not forward, would
// therefore attract traffic and drop it with nothing to tell the sender. So the
// advertisement is published by this package rather than by the configuration:
// Runtime.Announce is called with the prefixes whose family is both installed
// and forwardable, and with nothing at all while either is missing. It is the
// same fact internal/client warns about for transit, read from the same place,
// and acted on here because this end is the only one that knows.
package egress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/NickCao/ranet-lite/internal/schema"
)

const (
	// TableName is the nftables table this package owns, and the whole of its
	// ownership claim. It is the binary's own name so that an operator reading
	// `nft list ruleset` on a shared host can tell at a glance who wrote it.
	TableName = "ranet-lite"
	// ChainName is the one chain in that table, a nat postrouting base chain.
	ChainName = "postrouting"
	// DefaultSweep is the periodic pass a capability that names none takes.
	DefaultSweep = 30 * time.Second
	// minRetryInterval is the first delay after a failed pass; it doubles up
	// to the sweep interval, as in internal/kernel.
	minRetryInterval = time.Second
)

// FamilyIPv4 and FamilyIPv6 are AF_INET and AF_INET6, spelled here rather than
// taken from x/sys so that this file still builds where the capability is
// refused rather than absent from the type. internal/kernel spells them the
// same way for the same reason.
const (
	FamilyIPv4 uint8 = 2
	FamilyIPv6 uint8 = 10
)

// ErrUnsupported is returned by New on every platform with no backend, which
// is everything but linux today. A pf anchor on darwin is the second backend
// and is not written yet.
var ErrUnsupported = errors.New("egress: source translation is unsupported on this platform")

// Egress is the cap.egress capability: this node carries other nodes' traffic
// out of the mesh, the one action behind an exit node and a subnet router.
// Writing the block turns it on; there is no enable field to forget.
type Egress struct {
	// Advertise names the prefixes this node offers to carry: 0.0.0.0/0 and
	// ::/0 for an exit node, the prefixes behind it for a subnet router. It
	// decides which families are translated as well as which are announced,
	// because a family this node does not offer to carry is one it has no
	// reason to translate.
	Advertise []schema.Prefix `yaml:"advertise,omitempty" json:"advertise,omitempty" toml:"advertise,omitempty"`
	// Source4 and Source6 are the address a translated packet leaves under,
	// per family. See Source: "auto" is the address this node's own routes
	// would have used, which is the only answer available to a deployment that
	// owns no address block.
	Source4 Source `yaml:"source4,omitempty" json:"source4,omitempty,omitzero" toml:"source4,omitempty"`
	Source6 Source `yaml:"source6,omitempty" json:"source6,omitempty,omitzero" toml:"source6,omitempty"`
	// Return translates the other direction too: a packet arriving from one of
	// the advertised prefixes and leaving through the mesh goes out under this
	// node's own mesh address. A subnet router needs it where the mesh has no
	// route back to the LAN, which is every deployment that advertises a
	// prefix the far end does not hold a route for. An exit node does not:
	// nothing sits behind it to start a flow.
	Return bool `yaml:"return,omitempty" json:"return,omitempty" toml:"return,omitempty"`
	// Sweep is the periodic pass. It reinstalls a table somebody removed and
	// re-reads the forwarding sysctls, which is the half of readiness that
	// changes under a running node. Zero uses DefaultSweep.
	Sweep schema.Duration `yaml:"sweep,omitempty" json:"sweep,omitempty" toml:"sweep,omitempty"`
}

// Runtime holds the values the command resolves at startup rather than the
// ones a file carries, kept beside the capability rather than inside it so
// that a generated or round-tripped one holds only the fields an operator can
// write.
type Runtime struct {
	// Interface is the mesh device, named as the kernel named it. A packet
	// arriving on it and leaving by another link is translated; one arriving
	// on it and leaving by it again is mesh transit and is left alone.
	Interface string
	// MeshAddresses are the addresses this node carries on the mesh, which
	// "auto" resolves to for the return direction. They have to be unique per
	// node and routable within the mesh, which a mesh address already is.
	MeshAddresses []netip.Addr
	// Forwarding reports whether the host forwards, per family. It is supplied
	// rather than read here so that the node has one answer to the question
	// and not two; internal/client owns the reading.
	Forwarding func() (v4, v6 bool)
	// Announce publishes the prefixes this node may advertise right now. It is
	// called once per pass whose answer differs from the last, and with an
	// empty list while nothing may be advertised. Nil means the caller does
	// not announce, which only a test does.
	Announce func([]netip.Prefix)
}

// Normalized is the capability as the translator runs it: the sweep the file
// left out filled in, an omitted list and an empty one the same, and a source
// naming no address written as the auto it means. Two configurations are
// compared through this rather than as they were written, so "source4 = auto",
// the spelling examples/config.toml documents, is not a change and does not
// cost a restart.
func (e Egress) Normalized() Egress {
	if len(e.Advertise) == 0 {
		e.Advertise = nil
	}
	if e.Sweep == 0 {
		e.Sweep = schema.Duration(DefaultSweep)
	}
	e.Source4, e.Source6 = e.Source4.normalized(), e.Source6.normalized()
	return e
}

// Validate refuses a capability that cannot mean anything, in the package that
// knows what its fields mean. It runs at load, so a mistake costs a refusal to
// start rather than an exit that advertises and drops.
func (e Egress) Validate() error {
	if len(e.Advertise) == 0 {
		return errors.New("egress: cap.egress advertise is empty, so this node would translate nothing and offer nothing: name the prefixes it carries, or 0.0.0.0/0 and ::/0 for an exit node")
	}
	for _, entry := range e.Advertise {
		prefix := entry.Prefix
		if !prefix.IsValid() {
			return fmt.Errorf("egress: cap.egress advertise %s is not a prefix", entry)
		}
		if prefix.Masked() != prefix {
			// Refused rather than masked, as internal/kernel refuses the same
			// typo on a rule: masking it advertises a whole prefix where one
			// address was written, and says nothing.
			return fmt.Errorf("egress: cap.egress advertise %s has bits set below its prefix length", prefix)
		}
		if prefix.Addr().Zone() != "" {
			return fmt.Errorf("egress: cap.egress advertise %s carries a zone, which no prefix the mesh announces can", prefix)
		}
		if prefix.Addr().Is4In6() {
			// Refused rather than unmapped, because the two spellings send the
			// prefix to different tables here: the 4-in-6 form would be
			// translated by an IPv6 rule matching an address family no packet
			// on the wire carries, and the node would advertise a prefix it
			// silently never acts on.
			return fmt.Errorf("egress: cap.egress advertise %s is an IPv4 prefix written as IPv6, so write it as %s", prefix, netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96))
		}
	}
	for i, entry := range e.Advertise {
		if slices.ContainsFunc(e.Advertise[:i], func(other schema.Prefix) bool { return other.Prefix == entry.Prefix }) {
			return fmt.Errorf("egress: cap.egress advertise %s is written twice", entry)
		}
	}
	for _, named := range []struct {
		field  string
		source Source
		is4    bool
	}{{"source4", e.Source4, true}, {"source6", e.Source6, false}} {
		if !named.source.Addr.IsValid() {
			continue
		}
		if named.source.Addr.Is4() != named.is4 {
			return fmt.Errorf("egress: cap.egress %s %s is not of that family", named.field, named.source.Addr)
		}
		if !named.source.Addr.IsGlobalUnicast() && !named.source.Addr.IsPrivate() {
			// A translated packet has to be answerable, and a loopback,
			// multicast or unspecified source is one nothing replies to. The
			// check is here rather than in the backend because the backend
			// would install it and the failure would only show up as a flow
			// that never completes.
			return fmt.Errorf("egress: cap.egress %s %s is not an address a reply can be sent to", named.field, named.source.Addr)
		}
	}
	if e.Sweep < 0 {
		return fmt.Errorf("egress: cap.egress sweep %s is negative", e.Sweep)
	}
	return nil
}

// families is the address families this configuration covers, derived from the
// prefixes it advertises. A family nothing is advertised for is one this node
// has no reason to translate, so no table is created for it.
func (e Egress) families() []uint8 {
	var out []uint8
	for _, prefix := range e.Advertise {
		family := FamilyIPv6
		if prefix.Addr().Is4() {
			family = FamilyIPv4
		}
		if !slices.Contains(out, family) {
			out = append(out, family)
		}
	}
	slices.Sort(out)
	return out
}

func (e Egress) source(family uint8) Source {
	if family == FamilyIPv4 {
		return e.Source4
	}
	return e.Source6
}

// sweep is the interval with its default applied.
func (e Egress) sweep() time.Duration {
	if e.Sweep <= 0 {
		return DefaultSweep
	}
	return e.Sweep.Duration()
}

// Direction says which way through this node a packet is going, which decides
// both what the rule matches and what "auto" resolves to.
type Direction uint8

const (
	// Out is a packet the mesh handed this node, leaving by another link. The
	// reply has to come back to the link it left by, so the source is the one
	// this node's own routes would have used there.
	Out Direction = iota
	// In is a packet from behind this node, entering the mesh. The reply has
	// to come back through the mesh, so the source is this node's mesh
	// address.
	In
)

func (d Direction) String() string {
	if d == In {
		return "in"
	}
	return "out"
}

// Rule is one translation this node installs, and simultaneously the diff key:
// the backend writes String into the rule's own comment and reads it back, so
// two rules with equal fields are the same rule whatever the kernel does to
// the expressions in between.
type Rule struct {
	Family    uint8
	Direction Direction
	// Interface is the mesh device the direction is relative to.
	Interface string
	// Source is the address to translate to. An invalid address means the
	// backend lets the host pick, which is nftables masquerade: the address of
	// the link the packet is leaving by, chosen per packet.
	Source netip.Addr
	// From narrows an In rule to one advertised prefix. It is never set on an
	// Out rule, which selects on the direction alone, and it is left invalid
	// for a prefix covering every address, which selects nothing extra.
	From netip.Prefix
}

// String is the rule as an operator reads it in `nft list ruleset` and as the
// diff compares it. Every field that changes what the rule does is in it, so a
// changed source or prefix reads back as a different rule and is replaced.
func (r Rule) String() string {
	source := "masquerade"
	if r.Source.IsValid() {
		source = "source " + r.Source.String()
	}
	parts := []string{r.Direction.String(), "via", r.Interface, familyName(r.Family)}
	if r.From.IsValid() {
		parts = append(parts, "from", r.From.String())
	}
	return strings.Join(append(parts, source), " ")
}

func familyName(family uint8) string {
	if family == FamilyIPv4 {
		return "ipv4"
	}
	return "ipv6"
}

// Installed is one rule as the backend read it back: the spelling it was
// written under and what it has carried since. The counters are outside the
// diff on purpose, because they change on every packet and a diff holding them
// would rewrite the ruleset on every pass.
type Installed struct {
	Spec    string
	Packets uint64
	Bytes   uint64
}

// backend is the kernel surface a translator drives. Everything above it is
// portable and syscall-free, so the diff and the refusal rules are testable
// against a fake.
type backend interface {
	// Rules returns the rules held in this tool's own table, in order.
	Rules() ([]Installed, error)
	// Apply brings this tool's own chain to rules. It replaces the chain's
	// contents in one transaction rather than editing it, because nftables
	// commits a batch atomically and a chain rewritten rule by rule has a
	// window in which a packet leaves untranslated.
	Apply([]Rule) error
	// Conflicts names the source translation already on the host that this
	// node's traffic could meet, for an operator rather than as a number.
	Conflicts() ([]string, error)
	// Withdraw removes this tool's own tables. A table that is already gone is
	// success.
	Withdraw() error
	Close() error
	// where names the space this backend owns, for a log line.
	where(Egress) string
}

// Stats is one finished pass as an operator reads it. Installed counts the
// rules the host holds for this translator once the pass has applied, and
// Announced the prefixes it is willing to advertise as a result.
type Stats struct {
	At        time.Time
	Desired   int
	Installed int
	// Flows counts the connections the rules have translated, and Bytes the
	// first packet of each. A nat chain is consulted once per connection and
	// never again, so neither is a packet count.
	Flows     uint64
	Bytes     uint64
	Announced []netip.Prefix
	Conflicts []string
	Err       string
}

// Translator owns the capability on one node: the rules, the tables they live
// in, and the advertisement that depends on both.
type Translator struct {
	cfg Egress
	rt  Runtime
	be  backend

	// stats is the last pass as a reader takes it. The single run goroutine
	// publishes a whole value and a reader takes one, so this needs no lock
	// and a reader can never see half a pass.
	stats atomic.Pointer[Stats]
	// announced holds the prefixes Runtime.Announce was last given, so a pass
	// that changes nothing does not republish and a caller reading it directly
	// gets the same answer the speaker has.
	announced atomic.Pointer[[]netip.Prefix]
	// warned holds the conflicts already reported, so a shared host costs one
	// log line per new conflict rather than one per pass.
	warned []string
}

// New validates the capability against the platform and opens whatever the
// backend needs, so a deployment that cannot have it fails at startup rather
// than on the first packet. It installs nothing; Run does that.
func New(cfg Egress, rt Runtime) (*Translator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if rt.Interface == "" {
		return nil, errors.New("egress: the mesh interface is required")
	}
	if rt.Forwarding == nil {
		return nil, errors.New("egress: a forwarding reader is required")
	}
	// Resolved before the backend is opened, so a return direction with no
	// mesh address to translate to is refused with nothing to clean up.
	for _, family := range cfg.families() {
		if _, err := returnSource(cfg, rt, family); err != nil {
			return nil, err
		}
	}
	be, err := newBackend(cfg, rt)
	if err != nil {
		return nil, err
	}
	return &Translator{cfg: cfg, rt: rt, be: be}, nil
}

// returnSource is the address the In direction translates to for one family:
// the configured one, or this node's own mesh address of that family. A node
// with several is refused rather than picked from, because the choice decides
// which address every flow out of this node's LAN appears as and guessing it
// would change under an unrelated edit to the address list.
func returnSource(cfg Egress, rt Runtime, family uint8) (netip.Addr, error) {
	if !cfg.Return {
		return netip.Addr{}, nil
	}
	if source := cfg.source(family); source.Addr.IsValid() {
		return source.Addr, nil
	}
	var candidates []netip.Addr
	for _, address := range rt.MeshAddresses {
		if addressFamily(address) != family || !address.IsGlobalUnicast() && !address.IsPrivate() {
			continue
		}
		if !slices.Contains(candidates, address) {
			candidates = append(candidates, address)
		}
	}
	switch len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		return netip.Addr{}, fmt.Errorf("egress: return is set and this node carries no %s mesh address to translate to, so name one in egress.source%s",
			familyName(family), familyDigit(family))
	default:
		return netip.Addr{}, fmt.Errorf("egress: return is set and this node carries %d %s mesh addresses (%s), so name the one to translate to in egress.source%s",
			len(candidates), familyName(family), joinAddrs(candidates), familyDigit(family))
	}
}

func familyDigit(family uint8) string {
	if family == FamilyIPv4 {
		return "4"
	}
	return "6"
}

func joinAddrs(addresses []netip.Addr) string {
	text := make([]string, 0, len(addresses))
	for _, address := range addresses {
		text = append(text, address.String())
	}
	return strings.Join(text, ", ")
}

func addressFamily(address netip.Addr) uint8 {
	if address.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

// Capability is the block this translator is running, as the file spelled it.
func (t *Translator) Capability() Egress { return t.cfg }

// Where names the space this translator owns, for an operator reading a log
// line.
func (t *Translator) Where() string { return t.be.where(t.cfg) }

// Stats reports the last pass, and the zero value before the first one has
// run. A caller that wants to tell those apart reads At.
func (t *Translator) Stats() Stats {
	if s := t.stats.Load(); s != nil {
		return *s
	}
	return Stats{}
}

// Announce is the prefixes this node may advertise right now: the configured
// list narrowed to the families whose rule is installed and whose forwarding
// is on, and nothing at all before the first pass has run. A caller announces
// from this rather than from the configuration, which is how an exit that
// cannot translate refuses to advertise rather than advertising and dropping.
func (t *Translator) Announce() []netip.Prefix {
	if prefixes := t.announced.Load(); prefixes != nil {
		return slices.Clone(*prefixes)
	}
	return nil
}

// Run reconciles until ctx is canceled, then withdraws the tables this
// translator owns and closes what the backend holds. It is called once.
//
// Run returns the withdrawal error, never a reconcile error: a failed pass is
// logged, costs the advertisement, and is retried.
func (t *Translator) Run(ctx context.Context) error {
	slog.Info("egress translator started", "interface", t.rt.Interface, "where", t.Where(),
		"advertise", len(t.cfg.Advertise))
	ticker := time.NewTicker(t.cfg.sweep())
	defer ticker.Stop()
	retry := time.NewTimer(t.cfg.sweep())
	stopTimer(retry)
	defer retry.Stop()

	backoff := time.Duration(0)
	for ctx.Err() == nil {
		if err := t.reconcile(); err != nil {
			backoff = min(max(2*backoff, minRetryInterval), t.cfg.sweep())
			slog.Warn("egress pass failed, retrying", "err", err, "retry_in", backoff)
			stopTimer(retry)
			retry.Reset(backoff)
		} else if backoff != 0 {
			backoff = 0
			stopTimer(retry)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		case <-retry.C:
		}
	}
	// The advertisement goes before the rules do. A peer that keeps selecting
	// this node while its table is being taken down is a peer whose traffic
	// leaves untranslated, and babel's own retraction is the only thing that
	// can tell it otherwise.
	t.publish(nil)
	return errors.Join(t.withdraw(), t.be.Close())
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

// reconcile brings the host to the rules the configuration asks for and
// republishes what may be advertised as a result. The rules are compared
// before they are written, so a pass that changes nothing costs one dump and
// leaves the counters where they are.
func (t *Translator) reconcile() error {
	desired := t.desired()
	held, err := t.be.Rules()
	if err != nil {
		err = fmt.Errorf("list rules: %w", err)
	} else if !sameRules(held, desired) {
		if applyErr := t.be.Apply(desired); applyErr != nil {
			err = fmt.Errorf("install rules: %w", applyErr)
		} else {
			slog.Info("egress rules installed", "rules", len(desired), "replaced", len(held), "where", t.Where())
			// Read back rather than assumed. The counters below are the
			// host's, and a rule the kernel accepted under a spelling other
			// than the one asked for has to fail the readiness test rather
			// than pass it on this pass and fail on the next.
			if held, err = t.be.Rules(); err != nil {
				err = fmt.Errorf("list rules: %w", err)
			}
		}
	}
	conflicts, conflictErr := t.be.Conflicts()
	err = errors.Join(err, conflictErr)
	t.reportConflicts(conflicts)

	// Readiness is per family and is read from the host on every pass rather
	// than captured at startup, because both halves of it change under a
	// running node: a table can be flushed by somebody else and a forwarding
	// sysctl can be turned on after this process started.
	installed := make(map[string]bool, len(held))
	for _, rule := range held {
		installed[rule.Spec] = true
	}
	v4, v6 := t.rt.Forwarding()
	forwards := map[uint8]bool{FamilyIPv4: v4, FamilyIPv6: v6}
	ready := make(map[uint8]bool, 2)
	for _, family := range t.cfg.families() {
		ready[family] = forwards[family]
		for _, rule := range desired {
			if rule.Family == family && !installed[rule.String()] {
				ready[family] = false
			}
		}
	}
	announced := make([]netip.Prefix, 0, len(t.cfg.Advertise))
	for _, entry := range t.cfg.Advertise {
		if ready[addressFamily(entry.Addr())] {
			announced = append(announced, entry.Prefix)
		}
	}
	t.publish(announced)

	var flows, bytes uint64
	for _, rule := range held {
		flows += rule.Packets
		bytes += rule.Bytes
	}
	stats := Stats{
		At: time.Now(), Desired: len(desired), Installed: len(held),
		Flows: flows, Bytes: bytes,
		Announced: announced, Conflicts: conflicts,
	}
	if err != nil {
		stats.Err = err.Error()
	}
	t.stats.Store(&stats)
	return err
}

// sameRules compares what the host holds against what the configuration asks
// for, by the spelling the backend reads back rather than by the expressions
// it encoded them into. Order counts: a chain is read top to bottom, and the
// counters are deliberately outside the comparison so that a pass does not
// rewrite the ruleset over a packet having arrived.
func sameRules(held []Installed, desired []Rule) bool {
	if len(held) != len(desired) {
		return false
	}
	for i, rule := range desired {
		if held[i].Spec != rule.String() {
			return false
		}
	}
	return true
}

// desired is the rules this configuration asks for, grouped by family and
// then in the order a packet meets them within one chain. The grouping is not
// presentation: each family is a table of its own, so a backend reads them back
// one family at a time, and a list ordered any other way would never compare
// equal to its own readback and would be rewritten on every pass forever.
//
// Within a family the Out rule comes first, because every deployment has one
// and a chain reads top to bottom.
func (t *Translator) desired() []Rule {
	var out []Rule
	for _, family := range t.cfg.families() {
		rule := Rule{Family: family, Direction: Out, Interface: t.rt.Interface}
		if source := t.cfg.source(family); source.Addr.IsValid() {
			rule.Source = source.Addr
		}
		out = append(out, rule)
		if !t.cfg.Return {
			continue
		}
		// Resolved again rather than remembered, and its error dropped,
		// because New refused every configuration that cannot answer it.
		source, err := returnSource(t.cfg, t.rt, family)
		if err != nil || !source.IsValid() {
			continue
		}
		for _, prefix := range t.cfg.Advertise {
			if addressFamily(prefix.Addr()) != family {
				continue
			}
			inbound := Rule{Family: family, Direction: In, Interface: t.rt.Interface, Source: source}
			// A prefix covering every address narrows nothing, and a rule
			// carrying it would encode a mask no packet fails, so it is left
			// off and the rule selects on the direction alone.
			if prefix.Bits() > 0 {
				inbound.From = prefix.Prefix
			}
			out = append(out, inbound)
		}
	}
	return out
}

// publish hands the announcement to the caller, and only when it changed. A
// republish rebuilds the speaker's originated set, which an unchanged pass
// every thirty seconds has no reason to do.
func (t *Translator) publish(prefixes []netip.Prefix) {
	previous := t.announced.Load()
	if previous != nil && slices.Equal(*previous, prefixes) {
		return
	}
	stored := slices.Clone(prefixes)
	t.announced.Store(&stored)
	if previous != nil {
		// Said out loud on every transition, because a prefix silently leaving
		// the advertisement is a customer's exit node going away and the
		// counters alone would not name it.
		slog.Warn("egress advertisement changed", "prefixes", len(prefixes),
			"was", len(*previous), "detail", "a family is advertised only while its rule is installed and the kernel forwards it")
	}
	if t.rt.Announce != nil {
		t.rt.Announce(slices.Clone(prefixes))
	}
}

// reportConflicts names other source translation on this host once per new
// entry. It is a report rather than an action: several nat postrouting chains
// coexist, the first to translate a connection wins it, and taking another
// writer's rule away to win that race would break whatever installed it.
func (t *Translator) reportConflicts(conflicts []string) {
	for _, conflict := range conflicts {
		if slices.Contains(t.warned, conflict) {
			continue
		}
		slog.Warn("egress is sharing the source translation hook with another writer",
			"other", conflict,
			"detail", "the first chain to translate a connection keeps it, so a flow this node meant to translate may leave under that writer's address instead")
	}
	t.warned = slices.Clone(conflicts)
}

// withdraw removes the tables this translator owns. It is best effort by
// construction: the caller usually stops the mesh at the same moment, and a
// table that is already gone is not an error.
func (t *Translator) withdraw() error {
	if err := t.be.Withdraw(); err != nil {
		return fmt.Errorf("withdraw %s: %w", t.Where(), err)
	}
	slog.Info("egress translator withdrawn", "where", t.Where())
	return nil
}
