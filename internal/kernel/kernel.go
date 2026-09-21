// Package kernel mirrors the mesh forwarding table into the host's routing
// table, taking over from the BIRD kernel protocols a ranet deployment runs
// today. It is a one-way reconciler: internal/netstack keeps owning the
// forwarding decision and this package only teaches the kernel which packets
// to hand to the TUN, so every route it installs points at Config.Interface
// and the peer in a snapshot entry never selects a kernel next hop.
//
// # Ownership
//
// On linux, every route this package installs lives in Config.Table, carries
// rt_proto Config.Protocol and points out of Config.Interface. Those three
// together are the ownership marker. darwin has neither tables nor rt_proto,
// so ownership there is the interface and the shape of the route; see
// platform_darwin.go. The reconciler reads back only routes matching
// all three, deletes only routes it read back that way, and stamps
// rtm_protocol on every RTM_DELROUTE so the kernel itself refuses to remove a
// route belonging to another protocol. It never touches another table, a
// route written by another protocol, a route out of another device, a policy
// rule, a neighbor entry, or anything at all in the main table. Routes a
// previous instance of this process left behind carry the same marker and are
// therefore adopted, then withdrawn on the first pass if the mesh no longer
// wants them.
//
// Installation asks for the route exclusively, so a key another writer already
// holds in Config.Table is left alone and reported once rather than taken
// over. A replace would compare neither rtm_protocol nor the route type, which
// matters most in a VRF table: the kernel's own local and connected entries
// for an address on an enslaved link sit at priority 0, where an IPv4 route
// with no configured metric also sits. Give the reconciler a table no other
// daemon writes all the same, or the routes it declines to fight over are
// routes the mesh wanted.
//
// Addresses and VRF enslavement are narrower still. Only an address this
// reconciler added itself, in this process lifetime, is ever removed again;
// an address that was already on the link belongs to whoever put it there.
// The link is enslaved only when it has no master at all, so the reconciler
// never takes Config.Interface away from systemd-networkd or anything else
// that claimed it first.
//
// # Failure
//
// Every step reports its netlink errors rather than swallowing them, and a
// failed pass is retried with capped exponential backoff. The steps are
// independent, so one failing step never skips the others. Every apply is
// idempotent and every pass recomputes the difference against a fresh kernel
// dump, so a pass that fails halfway leaves the kernel in a state the next
// pass repairs.
package kernel

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/sadr"
)

const (
	// DefaultTable matches the table the fleet's kbabel4 and kbabel6 write,
	// which the policy rules and the End.DT46 SRv6 action look up.
	DefaultTable = 200
	// DefaultProtocol is the rt_proto stamped on every installed route. It
	// deliberately collides with nothing in rtnetlink.h, so a route of this
	// reconciler's stays distinguishable from BIRD's (12) and babeld's (42).
	DefaultProtocol = 155
	// DefaultReconcileInterval bounds how long drift caused by anything else
	// on the box survives when no notification announces it.
	DefaultReconcileInterval = 30 * time.Second

	// minRetryInterval is the first delay after a failed pass; it doubles up
	// to the reconcile interval.
	minRetryInterval = time.Second
	// settleDelay absorbs the rest of a burst of changes, including the route
	// notifications the reconciler's own writes generate, so one batch of
	// babel updates costs one kernel dump rather than one per route.
	settleDelay = 250 * time.Millisecond
	// reservedTable and lastByteTable bracket the rtnetlink table numbers the
	// kernel keeps for itself: 253 default, 254 main, 255 local. Named here
	// rather than taken from unix.RT_TABLE_DEFAULT because this file builds on
	// darwin too.
	reservedTable = 253
	lastByteTable = 255
	// protocolStatic is RTPROT_STATIC, which systemd-networkd stamps on every
	// route and rule it installs. It is the highest protocol number this
	// reconciler must not claim, and it is named here for the same reason the
	// tables above are.
	protocolStatic = 4
	// defaultIPv6Metric is IP6_RT_PRIO_USER, what the kernel stamps on an
	// IPv6 route that arrives without RTA_PRIORITY. The reconciler sends it
	// explicitly instead, so a dump reports back exactly what it installed.
	defaultIPv6Metric = 1024
)

// ErrUnsupported is returned by New on every platform without an
// implementation, which is everything but linux and darwin.
var ErrUnsupported = errors.New("kernel: route reconciliation is unsupported on this platform")

// errRouteSkipped distinguishes a route that was deliberately not installed
// from one that was, and from a transient failure. It covers a route the
// platform cannot represent and a key another writer already holds. The
// reconciler neither counts it as added nor retries with backoff: counting it
// would report the opposite of what the kernel holds, and backing off would
// stand down over something no retry can fix. The install is still attempted
// on the next pass, because the route stays in the diff until it is there.
var errRouteSkipped = errors.New("kernel: route was not installed")

type Config struct {
	// Interface is the TUN device every installed route points at, named as
	// the kernel named it (netstack.Mesh.Name, not the requested name).
	Interface string
	// Table is the routing table the reconciler owns. Zero uses DefaultTable.
	Table uint32
	// Protocol is the rt_proto marking this reconciler's routes. Zero uses
	// DefaultProtocol.
	Protocol uint8
	// Metric is RTA_PRIORITY. Zero takes the kernel's own default, which is 0
	// for IPv4 and 1024 for IPv6. BIRD's kernel protocols use 32.
	Metric uint32
	// PrefSrc4 is RTA_PREFSRC on every installed IPv4 route, the attribute
	// BIRD sets from krt_prefsrc. IPv6 routes carry no preferred source;
	// source-specific IPv6 routes carry RTA_SRC instead.
	PrefSrc4 netip.Addr
	// Addresses are assigned to Interface when absent and removed again at
	// shutdown. Empty leaves the link's addresses to the operator.
	Addresses []netip.Prefix
	// VRF enslaves Interface to that master device, but only while the link
	// has no master yet. Empty leaves the link's master alone.
	VRF string
	// CreateVRF makes the device VRF names when no device of that name
	// exists, bound to Table, rather than expecting the host's network
	// manager to have made it. One this reconciler created is removed again
	// at shutdown; one it found is left alone, the same rule addresses follow.
	CreateVRF bool
	// Rules are the policy rules this reconciler owns. Each carries Protocol
	// in FRA_PROTOCOL, the same ownership marker routes carry, so a dump
	// reads back only these and a delete can never reach another writer's.
	// They are withdrawn at shutdown as the routes are: a rule pointing into
	// an empty table costs only a lookup, and one left behind sends traffic
	// to a table nothing is writing any more.
	Rules []Rule
	// ReconcileInterval is the periodic sweep. Zero uses
	// DefaultReconcileInterval.
	ReconcileInterval time.Duration
	// Underlay names the addresses this node's own transport has to keep
	// reaching. The darwin backend asks once per pass and scopes a route that
	// covers one, see coversAny there; linux reads it never, and keeps the
	// underlay out with a socket mark instead. Nil decides scope on the
	// destination alone.
	Underlay func() []netip.Addr
}

// RouteSource is the seam onto internal/netstack: one coalesced wake-up per
// batch of changes, and one consistent view per reconcile pass. Reconciling
// from snapshots rather than from an event stream lets a missed wake-up, a
// restart and outside interference all converge on the same state.
type RouteSource interface {
	Changed() <-chan struct{}
	Snapshot() []sadr.Route[*netstack.Peer]
}

// Route is one kernel route the reconciler manages, and simultaneously the
// diff key: the table, the protocol and the next hop are the same for every
// route it installs, so two routes with equal fields are the same route. The
// metric is in the key even though it comes from the configuration, because
// the kernel keys routes on it too: changing Config.Metric has to withdraw
// the routes installed under the old one rather than leave them behind.
type Route struct {
	// Destination is canonical: masked and zoneless.
	Destination netip.Prefix
	// Source is RTA_SRC, invalid for an ordinary route. IPv6 only, because
	// the IPv4 FIB has no source-specific lookup.
	Source netip.Prefix
	// PrefSrc is RTA_PREFSRC, invalid when unset.
	PrefSrc netip.Addr
	// Metric is RTA_PRIORITY as the kernel holds it, never the zero that
	// means "your default" on the way in.
	Metric uint32
	// Scoped is set by the darwin backend on a route the kernel keys by
	// interface scope as well as by destination, so a withdrawal can name the
	// one it read back rather than re-deriving it. An unscoped route and a
	// scoped one to the same destination are different keys, and deleting by
	// destination alone removes whichever the flag happens to select.
	Scoped bool
	// Unreachable holds a prefix rather than carrying it, as
	// RFC 8966 section 3.5.4 requires of a retracted route until it is
	// flushed. Without it the entry leaves the table and a packet for that
	// prefix follows a shorter one instead, which on a node holding a default
	// is straight back out to the neighbor that just retracted it.
	Unreachable bool
}

func (r Route) String() string {
	kind := ""
	if r.Unreachable {
		kind = " unreachable"
	}
	if r.Source.IsValid() {
		return fmt.Sprintf("%s from %s metric %d%s", r.Destination, r.Source, r.Metric, kind)
	}
	return fmt.Sprintf("%s metric %d%s", r.Destination, r.Metric, kind)
}

// auditor is implemented by a platform that can report other writers in the
// space this reconciler is about to take over. A platform that cannot answer
// does not implement it.
type auditor interface {
	// foreignWriters returns each protocol already writing into the space,
	// labeled for an operator rather than numbered, since the numbering is
	// the platform's own registry.
	foreignWriters() ([]string, error)
}

// ruler is implemented by a platform that has a policy routing engine. linux
// has FIB rules and 2^32 tables; darwin has one FIB and neither; a mobile
// tunnel provider is handed a list of routes to include and exclude and never
// sees a table at all. A platform without one does not implement this, and New
// refuses a configuration that asks for rules there by name rather than
// accepting it and quietly doing nothing.
//
// What the rules express is portable even where the mechanism is not: keeping
// the underlay out of the mesh, and sending traffic from an address into it.
// Each backend reaches those its own way, and the ones that cannot take a rule
// list say so. See the platform notes in readme.md.
type ruler interface {
	// Rules returns only the rules carrying this reconciler's protocol.
	Rules() ([]Rule, error)
	AddRule(Rule) error
	// DelRule treats a rule that is already gone as success.
	DelRule(Rule) error
}

// vrfMaker is implemented by a platform that can create the master device a
// mesh table is bound to. Same rule as ruler: absent rather than stubbed, so a
// configuration asking for one where there are no VRFs is refused by name.
type vrfMaker interface {
	// EnsureVRF creates the device when no device of that name exists and
	// reports whether it created it. A device that is already there is left
	// alone, whatever it is bound to, because it belongs to whoever made it.
	EnsureVRF(name string, table uint32) (bool, error)
	// RemoveVRF deletes a device this reconciler created. A device that is
	// already gone is success.
	RemoveVRF(name string) error
}

// platform is the kernel surface the reconciler drives. Everything above it is
// portable and syscall-free, so the diff is testable against a
// fake kernel.
type platform interface {
	// Routes returns only the routes carrying the reconciler's protocol, in
	// its table, out of its interface.
	Routes() ([]Route, error)
	// where names the space this platform gives a reconciler to own.
	where(Config) string

	AddRoute(Route) error
	// DelRoute treats a route that is already gone as success.
	DelRoute(Route) error
	// Addrs returns every address on the interface, whoever put it there.
	Addrs() ([]netip.Prefix, error)
	AddAddr(netip.Prefix) error
	DelAddr(netip.Prefix) error
	// Master is the interface's current master device, empty when it has none.
	Master() (string, error)
	Enslave(master string) error
	Release() error
	// Notify carries one coalesced wake-up per batch of kernel route
	// notifications in the reconciler's table.
	Notify() <-chan struct{}
	Close() error
}

// Rule is one policy rule. It is compared with ==, so every field is part of
// the key: the kernel matches a delete against the selectors it is given, and
// two rules differing in any of them are two entries.
//
// A rule selects a lookup table and nothing else. This reconciler installs no
// action but FR_ACT_TO_TBL, so a rule it owns sends traffic to another table
// and can never make an address unreachable, which keeps the worst outcome of
// a mistaken rule a lookup in the wrong table rather than a black hole.
type Rule struct {
	// Family is AF_INET or AF_INET6. A rule selecting on an address takes its
	// family from that address; one selecting only on a mark has to name it,
	// because a mark says nothing about which family it belongs to.
	Family uint8
	// To is FRA_DST and From is FRA_SRC, each invalid when unset.
	To   netip.Prefix
	From netip.Prefix
	// FWMark and FWMask are FRA_FWMARK and FRA_FWMASK. A zero mark means the
	// rule does not select on one, and a zero mask with a nonzero mark is an
	// exact match, which is how the kernel reads an absent FRA_FWMASK.
	FWMark uint32
	FWMask uint32
	// Table is the table to look up, the reserved ones included: a rule
	// pointing at main is ordinary, and keeps an underlay out of a mesh table.
	Table uint32
	// Priority is FRA_PRIORITY, the position in the rule list. Zero belongs
	// to the local table's own rule and is refused.
	Priority uint32
}

func (r Rule) String() string {
	parts := []string{fmt.Sprintf("priority %d", r.Priority)}
	if r.From.IsValid() {
		parts = append(parts, "from "+r.From.String())
	}
	if r.To.IsValid() {
		parts = append(parts, "to "+r.To.String())
	}
	if r.FWMark != 0 {
		mark := fmt.Sprintf("fwmark %#x", r.FWMark)
		if r.FWMask != 0 {
			mark += fmt.Sprintf("/%#x", r.FWMask)
		}
		parts = append(parts, mark)
	}
	return strings.Join(append(parts, fmt.Sprintf("lookup %d", r.Table)), " ")
}

// canonical is the rule as the kernel reports it back. Two spellings can reach
// the kernel as one rule while only one of them survives a dump, and a diff
// holding the other deletes and reinstalls that rule on every pass, with a
// window each time in which it is not there.
//
// A mark with no mask matches every bit, which the kernel stores and reports
// as a mask of all ones: `ip rule add fwmark X` and `ip rule add fwmark
// X/0xffffffff` answer EEXIST to each other. A prefix of length zero selects
// every address, so the kernel emits no FRA_DST or FRA_SRC for it and a rule
// carrying nothing else is one that matches everything, which validate then
// refuses by name rather than installing.
func (r Rule) canonical() Rule {
	if r.FWMask == ^uint32(0) {
		r.FWMask = 0
	}
	if r.To.Bits() == 0 {
		r.To = netip.Prefix{}
	}
	if r.From.Bits() == 0 {
		r.From = netip.Prefix{}
	}
	return r
}

// validate refuses a rule the kernel would accept and an operator would not
// recognize afterwards. It runs at startup, so a mistake costs a refusal to
// start rather than a rule installed against a live fleet.
func (r Rule) validate() error {
	if r.Family != FamilyIPv4 && r.Family != FamilyIPv6 {
		return fmt.Errorf("kernel: rule %s: family must be ipv4 or ipv6", r)
	}
	for _, named := range []struct {
		name   string
		prefix netip.Prefix
	}{{"to", r.To}, {"from", r.From}} {
		if !named.prefix.IsValid() {
			continue
		}
		if ruleFamily(named.prefix.Addr()) != r.Family {
			return fmt.Errorf("kernel: rule %s: %s %s is not of the rule's family", r, named.name, named.prefix)
		}
		if named.prefix.Masked() != named.prefix {
			return fmt.Errorf("kernel: rule %s: %s %s has bits set below its prefix length", r, named.name, named.prefix)
		}
	}
	if !r.To.IsValid() && !r.From.IsValid() && r.FWMark == 0 {
		return fmt.Errorf("kernel: rule %s selects nothing, so it would match every packet", r)
	}
	if r.FWMark == 0 && r.FWMask != 0 {
		return fmt.Errorf("kernel: rule %s carries a mark mask and no mark", r)
	}
	if r.Priority == 0 {
		return fmt.Errorf("kernel: rule %s: priority 0 belongs to the local table", r)
	}
	if r.Table == 0 {
		return fmt.Errorf("kernel: rule %s: table is required", r)
	}
	return nil
}

// FamilyIPv4 and FamilyIPv6 are AF_INET and AF_INET6, spelled here rather than
// taken from x/sys so that this file still builds on every platform, including
// the ones where a rule is refused rather than absent from the type.
const (
	FamilyIPv4 uint8 = 2
	FamilyIPv6 uint8 = 10
)

func ruleFamily(address netip.Addr) uint8 {
	if address.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

type Reconciler struct {
	cfg  Config
	src  RouteSource
	plat platform

	// owned holds the addresses this reconciler put on the link, the only
	// ones it will ever take off again. An address a previous instance added
	// and left behind is not in here, so it stays: losing an address that
	// turns out to be somebody else's is worse than leaking one.
	owned map[netip.Prefix]bool
	// warnedAddrs is the addresses reported as held by somebody else under the
	// current pass, rotated the way warned is so a report costs one log line
	// rather than one per pass.
	warnedAddrs map[netip.Prefix]bool
	// enslaved records that this reconciler set the link's master itself.
	enslaved bool
	// master is the last master observed, so a link somebody else owns is
	// reported once per transition rather than once per pass.
	master string
	// warned holds the routes already reported as unrepresentable. It is
	// rebuilt from each pass, so it stays bounded by the snapshot.
	warned map[Route]bool

	// rules and vrfs are the optional halves of the platform, nil where it has
	// no policy engine or no VRFs. New refuses a configuration that needs one
	// of them on such a platform, so nil here means the configuration asked
	// for nothing.
	rules ruler
	vrfs  vrfMaker
	// madeVRF records that this reconciler created the VRF device itself, the
	// only condition under which it removes one again.
	madeVRF bool

	// stats is the last route pass as an operator reads it. The single
	// reconcile goroutine publishes a whole value and a reader takes one, so
	// this needs no lock and a reader can never see half a pass.
	stats atomic.Pointer[Stats]
	// routePass holds the counts applyRoutes took, between that step and the
	// record reconcile makes of the whole pass. Only the reconcile goroutine
	// touches it.
	routePass Stats
}

// Stats is one finished route pass. Installed counts the routes the kernel
// holds for this reconciler once the pass has applied, and Skipped the ones it wanted
// and did not get: one the platform cannot represent, or one whose key
// another writer already holds. A prefix the mesh has and the kernel does not
// is explained by Skipped or by Err and by nothing else.
type Stats struct {
	At        time.Time
	Desired   int
	Installed int
	Skipped   int
	Added     int
	Removed   int
	Err       string
}

// Stats reports the last route pass, and the zero value before the first one
// has run. A caller that wants to tell those apart reads At.
func (r *Reconciler) Stats() Stats {
	if s := r.stats.Load(); s != nil {
		return *s
	}
	return Stats{}
}

// New validates cfg, fills in its defaults and opens the netlink sockets, so
// a misconfigured or unsupported deployment fails at startup rather than on
// the first route. It installs nothing; Run does that.
func New(cfg Config, src RouteSource) (*Reconciler, error) {
	if cfg.Interface == "" {
		return nil, errors.New("kernel: interface is required")
	}
	if src == nil {
		return nil, errors.New("kernel: route source is required")
	}
	if cfg.Table == 0 {
		cfg.Table = DefaultTable
	}
	if cfg.Protocol == 0 {
		cfg.Protocol = DefaultProtocol
	}
	if cfg.Protocol <= protocolStatic {
		// rtnetlink reserves 0 through 3 for unspec, redirect, kernel and
		// boot, and 4 is the static protocol systemd-networkd stamps on the
		// rules it installs. Claiming any of them makes this reconciler's
		// routes indistinguishable from somebody else's, and since a rule
		// pass deletes every rule carrying this protocol that the config does
		// not name, claiming 4 deletes every static rule on the host.
		return nil, fmt.Errorf("kernel: protocol %d is reserved for the kernel and for networkd, use 5 through 255", cfg.Protocol)
	}
	if cfg.Table >= reservedTable && cfg.Table <= lastByteTable {
		// rtnetlink reserves 253, 254 and 255 for default, main and local, and
		// nothing above 255 at all: the linux backend sends RT_TABLE_UNSPEC
		// plus a 32-bit RTA_TABLE for those, which is how a table id like
		// 51820 reaches the kernel. Nothing else here would refuse a route in
		// main, and an announced default is installed unscoped on linux, so
		// the reconciler would put the whole machine's default out of the tun
		// and take the ESP underlay with it. collectForeignWriters also stops
		// reporting the kernel's own entries outside main, which is the one
		// warning that would have said so.
		return nil, fmt.Errorf("kernel: table %d is reserved, use anything else from 1 to %d", cfg.Table, ^uint32(0))
	}
	if cfg.PrefSrc4.IsValid() {
		if address := cfg.PrefSrc4.Unmap(); address.Is4() {
			cfg.PrefSrc4 = address.WithZone("")
		} else {
			return nil, fmt.Errorf("kernel: prefsrc4 %s is not an IPv4 address", cfg.PrefSrc4)
		}
	}
	addresses := make([]netip.Prefix, 0, len(cfg.Addresses))
	for _, prefix := range cfg.Addresses {
		if _, ok := canonicalPrefix(prefix); !ok {
			return nil, fmt.Errorf("kernel: address %s is not a valid prefix", prefix)
		}
		// an assigned address keeps its host bits; only a route key is masked.
		addresses = append(addresses, netip.PrefixFrom(prefix.Addr().WithZone(""), prefix.Bits()))
	}
	cfg.Addresses = addresses
	if cfg.ReconcileInterval <= 0 {
		cfg.ReconcileInterval = DefaultReconcileInterval
	}
	cfg.Rules = canonicalRules(cfg.Rules)
	for i, rule := range cfg.Rules {
		if err := rule.validate(); err != nil {
			return nil, err
		}
		if slices.Contains(cfg.Rules[:i], rule) {
			return nil, fmt.Errorf("kernel: rule %s is configured twice", rule)
		}
	}
	plat, err := newPlatform(cfg)
	if err != nil {
		return nil, err
	}
	if err := refuseWhatThePlatformLacks(cfg, plat); err != nil {
		plat.Close()
		return nil, err
	}
	return newReconciler(cfg, src, plat), nil
}

// refuseWhatThePlatformLacks stops a startup that asked for a facility this
// platform does not have. It is one place rather than one per backend, so a
// refusal says what the platform does instead as well as what it will not do.
//
// Refusing matters more than it looks. Policy rules and a VRF are the two
// halves of the steering a fleet node needs, and a platform that accepted the
// configuration and reconciled only the routes would come up with a working
// mesh and no steering at all, which is the shape of outage that reads as a
// routing problem for a day.
func refuseWhatThePlatformLacks(cfg Config, plat platform) error {
	if _, ok := plat.(ruler); !ok && len(cfg.Rules) > 0 {
		return fmt.Errorf("kernel: %d policy rules are configured and this platform has no policy routing: %s", len(cfg.Rules), rulesUnavailable)
	}
	if _, ok := plat.(vrfMaker); !ok && (cfg.CreateVRF || cfg.VRF != "") {
		return errors.New("kernel: vrf or vrf_create is set and this platform has no VRFs: there is one forwarding table here and the reconciler already writes it")
	}
	if cfg.CreateVRF && cfg.VRF == "" {
		return errors.New("kernel: vrf_create is set and vrf names no device, so there is nothing to create")
	}
	return nil
}

// rulesUnavailable says what a platform without rules does instead, so the
// refusal answers the next question as well as the current one.
const rulesUnavailable = "an announced default and a source-specific route are installed scoped to the tun instead, which keeps both off every unbound socket, and the underlay stays out of the mesh without needing a mark"

// canonicalRules is the configured rules in the spelling the kernel reports
// back, in a copy: New is handed the caller's slice and a reload compares one
// Config against another, so rewriting in place would change what that
// comparison reads. See Rule.canonical.
func canonicalRules(rules []Rule) []Rule {
	out := slices.Clone(rules)
	for i := range out {
		out[i] = out[i].canonical()
	}
	return out
}

func newReconciler(cfg Config, src RouteSource, plat platform) *Reconciler {
	cfg.Rules = canonicalRules(cfg.Rules)
	r := &Reconciler{
		cfg: cfg, src: src, plat: plat,
		owned:       make(map[netip.Prefix]bool),
		warnedAddrs: make(map[netip.Prefix]bool),
		warned:      make(map[Route]bool),
	}
	// Nil on a platform without them, which New has already refused to
	// configure, so every use below is reached only where the backend answers.
	r.rules, _ = plat.(ruler)
	r.vrfs, _ = plat.(vrfMaker)
	return r
}

// Where names the space this reconciler owns, for an operator reading a log
// line: a routing table where the platform has them, and the interface itself
// where it does not.
func (r *Reconciler) Where() string { return r.plat.where(r.cfg) }

// Config is the configuration this reconciler is running, defaults applied.
// New takes its argument by value and fills the gaps in its own copy, so the
// caller's is not the one in force and a diagnostic reporting that one names
// a table of zero on every deployment that left it out.
func (r *Reconciler) Config() Config { return r.cfg }

// Run reconciles until ctx is canceled, then withdraws everything this
// reconciler installed and closes its netlink sockets. It is called once.
//
// Withdrawal is best effort by construction: the caller usually cancels the
// mesh at the same moment, and the kernel drops routes and addresses on its
// own when the TUN disappears, so a device that is already gone is not an
// error. Run returns the withdrawal error, never a reconcile error: a failed
// pass is logged and retried instead.
func (r *Reconciler) Run(ctx context.Context) error {
	changed := r.src.Changed()
	notify := r.plat.Notify()
	ticker := time.NewTicker(r.cfg.ReconcileInterval)
	defer ticker.Stop()
	retry := time.NewTimer(r.cfg.ReconcileInterval)
	stopTimer(retry)
	defer retry.Stop()

	// The space this reconciler owns comes from the platform: darwin has one
	// FIB and no rt_proto, so naming a table and a protocol there prints two
	// settings it refuses to honor.
	slog.Info("kernel reconciler started", "interface", r.cfg.Interface, "where", r.Where())

	// An install refuses a key another writer already holds, so sharing a table
	// with another daemon means the routes it refuses are routes the mesh
	// wanted. Say so once at startup: on a fleet node mid-migration the other
	// writer is BIRD in table 200, which is the intended overlap and still
	// worth seeing.
	if audit, ok := r.plat.(auditor); ok {
		if writers, err := audit.foreignWriters(); err != nil {
			slog.Warn("kernel could not check the table for other writers", "err", err)
		} else if len(writers) > 0 {
			slog.Warn("kernel is sharing its table with another routing protocol",
				"table", r.cfg.Table, "protocols", strings.Join(writers, ", "),
				"detail", "an install refuses a key another writer already holds, so give this reconciler a table of its own")
		}
	}

	backoff := time.Duration(0)
	for ctx.Err() == nil {
		if err := r.reconcile(); err != nil {
			backoff = min(max(2*backoff, minRetryInterval), r.cfg.ReconcileInterval)
			slog.Warn("kernel reconcile failed, retrying", "err", err, "retry_in", backoff)
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
		case <-changed:
			r.settle(ctx, changed, notify)
		case <-notify:
			r.settle(ctx, changed, notify)
		}
	}

	return errors.Join(r.withdraw(), r.plat.Close())
}

// settle waits out a fixed window, discarding further wake-ups, so a burst of
// babel changes and the notifications of the reconciler's own writes collapse
// into one pass.
func (r *Reconciler) settle(ctx context.Context, changed, notify <-chan struct{}) {
	timer := time.NewTimer(settleDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-notify:
		case <-timer.C:
			return
		}
	}
}

func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// reconcile brings the kernel to one snapshot. The five steps are independent
// and every error is collected, so a VRF that cannot be joined does not stop
// routes from being installed.
//
// The pass is recorded here rather than inside applyRoutes, so that what a
// diagnostic reports is the error Run logged rather than one fifth of it: a
// node whose rules or VRF fail on every pass would otherwise answer `ranet-lite
// status` with a clean route count and no error at all, which is the outage
// that reads as a routing problem for a day.
func (r *Reconciler) reconcile() error {
	// The VRF first, because applyMaster enslaves the link to it and a master
	// that does not exist yet is a master the link cannot join.
	err := errors.Join(r.applyVRF(), r.applyMaster(), r.applyAddresses(), r.applyRoutes(), r.applyRules())
	r.recordPass(err)
	return err
}

// recordPass publishes the pass applyRoutes counted, with the whole pass's
// error rather than the route half's. A pass that failed before applyRoutes
// could count anything still records the attempt, so a stale PassAt cannot
// read as a reconciler that is keeping up.
func (r *Reconciler) recordPass(err error) {
	stats := r.routePass
	stats.At = time.Now()
	if err != nil {
		stats.Err = err.Error()
	}
	r.stats.Store(&stats)
}

// applyVRF creates the master device when the configuration asked for one and
// nothing of that name exists. A device that is already there is left as it
// is, whatever table it is bound to: it belongs to whoever created it, and
// rebinding somebody else's VRF would move every route in it.
func (r *Reconciler) applyVRF() error {
	if r.vrfs == nil || !r.cfg.CreateVRF || r.cfg.VRF == "" {
		return nil
	}
	created, err := r.vrfs.EnsureVRF(r.cfg.VRF, r.cfg.Table)
	if err != nil {
		return fmt.Errorf("create vrf %s: %w", r.cfg.VRF, err)
	}
	if created {
		r.madeVRF = true
		slog.Info("kernel created the mesh vrf", "vrf", r.cfg.VRF, "table", r.cfg.Table)
	}
	return nil
}

// applyRules brings the policy rules to the configured set. It removes before
// it installs for the same reason applyRoutes does, and it reads the kernel
// back rather than trusting a record, so rules an earlier instance left behind
// are adopted and then withdrawn rather than duplicated.
func (r *Reconciler) applyRules() error {
	if r.rules == nil {
		return nil
	}
	actual, err := r.rules.Rules()
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	var errs []error
	added, removed := 0, 0
	wanted := make(map[Rule]bool, len(r.cfg.Rules))
	for _, rule := range r.cfg.Rules {
		wanted[rule] = true
	}
	for _, rule := range actual {
		if wanted[rule] {
			continue
		}
		if err := r.rules.DelRule(rule); err != nil {
			errs = append(errs, fmt.Errorf("delete rule %s: %w", rule, err))
		} else {
			removed++
		}
	}
	held := make(map[Rule]bool, len(actual))
	for _, rule := range actual {
		held[rule] = true
	}
	for _, rule := range r.cfg.Rules {
		if held[rule] {
			continue
		}
		if err := r.rules.AddRule(rule); err != nil {
			errs = append(errs, fmt.Errorf("add rule %s: %w", rule, err))
		} else {
			added++
		}
	}
	if added > 0 || removed > 0 {
		slog.Info("kernel rules reconciled", "added", added, "removed", removed)
	}
	return errors.Join(errs...)
}

// applyRoutes removes before it installs, so a changed non-key attribute does
// not collide with the old route under the exclusive-install policy.
func (r *Reconciler) applyRoutes() error {
	actual, err := r.plat.Routes()
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	desired := r.desired(r.src.Snapshot())
	add, del := diffRoutes(desired, actual, r.platformScopes())
	var errs []error
	added, removed, skipped := 0, 0, 0
	// Withdraw before installing. An install refuses a key another writer
	// already holds rather than taking it over, so a route of ours that
	// changed only in an attribute the kernel does not key on, a preferred
	// source at an unchanged metric, has to leave before its replacement
	// arrives. Both lists are this reconciler's own routes, so the gap is
	// within one pass and touches nothing else.
	for _, route := range del {
		if err := r.plat.DelRoute(route); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", route, err))
		} else {
			removed++
		}
	}
	for _, route := range add {
		if err := r.plat.AddRoute(route); err == nil {
			added++
		} else if errors.Is(err, errRouteSkipped) {
			skipped++
		} else {
			errs = append(errs, fmt.Errorf("add route %s: %w", route, err))
		}
	}
	// Reported only when something moved. A route the platform refuses stays
	// in the diff on purpose, because the install is retried on every pass
	// until it lands, so a node holding one permanently unrepresentable route
	// would otherwise log "added=0 removed=0" once per pass for its whole
	// life.
	if added > 0 || removed > 0 {
		slog.Info("kernel routes reconciled", "added", added, "removed", removed)
	}
	// Installed is counted rather than re-listed: the kernel held len(actual)
	// when the pass started and every add and delete below was confirmed, so
	// the sum is exact and costs no second dump. reconcile publishes it, with
	// the error of the whole pass rather than this step's.
	r.routePass = Stats{
		Desired:   len(desired),
		Installed: len(actual) - removed + added,
		Skipped:   skipped,
		Added:     added,
		Removed:   removed,
	}
	return errors.Join(errs...)
}

// desired projects one forwarding table snapshot onto the routes the kernel
// can hold. The peer is dropped here: it says the route exists, not where it
// goes, because the mesh picks the peer after the kernel hands over the
// packet.
func (r *Reconciler) desired(snapshot []sadr.Route[*netstack.Peer]) []Route {
	out := make([]Route, 0, len(snapshot))
	warned := make(map[Route]bool, len(r.warned))
	for _, entry := range snapshot {
		destination, ok := canonicalPrefix(entry.Destination)
		if !ok {
			continue
		}
		if reason := unroutable(destination); reason != "" {
			key := Route{Destination: destination}
			if !r.warned[key] {
				slog.Warn("kernel is not installing a prefix the mesh cannot carry",
					"destination", destination, "detail", reason)
			}
			warned[key] = true
			continue
		}
		unreachable := entry.Value == netstack.Unreachable
		route := Route{
			Destination: destination,
			Metric:      routeMetric(r.cfg.Metric, destination, unreachable),
			Unreachable: unreachable,
		}
		// A source covering every address is not a source-specific route, and
		// installing it as one is beyond what the linux encoder can express: it
		// derives rtm_src_len from the length and omits RTA_SRC at zero, so
		// the route would install as a plain one, read back with no source,
		// never match the diff, and be withdrawn and reinstalled on every pass
		// for the life of the process. Dropping the source says the same thing
		// and installs.
		//
		// Nothing currently reaches this. RFC 9079 section 5 makes a
		// zero-length source prefix an ordinary route, so babel's decoder
		// refuses source plen 0 on the wire, originatedKey drops it from a
		// local announcement, and the config refuses "from: ::/0". It is here
		// because the cost of one of those changing is a route the kernel
		// tears down and reinstalls four times a second.
		if entry.Source.IsValid() && entry.Source.Bits() == 0 {
			entry.Source = netip.Prefix{}
		}
		if entry.Source.IsValid() {
			source, ok := canonicalPrefix(entry.Source)
			if !ok || source.Addr().Is4() || destination.Addr().Is4() {
				// the IPv4 FIB has no source-specific lookup, and installing
				// such a route as an ordinary one would steal traffic from
				// every other source. Report it and leave it to the mesh's
				// own table, where forwarding still honors it.
				key := Route{Destination: destination, Source: entry.Source}
				if !r.warned[key] {
					slog.Warn("kernel cannot install source-specific IPv4 route",
						"destination", destination, "source", entry.Source)
				}
				warned[key] = true
				continue
			}
			route.Source = source
		}
		if destination.Addr().Is4() && r.cfg.PrefSrc4.IsValid() {
			route.PrefSrc = r.cfg.PrefSrc4
		}
		out = append(out, route)
	}
	r.warned = warned
	return out
}

// limitedBroadcast is the one entry the darwin kernel installs that carries no
// flag separating it from a route of ours: scoped, RTF_STATIC, and leaving
// through the interface itself, the same shape that backend writes. It
// is not created for a tun configured the way this backend configures one
// (measured on a throwaway utun carrying a /24 and a /48, where every entry
// the kernel added named an address as its gateway and so was already
// excluded), but it is present on every broadcast-capable interface on that
// machine and on the utun another overlay configures differently.
var limitedBroadcast = netip.MustParsePrefix("255.255.255.255/32")

// unroutable names why a prefix has no business in a routing table that
// forwards out of a mesh tunnel, or is empty for one that does. These are
// prefixes whose meaning is the link they sit on: the kernel keys its own
// entries for them per interface, and a route the mesh installs at the same
// key shadows the machine's own plumbing. On darwin that is the single FIB
// every program shares, which this tool has to coexist with, and only a
// default or a source-specific route is interface-scoped there.
func unroutable(destination netip.Prefix) string {
	switch addr := destination.Addr(); {
	case addr.IsMulticast():
		return "multicast is delivered on a link, not routed through a tunnel"
	case addr.IsLinkLocalUnicast():
		return "a link-local prefix names the link it arrived on"
	case addr.IsLoopback():
		return "loopback belongs to the host"
	case destination == limitedBroadcast:
		return "the limited broadcast address is not a destination"
	}
	return ""
}

// holdMetric is where a retraction sits among the routes to the same prefix:
// last. A lookup is longest prefix first and only then by metric, so a hold
// still outranks the covering route it exists to keep a packet away from,
// while anything else holding that exact prefix wins. On a converted fleet
// node that anything else is the gravity VRF's connected route for the /60 the
// node itself originates, in the same table.
const holdMetric = ^uint32(0)

// routeMetric is the value the kernel will actually hold, so a dump compares
// equal to what was installed. An unset configured metric means the kernel's
// own default, which differs by family. Both the reconciler and the darwin
// backend answer through here, because darwin's FIB keeps no metric and
// mirrors this onto every route it decodes: two answers to the same question
// make a diff that adds and deletes the same route on every pass.
func routeMetric(configured uint32, destination netip.Prefix, unreachable bool) uint32 {
	switch {
	case unreachable:
		return holdMetric
	case configured == 0 && !destination.Addr().Is4():
		return defaultIPv6Metric
	}
	return configured
}

// diffRoutes reports the routes the kernel is missing and the reconciler's
// own routes it still holds that the mesh no longer wants. Both results are
// sorted so a pass is reproducible and its log lines are stable.
//
// scopes says which routes this platform files under interface scope, which on
// darwin is how the kernel keys them and everywhere else is nothing. A desired
// route is compared under the scope it would be installed with, and a route
// read back under the scope the kernel actually holds, so the two agree for
// every route this reconciler installed. They disagree only for a scoped route
// it did not install, and that has to be replaced rather than accepted: an
// unbound lookup does not reach a scoped route, so leaving one in place of an
// unscoped route the mesh asked for is a black hole the diff would never
// notice again.
func diffRoutes(desired, actual []Route, scopes func(Route) bool) (add, del []Route) {
	if scopes == nil {
		scopes = func(Route) bool { return false }
	}
	wanted := func(r Route) Route { r.Scoped = scopes(r); return r }
	held := func(r Route) Route { return r }
	want := make(map[Route]bool, len(desired))
	for _, route := range desired {
		want[wanted(route)] = true
	}
	have := make(map[Route]bool, len(actual))
	for _, route := range actual {
		have[held(route)] = true
	}
	emitted := make(map[Route]bool, len(desired)+len(actual))
	for _, route := range desired {
		if k := wanted(route); !have[k] && !emitted[k] {
			emitted[k] = true
			add = append(add, route)
		}
	}
	clear(emitted)
	for _, route := range actual {
		if k := held(route); !want[k] && !emitted[k] {
			emitted[k] = true
			del = append(del, route)
		}
	}
	slices.SortFunc(add, compareRoutes)
	slices.SortFunc(del, compareRoutes)
	return add, del
}

func boolOrder(b bool) int {
	if b {
		return 1
	}
	return 0
}

func compareRoutes(a, b Route) int {
	return cmp.Or(
		comparePrefixes(a.Destination, b.Destination),
		compareSourceSpecificity(a.Source, b.Source),
		a.PrefSrc.Compare(b.PrefSrc),
		cmp.Compare(a.Metric, b.Metric),
		cmp.Compare(boolOrder(a.Unreachable), boolOrder(b.Unreachable)),
		cmp.Compare(boolOrder(a.Scoped), boolOrder(b.Scoped)),
	)
}

func comparePrefixes(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
}

// compareSourceSpecificity orders the more specific source prefix first, which
// is the tiebreaker RFC 9079 section 4 applies among equally specific
// destinations, with an absent source last because it stands for every source.
//
// Ordering carries policy here rather than only presentation. darwin holds one
// source per destination, so where two source-specific routes reach the same
// destination the one this list offers first is the one installed and the
// other is skipped; ordering by address instead would hand that decision to
// whichever exit happened to be numbered lower. Nothing on linux depends on
// it, where both routes are installed and the FIB does the matching.
func compareSourceSpecificity(a, b netip.Prefix) int {
	return cmp.Or(cmp.Compare(b.Bits(), a.Bits()), a.Addr().Compare(b.Addr()))
}

// applyAddresses adds the configured addresses that are missing. It removes
// nothing: an address on the link that is not configured belongs to somebody
// else, and the only addresses ever removed are the ones recorded in owned.
func (r *Reconciler) applyAddresses() error {
	if len(r.cfg.Addresses) == 0 {
		return nil
	}
	actual, err := r.plat.Addrs()
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	have := make(map[netip.Prefix]bool, len(actual))
	held := make(map[netip.Addr]netip.Prefix, len(actual))
	for _, prefix := range actual {
		have[prefix] = true
		held[prefix.Addr()] = prefix
	}
	warned := make(map[netip.Prefix]bool, len(r.warnedAddrs))
	var errs []error
	for _, prefix := range r.cfg.Addresses {
		if have[prefix] {
			continue
		}
		// Both platforms assign an address by upsert: linux matches an
		// existing ifa by address alone and darwin's SIOCAIFADDR has no
		// "already present" at all, so assigning the same address under a
		// different prefix length rewrites somebody else's entry and reports
		// success. The reconciler would then record it as its own and take it
		// away at shutdown, against the rule that only an address it added
		// itself is ever removed. ranet-lite attaches to a tun it did not
		// necessarily create, so this is reachable without anything unusual.
		if existing, taken := held[prefix.Addr()]; taken {
			if !r.warnedAddrs[prefix] {
				slog.Warn("kernel is leaving an address another writer holds",
					"interface", r.cfg.Interface, "address", prefix, "held_as", existing)
			}
			warned[prefix] = true
			continue
		}
		if err := r.plat.AddAddr(prefix); err != nil {
			errs = append(errs, fmt.Errorf("add address %s: %w", prefix, err))
			continue
		}
		slog.Info("kernel address assigned", "interface", r.cfg.Interface, "address", prefix)
		r.owned[prefix] = true
	}
	r.warnedAddrs = warned
	return errors.Join(errs...)
}

// applyMaster joins the configured VRF, and only ever from no master at all.
// A link somebody else already enslaved is reported and left alone: taking it
// over would start a flap war with whatever put it there.
func (r *Reconciler) applyMaster() error {
	if r.cfg.VRF == "" {
		return nil
	}
	master, err := r.plat.Master()
	if err != nil {
		return fmt.Errorf("read master of %s: %w", r.cfg.Interface, err)
	}
	switch master {
	case r.cfg.VRF:
		r.master = master
		return nil
	case "":
		if err := r.plat.Enslave(r.cfg.VRF); err != nil {
			return fmt.Errorf("enslave %s to %s: %w", r.cfg.Interface, r.cfg.VRF, err)
		}
		r.enslaved, r.master = true, r.cfg.VRF
		slog.Info("kernel interface enslaved", "interface", r.cfg.Interface, "master", r.cfg.VRF)
		return nil
	default:
		if r.master != master {
			slog.Warn("kernel leaving interface in the master it already has",
				"interface", r.cfg.Interface, "master", master, "configured", r.cfg.VRF)
		}
		r.master = master
		return nil
	}
}

// withdraw removes exactly what this reconciler installed: every route still
// carrying its marker, every address it added itself, and the VRF master only
// if it set it. Routes are read back rather than remembered, so routes an
// earlier crashed instance left behind go with them.
func (r *Reconciler) withdraw() error {
	var errs []error
	routes, err := r.plat.Routes()
	if err != nil {
		errs = append(errs, fmt.Errorf("list routes: %w", err))
	}
	withdrawn := 0
	for _, route := range routes {
		if err := r.plat.DelRoute(route); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", route, err))
		} else {
			withdrawn++
		}
	}
	// An address is removed only while the link still carries exactly what was
	// installed. darwin's SIOCDIFADDR matches on the address alone, so another
	// writer that rewrote ours under a different prefix length, which its
	// SIOCAIFADDR upsert lets it do, would otherwise have its entry taken away
	// by this shutdown. applyAddresses reads the link back rather than
	// trusting the record for the same reason, and refuses on the same
	// failure: a readback that did not happen is not one that said yes.
	held, err := r.plat.Addrs()
	addresses := slices.SortedFunc(maps.Keys(r.owned), comparePrefixes)
	removed := 0
	if err != nil {
		errs = append(errs, fmt.Errorf("list addresses: %w", err))
		slog.Warn("kernel is leaving every address it installed, the link would not read back",
			"interface", r.cfg.Interface, "addresses", len(addresses))
		addresses = nil
	}
	for _, prefix := range addresses {
		if !slices.Contains(held, prefix) {
			slog.Warn("kernel is leaving an address it no longer holds as it installed it",
				"interface", r.cfg.Interface, "address", prefix)
			delete(r.owned, prefix)
			continue
		}
		if err := r.plat.DelAddr(prefix); err != nil {
			errs = append(errs, fmt.Errorf("delete address %s: %w", prefix, err))
			continue
		}
		delete(r.owned, prefix)
		removed++
	}
	if r.enslaved {
		if err := r.plat.Release(); err != nil {
			errs = append(errs, fmt.Errorf("release %s from %s: %w", r.cfg.Interface, r.cfg.VRF, err))
		} else {
			r.enslaved = false
		}
	}
	// Rules go the same way routes do, read back under this reconciler's own
	// protocol rather than remembered, so one an earlier instance left behind
	// leaves with them.
	rules := 0
	if r.rules != nil {
		held, err := r.rules.Rules()
		if err != nil {
			errs = append(errs, fmt.Errorf("list rules: %w", err))
		}
		for _, rule := range held {
			if err := r.rules.DelRule(rule); err != nil {
				errs = append(errs, fmt.Errorf("delete rule %s: %w", rule, err))
			} else {
				rules++
			}
		}
	}
	// Only a VRF this process created. One that was already there when it
	// started belongs to whoever made it, and removing it would take every
	// route in its table with it.
	if r.madeVRF {
		if err := r.vrfs.RemoveVRF(r.cfg.VRF); err != nil {
			errs = append(errs, fmt.Errorf("remove vrf %s: %w", r.cfg.VRF, err))
		} else {
			r.madeVRF = false
		}
	}
	// Every count is of something that left, so a line reporting nothing
	// removed is a shutdown that removed nothing.
	slog.Info("kernel reconciler withdrawn", "routes", withdrawn, "addresses", removed, "rules", rules)
	return errors.Join(errs...)
}

// canonicalPrefix puts a prefix in the one form the kernel reports, so a diff
// key built from a snapshot compares equal to one built from a route dump. The
// 4-in-6 form is deliberately left alone rather than unmapped: sadr keeps such
// a prefix in its IPv6 table and the kernel would hold it as an IPv6 route, so
// unmapping here would make the two sides disagree about the family.
func canonicalPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	canonical := netip.PrefixFrom(prefix.Addr().WithZone(""), prefix.Bits())
	if !canonical.IsValid() {
		return netip.Prefix{}, false
	}
	return canonical.Masked(), true
}

// scoper is implemented by a platform whose kernel keys a route by interface
// scope as well as by its destination, which is darwin alone.
type scoper interface{ scopes(Route) bool }

func (r *Reconciler) platformScopes() func(Route) bool {
	if p, ok := r.plat.(scoper); ok {
		return p.scopes
	}
	return nil
}
