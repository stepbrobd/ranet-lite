// Package kernel mirrors the mesh forwarding table into the host's routing
// table, taking over from the BIRD kernel protocols a ranet deployment runs
// today. It is a one-way reconciler: internal/netstack keeps owning the
// forwarding decision and this package only teaches the kernel which packets
// to hand to the TUN, so every route it installs points at the device
// and the peer in a snapshot entry never selects a kernel next hop.
//
// # Ownership
//
// On linux, every route this package installs lives in the table cap.table names,
// carries its rt_proto and points out of the mesh device. Those three
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
// holds in that table is left alone and reported once rather than taken
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
// never takes the device away from systemd-networkd or anything else
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
	"github.com/NickCao/ranet-lite/schema"
	"go.yaml.in/yaml/v3"
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

// Table is the cap.table capability, parsed straight out of the file: the
// routing table this reconciler owns and everything it writes into it.
// Writing the block turns the reconciler on, so a deployment configuring its
// routes externally writes no cap.table and gets no reconciler. Every field is checked by Validate, which the loader calls, and
// again by New.
type Table struct {
	// ID is the routing table the reconciler owns; the fleet uses 200, the
	// table its policy rules and its End.DT46 look up. Zero uses DefaultTable.
	ID schema.TableID `yaml:"id,omitempty" json:"id,omitempty" toml:"id,omitempty"`
	// Proto is the rt_proto stamped on every installed route, and the marker
	// separating this reconciler's routes from everyone else's. Zero uses
	// DefaultProtocol.
	Proto uint8 `yaml:"proto,omitempty" json:"proto,omitempty" toml:"proto,omitempty"`
	// Metric is RTA_PRIORITY. Zero takes the kernel's own default, which is 0
	// for IPv4 and 1024 for IPv6. Do not set it to BIRD's 32 while BIRD is
	// still exporting to the same table: both daemons would then key on the
	// same prefix and priority, and since an install refuses a key another
	// writer holds rather than taking it over, whichever daemon got there
	// first keeps the prefix and the other loses it quietly.
	Metric uint32 `yaml:"metric,omitempty" json:"metric,omitempty" toml:"metric,omitempty"`
	// PrefSrc4 is RTA_PREFSRC on every installed IPv4 route, the attribute
	// BIRD sets from krt_prefsrc. IPv6 routes carry no preferred source;
	// source-specific IPv6 routes carry RTA_SRC instead.
	PrefSrc4 schema.Addr `yaml:"prefsrc4,omitempty" json:"prefsrc4,omitzero" toml:"prefsrc4,omitempty"`
	// Addresses are assigned to the device when absent and removed again at
	// shutdown; only addresses the reconciler added itself are ever removed.
	Addresses []schema.Prefix `yaml:"addresses,omitempty" json:"addresses,omitempty" toml:"addresses,omitempty"`
	// AssignAnnounced assigns every prefix cap.route announces as well, which
	// is the locally originated address an operator otherwise configures by
	// hand. A default is announced and never assigned, so it is skipped.
	AssignAnnounced bool `yaml:"assign_announced,omitempty" json:"assign_announced,omitempty" toml:"assign_announced,omitempty"`
	// VRF enslaves the device to a master, and optionally creates it. Absent
	// leaves the link's master alone.
	VRF *VRF `yaml:"vrf,omitempty" json:"vrf,omitempty" toml:"vrf,omitempty"`
	// Rules are the policy rules this reconciler owns, in the order written.
	// Each carries Proto in FRA_PROTOCOL, the same ownership marker routes
	// carry, so a dump reads back only these and a delete can never reach
	// another writer's. They are withdrawn at shutdown as the routes are: a
	// rule pointing into an empty table costs only a lookup, and one left
	// behind sends traffic to a table nothing is writing any more. linux only:
	// darwin has one forwarding table and no rules, and a mobile tunnel
	// provider is handed a route list rather than a table, so a configuration
	// asking for one there is refused by name.
	Rules []Rule `yaml:"rules,omitempty" json:"rules,omitempty" toml:"rules,omitempty"`
	// Reconcile is the periodic sweep correcting drift nothing announced.
	// Zero uses DefaultReconcileInterval.
	Reconcile schema.Duration `yaml:"reconcile,omitempty" json:"reconcile,omitempty" toml:"reconcile,omitempty"`
	// CaptureGrace is how long a route that would carry this machine's own
	// traffic, an announced default above all, stays installed after the last
	// live session went away. Such a route is never installed before one has
	// been live and comes back on the next one, so this only sets how long a
	// node waits before falling back to its own uplink. Zero uses
	// DefaultCaptureGrace.
	CaptureGrace schema.Duration `yaml:"capture_grace,omitempty" json:"capture_grace,omitempty" toml:"capture_grace,omitempty"`
}

// VRF is the master device the mesh table is bound to.
type VRF struct {
	// Name is the device the reconciler enslaves its interface to, and only
	// while that link has no master, so networkd keeps whatever it claimed.
	Name string `yaml:"name" json:"name" toml:"name"`
	// Create makes that device when nothing of the name exists, bound to the
	// table above, so a deployment does not need its host's network manager to
	// make it first. One this process created is removed again at shutdown.
	// linux only: there are no VRFs on the other platforms this builds for,
	// and a configuration asking for one there is refused by name.
	Create bool `yaml:"create,omitempty" json:"create,omitempty" toml:"create,omitempty"`
}

// Runtime is the half the reconciler is handed rather than told: the device
// the mesh actually got, the addresses this node's transport has to keep
// reaching, and the prefixes cap.route announces. None of the three is a fact an
// operator writes down, so none of them is in the capability.
type Runtime struct {
	// Interface is the TUN device every installed route points at, named as
	// the kernel named it (netstack.Mesh.Name, not the requested name).
	Interface string
	// Underlay names the addresses this node's own transport has to keep
	// reaching. The darwin backend asks once per pass and scopes a route that
	// covers one, see coversAny there; linux reads it never, and keeps the
	// underlay out with a socket mark instead. Nil decides scope on the
	// destination alone.
	Underlay func() []netip.Addr
	// Announced carries the prefixes cap.route announces, which
	// Table.AssignAnnounced puts on the device beside the addresses written
	// here.
	Announced []netip.Prefix
	// BoundUnderlay says the transport's own socket no longer consults the
	// forwarding table, because it is bound to the interface the host's
	// default route leaves by. The darwin backend then installs an announced
	// default as a real default rather than scoping it out of every socket's
	// reach, which is the difference between a node that can hold a mesh
	// address and one that can use a mesh exit. Leaving it off keeps the
	// scoping. Nothing reads it on linux, where a socket mark and a policy
	// rule do the same job and a default is installed unscoped either way.
	// It is set from link.underlay, so it is handed here rather than written
	// in cap.table: one setting decides both halves and they cannot disagree.
	BoundUnderlay bool
	// Sessions reports how many of this node's mesh sessions have recently
	// proved their peer is there. Until one has, and once none has for
	// Table.CaptureGrace, no route that would carry this machine's own
	// traffic is installed: see captureGate, which is the whole of why. Nil
	// installs every route the mesh announces as soon as it announces it,
	// which is right for a reconciler driven by something that has no
	// sessions. It is here rather than in the capability because no operator
	// writes it down.
	Sessions func() int
	// Capture holds the rest of the routing a capturing route needs to be
	// safe, which on darwin is a default scoped to the underlay interface.
	// Nil where the platform needs nothing, which is everywhere but there.
	// It is opened by whatever owns the link watcher, so it is handed here
	// rather than written in cap.table.
	Capture CaptureRoutes
	// Host is the machine this reconciler reads and writes, nil for the one
	// this process is running on, as a daemon passes. A test hands
	// in a recorded routing table so the path from a configuration file to a
	// route on the wire can be run without a kernel; see Host. Only the darwin
	// backend reads it.
	Host Host
}

// Name is the master device, empty for a table bound to none.
func (t Table) Name() string {
	if t.VRF == nil {
		return ""
	}
	return t.VRF.Name
}

// creates reports a VRF this reconciler makes itself rather than expecting to
// find.
func (t Table) creates() bool { return t.VRF != nil && t.VRF.Create }

// Assigned is every address the reconciler puts on the device: the ones
// written in the capability and, when it asks for them, the prefixes
// cap.route announces. It is exported because a segment this node answers for
// must not also be an address it carries, and that check spans two
// capabilities and so is made where the file is read.
//
// A default is announced, never assigned: an exit originates "::/0" from its
// transit prefix, and assigning it would try to put "::/0" on the device on
// every pass and fail on every one. The test is the address rather than the
// prefix length, because a prefix length says nothing about whether an address
// can be assigned; Validate refuses every other zero-length spelling.
func (t Table) Assigned(announced []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	seen := make(map[netip.Prefix]bool)
	add := func(prefix netip.Prefix) {
		if !prefix.IsValid() || prefix.Addr().IsUnspecified() || seen[prefix] {
			return
		}
		seen[prefix] = true
		out = append(out, prefix)
	}
	for _, prefix := range t.Addresses {
		add(prefix.Prefix)
	}
	if t.AssignAnnounced {
		for _, prefix := range announced {
			add(prefix)
		}
	}
	return out
}

// Validate refuses a capability this reconciler could not honor, naming the
// field as the operator wrote it. It runs where the file is read, so a node
// that has no reconciler on this platform still refuses a table it could not
// have owned.
func (t Table) Validate() error {
	if t.Proto != 0 && t.Proto <= protocolStatic {
		// rtnetlink reserves 0 through 3 for unspec, redirect, kernel and
		// boot, and 4 is the static protocol systemd-networkd stamps on the
		// rules it installs. Claiming any of them makes this reconciler's
		// routes indistinguishable from somebody else's, and since a rule pass
		// deletes every rule carrying this protocol that the config does not
		// name, claiming 4 deletes every static rule on the host.
		return fmt.Errorf("kernel: cap.table proto %d is reserved for the kernel and for networkd, use 5 through 255", t.Proto)
	}
	if id := uint32(t.ID); id >= reservedTable && id <= lastByteTable {
		// rtnetlink reserves 253, 254 and 255 for default, main and local, and
		// nothing above 255 at all: the linux backend sends RT_TABLE_UNSPEC
		// plus a 32-bit RTA_TABLE for those, which is how a table id like
		// 51820 reaches the kernel. Nothing else here would refuse a route in
		// main, and an announced default is installed unscoped on linux, so
		// the reconciler would put the whole machine's default out of the tun
		// and take the ESP underlay with it. collectForeignWriters also stops
		// reporting the kernel's own entries outside main, which is the one
		// warning that would have said so.
		return fmt.Errorf("kernel: cap.table id %d is reserved, use anything else from 1 to %d", id, ^uint32(0))
	}
	if address := t.PrefSrc4; address.IsValid() && !address.Unmap().Is4() {
		return fmt.Errorf("kernel: cap.table prefsrc4 %s is not an IPv4 address", address)
	}
	for _, prefix := range t.Addresses {
		// Assigning the unspecified address is not something an interface can
		// do, and Assigned skips it, so taking the entry and dropping it
		// silently is the one outcome that tells the operator nothing.
		if prefix.Addr().IsUnspecified() {
			return fmt.Errorf("kernel: cap.table addresses %s is not an address an interface can carry", prefix)
		}
		// Its own message rather than the announcement's: an entry here is
		// assigned to an interface, never announced, so "write ::/0 if that is
		// what you mean" is advice the check above rejects.
		if prefix.Bits() == 0 {
			return fmt.Errorf("kernel: cap.table addresses %s has no prefix length, and an interface carries an address under one", prefix)
		}
	}
	if t.VRF != nil && t.VRF.Name == "" {
		return errors.New("kernel: cap.table vrf names no device, so there is nothing to join")
	}
	if t.Reconcile < 0 {
		return fmt.Errorf("kernel: cap.table reconcile %s is not an interval", t.Reconcile)
	}
	if t.CaptureGrace < 0 {
		return fmt.Errorf("kernel: cap.table capture_grace %s is not an interval", t.CaptureGrace)
	}
	if t.CaptureGrace > 0 && t.CaptureGrace.Duration() < MinCaptureGrace {
		return fmt.Errorf("kernel: cap.table capture_grace %s is shorter than %s, which the reconciler cannot honor: the gate is sampled once a pass and a pass reads the routing table",
			t.CaptureGrace, MinCaptureGrace)
	}
	expanded, err := expandRules(t.Rules)
	if err != nil {
		return err
	}
	for _, rule := range expanded {
		if err := rule.validate(); err != nil {
			return err
		}
	}
	// Canonicalized before the comparison, because that is the spelling the
	// kernel holds: an all-ones mask and a bare mark are one rule to it, which
	// an earlier round settled against a real one. Two entries spelled those
	// two ways install the same rule, AddRule sends NLM_F_EXCL, and every pass
	// reports EEXIST on the second and retries over a rule already there.
	//
	// Through a set rather than a scan over what came before: one entry
	// written "family = both" expands to two, so the list grows with the
	// fleet's, and the scan cost 1.5 seconds at sixteen thousand rules.
	seen := make(map[Rule]struct{}, len(expanded))
	for _, rule := range expanded {
		rule = rule.canonical()
		if _, twice := seen[rule]; twice {
			return fmt.Errorf("kernel: cap.table rules %s is configured twice", rule)
		}
		seen[rule] = struct{}{}
	}
	return nil
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
// the kernel keys routes on it too: changing the configured metric has to withdraw
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
	where(Table) string

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
	// To is FRA_DST and From is FRA_SRC, each optional. A rule naming neither
	// selects on a mark alone and has to name its Family, because a mark
	// belongs to no address family.
	To   schema.Prefix `yaml:"to,omitempty" json:"to,omitzero" toml:"to,omitempty"`
	From schema.Prefix `yaml:"from,omitempty" json:"from,omitzero" toml:"from,omitempty"`
	// FWMark and FWMask are FRA_FWMARK and FRA_FWMASK. A zero mark means the
	// rule does not select on one, and a zero mask with a nonzero mark is an
	// exact match, which is how the kernel reads an absent FRA_FWMASK. A hex
	// literal is ordinary in both file formats, so fwmark: 0x726c is written
	// as it reads elsewhere.
	FWMark uint32 `yaml:"fwmark,omitempty" json:"fwmark,omitempty" toml:"fwmark,omitempty"`
	FWMask uint32 `yaml:"fwmask,omitempty" json:"fwmask,omitempty" toml:"fwmask,omitempty"`
	// Table is the table to look up, as a number or as one of the three names
	// the kernel reserves: a rule pointing at main is ordinary, and keeps an
	// underlay out of a mesh table.
	Table schema.TableID `yaml:"table" json:"table" toml:"table"`
	// Priority is FRA_PRIORITY, the rule's position in the list. It is
	// required: leaving it to the kernel puts the rule just above the last
	// one, which is a different place on every node.
	Priority uint32 `yaml:"priority" json:"priority" toml:"priority"`
	// Family is needed only when neither To nor From says which, and "both"
	// installs the rule once per family. An installed rule always names one,
	// because expandRules resolves this before anything reaches the kernel.
	Family Family `yaml:"family,omitempty" json:"family,omitempty" toml:"family,omitempty"`
}

// Family is the address family a rule belongs to, spelled as an operator
// writes it rather than as AF_INET and AF_INET6, which are numbers on one
// platform and absent on the others.
type Family string

const (
	// FamilyUnset is a rule taking its family from the address it selects on.
	FamilyUnset Family = ""
	FamilyIPv4  Family = "ipv4"
	FamilyIPv6  Family = "ipv6"
	// FamilyBoth is written once and installed twice, because keeping an
	// underlay out of a mesh table needs both and writing them by hand is how
	// one of the two goes missing.
	FamilyBoth Family = "both"
)

func (f *Family) UnmarshalText(text []byte) error {
	switch Family(strings.ToLower(string(text))) {
	case FamilyUnset:
		*f = FamilyUnset
	case FamilyIPv4:
		*f = FamilyIPv4
	case FamilyIPv6:
		*f = FamilyIPv6
	case FamilyBoth:
		*f = FamilyBoth
	default:
		return fmt.Errorf("kernel: family %q is not ipv4, ipv6 or both", text)
	}
	return nil
}

func (f Family) MarshalText() ([]byte, error) { return []byte(f), nil }

func (f *Family) UnmarshalYAML(value *yaml.Node) error {
	return schema.Scalar(value, "a family, ipv4, ipv6 or both", f)
}

func (f Family) MarshalYAML() (any, error) { return string(f), nil }

// expandRules resolves each configured rule's address family, so that
// everything below this point names exactly one. A rule that names neither a
// destination nor a source selects on a mark alone, which belongs to no
// family, so it says which one it is for; "both" is written once and installed
// twice.
//
// Everything the reconciler itself judges is left to Rule.validate, so the one
// place deciding what a rule may say is the one that installs it.
func expandRules(rules []Rule) ([]Rule, error) {
	var out []Rule
	for _, rule := range rules {
		addressed := rule.To.IsValid() || rule.From.IsValid()
		if addressed && rule.Family != FamilyUnset {
			return nil, fmt.Errorf("kernel: cap.table rules at priority %d names family %q and an address, which already says which family it is", rule.Priority, rule.Family)
		}
		if addressed {
			address := rule.To.Addr()
			if !rule.To.IsValid() {
				address = rule.From.Addr()
			}
			rule.Family = FamilyIPv4
			if !address.Is4() {
				rule.Family = FamilyIPv6
			}
			out = append(out, rule)
			continue
		}
		switch rule.Family {
		case FamilyIPv4, FamilyIPv6:
			out = append(out, rule)
		case FamilyBoth:
			rule.Family = FamilyIPv4
			out = append(out, rule)
			rule.Family = FamilyIPv6
			out = append(out, rule)
		default:
			return nil, fmt.Errorf("kernel: cap.table rules at priority %d selects on a mark alone, so it has to name family: ipv4, ipv6 or both", rule.Priority)
		}
	}
	return out, nil
}

// String is the rule as an operator wrote it, which is how every refusal and
// every log line names one. The table is spelled the way the file spells it,
// since an operator who wrote "main" does not recognize 254, and the family is
// there because a message about two rules that differ only in it identifies
// neither without it.
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
	if r.Family != FamilyUnset {
		parts = append(parts, "family "+string(r.Family))
	}
	return strings.Join(append(parts, "lookup "+r.Table.String()), " ")
}

// canonical is the rule as the kernel reports it back. Two spellings can reach
// the kernel as one rule while only one of them survives a dump, and a diff
// holding the other deletes and reinstalls that rule on every pass, with a
// window each time in which it is not there.
//
// A mark with no mask matches every bit, which the kernel stores and reports
// as a mask of all ones: `ip rule add fwmark X` and `ip rule add fwmark
// X/0xffffffff` answer EEXIST to each other. The other spelling that does not
// survive a dump, a zero-length selector, is refused by validate instead, so
// that the refusal can name the field the operator wrote.
// ReadsMark reports a rule here that selects packets carrying mark and looks
// them up somewhere other than this reconciler's own table. It answers for
// link.underlay mark, whose whole effect is that some rule selects on it: a
// marked socket that no rule reads follows the mesh table exactly as an
// unmarked one would.
//
// A rule sending the mark back into the mesh table does not count. It reads
// the mark and still leaves the socket on the routes the mesh installed, which
// is the state it was set to get out of.
func (t Table) ReadsMark(mark uint32) bool {
	normalized := t.Normalized()
	for _, rule := range normalized.Rules {
		if rule.selectsMark(mark) && rule.Table != normalized.ID {
			return true
		}
	}
	return false
}

// selectsMark is the kernel's own comparison: (skb->mark & FRA_FWMASK) against
// FRA_FWMARK, with an absent mask read as all ones, which is how a rule
// written with a mark and no mask matches.
func (r Rule) selectsMark(mark uint32) bool {
	if r.FWMark == 0 {
		return false
	}
	mask := r.FWMask
	if mask == 0 {
		mask = ^uint32(0)
	}
	return mark&mask == r.FWMark
}

func (r Rule) canonical() Rule {
	if r.FWMask == ^uint32(0) {
		r.FWMask = 0
	}
	return r
}

// validate refuses a rule the kernel would accept and an operator would not
// recognize afterwards. It runs at startup, so a mistake costs a refusal to
// start rather than a rule installed against a live fleet.
func (r Rule) validate() error {
	if r.Family != FamilyIPv4 && r.Family != FamilyIPv6 {
		return fmt.Errorf("kernel: cap.table rules %s: family must be ipv4 or ipv6", r)
	}
	for _, named := range []struct {
		name   string
		prefix netip.Prefix
	}{{"to", r.To.Prefix}, {"from", r.From.Prefix}} {
		if !named.prefix.IsValid() {
			continue
		}
		if familyOf(named.prefix.Addr()) != r.Family {
			return fmt.Errorf("kernel: cap.table rules %s: %s %s is not of the rule's family", r, named.name, named.prefix)
		}
		if named.prefix.Masked() != named.prefix {
			return fmt.Errorf("kernel: cap.table rules %s: %s %s has bits set below its prefix length", r, named.name, named.prefix)
		}
		if named.prefix.Bits() == 0 {
			// The kernel emits no FRA_DST or FRA_SRC for a zero-length
			// selector, so a rule carrying one never matches its own readback
			// and the pass reinstalls it forever. Whatever else the rule
			// selects on is the honest way to write it.
			return fmt.Errorf("kernel: cap.table rules %s: %s %s selects every address, which the kernel reports back as no selector at all", r, named.name, named.prefix)
		}
	}
	if !r.To.IsValid() && !r.From.IsValid() && r.FWMark == 0 {
		return fmt.Errorf("kernel: cap.table rules %s selects nothing, so it would match every packet", r)
	}
	if r.FWMark == 0 && r.FWMask != 0 {
		return fmt.Errorf("kernel: cap.table rules %s carries a mark mask and no mark", r)
	}
	if r.Priority == 0 {
		return fmt.Errorf("kernel: cap.table rules %s: priority 0 belongs to the local table", r)
	}
	if r.Table == 0 {
		return fmt.Errorf("kernel: cap.table rules %s: table is required", r)
	}
	return nil
}

func familyOf(address netip.Addr) Family {
	if address.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

type Reconciler struct {
	// table is the capability with its defaults filled in, rt what the caller
	// resolved, and rules and addresses what New made of the two: the rules
	// with their families expanded and the address set the device is to carry.
	table     Table
	rt        Runtime
	ruleSet   []Rule
	addresses []netip.Prefix

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
	// uncovered records what the last pass found the underlay able to fall
	// back on, so holding a capture back costs one line per transition rather
	// than one per pass, and capturing says whether this pass left one
	// installed, the only state whose grace needs a wake-up of its own.
	uncovered Covered
	capturing bool

	// rules and vrfs are the optional halves of the platform, nil where it has
	// no policy engine or no VRFs. New refuses a configuration that needs one
	// of them on such a platform, so nil here means the configuration asked
	// for nothing.
	rules ruler
	vrfs  vrfMaker
	// madeVRF records that this reconciler created the VRF device itself, the
	// only condition under which it removes one again.
	madeVRF bool

	// gate holds back the routes that would carry this machine's own traffic
	// until the mesh has proved it can carry them. Only the reconcile
	// goroutine touches it, and capture is its answer for the pass now
	// running, sampled once so every route of a pass is judged the same way.
	gate    captureGate
	capture bool
	// now is the clock the gate reads, replaced by a test that drives the
	// grace without sleeping through it.
	now func() time.Time

	// enabled is whether this reconciler is writing to the kernel at all, and
	// wake carries a change of it to the loop. Both are touched from outside
	// the reconcile goroutine; withdrawn is the loop's own record of having
	// acted on a stop, and belongs to that goroutine like every field above.
	enabled   atomic.Bool
	wake      chan struct{}
	withdrawn bool

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

// New checks the capability, fills in its defaults, resolves it against the
// runtime the caller supplies and opens the netlink sockets, so a
// misconfigured or unsupported deployment fails at startup rather than on the
// first route. It installs nothing; Run does that.
func New(t Table, rt Runtime, src RouteSource) (*Reconciler, error) {
	if rt.Interface == "" {
		return nil, errors.New("kernel: interface is required")
	}
	if src == nil {
		return nil, errors.New("kernel: route source is required")
	}
	// Checked as written and canonicalized afterwards, so a refusal names the
	// field an operator can find in their own file rather than the one
	// canonicalization left behind. The loader has already run this; a caller
	// that built the capability by hand has not.
	if err := t.Validate(); err != nil {
		return nil, err
	}
	t = t.Normalized()
	if rt.BoundUnderlay && rt.Sessions == nil {
		// The two halves of one arrangement. A bound underlay lets this
		// backend install an announced default where every socket can see
		// it, and the gate is the only thing that keeps such a route out
		// of the kernel until the mesh has proved it can carry traffic. With
		// no session source the gate is open from the first pass, so the two
		// together would put this machine's traffic in a tun nothing has ever
		// answered on.
		return nil, errors.New("kernel: a bound underlay needs a session source, or an announced default would install before the mesh has carried anything")
	}
	addresses := make([]netip.Prefix, 0, len(t.Addresses))
	for _, prefix := range t.Assigned(rt.Announced) {
		if _, ok := canonicalPrefix(prefix); !ok {
			return nil, fmt.Errorf("kernel: address %s is not a valid prefix", prefix)
		}
		// an assigned address keeps its host bits; only a route key is masked.
		addresses = append(addresses, netip.PrefixFrom(prefix.Addr().WithZone(""), prefix.Bits()))
	}
	plat, err := newPlatform(t, rt)
	if err != nil {
		return nil, err
	}
	if err := refuseWhatThePlatformLacks(t, plat); err != nil {
		plat.Close()
		return nil, err
	}
	// The rules as Normalized left them: expanded, canonical and in one order,
	// which is the form the reconciler installs and diffs against the kernel.
	return newReconciler(t, rt, t.Rules, addresses, src, plat), nil
}

// Normalized is the capability as the reconciler runs it: every field the file
// left out filled in with the default it stands for, every rule expanded to
// the one family it installs under and spelled the way the kernel reports it
// back, and every list the reconciler reads as a set in one order. New
// resolves a capability through this and hands the rules straight on, and a
// reload compares two through it rather than as they were written, so neither
// a field written out as its own default nor a second spelling of one ruleset
// is a change. Leaving either out refuses a reload over nothing, and a restart
// drops every SA on the node.
//
// Both lists here are read as sets. applyRules diffs what the kernel holds
// against the rules by value, and the kernel orders them by the priority each
// one carries rather than by the order they arrived in; the addresses are
// assigned to one device. So "family = both" and the same rule written once
// per family describe one reconciler, as do two files listing the same
// addresses in different orders.
func (t Table) Normalized() Table {
	if t.ID == 0 {
		t.ID = DefaultTable
	}
	if t.Proto == 0 {
		t.Proto = DefaultProtocol
	}
	if t.PrefSrc4.IsValid() {
		t.PrefSrc4 = schema.AddrFrom(t.PrefSrc4.Unmap().WithZone(""))
	}
	if t.Reconcile <= 0 {
		t.Reconcile = schema.Duration(DefaultReconcileInterval)
	}
	if t.CaptureGrace <= 0 {
		t.CaptureGrace = schema.Duration(DefaultCaptureGrace)
	}
	if len(t.Addresses) == 0 {
		t.Addresses = nil
	} else {
		t.Addresses = slices.SortedFunc(slices.Values(t.Addresses), schema.ComparePrefix)
	}
	switch expanded, err := expandRules(t.Rules); {
	case len(t.Rules) == 0:
		t.Rules = nil
	case err != nil:
		// A rule expansion refuses is one Validate refuses, and New runs
		// Validate first, so this answers a caller comparing two capabilities
		// neither of which will ever run. Left as written, such a rule still
		// compares equal to itself.
		t.Rules = canonicalRules(t.Rules)
	default:
		t.Rules = sortedRules(canonicalRules(expanded))
	}
	return t
}

// sortedRules puts a rule set in one order, in place, over the copy
// canonicalRules already made. The order is the whole rule rather than the
// priority alone, so two rules sharing a priority still sort the same way
// every time.
func sortedRules(rules []Rule) []Rule {
	slices.SortFunc(rules, func(a, b Rule) int {
		return cmp.Or(
			cmp.Compare(a.Priority, b.Priority),
			cmp.Compare(a.Family, b.Family),
			cmp.Compare(a.Table, b.Table),
			cmp.Compare(a.FWMark, b.FWMark),
			cmp.Compare(a.FWMask, b.FWMask),
			schema.ComparePrefix(a.From, b.From),
			schema.ComparePrefix(a.To, b.To),
		)
	})
	return rules
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
func refuseWhatThePlatformLacks(t Table, plat platform) error {
	if _, ok := plat.(ruler); !ok && len(t.Rules) > 0 {
		return fmt.Errorf("kernel: %d cap.table rules are configured and this platform has no policy routing: %s", len(t.Rules), rulesUnavailable)
	}
	if _, ok := plat.(vrfMaker); !ok && t.Name() != "" {
		return errors.New("kernel: cap.table vrf is set and this platform has no VRFs: there is one forwarding table here and the reconciler already writes it")
	}
	return nil
}

// rulesUnavailable says what a platform without rules does instead, so the
// refusal answers the next question as well as the current one.
const rulesUnavailable = "an announced default and a source-specific route are installed scoped to the tun instead, which keeps both off every unbound socket, and the underlay stays out of the mesh without needing a mark"

// canonicalRules is the configured rules in the spelling the kernel reports
// back, in a copy: New is handed the caller's slice and a reload compares one
// capability against another, so rewriting in place would change what that
// comparison reads. See Rule.canonical.
func canonicalRules(rules []Rule) []Rule {
	out := slices.Clone(rules)
	for i := range out {
		out[i] = out[i].canonical()
	}
	return out
}

func newReconciler(t Table, rt Runtime, rules []Rule, addresses []netip.Prefix, src RouteSource, plat platform) *Reconciler {
	if t.CaptureGrace <= 0 {
		// Filled here rather than only in New, because the tests reach this
		// directly and a gate with no grace withdraws on the first idle pass.
		t.CaptureGrace = schema.Duration(DefaultCaptureGrace)
	}
	r := &Reconciler{
		table: t, rt: rt, ruleSet: rules, addresses: addresses,
		src: src, plat: plat,
		owned:       make(map[netip.Prefix]bool),
		warnedAddrs: make(map[netip.Prefix]bool),
		warned:      make(map[Route]bool),
		gate:        captureGate{grace: t.CaptureGrace.Duration()},
		now:         time.Now,
		wake:        make(chan struct{}, 1),
	}
	r.enabled.Store(true)
	// Nil on a platform without them, which New has already refused to
	// configure, so every use below is reached only where the backend answers.
	r.rules, _ = plat.(ruler)
	r.vrfs, _ = plat.(vrfMaker)
	return r
}

// Where names the space this reconciler owns, for an operator reading a log
// line: a routing table where the platform has them, and the interface itself
// where it does not.
func (r *Reconciler) Where() string { return r.plat.where(r.table) }

// Table is the capability this reconciler is running, defaults applied. New
// takes its argument by value and fills the gaps in its own copy, so the
// caller's is not the one in force and a diagnostic reporting that one names a
// table of zero on every deployment that left it out.
func (r *Reconciler) Table() Table { return r.table }

// SetEnabled stops or starts this reconciler while it runs, which is the
// `birdc disable` a kernel protocol took while Babel lived in BIRD. Stopping
// withdraws every route, address and rule it installed, and starting puts them
// back on the next pass, which is idempotent like every other pass. A table
// left holding routes nobody maintains is the state a stop exists to avoid,
// so the withdrawal is part of it rather than a separate ask.
//
// The withdrawal runs on the reconcile goroutine rather than here, because
// every field it touches belongs to that goroutine alone. This records the
// request and wakes the loop, so a caller returns before the kernel has
// caught up and reads Stats to see that it has.
func (r *Reconciler) SetEnabled(on bool) {
	r.enabled.Store(on)
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Enabled reports whether this reconciler is writing to the kernel.
func (r *Reconciler) Enabled() bool { return r.enabled.Load() }

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
	ticker := time.NewTicker(r.table.Reconcile.Duration())
	defer ticker.Stop()
	retry := time.NewTimer(r.table.Reconcile.Duration())
	stopTimer(retry)
	defer retry.Stop()
	// Nothing else wakes at the moment the capture grace expires: the mesh has
	// stopped changing, which is why the grace is running at all. Without this
	// the machine's own traffic stays in a dead tun until the periodic sweep,
	// which is three times the grace by default.
	grace := time.NewTimer(r.table.Reconcile.Duration())
	stopTimer(grace)
	defer grace.Stop()

	// The space this reconciler owns comes from the platform: darwin has one
	// FIB and no rt_proto, so naming a table and a protocol there prints two
	// settings it refuses to honor.
	slog.Info("kernel reconciler started", "interface", r.rt.Interface, "where", r.Where())

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
				"table", uint32(r.table.ID), "protocols", strings.Join(writers, ", "),
				"detail", "an install refuses a key another writer already holds, so give this reconciler a table of its own")
		}
	}

	backoff := time.Duration(0)
	for ctx.Err() == nil {
		switch {
		case !r.enabled.Load():
			// Stopped over the control socket. The withdrawal happens once per
			// stop rather than once per wake-up, and the pass recorded after
			// it reads zero installed, so a diagnostic does not go on
			// reporting the routes of the last pass that ran.
			if !r.withdrawn {
				err := r.withdraw()
				if err != nil {
					slog.Warn("kernel could not withdraw everything it was asked to stop holding", "err", err)
				}
				r.routePass = Stats{}
				r.recordPass(err)
				r.withdrawn = true
				backoff = 0
				stopTimer(retry)
				stopTimer(grace)
				slog.Info("kernel reconciler stopped, its routes withdrawn", "where", r.Where())
			}
		default:
			if r.withdrawn {
				r.withdrawn = false
				slog.Info("kernel reconciler started again", "where", r.Where())
			}
			if err := r.reconcile(); err != nil {
				backoff = min(max(2*backoff, minRetryInterval), r.table.Reconcile.Duration())
				slog.Warn("kernel reconcile failed, retrying", "err", err, "retry_in", backoff)
				stopTimer(retry)
				retry.Reset(backoff)
			} else if backoff != 0 {
				backoff = 0
				stopTimer(retry)
			}

			stopTimer(grace)
			if at, ok := r.captureDeadline(); ok {
				grace.Reset(max(at.Sub(r.now()), 0))
			}
		}

		select {
		case <-ctx.Done():
		case <-ticker.C:
		case <-retry.C:
		case <-grace.C:
		case <-r.wake:
		case <-changed:
			r.settle(ctx, changed, notify)
		case <-notify:
			r.settle(ctx, changed, notify)
		}
	}

	// A reconciler stopped over the socket has already withdrawn, and this
	// second pass then lists an empty table and removes nothing. Running it
	// anyway rather than skipping it on the flag keeps one exit path: what the
	// kernel holds is read back rather than remembered, so anything installed
	// between the stop and here still leaves.
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
// status` with a clean route count and no error at all. See
// refuseWhatThePlatformLacks for why that particular silence is the expensive
// one.
func (r *Reconciler) reconcile() error {
	// Sampled once for the whole pass, before any of the steps: a route
	// installed under one answer and withdrawn under another would leave the
	// kernel holding a key the diff never names again.
	r.sampleCapture()
	// The VRF first, because applyMaster enslaves the link to it and a master
	// that does not exist yet is a master the link cannot join.
	err := errors.Join(r.applyVRF(), r.applyMaster(), r.applyAddresses(), r.applyRoutes(), r.applyRules())
	r.recordPass(err)
	return err
}

// sampleCapture asks how much of the mesh is carrying traffic and records what
// this pass may therefore install. A reconciler with no session source keeps
// the behavior it had before the gate existed, because nothing it could ask
// would answer.
func (r *Reconciler) sampleCapture() {
	if r.rt.Sessions == nil {
		r.capture = true
		return
	}
	open, changed := r.gate.sample(r.now(), r.rt.Sessions())
	r.capture = open
	if !changed {
		return
	}
	if open {
		slog.Info("kernel is carrying this machine's own traffic over the mesh again",
			"detail", "a session is live, so an announced default is installed")
		return
	}
	slog.Warn("kernel is withdrawing the routes that would carry this machine's own traffic",
		"grace", r.table.CaptureGrace,
		"detail", "no session has been live for that long, so this node falls back to its own uplink")
}

// captureDeadline is when a pass has to run for the grace to expire on time,
// and nothing at all while no capturing route is installed or wanted.
//
// The condition matters more than it looks. The gate is open whenever a
// session is live, which on an ordinary node is always, so arming the wake
// from that alone made the grace the reconcile rate: a full pass, both dumps
// and on darwin a table read and two route lookups, once per grace rather than
// once per reconcile interval. Measured at 239 passes in 300 ms with a one
// millisecond grace, against two.
func (r *Reconciler) captureDeadline() (time.Time, bool) {
	if !r.capturing {
		return time.Time{}, false
	}
	return r.gate.deadline()
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
	if r.vrfs == nil || !r.table.creates() || r.table.Name() == "" {
		return nil
	}
	created, err := r.vrfs.EnsureVRF(r.table.Name(), uint32(r.table.ID))
	if err != nil {
		return fmt.Errorf("create vrf %s: %w", r.table.Name(), err)
	}
	if created {
		r.madeVRF = true
		slog.Info("kernel created the mesh vrf", "vrf", r.table.Name(), "table", uint32(r.table.ID))
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
	wanted := make(map[Rule]bool, len(r.ruleSet))
	for _, rule := range r.ruleSet {
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
	for _, rule := range r.ruleSet {
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
	// Cleared first, so a pass that fails before it can count anything reports
	// nothing rather than the counts of the last pass that succeeded.
	r.routePass = Stats{}
	actual, err := r.plat.Routes()
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	desired := r.desired(r.src.Snapshot())
	// Before the diff, not after it. A capturing route whose family has
	// nothing to fall back on is dropped from what this pass wants, so it is
	// neither installed nor kept: gating only the install list left one
	// already in the kernel exactly where it was when the host's default
	// moved to another interface.
	desired, coverErr := r.covered(desired)
	add, del := diffRoutes(desired, actual, r.platformScopes())
	var errs []error
	if coverErr != nil {
		errs = append(errs, coverErr)
	}
	added, removed, skipped := 0, 0, 0
	// Whether this pass leaves the mesh carrying this machine's own traffic.
	// The gate has already decided it: desired holds a capturing route only
	// while the gate is open and its family is covered, so this needs no
	// second opinion about either.
	r.capturing = slices.ContainsFunc(desired, capturesTheMachine)
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

// covered drops every capturing route whose own family the underlay cannot
// fall back on, and repairs that routing on the way.
//
// It runs once a pass and only where a capturing route is wanted, so a node
// announcing ordinary prefixes never asks and never pays for the answer.
func (r *Reconciler) covered(desired []Route) ([]Route, error) {
	if r.rt.Capture == nil || !slices.ContainsFunc(desired, capturesTheMachine) {
		r.uncovered = Covered{V4: true, V6: true}
		return desired, nil
	}
	covered, err := r.rt.Capture.Ready()
	if err != nil {
		err = fmt.Errorf("cover the underlay before capturing: %w", err)
	}
	out := desired[:0:0]
	held := false
	for _, route := range desired {
		if capturesTheMachine(route) && !covered.Has(route.Destination.Addr()) {
			// Left out of the pass rather than counted as skipped: skipped
			// counts what the kernel would not take, and this is the
			// reconciler refusing to ask. Installing it, or leaving one
			// installed, takes this node off the network for that family with
			// nothing to fall back on.
			if r.uncovered.Has(route.Destination.Addr()) {
				slog.Warn("kernel is holding back a route that would carry this machine's own traffic",
					"destination", route.Destination,
					"detail", "the underlay has no route of its own for that family, so this node would lose every network it has there")
			}
			held = true
			continue
		}
		out = append(out, route)
	}
	if !held {
		r.uncovered = Covered{V4: true, V6: true}
		return out, err
	}
	r.uncovered = covered
	return out, err
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
			Metric:      routeMetric(r.table.Metric, destination, unreachable),
			Unreachable: unreachable,
		}
		// Left out of the pass rather than reported as skipped: skipped counts
		// what the mesh wanted and the kernel would not take, and this is the
		// reconciler declining to ask. A hold is declined too, because a hold
		// at a default answers with an error for every destination and is the
		// same outage in a different shape.
		if capturesTheMachine(route) && !r.capture {
			continue
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
		if destination.Addr().Is4() && r.table.PrefSrc4.IsValid() {
			route.PrefSrc = r.table.PrefSrc4.Addr
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
// node that anything else is the mesh VRF's connected route for the /60 the
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
	if len(r.addresses) == 0 {
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
	for _, prefix := range r.addresses {
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
					"interface", r.rt.Interface, "address", prefix, "held_as", existing)
			}
			warned[prefix] = true
			continue
		}
		if err := r.plat.AddAddr(prefix); err != nil {
			errs = append(errs, fmt.Errorf("add address %s: %w", prefix, err))
			continue
		}
		slog.Info("kernel address assigned", "interface", r.rt.Interface, "address", prefix)
		r.owned[prefix] = true
	}
	r.warnedAddrs = warned
	return errors.Join(errs...)
}

// applyMaster joins the configured VRF, and only ever from no master at all.
// A link somebody else already enslaved is reported and left alone: taking it
// over would start a flap war with whatever put it there.
func (r *Reconciler) applyMaster() error {
	if r.table.Name() == "" {
		return nil
	}
	master, err := r.plat.Master()
	if err != nil {
		return fmt.Errorf("read master of %s: %w", r.rt.Interface, err)
	}
	switch master {
	case r.table.Name():
		r.master = master
		return nil
	case "":
		if err := r.plat.Enslave(r.table.Name()); err != nil {
			return fmt.Errorf("enslave %s to %s: %w", r.rt.Interface, r.table.Name(), err)
		}
		r.enslaved, r.master = true, r.table.Name()
		slog.Info("kernel interface enslaved", "interface", r.rt.Interface, "master", r.table.Name())
		return nil
	default:
		if r.master != master {
			slog.Warn("kernel leaving interface in the master it already has",
				"interface", r.rt.Interface, "master", master, "configured", r.table.Name())
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
			"interface", r.rt.Interface, "addresses", len(addresses))
		addresses = nil
	}
	for _, prefix := range addresses {
		if !slices.Contains(held, prefix) {
			slog.Warn("kernel is leaving an address it no longer holds as it installed it",
				"interface", r.rt.Interface, "address", prefix)
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
			errs = append(errs, fmt.Errorf("release %s from %s: %w", r.rt.Interface, r.table.Name(), err))
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
		if err := r.vrfs.RemoveVRF(r.table.Name()); err != nil {
			errs = append(errs, fmt.Errorf("remove vrf %s: %w", r.table.Name(), err))
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
