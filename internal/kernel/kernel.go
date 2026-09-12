// Package kernel mirrors the mesh forwarding table into a Linux routing
// table, taking over from the BIRD kernel protocols a ranet deployment runs
// today. It is a one-way reconciler: internal/netstack keeps owning the
// forwarding decision and this package only teaches the kernel which packets
// to hand to the TUN, so every route it installs points at Config.Interface
// and the peer in a snapshot entry never selects a kernel next hop.
//
// # Ownership
//
// Every route this package installs lives in Config.Table, carries rt_proto
// Config.Protocol and points out of Config.Interface. Those three together
// are the ownership marker. The reconciler reads back only routes matching
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
	// defaultIPv6Metric is IP6_RT_PRIO_USER, what the kernel stamps on an
	// IPv6 route that arrives without RTA_PRIORITY. The reconciler sends it
	// explicitly instead, so a dump reports back exactly what it installed.
	defaultIPv6Metric = 1024
)

// ErrUnsupported is returned by New on every platform without an
// implementation. A darwin backend is separate work.
var ErrUnsupported = errors.New("kernel: route reconciliation is unsupported on this platform")

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
	// ReconcileInterval is the periodic sweep. Zero uses
	// DefaultReconcileInterval.
	ReconcileInterval time.Duration
}

// RouteSource is the seam onto internal/netstack: one coalesced wake-up per
// batch of changes, and one consistent view per reconcile pass. Reconciling
// from snapshots rather than from an event stream is what lets a missed
// wake-up, a restart and outside interference all converge on the same state.
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
}

func (r Route) String() string {
	if r.Source.IsValid() {
		return fmt.Sprintf("%s from %s metric %d", r.Destination, r.Source, r.Metric)
	}
	return fmt.Sprintf("%s metric %d", r.Destination, r.Metric)
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

// platform is the kernel surface the reconciler drives. Everything above it is
// portable and syscall-free, which is what makes the diff testable against a
// fake kernel.
type platform interface {
	// Routes returns only the routes carrying the reconciler's protocol, in
	// its table, out of its interface.
	Routes() ([]Route, error)
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

type Reconciler struct {
	cfg  Config
	src  RouteSource
	plat platform

	// owned holds the addresses this reconciler put on the link, the only
	// ones it will ever take off again. An address a previous instance added
	// and left behind is not in here, so it stays: losing an address that
	// turns out to be somebody else's is worse than leaking one.
	owned map[netip.Prefix]bool
	// enslaved records that this reconciler set the link's master itself.
	enslaved bool
	// master is the last master observed, so a link somebody else owns is
	// reported once per transition rather than once per pass.
	master string
	// warned holds the routes already reported as unrepresentable. It is
	// rebuilt from each pass, so it stays bounded by the snapshot.
	warned map[Route]bool
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
	if cfg.Protocol < 4 {
		// rtnetlink reserves 0 through 3 for unspec, redirect, kernel and
		// boot; claiming one of those would make the reconciler's routes
		// indistinguishable from the kernel's own.
		return nil, fmt.Errorf("kernel: protocol %d is reserved, use 4 through 255", cfg.Protocol)
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
	plat, err := newPlatform(cfg)
	if err != nil {
		return nil, err
	}
	return newReconciler(cfg, src, plat), nil
}

func newReconciler(cfg Config, src RouteSource, plat platform) *Reconciler {
	return &Reconciler{
		cfg: cfg, src: src, plat: plat,
		owned:  make(map[netip.Prefix]bool),
		warned: make(map[Route]bool),
	}
}

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

	slog.Info("kernel reconciler started", "interface", r.cfg.Interface,
		"table", r.cfg.Table, "protocol", r.cfg.Protocol)

	// Installing takes over a same-key route rather than failing, so sharing a
	// table with another daemon loses its routes with no error. Say so once at
	// startup: on a fleet node mid-migration the other writer is BIRD in table
	// 200, which is the intended overlap and still worth seeing.
	if audit, ok := r.plat.(auditor); ok {
		if writers, err := audit.foreignWriters(); err != nil {
			slog.Warn("kernel could not check the table for other writers", "err", err)
		} else if len(writers) > 0 {
			slog.Warn("kernel is sharing its table with another routing protocol",
				"table", r.cfg.Table, "protocols", strings.Join(writers, ", "),
				"detail", "an install replaces a same-key route, so give this reconciler a table of its own")
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

// reconcile brings the kernel to one snapshot. The three steps are
// independent and every error is collected, so a VRF that cannot be joined
// does not stop routes from being installed.
func (r *Reconciler) reconcile() error {
	return errors.Join(r.applyMaster(), r.applyAddresses(), r.applyRoutes())
}

// applyRoutes removes before it installs. A route pointing at an interface
// carrying no address is harmless, but the kernel drops routes when the last
// address goes away, so putting additions first is never wrong and sometimes
// avoids a gap.
func (r *Reconciler) applyRoutes() error {
	actual, err := r.plat.Routes()
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	add, del := diffRoutes(r.desired(r.src.Snapshot()), actual)
	var errs []error
	// Withdraw before installing. An install refuses a key another writer
	// already holds rather than taking it over, so a route of ours that
	// changed only in an attribute the kernel does not key on, a preferred
	// source at an unchanged metric, has to leave before its replacement
	// arrives. Both lists are this reconciler's own routes, so the gap is
	// within one pass and touches nothing else.
	for _, route := range del {
		if err := r.plat.DelRoute(route); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", route, err))
		}
	}
	for _, route := range add {
		if err := r.plat.AddRoute(route); err != nil {
			errs = append(errs, fmt.Errorf("add route %s: %w", route, err))
		}
	}
	if len(add) > 0 || len(del) > 0 {
		slog.Info("kernel routes reconciled", "added", len(add), "removed", len(del))
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
		route := Route{Destination: destination, Metric: r.metric(destination)}
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

// metric is the value the kernel will actually hold, so a dump compares equal
// to what was installed. An unset metric means the kernel's own default,
// which differs by family.
func (r *Reconciler) metric(destination netip.Prefix) uint32 {
	if r.cfg.Metric == 0 && !destination.Addr().Is4() {
		return defaultIPv6Metric
	}
	return r.cfg.Metric
}

// diffRoutes reports the routes the kernel is missing and the reconciler's
// own routes it still holds that the mesh no longer wants. Both results are
// sorted so a pass is reproducible and its log lines are stable.
func diffRoutes(desired, actual []Route) (add, del []Route) {
	want := make(map[Route]bool, len(desired))
	for _, route := range desired {
		want[route] = true
	}
	have := make(map[Route]bool, len(actual))
	for _, route := range actual {
		have[route] = true
	}
	for route := range want {
		if !have[route] {
			add = append(add, route)
		}
	}
	for route := range have {
		if !want[route] {
			del = append(del, route)
		}
	}
	slices.SortFunc(add, compareRoutes)
	slices.SortFunc(del, compareRoutes)
	return add, del
}

func compareRoutes(a, b Route) int {
	return cmp.Or(
		comparePrefixes(a.Destination, b.Destination),
		comparePrefixes(a.Source, b.Source),
		a.PrefSrc.Compare(b.PrefSrc),
		cmp.Compare(a.Metric, b.Metric),
	)
}

func comparePrefixes(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
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
	for _, prefix := range actual {
		have[prefix] = true
	}
	var errs []error
	for _, prefix := range r.cfg.Addresses {
		if have[prefix] {
			continue
		}
		if err := r.plat.AddAddr(prefix); err != nil {
			errs = append(errs, fmt.Errorf("add address %s: %w", prefix, err))
			continue
		}
		slog.Info("kernel address assigned", "interface", r.cfg.Interface, "address", prefix)
		r.owned[prefix] = true
	}
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
	for _, route := range routes {
		if err := r.plat.DelRoute(route); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", route, err))
		}
	}
	addresses := slices.SortedFunc(maps.Keys(r.owned), comparePrefixes)
	for _, prefix := range addresses {
		if err := r.plat.DelAddr(prefix); err != nil {
			errs = append(errs, fmt.Errorf("delete address %s: %w", prefix, err))
			continue
		}
		delete(r.owned, prefix)
	}
	if r.enslaved {
		if err := r.plat.Release(); err != nil {
			errs = append(errs, fmt.Errorf("release %s from %s: %w", r.cfg.Interface, r.cfg.VRF, err))
		} else {
			r.enslaved = false
		}
	}
	slog.Info("kernel reconciler withdrawn", "routes", len(routes), "addresses", len(addresses))
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
