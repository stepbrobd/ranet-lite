package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }

// fakeKernel is an in-memory stand-in for rtnetlink. It models the ownership
// boundary the real platform enforces rather than the wire format: foreign
// holds routes written by somebody else, Routes never returns them, and a
// delete that reaches one fails the test.
type fakeKernel struct {
	t *testing.T

	mu      sync.Mutex
	routes  map[Route]bool
	foreign map[Route]bool
	addrs   map[netip.Prefix]bool
	deleted []netip.Prefix
	master  string
	name    string
	closed  bool
	adds    int
	dels    int

	rules    map[Rule]bool
	vrfs     map[string]uint32
	ruleAdds int
	ruleDels int
	vrfErr   error

	failAdd     map[Route]error
	failDel     map[Route]error
	failList    error
	failAddrs   error
	failRules   error
	failAddRule map[Rule]error

	signal chan struct{}
}

func newFakeKernel(t *testing.T) *fakeKernel {
	return &fakeKernel{
		t:           t,
		routes:      make(map[Route]bool),
		foreign:     make(map[Route]bool),
		addrs:       make(map[netip.Prefix]bool),
		rules:       make(map[Rule]bool),
		vrfs:        make(map[string]uint32),
		failAdd:     make(map[Route]error),
		failDel:     make(map[Route]error),
		failAddRule: make(map[Rule]error),
		signal:      make(chan struct{}, 1),
	}
}

func (f *fakeKernel) Routes() ([]Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList != nil {
		return nil, f.failList
	}
	out := make([]Route, 0, len(f.routes))
	for route := range f.routes {
		out = append(out, route)
	}
	slices.SortFunc(out, compareRoutes)
	return out, nil
}

func (f *fakeKernel) AddRoute(route Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failAdd[route]; err != nil {
		return err
	}
	f.adds++
	f.routes[route] = true
	return nil
}

func (f *fakeKernel) DelRoute(route Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.foreign[route] {
		f.t.Errorf("reconciler deleted a route it did not install: %s", route)
	}
	if err := f.failDel[route]; err != nil {
		return err
	}
	f.dels++
	delete(f.routes, route)
	return nil
}

func (f *fakeKernel) Addrs() ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAddrs != nil {
		return nil, f.failAddrs
	}
	out := make([]netip.Prefix, 0, len(f.addrs))
	for address := range f.addrs {
		out = append(out, address)
	}
	slices.SortFunc(out, comparePrefixes)
	return out, nil
}

// AddAddr and DelAddr model what both platforms do rather than what a map
// does: assignment is an upsert keyed on the address, and darwin's SIOCDIFADDR
// matches on the address alone, so a delete takes whatever length the link is
// carrying it under. The ownership checks exist for that asymmetry.
func (f *fakeKernel) AddAddr(address netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for held := range f.addrs {
		if held.Addr() == address.Addr() {
			delete(f.addrs, held)
		}
	}
	f.addrs[address] = true
	return nil
}

func (f *fakeKernel) DelAddr(address netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Recorded as asked, not as matched: the address-only match models what
	// the kernels do and would otherwise hide a withdrawal that named the
	// wrong prefix length, which linux does refuse.
	f.deleted = append(f.deleted, address)
	for held := range f.addrs {
		if held.Addr() == address.Addr() {
			delete(f.addrs, held)
		}
	}
	return nil
}

func (f *fakeKernel) Master() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.master, nil
}

func (f *fakeKernel) Enslave(master string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.master = master
	return nil
}

func (f *fakeKernel) Release() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.master = ""
	return nil
}

func (f *fakeKernel) Notify() <-chan struct{} { return f.signal }

func (f *fakeKernel) where(cfg Config) string {
	if f.name != "" {
		return f.name
	}
	return fmt.Sprintf("table %d", cfg.Table)
}

func (f *fakeKernel) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeKernel) has(route Route) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.routes[route]
}

func (f *fakeKernel) snapshot() []Route {
	routes, _ := f.Routes()
	return routes
}

func (f *fakeKernel) counts() (adds, dels int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds, f.dels
}

// harness wires one reconciler onto a real netstack.RouteTable, so the tests
// exercise the same Changed and Snapshot seam the daemon uses. The peer value
// is nil throughout: it tells the reconciler a route exists and nothing else.
func harness(t *testing.T, cfg Config) (*Reconciler, *netstack.RouteTable, *fakeKernel) {
	t.Helper()
	if cfg.Interface == "" {
		cfg.Interface = "ranet0"
	}
	if cfg.Table == 0 {
		cfg.Table = DefaultTable
	}
	if cfg.Protocol == 0 {
		cfg.Protocol = DefaultProtocol
	}
	if cfg.ReconcileInterval == 0 {
		cfg.ReconcileInterval = DefaultReconcileInterval
	}
	table := netstack.NewRouteTable()
	fake := newFakeKernel(t)
	return newReconciler(cfg, table, fake), table, fake
}

func TestReconcileInstallsSnapshotRoutes(t *testing.T) {
	reconciler, table, fake := harness(t, Config{PrefSrc4: addr("23.161.104.5")})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("2602:f590::/36"), nil)
	table.Set(prefix("2602:f590:1::/48"), prefix("::/0"), nil)

	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// an unset metric is the kernel's own default, which is 0 for IPv4 and
	// IP6_RT_PRIO_USER for IPv6.
	want := []Route{
		{Destination: prefix("10.0.0.0/8"), PrefSrc: addr("23.161.104.5")},
		{Destination: prefix("::/0"), Source: prefix("2602:f590:1::/48"), Metric: defaultIPv6Metric},
		{Destination: prefix("2602:f590::/36"), Metric: defaultIPv6Metric},
	}
	slices.SortFunc(want, compareRoutes)
	if got := fake.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("installed %v, want %v", got, want)
	}
}

func TestReconcileRemovesWithdrawnRoutes(t *testing.T) {
	reconciler, table, fake := harness(t, Config{})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("10.1.0.0/16"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	table.Remove(netip.Prefix{}, prefix("10.1.0.0/16"))
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if fake.has(Route{Destination: prefix("10.1.0.0/16")}) {
		t.Fatal("withdrawn route is still in the kernel")
	}
	if !fake.has(Route{Destination: prefix("10.0.0.0/8")}) {
		t.Fatal("surviving route was removed")
	}
}

func TestReconcileLeavesUnchangedRoutesAlone(t *testing.T) {
	reconciler, table, fake := harness(t, Config{})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(prefix("2602:f590:1::/48"), prefix("::/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	adds, dels := fake.counts()
	if adds != 2 || dels != 0 {
		t.Fatalf("first pass made %d adds and %d deletes, want 2 and 0", adds, dels)
	}

	for range 3 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	if adds, dels := fake.counts(); adds != 2 || dels != 0 {
		t.Fatalf("idle passes made %d adds and %d deletes, want 2 and 0", adds, dels)
	}
}

// A source-specific route and an ordinary route to the same destination are
// two kernel routes, not one, which is the distinction RTA_SRC carries.
func TestReconcileKeepsSourceSpecificAndOrdinaryApart(t *testing.T) {
	reconciler, table, fake := harness(t, Config{})
	table.Set(netip.Prefix{}, prefix("2602:f590::/36"), nil)
	table.Set(prefix("2602:f590:1::/48"), prefix("2602:f590::/36"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := len(fake.snapshot()); got != 2 {
		t.Fatalf("installed %d routes, want 2", got)
	}

	// retracting only the source-specific entry must leave the ordinary one.
	table.Remove(prefix("2602:f590:1::/48"), prefix("2602:f590::/36"))
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	want := []Route{{Destination: prefix("2602:f590::/36"), Metric: defaultIPv6Metric}}
	if got := fake.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("installed %v, want %v", got, want)
	}
}

// The metric is part of a route's identity in the kernel, so changing it has
// to withdraw the routes installed under the old one instead of leaving a
// second copy of every prefix behind.
func TestReconcileReplacesRoutesWhenMetricChanges(t *testing.T) {
	reconciler, table, fake := harness(t, Config{})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	reconciler.cfg.Metric = 32
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	want := []Route{{Destination: prefix("10.0.0.0/8"), Metric: 32}}
	if got := fake.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("installed %v, want %v", got, want)
	}
}

// The IPv4 FIB has no source-specific lookup, so such an entry is reported
// and dropped rather than installed as an ordinary route that would steal
// every other source's traffic.
func TestReconcileSkipsSourceSpecificIPv4(t *testing.T) {
	reconciler, table, fake := harness(t, Config{})
	table.Set(prefix("10.1.0.0/16"), prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("192.0.2.0/24"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	want := []Route{{Destination: prefix("192.0.2.0/24")}}
	if got := fake.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("installed %v, want %v", got, want)
	}
}

// Ownership: a route the reconciler did not install never appears in a dump
// and must never be deleted, even when the mesh does not want its prefix.
func TestReconcileNeverTouchesForeignRoutes(t *testing.T) {
	reconciler, table, fake := harness(t, Config{})
	foreign := Route{Destination: prefix("198.51.100.0/24")}
	fake.foreign[foreign] = true
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)

	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, dels := fake.counts(); dels != 1 {
		t.Fatalf("made %d deletes, want 1", dels)
	}
}

// A pass that fails halfway leaves the kernel short of a route; the next pass
// recomputes the difference from a fresh dump and installs it.
func TestReconcileRepairsAfterFailedApply(t *testing.T) {
	reconciler, table, fake := harness(t, Config{})
	broken := Route{Destination: prefix("10.1.0.0/16")}
	fake.failAdd[broken] = errors.New("netlink says no")
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("10.1.0.0/16"), nil)

	err := reconciler.reconcile()
	if err == nil {
		t.Fatal("a failed apply must be reported, not swallowed")
	}
	if !fake.has(Route{Destination: prefix("10.0.0.0/8")}) {
		t.Fatal("a failed route must not stop the rest of the pass")
	}
	if fake.has(broken) {
		t.Fatal("the failed route was installed anyway")
	}

	delete(fake.failAdd, broken)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("repairing reconcile: %v", err)
	}
	if !fake.has(broken) {
		t.Fatal("the repairing pass did not install the missing route")
	}
}

func captureKernelLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func TestReconcileCountsOnlyAppliedRoutes(t *testing.T) {
	logs := captureKernelLogs(t)
	reconciler, table, fake := harness(t, Config{})
	installed := Route{Destination: prefix("198.51.100.0/24")}
	occupied := Route{Destination: prefix("203.0.113.0/24")}
	removed := Route{Destination: prefix("192.0.2.0/25")}
	retained := Route{Destination: prefix("192.0.2.128/25")}
	fake.routes[removed], fake.routes[retained] = true, true
	fake.failAdd[occupied] = syscall.EEXIST
	fake.failDel[retained] = syscall.EPERM
	table.Set(netip.Prefix{}, installed.Destination, nil)
	table.Set(netip.Prefix{}, occupied.Destination, nil)
	for pass := range 2 {
		logs.Reset()
		err := reconciler.reconcile()
		if pass == 0 && (!errors.Is(err, syscall.EEXIST) || !errors.Is(err, syscall.EPERM)) {
			t.Fatalf("reconcile returned %v, want both refused operations", err)
		}
		if pass == 1 && err != nil {
			t.Fatal(err)
		}
		var counts struct {
			Added   int
			Removed int
		}
		if err := json.Unmarshal(logs.Bytes(), &counts); err != nil {
			t.Fatal(err)
		}
		if counts.Added != 1 || counts.Removed != 1 {
			t.Errorf("pass %d reported added=%d removed=%d, want added=1 removed=1", pass, counts.Added, counts.Removed)
		}
		want := []Route{installed, retained}
		if pass == 1 {
			want = []Route{installed, occupied}
		}
		slices.SortFunc(want, compareRoutes)
		if got := fake.snapshot(); !slices.Equal(got, want) {
			t.Fatalf("pass %d holds %v, want %v", pass, got, want)
		}
		delete(fake.failAdd, occupied)
		delete(fake.failDel, retained)
	}
}

// A route the platform refuses stays in the diff on purpose, because the
// install is retried until it lands. It must not be counted as added, and a
// pass that moved nothing must say nothing: a node holding one permanently
// unrepresentable route would otherwise log once per pass for its whole life.
func TestReconcileSaysNothingAboutPassThatMovedNothing(t *testing.T) {
	logs := captureKernelLogs(t)
	reconciler, table, fake := harness(t, Config{})
	skipped := Route{Destination: prefix("::/0"), Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}
	fake.failAdd[skipped] = errRouteSkipped
	table.Set(skipped.Source, skipped.Destination, nil)
	for pass := range 3 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("pass %d: an unrepresentable route triggered retry: %v", pass, err)
		}
	}
	if bytes.Contains(logs.Bytes(), []byte("kernel routes reconciled")) {
		t.Errorf("a pass that installed nothing reported itself: %s", logs.Bytes())
	}

	// The line is still there for a pass that does move something.
	logs.Reset()
	table.Set(netip.Prefix{}, prefix("198.51.100.0/24"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	var counts map[string]any
	if err := json.Unmarshal(logs.Bytes(), &counts); err != nil {
		t.Fatal(err)
	}
	if counts["added"] != float64(1) {
		t.Errorf("the installed route was counted as %v, want one", counts["added"])
	}
}

// A dump that fails must not be read as an empty kernel, which would delete
// nothing but would also install every route a second time.
func TestReconcileReportsFailedDump(t *testing.T) {
	reconciler, table, fake := harness(t, Config{})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	fake.failList = errors.New("netlink says no")
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a failed dump must be reported")
	}
	if adds, _ := fake.counts(); adds != 0 {
		t.Fatalf("made %d adds after a failed dump, want 0", adds)
	}
}

func TestApplyAddressesOnlyRemovesWhatItAdded(t *testing.T) {
	operator := prefix("192.0.2.1/32")
	ours := prefix("23.161.104.5/32")
	reconciler, _, fake := harness(t, Config{Addresses: []netip.Prefix{operator, ours}})
	fake.addrs[operator] = true

	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !fake.addrs[ours] {
		t.Fatal("configured address was not assigned")
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if fake.addrs[ours] {
		t.Fatal("the reconciler's own address survived withdrawal")
	}
	if !fake.addrs[operator] {
		t.Fatal("an address the reconciler did not add was removed")
	}
	// Named exactly as it was assigned. Both kernels match a delete on the
	// address, so naming another length would take the same entry away and
	// nothing here would notice; linux refuses one, which is a withdrawal that
	// silently leaves the address behind.
	if !slices.Equal(fake.deleted, []netip.Prefix{ours}) {
		t.Errorf("withdrawal asked to delete %v, want only %s", fake.deleted, ours)
	}
}

func TestApplyMasterEnslavesOnlyUnclaimedLink(t *testing.T) {
	reconciler, _, fake := harness(t, Config{VRF: "gravity"})
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if fake.master != "gravity" {
		t.Fatalf("master is %q, want gravity", fake.master)
	}
	// idempotent: a second pass must not touch a link already in place.
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if fake.master != "" {
		t.Fatalf("master is %q after withdrawal, want empty", fake.master)
	}
}

func TestApplyMasterLeavesAnotherManagersLinkAlone(t *testing.T) {
	reconciler, _, fake := harness(t, Config{VRF: "gravity"})
	fake.master = "somebody-else"
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if fake.master != "somebody-else" {
		t.Fatalf("master is %q, want the one already there", fake.master)
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if fake.master != "somebody-else" {
		t.Fatal("withdrawal released a master the reconciler did not set")
	}
}

func TestRunWithdrawsOnCancel(t *testing.T) {
	reconciler, table, fake := harness(t, Config{
		Addresses:         []netip.Prefix{prefix("23.161.104.5/32")},
		ReconcileInterval: 10 * time.Millisecond,
	})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()

	waitFor(t, func() bool { return fake.has(Route{Destination: prefix("10.0.0.0/8")}) })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancellation")
	}

	if got := fake.snapshot(); len(got) != 0 {
		t.Fatalf("routes survived shutdown: %v", got)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.addrs) != 0 {
		t.Fatalf("addresses survived shutdown: %v", fake.addrs)
	}
	if !fake.closed {
		t.Fatal("the platform was not closed")
	}
}

// A rule pass deletes every rule carrying this reconciler's protocol that the
// configuration does not name, so claiming RTPROT_STATIC would delete every
// static rule on the host, since systemd-networkd stamps it on its own.
func TestNewRejectsReservedProtocol(t *testing.T) {
	for _, protocol := range []uint8{2, protocolStatic} {
		_, err := New(Config{Interface: "ranet0", Protocol: protocol}, netstack.NewRouteTable())
		if err == nil || !strings.Contains(err.Error(), "is reserved") {
			t.Errorf("protocol %d was refused with %v, want it named as reserved", protocol, err)
		}
	}
}

// An announced default is installed unscoped on linux, so a reconciler given
// the main table would put the whole machine's default out of the tun and take
// the ESP underlay with it. Nothing else refuses a route in main, and the one
// warning that would have said so is off outside it.
func TestNewRejectsReservedTable(t *testing.T) {
	// On the reason, not on failure: New never succeeds here, because there is
	// no such interface on the machine running the suite.
	for _, table := range []uint32{253, 254, 255} {
		_, err := New(Config{Interface: "ranet0", Table: table}, netstack.NewRouteTable())
		if err == nil || !strings.Contains(err.Error(), "is reserved") {
			t.Errorf("table %d was refused with %v, and the kernel keeps it for itself", table, err)
		}
	}
	// A table the kernel does not reserve goes through, and the reservation is
	// three byte-sized ids rather than everything above 252:
	// the linux backend sends RT_TABLE_UNSPEC plus a 32-bit RTA_TABLE for a
	// table above 255, which is how ids like 51820 reach the kernel at all.
	// New still fails here, because there is no such interface on the machine
	// running the suite, so the check is on the reason rather than on success.
	for _, table := range []uint32{1, 52, 200, 252, 256, 1000, 51820, ^uint32(0)} {
		_, err := New(Config{Interface: "ranet0", Table: table}, netstack.NewRouteTable())
		if err != nil && strings.Contains(err.Error(), "is reserved") {
			t.Errorf("table %d was refused as reserved: %v", table, err)
		}
	}
}

// Both lists come out sorted, so one pass produces the same order as the next
// and a log line or a diff of two passes is comparable. A one-element list is
// sorted whatever the code does, so this needs several on each side.
func TestDiffRoutesIsSorted(t *testing.T) {
	desired := []Route{
		{Destination: prefix("10.1.0.0/16")},
		{Destination: prefix("10.0.0.0/8")},
		{Destination: prefix("2001:db8:1::/48")},
		{Destination: prefix("2001:db8::/48")},
		{Destination: prefix("10.2.0.0/16")},
	}
	actual := []Route{
		{Destination: prefix("10.1.0.0/16")},
		{Destination: prefix("192.0.2.0/24")},
		{Destination: prefix("203.0.113.0/24")},
		{Destination: prefix("2001:db8:99::/48")},
		{Destination: prefix("198.51.100.0/24")},
	}
	add, del := diffRoutes(desired, actual, nil)
	if len(add) < 2 || len(del) < 2 {
		t.Fatalf("add %v and del %v are too short to be a test of ordering", add, del)
	}
	if !slices.IsSortedFunc(add, compareRoutes) {
		t.Errorf("the routes to install came out unsorted: %v", add)
	}
	if !slices.IsSortedFunc(del, compareRoutes) {
		t.Errorf("the routes to withdraw came out unsorted: %v", del)
	}
	// And the sets themselves are still right.
	want := []Route{
		{Destination: prefix("10.0.0.0/8")}, {Destination: prefix("10.2.0.0/16")},
		{Destination: prefix("2001:db8::/48")}, {Destination: prefix("2001:db8:1::/48")},
	}
	slices.SortFunc(want, compareRoutes)
	if !slices.Equal(add, want) {
		t.Errorf("add is %v, want %v", add, want)
	}
}

func waitFor(t *testing.T, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not reached in time")
}

// A route the platform refuses is neither installed nor a failure. Counting it
// as added makes the reconcile line report the opposite of what the kernel
// holds, for as long as the other writer keeps the key, and the route stays in
// the diff so the count repeats every pass.
func TestSkippedRoutesAreNotCountedAndDoNotFailPass(t *testing.T) {
	r, table, kernel := harness(t, Config{})
	occupied := prefix("2001:db8::/48")
	table.Set(netip.Prefix{}, occupied, nil)
	table.Set(netip.Prefix{}, prefix("2001:db8:1::/48"), nil)
	for _, route := range r.desired(table.Snapshot()) {
		if route.Destination == occupied {
			kernel.failAdd[route] = fmt.Errorf("another writer holds it: %w", errRouteSkipped)
		}
	}
	if len(kernel.failAdd) != 1 {
		t.Fatalf("the occupied route was not among the desired ones: %v", r.desired(table.Snapshot()))
	}

	if err := r.applyRoutes(); err != nil {
		t.Fatalf("a refused route failed the whole pass: %v", err)
	}
	if kernel.adds != 1 {
		t.Fatalf("the kernel took %d routes, want 1", kernel.adds)
	}
	// Still wanted, so the next pass tries again rather than forgetting it.
	if err := r.applyRoutes(); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if kernel.adds != 1 {
		t.Fatalf("the kernel took %d routes across two passes, want 1", kernel.adds)
	}
}

// RFC 8966 section 3.5.4 holds a retracted prefix until it is flushed, so a
// packet for it does not follow a shorter prefix instead. The mesh's own table
// does that; the kernel table this mirrors into has to as well, or longest
// prefix match falls through to the covering route for the whole window, which
// on a node holding a default is straight back out to the neighbor that just
// retracted it.
func TestRetractedPrefixIsHeldInKernelTable(t *testing.T) {
	r, table, kernel := harness(t, Config{})
	peer := netstack.NewPeer("peer", nil, nil)
	covering := prefix("2001:db8::/32")
	retracted := prefix("2001:db8:1::/48")
	table.Set(netip.Prefix{}, covering, peer)
	table.Set(netip.Prefix{}, retracted, peer)
	if err := r.applyRoutes(); err != nil {
		t.Fatal(err)
	}

	table.Set(netip.Prefix{}, retracted, netstack.Unreachable)
	if err := r.applyRoutes(); err != nil {
		t.Fatal(err)
	}
	routes, err := kernel.Routes()
	if err != nil {
		t.Fatal(err)
	}
	var held, carried bool
	var heldAt, carriedAt uint32
	for _, route := range routes {
		switch route.Destination {
		case retracted:
			held, carried = route.Unreachable, !route.Unreachable
			heldAt = route.Metric
		case covering:
			carriedAt = route.Metric
		}
	}
	if carried {
		t.Error("the retracted prefix is still a unicast route, so the mesh and the kernel disagree")
	}
	if !held {
		t.Errorf("the retracted prefix left the kernel table, so a packet for it follows %s instead", covering)
	}
	// A lookup is longest prefix first and only then by metric, so the hold
	// keeps its job while losing to anything else holding that exact prefix.
	// A converted fleet node has one: its gravity /60 is a connected route in
	// the table this reconciler owns, and the node has to originate that same
	// /60, so a hold that wins there rejects every packet for the node's own
	// prefix.
	if heldAt <= carriedAt {
		t.Errorf("the hold sits at metric %d against %d for a carried route, so it outranks a connected route to the same prefix",
			heldAt, carriedAt)
	}

	// And it goes when the hold is flushed, rather than staying an error route
	// nothing announces.
	table.Remove(netip.Prefix{}, retracted)
	if err := r.applyRoutes(); err != nil {
		t.Fatal(err)
	}
	routes, err = kernel.Routes()
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.Destination == retracted {
			t.Errorf("the hold outlived the entry it was holding: %v", route)
		}
	}
}

// The startup line tells an operator where this reconciler's routes went. On a
// platform with no routing tables it used to print table 0, the config's
// zero value read before defaults were applied, on a machine that has no
// tables at all.
func TestWhereComesFromThePlatform(t *testing.T) {
	r, _, fake := harness(t, Config{Interface: "utun9", Table: DefaultTable})
	fake.name = "somewhere"
	if got := r.Where(); got != "somewhere" {
		t.Errorf("the reconciler reports %q rather than asking the platform", got)
	}
}

// A prefix whose meaning is the link it sits on has no business in a routing
// table that forwards out of a tunnel. The kernel keys its own entries for
// these per interface, and only a default or a source-specific route is
// interface-scoped on darwin, so an announced "ff00::/8" or "fe80::/64" went
// into the one FIB every program on that machine shares and shadowed its own
// multicast and link-local plumbing. Coexisting with whatever else is on the
// box is a requirement of this tool, not a nicety.
func TestPrefixesTheMeshCannotCarryAreNotInstalled(t *testing.T) {
	r, table, kernel := harness(t, Config{})
	peer := netstack.NewPeer("peer", nil, nil)
	refused := []netip.Prefix{
		prefix("ff00::/8"),
		prefix("ff02::1/128"),
		prefix("fe80::/64"),
		prefix("224.0.0.0/4"),
		prefix("169.254.0.0/16"),
		prefix("127.0.0.0/8"),
		prefix("::1/128"),
		limitedBroadcast,
	}
	wanted := prefix("2001:db8::/48")
	for _, p := range append(refused, wanted) {
		table.Set(netip.Prefix{}, p, peer)
	}
	if err := r.applyRoutes(); err != nil {
		t.Fatal(err)
	}
	installed := kernel.snapshot()
	if len(installed) != 1 {
		t.Fatalf("the reconciler installed %v, want only %s", installed, wanted)
	}
	if installed[0].Destination != wanted {
		t.Errorf("the reconciler installed %s rather than %s", installed[0].Destination, wanted)
	}
}

// "Only an address this reconciler added itself, in this process lifetime, is
// ever removed again." Both platforms assign by upsert, so the same address
// under a different prefix length rewrites an entry somebody else put there
// and reports success. Recording that as owned takes it away at shutdown, and
// ranet-lite attaches to a tun it did not necessarily create.
func TestAddressAnotherWriterHoldsIsLeftAlone(t *testing.T) {
	wanted := prefix("2001:db8::1/128")
	r, _, kernel := harness(t, Config{Addresses: []netip.Prefix{wanted}})
	kernel.addrs[prefix("2001:db8::1/64")] = true

	if err := r.applyAddresses(); err != nil {
		t.Fatalf("applying addresses failed rather than skipping one: %v", err)
	}
	if r.owned[wanted] {
		t.Error("an address another writer put on the link was recorded as ours, so shutdown takes it away")
	}
	if kernel.addrs[wanted] {
		t.Error("the reconciler rewrote an address it does not own")
	}
	if !kernel.addrs[prefix("2001:db8::1/64")] {
		t.Error("the other writer's address is gone")
	}

	// An address nothing else holds is still assigned and still owned.
	free := prefix("2001:db8::2/128")
	r.cfg.Addresses = append(r.cfg.Addresses, free)
	if err := r.applyAddresses(); err != nil {
		t.Fatal(err)
	}
	if !r.owned[free] || !kernel.addrs[free] {
		t.Error("a free address was not assigned")
	}
}

// darwin's SIOCDIFADDR matches on the address alone, so another writer that
// rewrote this reconciler's address under a different prefix length, which its
// SIOCAIFADDR upsert lets it do, would have its entry taken away by shutdown.
// The rule is that only an address this reconciler added itself is ever
// removed, and an address that no longer looks the way it was installed is no
// longer that address.
func TestWithdrawLeavesAnAddressAnotherWriterRewrote(t *testing.T) {
	ours := prefix("2001:db8::1/128")
	kept := prefix("2001:db8::2/128")
	r, _, kernel := harness(t, Config{Addresses: []netip.Prefix{ours, kept}})
	if err := r.applyAddresses(); err != nil {
		t.Fatal(err)
	}
	if !r.owned[ours] || !r.owned[kept] {
		t.Fatal("the reconciler did not record what it assigned, so this proves nothing")
	}

	// Somebody rewrites one of them under a different length.
	delete(kernel.addrs, ours)
	kernel.addrs[prefix("2001:db8::1/64")] = true

	if err := r.withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if !kernel.addrs[prefix("2001:db8::1/64")] {
		t.Error("shutdown removed an address this reconciler no longer held as it installed it")
	}
	if kernel.addrs[kept] {
		t.Error("shutdown left an address it did install")
	}
}

// The same rule when the link will not say what it holds. A readback that did
// not happen is not one that said yes, and treating it as one deletes exactly
// the address the guard above exists to protect. applyAddresses refuses the
// whole pass on the identical failure.
func TestWithdrawLeavesEveryAddressWhenTheLinkWillNotReadBack(t *testing.T) {
	ours := prefix("2001:db8::1/128")
	r, _, kernel := harness(t, Config{Addresses: []netip.Prefix{ours}})
	if err := r.applyAddresses(); err != nil {
		t.Fatal(err)
	}
	if !r.owned[ours] {
		t.Fatal("the reconciler did not record what it assigned, so this proves nothing")
	}

	kernel.failAddrs = errors.New("link is gone")
	if err := r.withdraw(); err == nil {
		t.Error("a shutdown that could not read the link back reported success")
	}
	if !kernel.addrs[ours] {
		t.Error("shutdown removed an address it could not confirm it still held as it installed it")
	}
	if !r.owned[ours] {
		t.Error("shutdown forgot an address it did not withdraw")
	}
}

// An address another writer holds is reported once, not once per pass: the
// record rotates the way the route warning set does, so a report costs one log
// line for as long as the situation lasts rather than one every reconcile
// interval for the life of the process.
func TestAddressReportIsNotRepeatedEveryPass(t *testing.T) {
	logs := captureKernelLogs(t)
	wanted := prefix("2001:db8::1/128")
	r, _, kernel := harness(t, Config{Addresses: []netip.Prefix{wanted}})
	kernel.addrs[prefix("2001:db8::1/64")] = true

	const passes = 4
	for pass := range passes {
		if err := r.applyAddresses(); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
	}
	if got := bytes.Count(logs.Bytes(), []byte("another writer holds")); got != 1 {
		t.Errorf("the address was reported %d times across %d passes, want once", got, passes)
	}
}

// A prefix the mesh has and the kernel does not is explained by Skipped, by
// Err, or by nothing at all, so both have to survive a pass rather than being
// counted only into a log line.
func TestStatsReportWhatThePassDidAndDidNotInstall(t *testing.T) {
	reconciler, table, fake := harness(t, Config{})
	if before := reconciler.Stats(); !before.At.IsZero() {
		t.Fatalf("stats before the first pass read %+v, want the zero value", before)
	}

	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("2602:f590::/36"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	first := reconciler.Stats()
	if first.At.IsZero() {
		t.Fatal("a finished pass left no timestamp")
	}
	if first.Desired != 2 || first.Installed != 2 || first.Added != 2 || first.Removed != 0 || first.Skipped != 0 {
		t.Fatalf("the first pass reports %+v, want two desired, installed and added", first)
	}

	// A route another writer holds is refused rather than taken over, which
	// the platform reports as errRouteSkipped.
	refused := Route{Destination: prefix("10.1.0.0/16")}
	fake.failAdd[refused] = errRouteSkipped
	table.Set(netip.Prefix{}, prefix("10.1.0.0/16"), nil)
	table.Remove(netip.Prefix{}, prefix("10.0.0.0/8"))
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	second := reconciler.Stats()
	if second.Skipped != 1 {
		t.Errorf("a refused install reports %+v, want one skipped", second)
	}
	if second.Removed != 1 || second.Added != 0 {
		t.Errorf("the second pass reports %+v, want one removed and none added", second)
	}
	if second.Installed != 1 {
		t.Errorf("the second pass reports %d installed, want the one route the kernel still holds", second.Installed)
	}
	if second.Err != "" {
		t.Errorf("a skipped route was reported as a failure: %s", second.Err)
	}
}

// The fake's policy engine. It models what the linux backend guarantees rather
// than the wire format: Rules returns only what this reconciler installed, so
// a test that saw another writer's rule in the list would be testing a promise
// the backend does not make.
func (f *fakeKernel) Rules() ([]Rule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRules != nil {
		return nil, f.failRules
	}
	out := make([]Rule, 0, len(f.rules))
	for rule := range f.rules {
		out = append(out, rule)
	}
	slices.SortFunc(out, func(a, b Rule) int { return strings.Compare(a.String(), b.String()) })
	return out, nil
}

func (f *fakeKernel) AddRule(rule Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failAddRule[rule]; err != nil {
		return err
	}
	f.ruleAdds++
	f.rules[rule] = true
	return nil
}

func (f *fakeKernel) DelRule(rule Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ruleDels++
	delete(f.rules, rule)
	return nil
}

func (f *fakeKernel) EnsureVRF(name string, table uint32) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.vrfErr != nil {
		return false, f.vrfErr
	}
	if _, exists := f.vrfs[name]; exists {
		return false, nil
	}
	f.vrfs[name] = table
	return true, nil
}

func (f *fakeKernel) RemoveVRF(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.vrfs, name)
	return nil
}

// routesOnly is a platform with no policy engine and no VRFs, which is every
// platform but linux. It delegates rather than embedding, because embedding
// promotes the rule methods and the point of this type is not having them.
type routesOnly struct{ inner *fakeKernel }

func (p routesOnly) Routes() ([]Route, error)          { return p.inner.Routes() }
func (p routesOnly) where(cfg Config) string           { return p.inner.where(cfg) }
func (p routesOnly) AddRoute(r Route) error            { return p.inner.AddRoute(r) }
func (p routesOnly) DelRoute(r Route) error            { return p.inner.DelRoute(r) }
func (p routesOnly) Addrs() ([]netip.Prefix, error)    { return p.inner.Addrs() }
func (p routesOnly) AddAddr(prefix netip.Prefix) error { return p.inner.AddAddr(prefix) }
func (p routesOnly) DelAddr(prefix netip.Prefix) error { return p.inner.DelAddr(prefix) }
func (p routesOnly) Master() (string, error)           { return p.inner.Master() }
func (p routesOnly) Enslave(master string) error       { return p.inner.Enslave(master) }
func (p routesOnly) Release() error                    { return p.inner.Release() }
func (p routesOnly) Notify() <-chan struct{}           { return p.inner.Notify() }
func (p routesOnly) Close() error                      { return p.inner.Close() }

// A platform with no policy engine refuses a configuration that asks for one,
// rather than coming up with a working mesh and no steering at all.
func TestPlatformWithoutRulesRefusesThemByName(t *testing.T) {
	plat := routesOnly{inner: newFakeKernel(t)}
	rule := Rule{Family: FamilyIPv6, From: prefix("2001:db8::/32"), Table: 200, Priority: 150}
	err := refuseWhatThePlatformLacks(Config{Rules: []Rule{rule}}, plat)
	if err == nil {
		t.Fatal("a rule was accepted on a platform that cannot install one")
	}
	if !strings.Contains(err.Error(), "scoped") {
		t.Errorf("the refusal reads %q, want it to say what the platform does instead", err)
	}
	if err := refuseWhatThePlatformLacks(Config{CreateVRF: true, VRF: "gravity"}, plat); err == nil {
		t.Fatal("vrf creation was accepted on a platform with no VRFs")
	}
	// Naming a VRF without asking for one to be created still needs the link
	// enslaved to it, which the same platforms cannot do.
	if err := refuseWhatThePlatformLacks(Config{VRF: "gravity"}, plat); err == nil {
		t.Fatal("a vrf was accepted on a platform with no VRFs")
	}
	// Asking for a device with no name to create is a configuration that
	// cannot mean anything.
	if err := refuseWhatThePlatformLacks(Config{CreateVRF: true}, newFakeKernel(t)); err == nil {
		t.Fatal("vrf_create with no vrf was accepted")
	}
	// The same configuration on a platform that has both is accepted.
	if err := refuseWhatThePlatformLacks(Config{Rules: []Rule{rule}, CreateVRF: true, VRF: "gravity"}, newFakeKernel(t)); err != nil {
		t.Errorf("a platform with rules and VRFs refused them: %v", err)
	}
}

// A rule the kernel would take and an operator would not recognize afterwards
// is refused at startup, because the alternative is finding it in a rule list
// on a live node.
func TestRuleValidationRefusesWhatReadsWrong(t *testing.T) {
	for name, rule := range map[string]Rule{
		"no family":           {To: prefix("10.0.0.0/8"), Table: 200, Priority: 100},
		"the wrong family":    {Family: FamilyIPv6, To: prefix("10.0.0.0/8"), Table: 200, Priority: 100},
		"host bits":           {Family: FamilyIPv4, To: netip.MustParsePrefix("10.1.2.3/8"), Table: 200, Priority: 100},
		"no selector":         {Family: FamilyIPv4, Table: 200, Priority: 100},
		"a mask with no mark": {Family: FamilyIPv4, FWMask: 0xffff, Table: 200, Priority: 100},
		"the local priority":  {Family: FamilyIPv4, To: prefix("10.0.0.0/8"), Table: 200},
		"no table":            {Family: FamilyIPv4, To: prefix("10.0.0.0/8"), Priority: 100},
	} {
		t.Run(name, func(t *testing.T) {
			if err := rule.validate(); err == nil {
				t.Errorf("%s was accepted: %s", name, rule)
			}
		})
	}
	for name, rule := range map[string]Rule{
		"an address rule": {Family: FamilyIPv6, From: prefix("2001:db8::/32"), Table: 200, Priority: 150},
		"a mark rule":     {Family: FamilyIPv4, FWMark: 0x726c, Table: 254, Priority: 40},
		"a masked mark":   {Family: FamilyIPv6, FWMark: 0x726c, FWMask: 0xffff, Table: 254, Priority: 40},
	} {
		t.Run(name, func(t *testing.T) {
			if err := rule.validate(); err != nil {
				t.Errorf("%s was refused: %v", name, err)
			}
		})
	}
}

// The rule pass installs what is configured, removes what is not, and does
// neither twice. The second half is the one that matters: a rule read back in
// a different spelling than it was written in would be deleted and reinstalled
// on every pass, at four passes a second on a busy node.
func TestRulePassInstallsOnceAndWithdrawsWhatIsGone(t *testing.T) {
	underlay := Rule{Family: FamilyIPv4, FWMark: 0x726c, Table: 254, Priority: 40}
	mesh := Rule{Family: FamilyIPv6, From: prefix("2001:db8::/32"), Table: 200, Priority: 150}
	reconciler, _, fake := harness(t, Config{Rules: []Rule{underlay, mesh}, VRF: "gravity", CreateVRF: true})

	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, err := fake.Rules(); err != nil || len(got) != 2 {
		t.Fatalf("the first pass installed %v (%v), want both rules", got, err)
	}
	if table, ok := fake.vrfs["gravity"]; !ok || table != DefaultTable {
		t.Fatalf("the vrf is %v bound to %d, want the reconciler's table", ok, table)
	}

	adds, dels := fake.ruleAdds, fake.ruleDels
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.ruleAdds != adds || fake.ruleDels != dels {
		t.Fatalf("a second pass over an unchanged configuration moved %d adds and %d dels",
			fake.ruleAdds-adds, fake.ruleDels-dels)
	}

	// A rule an earlier instance left behind is adopted by the readback and
	// withdrawn, rather than left for somebody to find later.
	stale := Rule{Family: FamilyIPv4, To: prefix("10.0.0.0/8"), Table: 200, Priority: 100}
	fake.rules[stale] = true
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.Rules(); len(got) != 2 || slices.Contains(got, stale) {
		t.Fatalf("a stale rule survived the pass: %v", got)
	}

	if err := reconciler.withdraw(); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.Rules(); len(got) != 0 {
		t.Errorf("shutdown left %v behind", got)
	}
	if _, ok := fake.vrfs["gravity"]; ok {
		t.Error("shutdown left behind the vrf it created")
	}
}

// A VRF that was already there belongs to whoever made it: rebinding it moves
// every route in its table, and removing it at shutdown takes them with it.
func TestVRFThatWasAlreadyThereIsLeftAlone(t *testing.T) {
	reconciler, _, fake := harness(t, Config{VRF: "gravity", CreateVRF: true})
	fake.vrfs["gravity"] = 42

	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if table := fake.vrfs["gravity"]; table != 42 {
		t.Fatalf("the existing vrf was rebound to %d", table)
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatal(err)
	}
	if table, ok := fake.vrfs["gravity"]; !ok || table != 42 {
		t.Errorf("shutdown removed a vrf it did not create: %v %d", ok, table)
	}
}

// Two spellings the kernel stores as one rule have to reach the diff as one
// rule. A mark with no mask is stored and reported back with a mask of all
// ones, and a prefix of length zero is reported back as no prefix at all, so a
// configuration holding either spelling never matches its own readback: every
// pass deletes the rule and installs it again, with a window each time in
// which the traffic it steers is unsteered.
func TestRulesAreCanonicalizedToWhatTheKernelReportsBack(t *testing.T) {
	masked := Rule{Family: FamilyIPv4, FWMark: 0x726c, FWMask: ^uint32(0), Table: 254, Priority: 40}
	if got := masked.canonical(); got.FWMask != 0 {
		t.Errorf("an all-ones mask survived canonicalization as %#x", got.FWMask)
	}
	wide := Rule{Family: FamilyIPv6, To: prefix("::/0"), FWMark: 1, Table: 200, Priority: 100}
	if got := wide.canonical(); got.To.IsValid() {
		t.Errorf("a zero-length prefix survived canonicalization as %s", got.To)
	}

	// The reconciler holds the canonical form, so the diff compares the dump
	// against what the kernel would report rather than against the spelling.
	reconciler, _, fake := harness(t, Config{Rules: []Rule{masked}})
	if got := reconciler.cfg.Rules[0].FWMask; got != 0 {
		t.Fatalf("the reconciler kept mask %#x", got)
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	adds, dels := fake.ruleAdds, fake.ruleDels
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.ruleAdds != adds || fake.ruleDels != dels {
		t.Errorf("a second pass moved %d adds and %d deletes", fake.ruleAdds-adds, fake.ruleDels-dels)
	}

	// Dropping a zero-length prefix leaves a rule selecting nothing, which is
	// refused by name rather than installed as a rule matching everything.
	everything := Rule{Family: FamilyIPv6, To: prefix("::/0"), Table: 200, Priority: 100}
	if err := everything.canonical().validate(); err == nil {
		t.Error("a rule selecting every address was accepted")
	}
}

// A pass that fails anywhere has to say so where an operator reads it. Only
// applyRoutes counts, so a node whose rules or VRF fail on every pass would
// otherwise report a clean route count and no error at all.
func TestStatsCarryTheWholePassError(t *testing.T) {
	reconciler, _, fake := harness(t, Config{VRF: "gravity", CreateVRF: true})
	fake.vrfErr = errors.New("no permission to create a vrf")

	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a failing vrf did not fail the pass")
	}
	stats := reconciler.Stats()
	if stats.Err == "" {
		t.Error("the pass failed and Stats reported no error")
	}
	if stats.At.IsZero() {
		t.Error("a failing pass left no timestamp, so a stale one reads as current")
	}
}
