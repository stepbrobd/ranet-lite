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
	master  string
	closed  bool
	adds    int
	dels    int

	failAdd  map[Route]error
	failDel  map[Route]error
	failList error

	signal chan struct{}
}

func newFakeKernel(t *testing.T) *fakeKernel {
	return &fakeKernel{
		t:       t,
		routes:  make(map[Route]bool),
		foreign: make(map[Route]bool),
		addrs:   make(map[netip.Prefix]bool),
		failAdd: make(map[Route]error),
		failDel: make(map[Route]error),
		signal:  make(chan struct{}, 1),
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
	out := make([]netip.Prefix, 0, len(f.addrs))
	for address := range f.addrs {
		out = append(out, address)
	}
	slices.SortFunc(out, comparePrefixes)
	return out, nil
}

func (f *fakeKernel) AddAddr(address netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs[address] = true
	return nil
}

func (f *fakeKernel) DelAddr(address netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.addrs, address)
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
// two kernel routes, not one, which is the whole point of RTA_SRC.
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
func TestReconcileReplacesRoutesWhenTheMetricChanges(t *testing.T) {
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

func TestReconcileDoesNotCountSkippedRoutes(t *testing.T) {
	logs := captureKernelLogs(t)
	reconciler, table, fake := harness(t, Config{})
	skipped := Route{Destination: prefix("::/0"), Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}
	fake.failAdd[skipped] = errRouteSkipped
	table.Set(skipped.Source, skipped.Destination, nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("an unrepresentable route triggered retry: %v", err)
	}
	var counts map[string]any
	if err := json.Unmarshal(logs.Bytes(), &counts); err != nil {
		t.Fatal(err)
	}
	if counts["added"] != float64(0) {
		t.Errorf("an unrepresentable route was counted as added: %v", counts["added"])
	}
}

// A dump that fails must not be read as an empty kernel, which would delete
// nothing but would also install every route a second time.
func TestReconcileReportsAFailedDump(t *testing.T) {
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
}

func TestApplyMasterEnslavesOnlyAnUnclaimedLink(t *testing.T) {
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

func TestNewRejectsAReservedProtocol(t *testing.T) {
	if _, err := New(Config{Interface: "ranet0", Protocol: 2}, netstack.NewRouteTable()); err == nil {
		t.Fatal("RTPROT_KERNEL must be rejected")
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
	add, del := diffRoutes(desired, actual)
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
func TestSkippedRoutesAreNotCountedAndDoNotFailThePass(t *testing.T) {
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
