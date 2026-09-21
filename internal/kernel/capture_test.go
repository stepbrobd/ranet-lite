package kernel

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/schema"
)

// start is an arbitrary fixed instant, so every elapsed time below reads as
// the offset it is.
var start = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// step is one liveness observation at an offset from start, and what the gate
// must answer for it.
type step struct {
	at   time.Duration
	live int
	open bool
}

// The three rules the gate exists to hold, each stated as a sequence of
// observations: nothing capturing before the first live session, a withdrawal
// once none has been live for the grace, and a restore on the next one.
func TestCaptureGateOpensOnlyWhileTheMeshIsLive(t *testing.T) {
	const grace = 10 * time.Second
	for name, steps := range map[string][]step{
		"a node that has never had a session installs nothing": {
			{at: 0, live: 0, open: false},
			{at: time.Hour, live: 0, open: false},
		},
		"the first live session opens it": {
			{at: 0, live: 0, open: false},
			{at: time.Second, live: 1, open: true},
		},
		"the grace runs from the last live sample, not from the first idle one": {
			{at: 0, live: 1, open: true},
			{at: 2 * time.Second, live: 0, open: true},
			{at: 9 * time.Second, live: 0, open: true},
			{at: grace, live: 0, open: false},
		},
		"a session that comes back before the grace expires restarts it": {
			{at: 0, live: 1, open: true},
			{at: 9 * time.Second, live: 0, open: true},
			{at: 9500 * time.Millisecond, live: 2, open: true},
			{at: 19 * time.Second, live: 0, open: true},
			{at: 19500 * time.Millisecond, live: 0, open: false},
		},
		"a session after a withdrawal restores it at once": {
			{at: 0, live: 1, open: true},
			{at: grace, live: 0, open: false},
			{at: grace + time.Second, live: 1, open: true},
		},
		"a pass that finds nothing live long after the grace keeps it shut": {
			{at: 0, live: 1, open: true},
			{at: time.Hour, live: 0, open: false},
			{at: 2 * time.Hour, live: 0, open: false},
		},
	} {
		t.Run(name, func(t *testing.T) {
			gate := captureGate{grace: grace}
			for _, s := range steps {
				open, _ := gate.sample(start.Add(s.at), s.live)
				if open != s.open {
					t.Errorf("at %s with %d live sessions the gate reported %v, want %v",
						s.at, s.live, open, s.open)
				}
			}
		})
	}
}

// changed says a caller may report the transition once. A gate that reported
// it on every pass would log a line per pass for as long as the mesh is down,
// which is exactly the stretch an operator is reading the log.
func TestCaptureGateReportsEachTransitionOnce(t *testing.T) {
	gate := captureGate{grace: 10 * time.Second}
	var transitions []bool
	for _, s := range []step{
		{at: 0, live: 0}, {at: time.Second, live: 1}, {at: 2 * time.Second, live: 1},
		{at: 3 * time.Second, live: 0}, {at: 20 * time.Second, live: 0},
		{at: 30 * time.Second, live: 0}, {at: 40 * time.Second, live: 1},
	} {
		open, changed := gate.sample(start.Add(s.at), s.live)
		if changed {
			transitions = append(transitions, open)
		}
	}
	// Opened at the first live session, shut once the grace expired, opened
	// again on the session after it, and nothing in between.
	if want := []bool{true, false, true}; !slices.Equal(transitions, want) {
		t.Errorf("the gate reported the transitions %v, want %v", transitions, want)
	}
}

// Only a running grace needs a wake-up of its own. A gate that is open because
// a session is live will be woken by the next mesh change, and a shut one has
// nothing scheduled to happen at all.
func TestCaptureGateAsksToBeWokenOnlyWhileTheGraceRuns(t *testing.T) {
	const grace = 10 * time.Second
	gate := captureGate{grace: grace}
	if _, ok := gate.deadline(); ok {
		t.Error("a gate that has seen nothing asked to be woken")
	}
	gate.sample(start, 1)
	if _, ok := gate.deadline(); ok {
		t.Error("a gate held open by a live session asked to be woken")
	}
	gate.sample(start.Add(time.Second), 0)
	at, ok := gate.deadline()
	if !ok {
		t.Fatal("a running grace did not ask to be woken")
	}
	// The grace runs from the last live sample, not from the pass that found
	// nothing live, so the deadline cannot move by waiting.
	if want := start.Add(grace); !at.Equal(want) {
		t.Errorf("the grace expires at %s, want %s", at, want)
	}
	gate.sample(start.Add(grace), 0)
	if _, ok := gate.deadline(); ok {
		t.Error("a gate that has already withdrawn asked to be woken again")
	}
}

// Every prefix covering half the address space or more carries this machine's
// own traffic, whichever spelling the announcement uses.
func TestCapturesTheMachineCoversEverySpellingOfADefault(t *testing.T) {
	for _, destination := range []string{"0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		if !capturesTheMachine(Route{Destination: prefix(destination)}) {
			t.Errorf("%s does not read as carrying this machine's own traffic", destination)
		}
	}
	for _, destination := range []string{"10.0.0.0/8", "2000::/3", "3fff:a::/36", "0.0.0.0/2"} {
		if capturesTheMachine(Route{Destination: prefix(destination)}) {
			t.Errorf("%s reads as carrying this machine's own traffic", destination)
		}
	}
}

// The gate as the reconciler applies it: an announced default reaches the
// kernel only while the mesh can carry it, and the ordinary mesh prefixes
// around it are never held back, because a prefix route leaves the machine's
// own uplink alone.
func TestReconcileInstallsAnAnnouncedDefaultOnlyWhileASessionIsLive(t *testing.T) {
	live := 0
	reconciler, table, fake := harness(t,
		Table{CaptureGrace: schema.Duration(10 * time.Second)},
		Runtime{Sessions: func() int { return live }})
	clock := start
	reconciler.now = func() time.Time { return clock }
	table.Set(netip.Prefix{}, prefix("::/0"), nil)
	table.Set(netip.Prefix{}, prefix("3fff:a::/36"), nil)

	mesh := Route{Destination: prefix("3fff:a::/36"), Metric: defaultIPv6Metric}
	def := Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}

	// The mesh announces a default before anything has connected, which is
	// what a node reading a peer's stale announcement at startup would see.
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.has(def) {
		t.Fatal("a default was installed before any session had been live")
	}
	if !fake.has(mesh) {
		t.Fatal("an ordinary mesh prefix was held back with the default")
	}

	live = 1
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(def) {
		t.Fatal("a live session did not install the announced default")
	}

	// The session goes, and the default stays for the grace: a reconnect
	// inside it must not cost the machine its route.
	live = 0
	clock = start.Add(9 * time.Second)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(def) {
		t.Fatal("the default was withdrawn inside the grace")
	}

	clock = start.Add(11 * time.Second)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.has(def) {
		t.Fatal("the default survived the grace with nothing live")
	}
	if !fake.has(mesh) {
		t.Fatal("the mesh prefixes went with the default")
	}

	// And it comes back on its own, which is the half that makes the
	// withdrawal a fallback rather than an outage.
	live = 2
	clock = start.Add(12 * time.Second)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(def) {
		t.Fatal("the default was not restored by the next live session")
	}
}

// A retracted default is a hold: unscoped it answers with an error for every
// destination, which is the same machine with no network in a different shape.
// It is held back by the same gate.
func TestReconcileHoldsBackARetractedDefaultToo(t *testing.T) {
	reconciler, table, fake := harness(t, Table{}, Runtime{Sessions: func() int { return 0 }})
	reconciler.now = func() time.Time { return start }
	table.Set(netip.Prefix{}, prefix("::/0"), netstack.Unreachable)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := fake.snapshot(); len(got) != 0 {
		t.Fatalf("installed %v with nothing live, want nothing", got)
	}
}

// A reconciler nobody told about sessions keeps the behavior it had before the
// gate existed. It is driven by something that has no sessions to report, and
// answering zero for it would leave every default uninstallable.
func TestReconcileInstallsADefaultWhenNothingReportsSessions(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("::/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}) {
		t.Fatal("a reconciler with no session source held back an announced default")
	}
}

// Run has to wake at the moment the grace expires. Nothing else will: the mesh
// has stopped changing, which is why the grace is running.
func TestReconcilerAsksToBeWokenWhenTheGraceExpires(t *testing.T) {
	live := 1
	reconciler, table, _ := harness(t,
		Table{CaptureGrace: schema.Duration(10 * time.Second)},
		Runtime{Sessions: func() int { return live }})
	clock := start
	reconciler.now = func() time.Time { return clock }
	table.Set(netip.Prefix{}, prefix("::/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, ok := reconciler.captureDeadline(); ok {
		t.Fatal("a reconciler carrying a live session asked to be woken")
	}
	live = 0
	clock = start.Add(time.Second)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	at, ok := reconciler.captureDeadline()
	if !ok {
		t.Fatal("a reconciler running the grace did not ask to be woken")
	}
	if want := start.Add(10 * time.Second); !at.Equal(want) {
		t.Errorf("it asked to be woken at %s, want %s", at, want)
	}
}

// recordingCapture is the routing a capturing route depends on, which on
// darwin is the underlay's own default. It records what the kernel held at
// each call, because the ordering is the property: the underlay's route has to
// be in before the route that would strand it and out after.
type recordingCapture struct {
	fake *fakeKernel
	at   []string
	held bool
}

func (c *recordingCapture) Hold() error {
	c.held = true
	c.at = append(c.at, "hold with "+c.capturing())
	return nil
}

func (c *recordingCapture) Release() error {
	c.held = false
	c.at = append(c.at, "release with "+c.capturing())
	return nil
}

// capturing describes whether the kernel currently holds a route that would
// carry this machine's own traffic.
func (c *recordingCapture) capturing() string {
	for _, route := range c.fake.snapshot() {
		if capturesTheMachine(route) {
			return "the default installed"
		}
	}
	return "no default installed"
}

// The underlay's own routing goes in before the route that would strand it and
// comes out after the last one is gone. Any other order leaves a window in
// which this machine's traffic is in the tun while the socket carrying the tun
// has nothing to fall back on, which is the outage the whole arrangement
// exists to avoid.
func TestReconcileHoldsTheUnderlayRouteAroundTheCapture(t *testing.T) {
	live := 1
	reconciler, table, fake := harness(t,
		Table{CaptureGrace: schema.Duration(10 * time.Second)},
		Runtime{Sessions: func() int { return live }})
	capture := &recordingCapture{fake: fake}
	reconciler.rt.Capture = capture
	clock := start
	reconciler.now = func() time.Time { return clock }
	table.Set(netip.Prefix{}, prefix("::/0"), nil)
	table.Set(netip.Prefix{}, prefix("3fff:a::/36"), nil)

	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !capture.held {
		t.Fatal("the underlay route was not held while the mesh carries the default")
	}

	// The mesh goes and the grace expires, which withdraws both together.
	live = 0
	clock = start.Add(11 * time.Second)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if capture.held {
		t.Fatal("the underlay route was still held after the default was withdrawn")
	}

	want := []string{"hold with no default installed", "release with no default installed"}
	if !slices.Equal(capture.at, want) {
		t.Errorf("the calls landed as %v, want %v", capture.at, want)
	}
}

// A node whose mesh never announces a default never touches the routing of the
// interface it reaches its peers through.
func TestReconcileLeavesTheUnderlayAloneWithoutADefault(t *testing.T) {
	reconciler, table, fake := harness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	capture := &recordingCapture{fake: fake}
	reconciler.rt.Capture = capture
	reconciler.now = func() time.Time { return start }
	table.Set(netip.Prefix{}, prefix("3fff:a::/36"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if capture.held {
		t.Error("an ordinary mesh prefix held the underlay route")
	}
}

// Shutdown withdraws the routes first and the underlay's own route after, for
// the same reason a pass does.
func TestWithdrawReleasesTheUnderlayRouteLast(t *testing.T) {
	reconciler, table, fake := harness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	capture := &recordingCapture{fake: fake}
	reconciler.rt.Capture = capture
	reconciler.now = func() time.Time { return start }
	table.Set(netip.Prefix{}, prefix("::/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatal(err)
	}
	if capture.held {
		t.Error("shutdown left the underlay route held")
	}
	last := capture.at[len(capture.at)-1]
	if last != "release with no default installed" {
		t.Errorf("the last call was %q, so the underlay route went while the default was still in the kernel", last)
	}
}
