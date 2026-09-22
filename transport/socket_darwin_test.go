//go:build darwin

package transport

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeLinks stands in for the host's own routing. Every test here drives the
// binding from it rather than from a real link change, because moving a
// machine between wifi and a dock is not something a test can do.
type fakeLinks struct {
	mu     sync.Mutex
	index  int
	err    error
	signal chan struct{}
}

func newFakeLinks(index int) *fakeLinks {
	return &fakeLinks{index: index, signal: make(chan struct{}, 1)}
}

func (f *fakeLinks) DefaultInterface() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.index, f.err
}

func (f *fakeLinks) Changed() <-chan struct{} { return f.signal }

// move is the host's default route arriving on another interface.
func (f *fakeLinks) move(index int, err error) {
	f.mu.Lock()
	f.index, f.err = index, err
	f.mu.Unlock()
	select {
	case f.signal <- struct{}{}:
	default:
	}
}

// boundInterface reads back what the kernel holds, so the tests assert on the
// socket rather than on the bookkeeping beside it.
func boundInterface(t *testing.T, socket *darwinSocket) int {
	t.Helper()
	level, option := socket.boundInterfaceOption()
	var index int
	var readErr error
	if err := socket.raw.Control(func(fd uintptr) {
		index, readErr = unix.GetsockoptInt(int(fd), level, option)
	}); err != nil {
		t.Fatal(err)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return index
}

// twoInterfaces is the loopback and one other link this host really has, so a
// rebind moves between two indices the kernel will accept.
func twoInterfaces(t *testing.T) (first, second int) {
	t.Helper()
	devices, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range devices {
		if device.Flags&net.FlagLoopback != 0 {
			first = device.Index
			continue
		}
		if second == 0 && device.Flags&net.FlagUp != 0 {
			second = device.Index
		}
	}
	if first == 0 || second == 0 {
		t.Skip("this host has no loopback and a second live interface to move between")
	}
	return first, second
}

// waitFor polls until the socket carries index, because the rebind happens on
// the hub's own goroutine and a link change carries no acknowledgement.
func waitFor(t *testing.T, bind *darwinBind, index int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if boundInterface(t, bind.v4) == index && boundInterface(t, bind.v6) == index {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the socket did not reach interface %d: udp4 on %d, udp6 on %d",
		index, boundInterface(t, bind.v4), boundInterface(t, bind.v6))
}

// Both families have to be bound. A node with one socket on the host's own
// interface and the other following the forwarding table reaches half its
// peers, and the half it loses is whichever family an exit announced into.
func TestUnderlayBindingReachesBothFamilies(t *testing.T) {
	index, _ := twoInterfaces(t)
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: newFakeLinks(index)})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)
	if got := boundInterface(t, bind.v4); got != index {
		t.Errorf("the udp4 socket is bound to %d, want %d", got, index)
	}
	if got := boundInterface(t, bind.v6); got != index {
		t.Errorf("the udp6 socket is bound to %d, want %d", got, index)
	}
	if !hub.UnderlayReady() {
		t.Error("a bound hub reports its underlay is not where it should be")
	}
}

// A link change moves the option on the descriptor that is already open. The
// alternative, reopening, would drop every SA on the node to follow a change
// no peer ever saw, so the port has to survive the move.
func TestUnderlayRebindsWithoutReplacingTheSocket(t *testing.T) {
	first, second := twoInterfaces(t)
	links := newFakeLinks(first)
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)
	port := hub.LocalAddr().(*net.UDPAddr).Port
	v4, v6 := bind.v4.conn, bind.v6.conn

	links.move(second, nil)
	waitFor(t, bind, second)

	if got := hub.LocalAddr().(*net.UDPAddr).Port; got != port {
		t.Errorf("the hub moved from port %d to %d, so every SA on it went with it", port, got)
	}
	if bind.v4.conn != v4 || bind.v6.conn != v6 {
		t.Error("the sockets were replaced rather than rebound")
	}
}

// A laptop that boots with no network has no default route to bind to. That is
// an ordinary morning rather than a failure, so the hub opens; what it must
// not do is report the underlay as being where the configuration says, because
// the reconciler reads that before it hands the machine's traffic to the mesh.
func TestUnderlayStaysUnboundUntilTheHostHasADefaultRoute(t *testing.T) {
	index, _ := twoInterfaces(t)
	links := newFakeLinks(0)
	links.move(0, errors.New("no default route"))
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links})
	if err != nil {
		t.Fatalf("a hub on a host with no default route was refused: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)
	if got := boundInterface(t, bind.v4); got != 0 {
		t.Errorf("the udp4 socket was bound to %d with no default route to read", got)
	}
	if hub.UnderlayReady() {
		t.Fatal("an unbound socket reported that the underlay is where it should be")
	}

	links.move(index, nil)
	waitFor(t, bind, index)
	// Polled rather than read once: the socket carries the option before the
	// hub records where it is, because the reachability probe runs between
	// the two, and that probe is two connect calls rather than nothing.
	if !waitReady(t, hub) {
		t.Error("the underlay bound and still reports that it is not where it should be")
	}
}

// waitReady polls until the hub says its underlay is where it should be.
func waitReady(t *testing.T, hub *Hub) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hub.UnderlayReady() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// A default route that disappears leaves the binding where it is. Unbinding
// would hand the socket back to the forwarding table for the length of the
// gap, and that table may hold a default out of our own tun.
func TestUnderlayKeepsItsBindingWhenTheDefaultRouteGoes(t *testing.T) {
	index, _ := twoInterfaces(t)
	links := newFakeLinks(index)
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)

	links.move(0, errors.New("no default route"))
	// Nothing acknowledges a change that is meant to do nothing, so this is a
	// deliberate wait rather than a poll: the failure it is looking for is the
	// socket being unbound, which would happen promptly if it happened.
	time.Sleep(100 * time.Millisecond)
	if got := boundInterface(t, bind.v4); got != index {
		t.Errorf("the udp4 socket moved to %d when the host lost its default route", got)
	}
	if got := boundInterface(t, bind.v6); got != index {
		t.Errorf("the udp6 socket moved to %d when the host lost its default route", got)
	}
}

// SO_MARK is a linux facility. Asking for one here has to be refused by name
// rather than ignored: what asked for it was written to keep the underlay out
// of the mesh's routing, and darwin does that by binding instead.
func TestSocketMarkIsRefusedOnDarwin(t *testing.T) {
	_, err := NewHub(":0", Underlay{Mark: 0x5115}, Runtime{})
	if err == nil {
		t.Fatal("a mark this platform cannot set was accepted")
	}
	if got := err.Error(); !strings.Contains(got, "mark") || strings.Count(got, "transport:") != 1 {
		t.Errorf("the refusal reads %q", got)
	}
}

// The reachability probe runs on every binding, so it has to answer for both
// families without reaching for the wrong one: netip.Addr.As4 panics on an
// IPv6 address, and this runs on the goroutine that follows link changes.
func TestBoundReachProbeAnswersForBothFamilies(t *testing.T) {
	index, _ := twoInterfaces(t)
	for _, probe := range offLinkProbes {
		// Whether the host can reach them is the host's business; what is
		// asserted is that asking does not panic and does not come back with
		// something that is not a routing answer.
		err := reachesWhenBound(index, probe)
		t.Logf("interface %d to %s: %v", index, probe, err)
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			// A sandbox that forbids the syscall is not the host answering
			// about a route, so there is nothing here to assert against. The
			// nix darwin builder refuses a connect to anything off the loopback
			// even with __darwinAllowLocalNetworking.
			t.Skipf("this sandbox will not let a socket ask about %s: %v", probe, err)
		}
		if err != nil && !errors.Is(err, unix.ENETUNREACH) && !errors.Is(err, unix.EHOSTUNREACH) &&
			!errors.Is(err, unix.EADDRNOTAVAIL) && !errors.Is(err, unix.ENETDOWN) {
			t.Errorf("probing %s answered %v, which is not a routing answer", probe, err)
		}
	}
}

// lockedLog is a log sink two goroutines may use. The link follower reports
// from its own, and a test watching for that report reads while it writes, so
// the plain buffer the rest of this package captures into would be a race.
type lockedLog struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *lockedLog) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.Reset()
}

func captureBoundReachLogs(t *testing.T) *lockedLog {
	t.Helper()
	logs := &lockedLog{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logs
}

// answering replaces the probe with one the test decides, per family, and puts
// the real one back afterwards.
func answering(t *testing.T, reaches map[bool]error) {
	t.Helper()
	previous := boundReachProbe
	t.Cleanup(func() { boundReachProbe = previous })
	boundReachProbe = func(_ int, target netip.Addr) error { return reaches[target.Is4()] }
}

// An unreachable socket is reported rather than refused, so the report is the
// whole of what this mechanism does and every rule it holds is a rule about
// what it says.
//
// Warning per family would warn on every single-stack uplink, which is an
// ordinary host and not a fault, so the report is made only where neither
// family can get off the link. And the two messages differ, because a scoped
// default this tool wrote and did not help is a different thing to go looking
// at than an interface whose routing nothing here writes.
func TestBoundReachIsReportedOnlyWhenNeitherFamilyWorks(t *testing.T) {
	unreach := unix.ENETUNREACH
	for name, test := range map[string]struct {
		reaches map[bool]error
		index   int
		routed  bool
		want    string
	}{
		"neither family reaches, and nothing wrote that interface's routing": {
			reaches: map[bool]error{true: unreach, false: unreach},
			index:   7,
			want:    "cannot reach off",
		},
		"neither family reaches although the scoped default was written": {
			reaches: map[bool]error{true: unreach, false: unreach},
			index:   7, routed: true,
			want: "still cannot reach off",
		},
		"only IPv6 reaches, which is an ordinary IPv6-only uplink": {
			reaches: map[bool]error{true: unreach},
			index:   7,
		},
		"only IPv4 reaches, which is an ordinary IPv4-only uplink": {
			reaches: map[bool]error{false: unreach},
			index:   7,
		},
		"both reach": {reaches: map[bool]error{}, index: 7},
		// Zero is the socket that was never bound, so the forwarding table is
		// answering for it as it does for every other socket on the machine.
		"an unbound socket": {
			reaches: map[bool]error{true: unreach, false: unreach},
			index:   0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			answering(t, test.reaches)
			logs := captureBoundReachLogs(t)
			reportBoundReach(test.index, test.routed)
			got := logs.String()
			switch {
			case test.want == "" && got != "":
				t.Errorf("nothing was wrong and the report reads %s", got)
			case test.want == "":
			case !strings.Contains(got, test.want):
				t.Errorf("the report reads %s, want it to say %q", got, test.want)
			}
			if test.want == "" {
				return
			}
			// Both probes named, since an operator reading this has to know
			// which destinations were asked about.
			for _, probe := range offLinkProbes {
				if !strings.Contains(got, probe.String()) {
					t.Errorf("the report does not name the probe %s: %s", probe, got)
				}
			}
			// And the other message is not the one that was made.
			other := "still cannot reach off"
			if test.routed {
				other = `msg="transport bound the underlay socket to an interface it cannot reach off"`
			}
			if strings.Contains(got, other) {
				t.Errorf("the report says %q as well, so routed decides nothing: %s", other, got)
			}
		})
	}
}

// The report is made where the socket is bound, on both paths that bind one:
// the first binding at startup, which is the one a node starting next to the
// default a previous run installed depends on, and every rebind the link
// follower makes afterwards.
func TestBindingReportsWhatTheSocketCanReach(t *testing.T) {
	first, second := twoInterfaces(t)
	answering(t, map[bool]error{true: unix.ENETUNREACH, false: unix.ENETUNREACH})

	logs := captureBoundReachLogs(t)
	links := newFakeLinks(first)
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	if got := logs.String(); !strings.Contains(got, "cannot reach off") {
		t.Errorf("the first binding said nothing about a socket that reaches nothing: %s", got)
	}

	logs.Reset()
	links.move(second, nil)
	waitFor(t, hub.bind.(*darwinBind), second)
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "cannot reach off") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := logs.String(); !strings.Contains(got, "cannot reach off") {
		t.Errorf("the rebind said nothing about a socket that reaches nothing: %s", got)
	}
}

// Binding needs something to say which interface to bind to. A caller that
// asks for it and supplies nothing gets an error rather than a socket that
// silently follows the forwarding table.
func TestBindingWithoutALinkSourceIsRefused(t *testing.T) {
	if _, err := NewHub(":0", Underlay{Bind: true}, Runtime{}); err == nil {
		t.Fatal("a hub asked to bind with no link source was opened anyway")
	}
}

// A hub that was never asked to bind reports its underlay ready, because
// nothing was asked of it. Otherwise every linux node and every node that
// leaves the block out would hold its announced default back forever.
func TestUnboundUnderlayReportsReady(t *testing.T) {
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	if !hub.UnderlayReady() {
		t.Error("a hub that was never asked to bind reports that it is not where it should be")
	}
	if got := hub.bind.(*darwinBind); boundInterface(t, got.v4) != 0 {
		t.Error("a hub that was never asked to bind set IP_BOUND_IF anyway")
	}
}

// recordingRoutes is the routing a bound socket depends on, which on darwin is
// a default scoped to the interface it is bound to. It records the order of
// every call against the interface the socket was on at the time, because the
// order is the property under test.
type recordingRoutes struct {
	hub *Hub
	mu  sync.Mutex
	at  []string
}

func (r *recordingRoutes) note(what string, index int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	bound := 0
	if r.hub != nil {
		r.hub.mu.Lock()
		bound = r.hub.boundTo
		r.hub.mu.Unlock()
	}
	r.at = append(r.at, fmt.Sprintf("%s %d while bound to %d", what, index, bound))
}

func (r *recordingRoutes) Prepare(index int) error { r.note("prepare", index); return nil }
func (r *recordingRoutes) Settle(index int) error  { r.note("settle", index); return nil }

func (r *recordingRoutes) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.at)
}

// A move makes the interface the socket is going to usable before the socket
// moves onto it, and clears the one it left only after. On this platform a
// bound socket still reads the shared forwarding table, so a socket on an
// interface whose scoped default has already gone reaches nothing at all.
func TestUnderlayPreparesAnInterfaceBeforeBindingToIt(t *testing.T) {
	first, second := twoInterfaces(t)
	links := newFakeLinks(first)
	routes := &recordingRoutes{}
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links, Routes: routes})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	routes.mu.Lock()
	routes.hub = hub
	routes.mu.Unlock()
	bind := hub.bind.(*darwinBind)

	links.move(second, nil)
	waitFor(t, bind, second)
	// The settle after the move is the last call, and a poll can read the
	// list between the bind and it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(routes.calls()) < 4 {
		time.Sleep(5 * time.Millisecond)
	}

	calls := routes.calls()
	if len(calls) < 4 {
		t.Fatalf("the move made %v, want a prepare and a settle for each interface", calls)
	}
	// The opening pair is on the interface the socket was born on, and the
	// hub's own binding happened inside the listen hook, so the first prepare
	// reads as bound to nothing.
	if want := fmt.Sprintf("prepare %d while bound to 0", first); calls[0] != want {
		t.Errorf("the first call was %q, want %q", calls[0], want)
	}
	// The move: prepared while still on the old interface, settled once on
	// the new one. Either half in the other order is a window with no route.
	if want := fmt.Sprintf("prepare %d while bound to %d", second, first); calls[2] != want {
		t.Errorf("the move prepared as %q, want %q", calls[2], want)
	}
	if want := fmt.Sprintf("settle %d while bound to %d", second, second); calls[3] != want {
		t.Errorf("the move settled as %q, want %q", calls[3], want)
	}
}

// A prepare that fails stops the move. Binding onto an interface whose routing
// could not be written is the outage the ordering exists to avoid, so the
// socket stays where it is and the failure is reported.
func TestUnderlayStaysPutWhenAnInterfaceCannotBePrepared(t *testing.T) {
	first, second := twoInterfaces(t)
	links := newFakeLinks(first)
	refusing := &refusingRoutes{}
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links, Routes: refusing})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)

	refusing.refuse.Store(true)
	links.move(second, nil)
	// Nothing acknowledges a move that is meant not to happen, so this waits
	// rather than polling: the failure it looks for is the socket moving.
	time.Sleep(200 * time.Millisecond)
	if got := boundInterface(t, bind.v4); got != first {
		t.Errorf("the socket moved to %d although its routing could not be written", got)
	}

	// And it follows the next notification once the routing can be written.
	refusing.refuse.Store(false)
	links.move(second, nil)
	waitFor(t, bind, second)
}

// refusingRoutes fails Prepare on demand.
type refusingRoutes struct{ refuse atomic.Bool }

func (r *refusingRoutes) Prepare(int) error {
	if r.refuse.Load() {
		return errors.New("the routing could not be written")
	}
	return nil
}

func (r *refusingRoutes) Settle(int) error { return nil }

// failingRoutes fails Settle on demand, which is the path that used to leave
// both sockets open on the port for the life of the process.
type failingRoutes struct{ settle atomic.Bool }

func (r *failingRoutes) Prepare(int) error { return nil }
func (r *failingRoutes) Settle(int) error {
	if r.settle.Load() {
		return errors.New("the record could not be settled")
	}
	return nil
}

// A hub that fails on the way up has to leave nothing behind. Settle runs
// after the sockets are open, so returning without closing them held the port
// until the process exited and the next attempt on it answered EADDRINUSE.
func TestFailedSettleLeavesNoSocketOnThePort(t *testing.T) {
	index, _ := twoInterfaces(t)
	// A fixed port, so the second attempt asks for the one the first would
	// have leaked rather than for whatever is free.
	probe, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	routes := &failingRoutes{}
	routes.settle.Store(true)
	address := fmt.Sprintf(":%d", port)
	if _, err := NewHub(address, Underlay{Bind: true},
		Runtime{Links: newFakeLinks(index), Routes: routes}); err == nil {
		t.Fatal("a hub whose settle failed was returned anyway")
	}
	// The port has to be free again, which it is only if both sockets closed.
	again, err := NewHub(address, Underlay{}, Runtime{})
	if err != nil {
		t.Fatalf("the port is still held after a failed settle: %v", err)
	}
	_ = again.Close()
}

// A move that fails partway puts both families back where they were. One on
// each interface reaches half this node's peers, and recording the index it
// did not reach makes UnderlayReady answer from a value nothing holds.
func TestPartialRebindLeavesBothFamiliesWhereTheyWere(t *testing.T) {
	first, _ := twoInterfaces(t)
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: newFakeLinks(first)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)
	if got := boundInterface(t, bind.v4); got != first {
		t.Fatalf("the hub opened on interface %d, want %d", got, first)
	}

	// The v6 half refuses while the v4 half has already moved, which is the
	// half-finished move. It is injected because the kernel will not produce
	// one: every index it refuses, it refuses for both families, measured.
	_, second := twoInterfaces(t)
	bind.v6.bindOption = func(int) error { return errors.New("the option was refused") }
	t.Cleanup(func() { bind.v6.bindOption = nil })
	if err := hub.BindUnderlay(second); err == nil {
		t.Fatal("a move whose second family refused reported success")
	}
	if got := boundInterface(t, bind.v4); got != first {
		t.Errorf("the udp4 socket was left on %d after a failed move, want %d", got, first)
	}
	if got := boundInterface(t, bind.v6); got != first {
		t.Errorf("the udp6 socket was left on %d after a failed move, want %d", got, first)
	}
	if hub.UnderlayReady() {
		t.Error("a hub that could not complete a move reports its underlay ready")
	}
}
