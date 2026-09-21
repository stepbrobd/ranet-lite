//go:build darwin

package transport

import (
	"errors"
	"fmt"
	"net"
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
	if !hub.UnderlayReady() {
		t.Error("the underlay bound and still reports that it is not where it should be")
	}
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
	// Index zero is the unbound socket, which nothing should be warned about.
	reportBoundReach(0, false)
	reportBoundReach(0, true)
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
