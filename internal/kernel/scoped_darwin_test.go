//go:build darwin && !ios

package kernel

import (
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestDarwinScopedRouteSelection establishes which sockets reach a route
// carrying RTF_IFSCOPE, which decides whether a Mac can hold an
// address an exit announces without taking the whole default route.
//
// This test owns the utun's file descriptor, so a packet arriving on it proves
// the kernel selected that route, without needing a peer or a second host.
func TestDarwinScopedRouteSelection(t *testing.T) {
	requireNetTest(t)

	device, tun := createUTUNWithFD(t)
	setInterfaceUp(t, device)
	tbl, rt := platformFor(device)
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		t.Fatalf("open the darwin platform on %s: %v", device, err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)

	local := netip.MustParsePrefix("198.51.100.1/24")
	if err := plat.AddAddr(local); err != nil {
		t.Fatalf("assign %s to %s: %v", local, device, err)
	}
	// TEST-NET-3, which cannot collide with anything real on this machine.
	remote := netip.MustParsePrefix("203.0.113.0/24")
	target := netip.MustParseAddr("203.0.113.9")

	t.Run("unscoped route", func(t *testing.T) {
		if err := plat.AddRoute(Route{Destination: remote}); err != nil {
			t.Fatalf("install %s: %v", remote, err)
		}
		t.Cleanup(func() { _ = plat.DelRoute(Route{Destination: remote}) })
		// An ordinary destination route is the kind every macOS VPN installs for
		// split tunneling, and it is reached without scoping anything.
		if !reaches(t, tun, target, netip.Addr{}, 0) {
			t.Error("an unscoped route did not carry a packet from an unbound socket")
		}
		if !reaches(t, tun, target, local.Addr(), 0) {
			t.Error("an unscoped route did not carry a packet from a socket bound to its address")
		}
	})

	t.Run("scoped route", func(t *testing.T) {
		if err := plat.addScopedRoute(remote); err != nil {
			t.Fatalf("install %s scoped to %s: %v", remote, device, err)
		}
		t.Cleanup(func() { _ = plat.delScopedRoute(remote) })

		unbound := reaches(t, tun, target, netip.Addr{}, 0)
		bound := reaches(t, tun, target, local.Addr(), 0)
		boundIf := reaches(t, tun, target, netip.Addr{}, plat.index)

		// Report before asserting: this test exists to answer the question,
		// and the three answers together are the answer.
		t.Logf("scoped route reached by: unbound socket %v, socket bound to %s %v, IP_BOUND_IF %v",
			unbound, local.Addr(), bound, boundIf)
		switch {
		case bound:
			t.Log("binding a source address scopes the lookup: a Mac can hold an " +
				"exit-announced address with a scoped route and keep its own default")
		case boundIf:
			t.Log("only IP_BOUND_IF scopes the lookup, so a scoped route is invisible " +
				"to an ordinary application and a Mac needs either a full tunnel or pf")
		default:
			t.Log("nothing reached the scoped route, so RTF_IFSCOPE is not usable here at all")
		}
		if unbound && !bound {
			t.Error("an unbound socket reached a scoped route while a bound one did not, " +
				"which contradicts what scoping is for")
		}
		if !bound {
			t.Error("a socket bound to an address on the interface did not reach the " +
				"scoped route, so AddRoute must go back to skipping source-specific routes")
		}
	})

	// What the reconciler actually does with an exit's announcement, end to
	// end: a source-specific route installs, is reachable only from an address
	// of ours, is stable across a dump so a pass does not churn it, and comes
	// back out again.
	t.Run("source-specific route through the reconciler", func(t *testing.T) {
		// Scoped is how the kernel keys it, and a dump fills it in; a route
		// built by hand has to say so, or the withdrawal below goes unscoped
		// and removes nothing.
		announced := Route{Destination: remote, Source: local.Masked(), Scoped: true}
		if err := plat.AddRoute(announced); err != nil {
			t.Fatalf("install %s: %v", announced, err)
		}
		t.Cleanup(func() { _ = plat.DelRoute(announced) })

		if reaches(t, tun, target, netip.Addr{}, 0) {
			t.Error("an unbound socket reached a source-specific route, which would " +
				"mean the Mac's own traffic was captured by the mesh")
		}
		if !reaches(t, tun, target, local.Addr(), 0) {
			t.Error("a socket bound to our address did not reach the source-specific route")
		}

		// The dump has to report it the way it was installed, or every
		// reconcile pass would delete and reinstall it.
		routes, err := plat.Routes()
		if err != nil {
			t.Fatalf("list routes: %v", err)
		}
		found := false
		for _, r := range routes {
			if r.Destination == announced.Destination && r.Source == announced.Source {
				found = true
			}
		}
		if !found {
			t.Fatalf("the dump does not report %s as installed: %v", announced, routes)
		}

		if err := plat.DelRoute(announced); err != nil {
			t.Fatalf("withdraw %s: %v", announced, err)
		}
		if reaches(t, tun, target, local.Addr(), 0) {
			t.Error("the source-specific route still carries traffic after withdrawal")
		}
	})

	// A source prefix that is not ours cannot be expressed by interface scope,
	// and must be refused rather than installed as an ordinary route that would
	// capture everything to that destination.
	t.Run("a source prefix that is not ours is refused", func(t *testing.T) {
		foreign := Route{Destination: remote, Source: netip.MustParsePrefix("192.0.2.0/24")}
		if err := plat.AddRoute(foreign); !errors.Is(err, errRouteSkipped) {
			t.Fatalf("AddRoute reported %v rather than reporting the route skipped", err)
		}
		if reaches(t, tun, target, netip.Addr{}, 0) || reaches(t, tun, target, local.Addr(), 0) {
			t.Error("a source prefix belonging to another node installed a route anyway")
		}
	})
}

// A prefix that covers a peer's own endpoint takes the ESP into the tun it is
// carrying, and a default is not the only one that can: nothing bounds what a
// mesh member announces, and the guarantee the readme and the fwmark refusal
// both state rested on the destination's own length alone.
func TestDarwinScopesARouteThatCoversTheUnderlay(t *testing.T) {
	peer := netip.MustParseAddr("2001:db8:beef::1")
	plat, _ := testPlatform(t, Table{}, Runtime{Underlay: func() []netip.Addr { return []netip.Addr{peer} }})
	capturing := Route{Destination: prefix("2000::/3")}
	elsewhere := Route{Destination: prefix("3fff:1::/32")}
	if plat.scopeRoute(capturing) {
		t.Fatal("the underlay was consulted before Routes took it, so a pass would decide scope two ways")
	}
	if _, err := plat.Routes(); err != nil {
		t.Fatal(err)
	}
	if !plat.scopeRoute(capturing) {
		t.Error("a /3 holding a peer's endpoint installs unscoped, so an unbound socket routes the ESP into the tun")
	}
	if plat.scopeRoute(elsewhere) {
		t.Error("a mesh prefix holding no endpoint was scoped, so the mesh is reachable only from a bound socket")
	}
}

// addScopedRoute and delScopedRoute install and withdraw a scoped route the
// reconciler would not: a plain destination, which scopeRoute leaves
// unscoped. The pair exists to isolate what RTF_IFSCOPE does to a lookup from
// what the reconciler chooses to do with it, so neither touches the
// bookkeeping. The kernel keys a scoped route separately, so the withdrawal
// has to carry the flag too, or the route stays and the next subtest's install
// collides with it.
func (p *routePlatform) addScopedRoute(destination netip.Prefix) error {
	return p.writeScopedRoute(unix.RTM_ADD, destination)
}

func (p *routePlatform) delScopedRoute(destination netip.Prefix) error {
	return p.writeScopedRoute(unix.RTM_DELETE, destination)
}

func (p *routePlatform) writeScopedRoute(kind int, destination netip.Prefix) error {
	message, err := p.routeMessage(kind, Route{Destination: destination})
	if err != nil {
		return err
	}
	message.Flags |= unix.RTF_IFSCOPE
	return p.sock.WriteRoute(message)
}

// reaches sends one UDP datagram to target and reports whether it arrived on
// the tun descriptor, which only happens if the kernel selected the route out
// of that interface. An invalid source leaves the socket unbound, and a
// nonzero index sets IP_BOUND_IF instead.
func reaches(t *testing.T, tun int, target, source netip.Addr, boundIf int) bool {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("open a udp socket: %v", err)
	}
	defer unix.Close(fd)
	if boundIf != 0 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, boundIf); err != nil {
			t.Fatalf("IP_BOUND_IF %d: %v", boundIf, err)
		}
	}
	if source.IsValid() {
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: source.As4()}); err != nil {
			t.Fatalf("bind to %s: %v", source, err)
		}
	}
	drainTUN(tun)
	if err := unix.Sendto(fd, []byte("scope probe"), 0, &unix.SockaddrInet4{Addr: target.As4(), Port: 9}); err != nil {
		// An unreachable destination is the answer rather than a failure: it
		// means no route was selected for this socket.
		t.Logf("sendto %s (source %v, boundif %d): %v", target, source, boundIf, err)
		return false
	}
	return readTUN(tun, 300*time.Millisecond)
}

// drainTUN empties anything already queued so a read cannot see an earlier
// probe's packet.
func drainTUN(fd int) {
	_ = unix.SetNonblock(fd, true)
	buf := make([]byte, 2048)
	for {
		if _, err := unix.Read(fd, buf); err != nil {
			return
		}
	}
}

// readTUN waits for one packet, which the kernel prefixes with a four byte
// address family on a utun.
func readTUN(fd int, within time.Duration) bool {
	_ = unix.SetNonblock(fd, true)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		n, err := unix.Read(fd, buf)
		if err == nil && n > 4 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func requireNetTest(t *testing.T) {
	t.Helper()
	if os.Getenv("RANET_LITE_DARWIN_NETTEST") != "1" {
		t.Skip("set RANET_LITE_DARWIN_NETTEST=1 to run against the real kernel")
	}
	if os.Geteuid() != 0 {
		t.Skip("run as root to create a utun and write routes")
	}
}

// createUTUNWithFD is createUTUN plus the control descriptor, which
// makes the packet observable: a datagram the kernel routes out of this
// interface is readable here and nowhere else.
func createUTUNWithFD(t *testing.T) (string, int) {
	t.Helper()
	const (
		utunControl     = "com.apple.net.utun_control"
		sysprotoControl = 2
		utunOptIfname   = 2
	)
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		t.Fatalf("open a system control socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControl)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		t.Fatalf("look up %s: %v", utunControl, err)
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		t.Fatalf("create a utun: %v", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		t.Fatalf("read the name of the new utun: %v", err)
	}
	t.Logf("created %s, which goes away with this test", name)
	return name, fd
}
