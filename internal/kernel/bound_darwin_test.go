//go:build darwin && !ios

package kernel

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// What a socket bound with IP_BOUND_IF actually does when the mesh holds a
// route covering the whole address space, which is the arrangement
// Config.BoundUnderlay exists for. It is measured rather than assumed, because
// the claim it rests on, that a bound socket leaves the forwarding table
// behind, turns out to be false on this kernel and the cost of being wrong is
// a Mac with no network at all.
//
// The three states below are the whole answer:
//
//   - clean: every socket reaches off the link.
//   - a default out of the tun, unscoped: an unbound socket follows it, which
//     is the feature; a bound socket reports ENETUNREACH, which is the
//     underlay gone. The scoped lookup still finds the most specific route,
//     and where that route leaves another interface it falls back only to a
//     route already on the bound one.
//   - the same, plus a default scoped to the underlay's own interface: both
//     work. macOS writes exactly that route for every interface but the
//     primary one, which is why binding looks sufficient until the mesh takes
//     the default away from the primary.
//
// It installs the pair of halves rather than a real default, which is the
// spelling wg-quick and the tunnels on this platform use and which wins the
// lookup outright instead of colliding with the host's own default. While they
// are installed this machine's traffic goes into a tun nothing reads. Closing
// the control descriptor destroys the device with every route on it, and that
// happens on every exit from this test.
func TestDarwinBoundSocketNeedsAScopedDefault(t *testing.T) {
	requireNetTest(t)
	links, err := WatchLinks()
	if err != nil {
		t.Fatalf("open the link watcher: %v", err)
	}
	t.Cleanup(func() { _ = links.Close() })
	host, err := links.DefaultInterface()
	if err != nil {
		t.Skipf("this host has no default route to bind to: %v", err)
	}
	device, err := net.InterfaceByIndex(host)
	if err != nil {
		t.Fatal(err)
	}
	// Read before anything is installed: once the halves are in, the lookup
	// for the unspecified address answers with the tun.
	gateway := hostNextHop(t)
	t.Logf("the host's own traffic leaves by %s (index %d, next hop %q)", device.Name, host, gateway)

	target := netip.MustParseAddr("192.0.2.1")
	if err := boundReach(0, target); err != nil {
		t.Skipf("this host cannot reach %s at all: %v", target, err)
	}
	if err := boundReach(host, target); err != nil {
		t.Skipf("a socket bound to %s cannot reach %s before anything is installed: %v", device.Name, target, err)
	}

	name, tun := createUTUNWithFD(t)
	setInterfaceUp(t, name)
	opened, err := newPlatform(Config{
		Interface: name, Table: DefaultTable, Protocol: DefaultProtocol,
		BoundUnderlay: true,
	})
	if err != nil {
		t.Fatalf("open the darwin platform on %s: %v", name, err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)
	if plat.index == host {
		t.Skip("the test utun is the interface the host's own traffic leaves by")
	}
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatalf("assign an address to %s: %v", name, err)
	}
	for _, half := range []Route{{Destination: prefix("0.0.0.0/1")}, {Destination: prefix("128.0.0.0/1")}} {
		if err := plat.AddRoute(half); err != nil {
			t.Skipf("%s is held by another program on this host: %v", half.Destination, err)
		}
		t.Cleanup(func() { _ = plat.DelRoute(half) })
	}

	// The feature: an ordinary socket now goes through the mesh. TEST-NET-3,
	// which cannot collide with anything real on this machine.
	if !reaches(t, tun, netip.MustParseAddr("203.0.113.9"), netip.Addr{}, 0) {
		t.Fatal("the plain default did not carry an ordinary socket's packet, so this measures nothing")
	}
	// The catch, asserted rather than hoped for, so that a kernel which starts
	// behaving the way the design assumed reports it here first.
	if err := boundReach(host, target); err == nil {
		t.Logf("a bound socket reached %s with no scoped default, so this kernel no longer needs one", target)
	} else {
		t.Logf("a bound socket cannot reach %s while the mesh holds the address space: %v", target, err)
	}

	if gateway == "" {
		t.Skip("the host's default has no next hop, so there is nothing to scope")
	}
	add := exec.Command("route", "-n", "add", "-net", "0.0.0.0/0", gateway, "-ifscope", device.Name)
	if out, err := add.CombinedOutput(); err != nil {
		t.Skipf("could not give %s a scoped default: %v %s", device.Name, err, out)
	}
	t.Cleanup(func() {
		out, err := exec.Command("route", "-n", "delete", "-net", "0.0.0.0/0", gateway, "-ifscope", device.Name).CombinedOutput()
		if err != nil {
			t.Errorf("the scoped default added by this test was left behind: %v %s", err, out)
		}
	})
	if err := boundReach(host, target); err != nil {
		t.Errorf("a bound socket still cannot reach %s with a default scoped to %s: %v", target, device.Name, err)
	}
	if !reaches(t, tun, netip.MustParseAddr("203.0.113.9"), netip.Addr{}, 0) {
		t.Error("the scoped default took the mesh's own capture away from an unbound socket")
	}
}

// boundReach resolves the route a socket bound to index would take, without
// sending anything: connect on a UDP socket consults the forwarding table and
// puts nothing on the wire. Index zero leaves the socket unbound.
func boundReach(index int, target netip.Addr) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if index != 0 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, index); err != nil {
			return err
		}
	}
	return unix.Connect(fd, &unix.SockaddrInet4{Addr: target.As4(), Port: 9})
}

// hostNextHop is the address the host's own IPv4 default points at, or empty
// where it leaves through a link instead.
func hostNextHop(t *testing.T) string {
	t.Helper()
	answer, err := routeTo(netip.IPv4Unspecified())
	if err != nil || len(answer.Addrs) <= unix.RTAX_GATEWAY {
		return ""
	}
	gateway, ok := answer.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", gateway.IP[0], gateway.IP[1], gateway.IP[2], gateway.IP[3])
}
