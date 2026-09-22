//go:build darwin && !ios

package kernel

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// What a socket bound with IP_BOUND_IF actually does when the mesh holds a
// route covering the whole address space, which is the arrangement
// Runtime.BoundUnderlay exists for, and what UnderlayDefaults writes to make it
// work. It is measured rather than assumed, because the claim it rests on,
// that a bound socket leaves the forwarding table behind, turns out to be
// false on this kernel and the cost of being wrong is a Mac with no network.
//
// The three states below are the whole answer:
//
//   - clean: every socket reaches off the link.
//   - a default out of the tun, unscoped: an unbound socket follows it, which
//     is the feature; a bound socket reports ENETUNREACH, which is the
//     underlay gone. The scoped lookup still finds the most specific route,
//     and where that route leaves another interface it falls back only to a
//     route already on the bound one.
//   - the same, plus the default UnderlayDefaults writes on the underlay's own
//     interface: both work. macOS writes exactly that route for every
//     interface but the primary one, which is why binding looks sufficient
//     until the mesh takes the default away from the primary.
//
// It installs the pair of halves rather than a real default, which is the
// spelling wg-quick and the tunnels on this platform use and which wins the
// lookup outright instead of colliding with the host's own default. While they
// are installed this machine's traffic goes into a tun nothing reads. Closing
// the control descriptor destroys the device with every route on it, and that
// happens on every exit from this test.
func TestDarwinBoundSocketNeedsAScopedDefault(t *testing.T) {
	requireNetTest(t)
	mesh, tun := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	meshDevice, err := net.InterfaceByName(mesh)
	if err != nil {
		t.Fatal(err)
	}
	links, err := WatchLinks(nil, meshDevice.Index)
	if err != nil {
		t.Fatalf("open the link watcher: %v", err)
	}
	t.Cleanup(func() { _ = links.Close() })
	host, gateway, err := links.Default(netip.IPv4Unspecified())
	if err != nil {
		t.Skipf("this host has no IPv4 default route to fall back on: %v", err)
	}
	if !gateway.IsValid() {
		t.Skip("this host's default leaves through a link, so there is no next hop to scope")
	}
	device, err := net.InterfaceByIndex(host)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the host's own traffic leaves by %s (index %d) via %s", device.Name, host, gateway)

	target := netip.MustParseAddr("192.0.2.1")
	if err := boundReach(0, target); err != nil {
		t.Skipf("this host cannot reach %s at all: %v", target, err)
	}
	if err := boundReach(host, target); err != nil {
		t.Skipf("a socket bound to %s cannot reach %s before anything is installed: %v", device.Name, target, err)
	}
	before := defaultRoutesOnHost(t)

	opened, err := newPlatform(
		Table{ID: DefaultTable, Proto: DefaultProtocol},
		Runtime{Interface: mesh, BoundUnderlay: true})
	if err != nil {
		t.Fatalf("open the darwin platform on %s: %v", mesh, err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)
	if plat.index == host {
		t.Skip("the test utun is the interface the host's own traffic leaves by")
	}
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatalf("assign an address to %s: %v", mesh, err)
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
	// The catch this whole file is arranged around, asserted rather than
	// hoped for, so that a kernel which stops needing the remedy says so here.
	if err := boundReach(host, target); err == nil {
		t.Errorf("a bound socket reached %s with no scoped default, so this kernel no longer needs one", target)
	} else {
		t.Logf("without a scoped default a bound socket reports: %v", err)
	}

	state := filepath.Join(t.TempDir(), "underlay.json")
	underlay, err := NewUnderlayDefaults(nil, links, meshDevice.Index, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = underlay.Close() })
	if err := underlay.Prepare(host); err != nil {
		t.Fatal(err)
	}
	if covered, err := underlay.Ready(); err != nil || !covered.V4 {
		t.Fatalf("cover the underlay: covered %+v, err %v", covered, err)
	}
	if err := underlay.Settle(host); err != nil {
		t.Fatal(err)
	}
	if got := underlay.Written(); len(got) == 0 {
		// The interface already carried one, which macOS writes for every
		// secondary interface and a crashed run leaves behind. It satisfies
		// the key and it is not ours, so there is nothing here to reclaim and
		// this test cannot measure ownership.
		t.Skip("this interface already carries a scoped default this process does not own")
	} else if len(got) != 1 || got[0].index != host {
		t.Fatalf("covering the underlay wrote %+v, want one route on interface %d", got, host)
	}
	if got := underlay.Written(); got[0].device != device.Name {
		t.Errorf("the record names interface %q, want %q", got[0].device, device.Name)
	}

	// The remedy, measured: the bound socket reaches again, and the mesh is
	// still carrying everything unbound.
	if err := boundReach(host, target); err != nil {
		t.Errorf("a bound socket still cannot reach %s with a default scoped to %s: %v", target, device.Name, err)
	}
	if !reaches(t, tun, netip.MustParseAddr("203.0.113.9"), netip.Addr{}, 0) {
		t.Error("the scoped default took the mesh's own capture away from an unbound socket")
	}

	// A process that came back with no record of its own withdraws nothing,
	// whatever it finds in the table.
	empty := filepath.Join(t.TempDir(), "underlay.json")
	restarted, err := NewUnderlayDefaults(nil, links, meshDevice.Index, empty)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	if err := boundReach(host, target); err != nil {
		t.Errorf("a restarted process withdrew a route it never wrote: %v", err)
	}

	// The kill: a process that wrote the route, recorded it, and never lived
	// to withdraw it. Closing the socket without releasing leaves the table in
	// the state a SIGKILL leaves it, minus the tun, which this test needs.
	if err := underlay.sock.Close(); err != nil {
		t.Fatal(err)
	}
	underlay.sock = nil
	// And the claim on the record, which a killed process releases with every
	// other descriptor it held. Without this the restart below finds the lock
	// still taken and reclaims nothing, which is the right answer to a second
	// live daemon and the wrong model of a dead one.
	if err := underlay.state.Close(); err != nil {
		t.Fatal(err)
	}
	underlay.state = nil
	if err := boundReach(host, target); err != nil {
		t.Fatalf("the killed process's route is not in the table: %v", err)
	}
	if recorded, err := loadUnderlayState(state); err != nil || len(recorded) != 1 {
		t.Fatalf("the killed process recorded %v (%v), want one route", recorded, err)
	}

	// The restart reclaims it, because it wrote the record down.
	reclaimed, err := NewUnderlayDefaults(nil, links, meshDevice.Index, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reclaimed.Close() })
	if got := reclaimed.Written(); len(got) != 0 {
		t.Errorf("the reclaim kept %+v rather than withdrawing it", got)
	}
	if err := boundReach(host, target); err == nil {
		t.Error("the route the killed process left is still in the table after a restart")
	}
	if recorded, err := loadUnderlayState(state); err != nil || len(recorded) != 0 {
		t.Errorf("the reclaim left %v recorded (%v)", recorded, err)
	}
	// The rule that matters: the host's own defaults are exactly as they were.
	if after := defaultRoutesOnHost(t); !sameDefaults(before, after) {
		t.Errorf("the host's default routes changed over the test\nbefore: %v\nafter:  %v", before, after)
	}
}

// defaultRoutesOnHost is every unscoped default in the table, described so two
// snapshots can be compared. The scoped ones are left out because this test
// writes and removes one of those on purpose.
func defaultRoutesOnHost(t *testing.T) []string {
	t.Helper()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Type != unix.RTM_GET || rm.Flags&unix.RTF_IFSCOPE != 0 {
			continue
		}
		for _, destination := range defaultPrefixes {
			if !isDefaultKey(rm, destination) {
				continue
			}
			gateway := netip.Addr{}
			if len(rm.Addrs) > unix.RTAX_GATEWAY {
				gateway, _ = addressFromRouteAddr(rm.Addrs[unix.RTAX_GATEWAY])
			}
			out = append(out, fmt.Sprintf("%s index %d via %s", destination, rm.Index, gateway))
		}
	}
	return out
}

func sameDefaults(before, after []string) bool {
	if len(before) != len(after) {
		return false
	}
	held := make(map[string]int, len(before))
	for _, line := range before {
		held[line]++
	}
	for _, line := range after {
		held[line]--
	}
	for _, count := range held {
		if count != 0 {
			return false
		}
	}
	return true
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

// The lookup that decides where the underlay socket binds must never answer
// with the mesh's own tun. Once the mesh holds a route covering the address
// space, an ordinary longest-prefix lookup does exactly that, and binding to
// it would put every datagram this node sends inside its own tunnel.
func TestDefaultInterfaceIgnoresTheMeshItself(t *testing.T) {
	requireNetTest(t)
	mesh, _ := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	device, err := net.InterfaceByName(mesh)
	if err != nil {
		t.Fatal(err)
	}
	links, err := WatchLinks(nil, device.Index)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = links.Close() })

	opened, err := newPlatform(
		Table{ID: DefaultTable, Proto: DefaultProtocol},
		Runtime{Interface: mesh, BoundUnderlay: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}
	if err := plat.AddAddr(prefix("2001:db8:99::1/64")); err != nil {
		t.Fatal(err)
	}
	for _, half := range []Route{
		{Destination: prefix("0.0.0.0/1")}, {Destination: prefix("128.0.0.0/1")},
		{Destination: prefix("::/1")}, {Destination: prefix("8000::/1")},
	} {
		if err := plat.AddRoute(half); err != nil {
			t.Logf("could not install %s: %v", half.Destination, err)
			continue
		}
		t.Cleanup(func() { _ = plat.DelRoute(half) })
	}

	// The ordinary question answers with the tun, which is the trap.
	if answer, err := routeTo(netip.IPv4Unspecified()); err == nil && answer.Index != plat.index {
		t.Logf("a longest-prefix lookup answered index %d rather than the tun, so the trap is not armed here", answer.Index)
	}
	index, err := links.DefaultInterface()
	if err != nil {
		t.Logf("with the mesh holding the address space the lookup reports: %v", err)
		return
	}
	if index == plat.index {
		t.Fatalf("the underlay would be bound to the mesh tun itself (index %d)", index)
	}
	t.Logf("the lookup answered index %d with the mesh holding the address space", index)
}
