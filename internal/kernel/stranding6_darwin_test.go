//go:build darwin && !ios

package kernel

import (
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// The IPv6 arm of capturesTheMachine, measured rather than inferred from the
// IPv4 one.
//
// It needs an unscoped ::/0 to fall back to, and this host has none: every
// ::/0 here is a scoped route on somebody's utun. So the uplink is built
// rather than borrowed, on a second throwaway utun, and the whole arrangement
// lives and dies with the two control descriptors. That makes it a measurement
// of the kernel's lookup rather than of this machine's uplink, which is the
// part the predicate rests on.
//
// The expected rule, the same one IPv4 measures: a socket bound with
// IPV6_BOUND_IF loses destination D exactly when the tun's unscoped routes
// best-match both D and ::.
func TestDarwinStrandsABoundIPv6SocketThroughTheZeroAddress(t *testing.T) {
	requireNetTest(t)
	uplink, mesh := twoTestTUNs(t)
	uplinkIndex := interfaceIndex(t, uplink)

	uplinkPlat := testTUNPlatform(t, uplink)
	if err := uplinkPlat.AddAddr(prefix("2001:db8:aa::1/64")); err != nil {
		t.Fatal(err)
	}
	meshPlat := testTUNPlatform(t, mesh)
	if err := meshPlat.AddAddr(prefix("2001:db8:bb::1/64")); err != nil {
		t.Fatal(err)
	}

	// The uplink's own default, unscoped, which the kernel's fallback looks
	// for. `route add -interface` writes it without a next hop, the one shape
	// that installs on a point-to-point device.
	out, err := exec.Command("route", "-n", "add", "-inet6", "-net", "::/0", "-interface", uplink).CombinedOutput()
	if err != nil {
		t.Skipf("this host will not take an unscoped ::/0, so the IPv6 arm cannot be measured here: %v %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("route", "-n", "delete", "-inet6", "-net", "::/0", "-interface", uplink).CombinedOutput(); err != nil {
			t.Errorf("the ::/0 this test added was left behind: %v %s", err, out)
		}
	})
	if !unscopedDefaultOn(t, uplinkIndex) {
		t.Skip("the ::/0 this test added was scoped by the kernel, so there is no fallback to measure")
	}

	// In ::/1, so the lower half covers it and the upper half does not.
	target := netip.MustParseAddr("2001:db8:ffff::1")
	if err := boundReach6(uplinkIndex, target); err != nil {
		t.Skipf("a socket bound to the built uplink cannot reach %s to begin with: %v", target, err)
	}

	for _, test := range []struct {
		set     []string
		strands bool
	}{
		// Covers the target and the zero address.
		{[]string{"::/1", "8000::/1"}, true},
		{[]string{"::/1"}, true},
		{[]string{"::/64", "2001:db8::/32"}, true},
		{[]string{"::/16", "2001:db8::/32"}, true},
		// Covers the target and no zero address.
		{[]string{"2001:db8::/32"}, false},
		// Covers neither.
		{[]string{"8000::/1"}, false},
	} {
		t.Run(strings.Join(test.set, " "), func(t *testing.T) {
			for _, one := range test.set {
				route := Route{Destination: prefix(one), Metric: defaultIPv6Metric}
				if err := meshPlat.AddRoute(route); err != nil {
					t.Skipf("%s is held by another program on this host: %v", one, err)
				}
				t.Cleanup(func() { _ = meshPlat.DelRoute(route) })
			}
			reachErr := boundReach6(uplinkIndex, target)
			if test.strands && reachErr == nil {
				t.Errorf("a bound socket still reaches %s, so IPv6 no longer needs the fallback", target)
			}
			if !test.strands && reachErr != nil {
				t.Errorf("a bound socket lost %s to a set covering no zero address: %v", target, reachErr)
			}
			held := false
			for _, one := range test.set {
				if capturesTheMachine(Route{Destination: prefix(one)}) {
					held = true
				}
			}
			if test.strands && !held {
				t.Error("the set strands a bound IPv6 socket and the gate holds none of it back")
			}
		})
	}
}

// twoTestTUNs makes an uplink and a mesh device, both of which go away with
// their control descriptors.
func twoTestTUNs(t *testing.T) (uplink, mesh string) {
	t.Helper()
	uplink, _ = createUTUNWithFD(t)
	setInterfaceUp(t, uplink)
	mesh, _ = createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	return uplink, mesh
}

func interfaceIndex(t *testing.T, name string) int {
	t.Helper()
	device, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return device.Index
}

// testTUNPlatform opens the backend on one device, with the binding on so that
// nothing it writes is scoped.
func testTUNPlatform(t *testing.T, name string) *routePlatform {
	t.Helper()
	opened, err := newPlatform(
		Table{ID: DefaultTable, Proto: DefaultProtocol},
		Runtime{Interface: name, BoundUnderlay: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return opened.(*routePlatform)
}

// unscopedDefaultOn reports whether the kernel holds an unscoped ::/0 on that
// interface, the route the scoped lookup falls back to.
func unscopedDefaultOn(t *testing.T, index int) bool {
	t.Helper()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatal(err)
	}
	found, ok := unscopedDefaultIndex(messages, netip.PrefixFrom(netip.IPv6Unspecified(), 0))
	return ok && found == index
}

// boundReach6 resolves the route a socket bound to index would take for an
// IPv6 destination, sending nothing.
func boundReach6(index int, target netip.Addr) error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index); err != nil {
		return err
	}
	return unix.Connect(fd, &unix.SockaddrInet6{Addr: target.As16(), Port: 9})
}
