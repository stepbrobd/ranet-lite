//go:build darwin && !ios

package kernel

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

// Which sets of unscoped routes out of a tun cost a bound socket its route,
// measured rather than assumed, because capturesTheMachine's second arm is
// this table and nothing else.
//
// The rule the kernel applies: a socket bound with IP_BOUND_IF loses
// destination D exactly when the tun's unscoped routes best-match both D and
// the all-zeros address of D's family. The scoped lookup falls back to a
// longest-prefix match on the unspecified address and requires that answer to
// be on the bound interface, so the size of the covering prefix is beside the
// point: 0.0.0.0/24 takes the fallback away and 64.0.0.0/2 does not.
//
// It matters because a prefix length is the wrong predicate. Three ordinary
// announcements, none of them half the address space, took this machine off
// the network before the second arm existed.
func TestDarwinStrandsABoundSocketOnlyThroughTheZeroAddress(t *testing.T) {
	requireNetTest(t)
	mesh, _ := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	device, err := net.InterfaceByName(mesh)
	if err != nil {
		t.Fatal(err)
	}
	links, err := WatchLinks(device.Index)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = links.Close() })
	host, _, err := links.Default(netip.IPv4Unspecified())
	if err != nil {
		t.Skip(err)
	}
	// TEST-NET-1, which nothing on this machine routes specially.
	target := netip.MustParseAddr("192.0.2.1")
	if err := boundReach(host, target); err != nil {
		t.Skipf("a bound socket cannot reach %s before anything is installed: %v", target, err)
	}

	opened, err := newPlatform(
		Table{ID: DefaultTable, Proto: DefaultProtocol},
		Runtime{Interface: mesh, BoundUnderlay: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)
	if plat.index == host {
		t.Skip("the test utun is the interface the host's own traffic leaves by")
	}
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		set     []string
		strands bool
	}{
		// Covers the target and the zero address: stranded.
		{[]string{"0.0.0.0/1", "128.0.0.0/1"}, true},
		{[]string{"0.0.0.0/1", "192.0.2.0/24"}, true},
		{[]string{"0.0.0.0/2", "64.0.0.0/2", "192.0.2.0/24"}, true},
		// The one a prefix length misses entirely: a /24 over the zero
		// address costs as much as half the space.
		{[]string{"0.0.0.0/24", "192.0.2.0/24"}, true},
		{[]string{"0.0.0.0/8", "192.0.2.0/24"}, true},
		// Covers the target and no zero address: the fallback survives.
		{[]string{"192.0.2.0/24"}, false},
		{[]string{"64.0.0.0/2", "192.0.2.0/24"}, false},
		{[]string{"128.0.0.0/1"}, false},
		// Covers the zero address and not the target, so the target's best
		// match is still the host's own route and no fallback is needed.
		{[]string{"0.0.0.0/1"}, false},
		{[]string{"0.0.0.0/2", "64.0.0.0/2"}, false},
	} {
		t.Run(strings.Join(test.set, " "), func(t *testing.T) {
			for _, one := range test.set {
				route := Route{Destination: prefix(one)}
				if err := plat.AddRoute(route); err != nil {
					t.Skipf("%s is held by another program on this host: %v", one, err)
				}
				t.Cleanup(func() { _ = plat.DelRoute(route) })
			}
			reachErr := boundReach(host, target)
			if test.strands && reachErr == nil {
				t.Errorf("a bound socket still reaches %s, so this set no longer needs the fallback", target)
			}
			if !test.strands && reachErr != nil {
				t.Errorf("a bound socket lost %s to a set covering no zero address: %v", target, reachErr)
			}
			// The predicate has to agree with the kernel: every set that
			// strands has a member the gate holds back, and holding those
			// back restores the fallback.
			held := false
			for _, one := range test.set {
				if capturesTheMachine(Route{Destination: prefix(one)}) {
					held = true
				}
			}
			if test.strands && !held {
				t.Error("the set strands a bound socket and the gate holds none of it back")
			}
		})
	}
}

// And the other half of the same measurement: with the route this tool writes
// in place, every one of those sets reaches again, which is why writing it
// whenever the socket is bound fixes the whole class rather than one shape of
// it.
func TestDarwinScopedDefaultUnstrandsEverySetThatStranded(t *testing.T) {
	requireNetTest(t)
	mesh, _ := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	device, err := net.InterfaceByName(mesh)
	if err != nil {
		t.Fatal(err)
	}
	links, err := WatchLinks(device.Index)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = links.Close() })
	host, gateway, err := links.Default(netip.IPv4Unspecified())
	if err != nil || !gateway.IsValid() {
		t.Skipf("this host has no IPv4 default with a next hop: %v", err)
	}
	target := netip.MustParseAddr("192.0.2.1")
	if err := boundReach(host, target); err != nil {
		t.Skipf("a bound socket cannot reach %s before anything is installed: %v", target, err)
	}

	opened, err := newPlatform(
		Table{ID: DefaultTable, Proto: DefaultProtocol},
		Runtime{Interface: mesh, BoundUnderlay: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)
	if plat.index == host {
		t.Skip("the test utun is the interface the host's own traffic leaves by")
	}
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}

	before := defaultRoutesOnHost(t)
	underlay, err := NewUnderlayDefaults(links, device.Index, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = underlay.Close() })
	if err := underlay.Prepare(host); err != nil {
		t.Fatal(err)
	}
	if covered, err := underlay.Ready(); err != nil || !covered.V4 {
		t.Fatalf("the underlay reports itself uncovered: %+v %v", covered, err)
	}

	for _, set := range [][]string{
		{"0.0.0.0/1", "128.0.0.0/1"},
		{"0.0.0.0/1", "192.0.2.0/24"},
		{"0.0.0.0/24", "192.0.2.0/24"},
		{"0.0.0.0/2", "64.0.0.0/2", "192.0.2.0/24"},
	} {
		t.Run(strings.Join(set, " "), func(t *testing.T) {
			for _, one := range set {
				route := Route{Destination: prefix(one)}
				if err := plat.AddRoute(route); err != nil {
					t.Skipf("%s is held by another program on this host: %v", one, err)
				}
				t.Cleanup(func() { _ = plat.DelRoute(route) })
			}
			if err := boundReach(host, target); err != nil {
				t.Errorf("a bound socket lost %s although the underlay carries a default of its own: %v", target, err)
			}
		})
	}
	// The host's own defaults are exactly as they were.
	if after := defaultRoutesOnHost(t); !sameDefaults(before, after) {
		t.Errorf("the host's default routes changed over the test\nbefore: %v\nafter:  %v", before, after)
	}
}
