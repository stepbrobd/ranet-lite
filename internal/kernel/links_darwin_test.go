//go:build darwin && !ios

package kernel

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// The lookup has to name an interface this host really has, and not the
// loopback: the use of the answer is to take the underlay socket off the
// forwarding table and onto the link the machine reaches its peers through.
//
// It needs no privilege and writes nothing, so it runs in the ordinary suite
// rather than behind RANET_LITE_DARWIN_NETTEST. A host with no default route
// is the one honest reason to skip.
func TestDefaultInterfaceNamesALinkThisHostHas(t *testing.T) {
	links, err := WatchLinks(nil, 0)
	if err != nil {
		t.Fatalf("open the link watcher: %v", err)
	}
	t.Cleanup(func() { _ = links.Close() })

	index, err := links.DefaultInterface()
	if errors.Is(err, ErrNoDefaultRoute) {
		t.Skip("this host has no default route, so there is nothing to bind to")
	}
	if err != nil {
		t.Fatalf("look up the default interface: %v", err)
	}
	device, err := net.InterfaceByIndex(index)
	if err != nil {
		t.Fatalf("the lookup returned index %d, which names no interface: %v", index, err)
	}
	t.Logf("the host's own traffic leaves by %s (index %d, flags %s)", device.Name, index, device.Flags)
	if device.Flags&net.FlagUp == 0 {
		t.Errorf("%s is not up, so the underlay would be bound to a dead link", device.Name)
	}
	if device.Flags&net.FlagLoopback != 0 {
		t.Errorf("%s is the loopback, so nothing bound to it would reach a peer", device.Name)
	}
}

// A default route on this platform usually has a next hop address rather than
// a link as its gateway, so the one level of recursion is the ordinary path
// and not the exception. Asking for that next hop directly, with no recursion
// left, has to answer the same interface the default did.
func TestDefaultInterfaceResolvesANextHopToItsLink(t *testing.T) {
	answer, err := routeTo(netip.IPv4Unspecified())
	if errors.Is(err, ErrNoDefaultRoute) {
		t.Skip("this host has no IPv4 default route")
	}
	if err != nil {
		t.Fatalf("ask for the IPv4 default: %v", err)
	}
	if len(answer.Addrs) <= unix.RTAX_GATEWAY {
		t.Fatal("the answer carries no gateway at all")
	}
	gateway, ok := answer.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
	if !ok {
		t.Skip("this host's default leaves through a link rather than a next hop")
	}
	nextHop := netip.AddrFrom4(gateway.IP)

	recursed, err := gatewayIndex(answer, true)
	if err != nil {
		t.Fatalf("resolve the next hop %s: %v", nextHop, err)
	}
	if _, err := gatewayIndex(answer, false); !errors.Is(err, ErrNoDefaultRoute) {
		t.Errorf("a next hop resolved without recursing, reporting %v", err)
	}
	direct, err := interfaceIndexFor(nextHop, false)
	if err != nil {
		t.Fatalf("look up %s on its own: %v", nextHop, err)
	}
	if direct != recursed {
		t.Errorf("the next hop %s is on index %d and the recursion answered %d", nextHop, direct, recursed)
	}
}

// Every lookup carries its own sequence number, so two running at once cannot
// read each other's answers off a socket the whole machine shares.
func TestRouteLookupsCarryDistinctSequenceNumbers(t *testing.T) {
	first, err := routeTo(netip.IPv4Unspecified())
	if errors.Is(err, ErrNoDefaultRoute) {
		t.Skip("this host has no IPv4 default route")
	}
	if err != nil {
		t.Fatal(err)
	}
	second, err := routeTo(netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq == second.Seq {
		t.Errorf("two lookups both answered sequence %d", first.Seq)
	}
}
