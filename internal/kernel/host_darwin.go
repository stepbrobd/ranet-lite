//go:build darwin && !ios

package kernel

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// runningKernel is Host over PF_ROUTE and the address ioctls, the machine the
// daemon runs on. It carries no state: every descriptor it opens is either
// handed to the caller to close or closed before the call returns, so the
// lifetime questions stay with the objects that already own descriptors.
type runningKernel struct{}

// hostOr is the Host a caller named, or the running kernel where it named
// none. Every constructor in this package goes through it, so nil means the
// same thing everywhere rather than in each of them separately.
func hostOr(h Host) Host {
	if h == nil {
		return runningKernel{}
	}
	return h
}

func (runningKernel) RouteSocket() (RouteWriter, error) { return dialRouteSocket() }

func (runningKernel) Dump(kind, index int) ([]byte, error) {
	return route.FetchRIB(unix.AF_UNSPEC, route.RIBType(kind), index)
}

func (runningKernel) Lookup(destination, mask netip.Addr) (RouteAnswer, error) {
	answer, err := routeRequest(destination, mask)
	if err != nil {
		return RouteAnswer{}, err
	}
	out := RouteAnswer{Index: answer.Index}
	if len(answer.Addrs) > unix.RTAX_GATEWAY {
		if next, ok := addressFromRouteAddr(answer.Addrs[unix.RTAX_GATEWAY]); ok {
			out.Gateway = next.WithZone("")
		}
	}
	return out, nil
}

func (runningKernel) InterfaceIndex(name string) (int, error) {
	device, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("kernel: look up interface %s: %w", name, err)
	}
	return device.Index, nil
}

func (runningKernel) InterfaceName(index int) (string, error) {
	device, err := net.InterfaceByIndex(index)
	if err != nil {
		return "", fmt.Errorf("kernel: name interface %d: %w", index, err)
	}
	return device.Name, nil
}

func (runningKernel) Watch(index, skip int, quiet bool) (Watcher, error) {
	return newRouteMonitor(index, skip, quiet)
}

// Assign sends the one ioctl of the four that names this family and this
// direction, down a control socket of that family: the request structures are
// dispatched by the domain of the socket they arrive on, so each family needs
// its own. The socket is opened per call because an assignment happens when an
// address is missing and at no other time, which on a settled node is never.
func (runningKernel) Assign(add bool, device string, prefix netip.Prefix) error {
	family, name, number := unix.AF_INET, "SIOCAIFADDR", uintptr(unix.SIOCAIFADDR)
	build := func() ([]byte, error) { return aliasRequest4(device, prefix) }
	switch v6 := !prefix.Addr().Is4(); {
	case add && v6:
		family, name, number = unix.AF_INET6, "SIOCAIFADDR_IN6", siocAIfAddrIn6
		build = func() ([]byte, error) { return aliasRequest6(device, prefix) }
	case !add && v6:
		family, name, number = unix.AF_INET6, "SIOCDIFADDR_IN6", siocDIfAddrIn6
		build = func() ([]byte, error) { return deleteRequest6(device, prefix), nil }
	case !add:
		name, number = "SIOCDIFADDR", uintptr(unix.SIOCDIFADDR)
		build = func() ([]byte, error) { return deleteRequest4(device, prefix), nil }
	}
	request, err := build()
	if err != nil {
		return err
	}
	fd, err := controlSocket(family)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := ioctlRequest(fd, number, request); err != nil {
		return fmt.Errorf("%s on %s: %w", name, device, err)
	}
	return nil
}
