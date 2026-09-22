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

func (runningKernel) Dump() ([]byte, error) {
	return route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
}

func (runningKernel) Addresses(index int) ([]netip.Prefix, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, index)
	if err != nil {
		return nil, fmt.Errorf("kernel: dump the addresses of interface %d: %w", index, err)
	}
	return interfaceAddrs(index, rib)
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
// its own. The ioctl is named in the error, because an errno alone does not
// say which of the four answered.
//
// The request is built inside the branch that knows the family, never before
// it: deleteRequest4 reads the address as four bytes and panics on a v6
// prefix. The socket is opened per call because an assignment happens when an
// address is missing and at no other time, which on a settled node is never.
func (runningKernel) Assign(add bool, device string, prefix netip.Prefix) error {
	var (
		family  = unix.AF_INET
		name    string
		number  uintptr
		request []byte
		err     error
	)
	if !prefix.Addr().Is4() {
		family = unix.AF_INET6
	}
	switch v6 := family == unix.AF_INET6; {
	case add && v6:
		name, number = "SIOCAIFADDR_IN6", siocAIfAddrIn6
		request, err = aliasRequest6(device, prefix)
	case add:
		name, number = "SIOCAIFADDR", uintptr(unix.SIOCAIFADDR)
		request, err = aliasRequest4(device, prefix)
	case v6:
		name, number = "SIOCDIFADDR_IN6", siocDIfAddrIn6
		request = deleteRequest6(device, prefix)
	default:
		name, number = "SIOCDIFADDR", uintptr(unix.SIOCDIFADDR)
		request = deleteRequest4(device, prefix)
	}
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
