//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Links answers which interface the host's own traffic leaves by, and says
// when that changes. It is the read side of the same PF_ROUTE socket the
// reconciler writes, and it exists for internal/transport: on darwin the
// underlay socket is kept out of the mesh's routing by being bound to that
// interface, and nothing but the routing table knows which one it is.
//
// It answers one index for both families. A host whose IPv4 and IPv6 defaults
// leave by different interfaces would have one of its two sockets on the wrong
// one; that is a configuration nothing here produces and no laptop has, and
// splitting the answer is the fix if one ever appears.
type Links struct {
	watcher Watcher
	host    Host
	// mesh is the tun this node carries the overlay on, which can never be
	// the answer. Once the mesh holds routes covering the address space, an
	// ordinary lookup for the unspecified address answers with the tun, and
	// binding the underlay socket to that would put every datagram this node
	// sends inside the tunnel it is supposed to be running under.
	mesh int
}

// WatchLinks opens the notification half. mesh is the index of this node's own
// tun, which no answer may name, and host is the machine this reads, nil for
// the one this process is running on. The caller closes it.
func WatchLinks(host Host, mesh int) (*Links, error) {
	host = hostOr(host)
	// Index zero, so a change on any interface wakes it: the route being
	// followed moves between wifi, ethernet, a dock and a VPN of the user's
	// own, so no one interface can be named. The mesh tun is skipped and this
	// process's own writes are dropped, which together are the whole of the
	// churn a peer can drive: applyRoutes writes one RTM_ADD per route and the
	// kernel broadcasts every one, so an unfiltered watcher wakes once per
	// route installed, each wake costing a route lookup and a socket.
	watcher, err := host.Watch(0, mesh, true)
	if err != nil {
		return nil, err
	}
	return &Links{watcher: watcher, host: host, mesh: mesh}, nil
}

// WatchLinksOn is WatchLinks for an interface named rather than numbered.
func WatchLinksOn(host Host, mesh string) (*Links, error) {
	host = hostOr(host)
	index, err := host.InterfaceIndex(mesh)
	if err != nil {
		return nil, err
	}
	return WatchLinks(host, index)
}

func (l *Links) Changed() <-chan struct{} { return l.watcher.Changed() }
func (l *Links) Close() error             { return l.watcher.Close() }

// Mesh is the interface index no answer may name.
func (l *Links) Mesh() int { return l.mesh }

// Default is the host's own default route of one family: the interface it
// leaves by and the next hop it points at, invalid where it leaves through a
// link instead.
//
// It is an exact lookup of the one entry keyed on the unspecified address
// rather than a longest-prefix match, because the mesh installs routes that
// cover the whole address space and a match answers with those. Measured on
// Darwin 27.2.0: with 0.0.0.0/1 and 128.0.0.0/1 out of the tun, the match
// answers utun and the exact lookup answers the physical interface. Where
// there is no entry at all the exact lookup falls back to a match, which is
// why the mesh interface is rejected here too and not only there.
func (l *Links) Default(family netip.Addr) (index int, gateway netip.Addr, err error) {
	answer, err := l.host.Lookup(family.Unmap(), zeroMaskOf(family))
	if err != nil {
		return 0, netip.Addr{}, err
	}
	if answer.Index == l.mesh {
		// The only entry covering the unspecified address of this family is
		// one of ours, so the host has no default of its own to fall back to.
		return 0, netip.Addr{}, ErrNoDefaultRoute
	}
	return answer.Index, answer.Gateway, nil
}

// zeroMaskOf is the all-zeros netmask of one family, which turns a lookup from
// a longest-prefix match into a request for that exact key.
func zeroMaskOf(family netip.Addr) netip.Addr {
	if family.Is6() {
		return netip.AddrFrom16([16]byte{})
	}
	return netip.AddrFrom4([4]byte{})
}

// DefaultInterface is the index of the interface the host's own default route
// leaves by. IPv4 is asked first and IPv6 only if that has no answer, so a
// dual-stacked host binds to the interface its IPv4 uses and a v6-only one
// still binds to something.
func (l *Links) DefaultInterface() (int, error) {
	var errs []error
	for _, family := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		index, _, err := l.Default(family)
		if err == nil {
			return index, nil
		}
		errs = append(errs, err)
	}
	return 0, errors.Join(append(errs, ErrNoDefaultRoute)...)
}

// lookupSeq numbers the RTM_GET requests this process makes, so a reply can be
// matched to the request that asked for it. A routing socket carries every
// other program's traffic too, and a reply read off the wrong message would
// name whichever interface somebody else was asking about.
var lookupSeq atomic.Int32

// lookupTimeout bounds one request. Without it a reply that never comes holds
// the goroutine asking for it forever, and one of the callers is the startup
// path that opens the transport socket.
const lookupTimeout = 2 * time.Second

// interfaceIndexFor asks the kernel which interface it would send to
// destination through, by making the same RTM_GET request `route -n get` makes
// and reading the link index off the gateway of the answer.
//
// A gateway that is an address rather than a link is a next hop, which names
// no interface of its own, so the address is looked up in turn. That recursion
// runs exactly once: a correct table resolves a next hop to a connected route
// on the second lookup, and a table that does not is a loop rather than a
// deeper answer.
//
// The technique is tailscale's, read from net/netns/netns_darwin.go, which is
// BSD-3-Clause. Nothing here is copied from it.
func interfaceIndexFor(destination netip.Addr, canRecurse bool) (int, error) {
	answer, err := routeTo(destination)
	if err != nil {
		return 0, err
	}
	return gatewayIndex(answer, canRecurse)
}

// routeTo is a longest-prefix lookup, the question `route -n get` asks.
func routeTo(destination netip.Addr) (*route.RouteMessage, error) {
	return routeRequest(destination, netip.Addr{})
}

// routeRequest is the request itself, separated from what is read off the
// answer so that a test can look at the gateway the kernel named rather than
// guess which address it was. An invalid mask sends no RTAX_NETMASK, which is
// the longest-prefix question; a valid one asks for that exact key, because
// XNU turns an RTM_GET carrying a netmask into a lookup of that key alone.
// Links.Default asks that way, since the mesh's own routes cover the key it
// is after and a match would answer with those.
func routeRequest(destination, mask netip.Addr) (*route.RouteMessage, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("kernel: open a routing socket to ask for a route: %w", err)
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	// SO_USELOOPBACK stays on, unlike the reconciler's write socket: the reply
	// to an RTM_GET comes back the same way an echo does, and silencing the
	// echo would silence the answer.
	timeout := unix.NsecToTimeval(int64(lookupTimeout))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return nil, fmt.Errorf("kernel: bound the route lookup: %w", err)
	}
	seq := int(lookupSeq.Add(1))
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = routeAddr(destination)
	if mask.IsValid() {
		addrs[unix.RTAX_NETMASK] = routeAddr(mask)
	}
	request := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   unix.RTF_UP,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   addrs,
	}
	raw, err := request.Marshal()
	if err != nil {
		return nil, fmt.Errorf("kernel: encode a route lookup for %s: %w", destination, err)
	}
	if _, err := unix.Write(fd, raw); err != nil {
		// ESRCH is the kernel saying it has no route at all, which is the
		// answer rather than a failure of the mechanism.
		if gone(err) {
			return nil, ErrNoDefaultRoute
		}
		return nil, fmt.Errorf("kernel: ask for the route to %s: %w", destination, err)
	}
	// A routing socket reports one message per read and the reply shares the
	// socket with whatever else the kernel is announcing, so the reads are
	// bounded rather than single and each one is matched against the request.
	buf := make([]byte, 4096)
	for range 16 {
		n, err := unix.Read(fd, buf)
		if err != nil {
			return nil, fmt.Errorf("kernel: read the route to %s: %w", destination, err)
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
		if err != nil {
			continue
		}
		for _, message := range messages {
			rm, ok := message.(*route.RouteMessage)
			if !ok || rm.Type != unix.RTM_GET || rm.Seq != seq || rm.ID != uintptr(os.Getpid()) {
				continue
			}
			return rm, nil
		}
	}
	return nil, fmt.Errorf("kernel: the route to %s was not answered", destination)
}

// gatewayIndex reads the interface off one RTM_GET answer.
func gatewayIndex(rm *route.RouteMessage, canRecurse bool) (int, error) {
	if len(rm.Addrs) <= unix.RTAX_GATEWAY {
		return 0, ErrNoDefaultRoute
	}
	switch gateway := rm.Addrs[unix.RTAX_GATEWAY].(type) {
	case *route.LinkAddr:
		if gateway.Index == 0 {
			return 0, ErrNoDefaultRoute
		}
		return gateway.Index, nil
	case *route.Inet4Addr:
		if !canRecurse {
			return 0, ErrNoDefaultRoute
		}
		return interfaceIndexFor(netip.AddrFrom4(gateway.IP), false)
	case *route.Inet6Addr:
		if !canRecurse {
			return 0, ErrNoDefaultRoute
		}
		// The zone the kernel embeds in a link-local gateway is dropped the
		// way addressFromRouteAddr drops it, because the lookup that follows
		// is keyed on the address alone.
		return interfaceIndexFor(netip.AddrFrom16(gateway.IP), false)
	}
	return 0, ErrNoDefaultRoute
}
