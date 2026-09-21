//go:build darwin && !ios

package kernel

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// UnderlayDefaults writes the one route this package puts out of an interface
// it does not own: a default carrying RTF_IFSCOPE on whichever physical
// interface the underlay socket is bound to.
//
// # Why it has to exist
//
// IP_BOUND_IF does not take a socket off the forwarding table, which was
// measured rather than assumed, see TestDarwinBoundSocketNeedsAScopedDefault.
// A scoped lookup still finds the most specific route, and where that route
// leaves another interface it falls back only to a route already on the bound
// one. So the moment the mesh holds 0.0.0.0/1 and 128.0.0.0/1 out of the tun,
// a socket bound to the physical interface answers ENETUNREACH, unless that
// interface carries a default of its own scoped to it. macOS writes exactly
// such a route for every interface except the primary one, which is why
// binding looks sufficient until the mesh takes the default away from the
// primary. This writes the missing one.
//
// # Ownership, which is deliberately narrower than the tun's
//
// The reconciler's rule for Config.Interface is that a route of the right
// shape out of that interface is ours, adopted and withdrawn, because nothing
// else writes routes out of a utun this process created. None of that reasoning
// carries to a physical interface the whole machine shares, so nothing here is
// ever adopted by shape:
//
//   - only a default this process wrote in this process lifetime is a
//     candidate for deletion, recorded in written;
//   - a delete is sent only after reading the kernel back and finding a route
//     that still carries RTF_IFSCOPE, the recorded interface and the recorded
//     next hop. A readback that does not match is left alone and reported;
//   - a delete message is refused outright unless it carries RTF_IFSCOPE, so
//     no path through this file can name the host's own unscoped default;
//   - an add that answers EEXIST is success and not ownership, so a route
//     macOS wrote for a secondary interface is used and never withdrawn;
//   - the record outlives the process. It is written to the runtime directory
//     before the route is, so an instance killed while holding one is
//     withdrawn by the next instance rather than leaking for good. That is the
//     same ownership claim and not a weaker one: see reclaim, which still
//     refuses to act on a record whose route no longer matches it.
//
// The failure that rule exists to prevent is tailscale's #21395, where
// clearing an exit node deleted the physical default route.
//
// # Lifetime
//
// The pair is part of the capture, so Hold is called before the capturing
// routes are installed and Release after the last one is withdrawn; the
// capture gate's grace therefore withdraws both together. Prepare and Settle
// come from the transport as the socket moves between interfaces, and are
// ordered so the new interface is usable before the socket moves onto it.
type UnderlayDefaults struct {
	mu   sync.Mutex
	sock rtSocket
	// links answers which interface the host's own default leaves by and what
	// its next hop is. It is an interface so a test can drive a move between
	// two interfaces without two uplinks to move between.
	links defaultRoutes
	// held is the capture gate's answer: the mesh is carrying this machine's
	// own traffic, so the underlay needs a route of its own.
	held bool
	// on is the interface the underlay socket is using, zero for none.
	on int
	// written is the set of routes this process actually put in the kernel,
	// each identified by everything the kernel keys one on. Nothing outside it
	// is ever deleted, and a move holds two of them for one destination until
	// the socket has left the first.
	written map[writtenDefault]bool
	// statePath is where that set is written so it survives this process.
	// Empty keeps it in memory alone, which a test uses and which leaks one
	// route per kill.
	statePath string
	// dump reads the routing table back, and lookupDevice resolves an
	// interface name. Both are fields so a test can drive reclaim against a
	// table and a set of devices it decides.
	dump         func() ([]byte, error)
	lookupDevice func(string) (int, error)
	// warned bounds a repeated report to one line per transition.
	warned map[netip.Prefix]bool
}

// defaultRoutes answers where the host's own traffic of one family goes.
// *Links implements it over the route socket.
type defaultRoutes interface {
	Default(family netip.Addr) (index int, gateway netip.Addr, err error)
}

// writtenDefault is one route this process wrote, in enough detail that the
// withdrawal can prove the kernel still holds that exact route. The kernel
// keys a scoped route on its destination and its interface, so two of these
// differing in the interface are two routes and can be held at once.
//
// device is the interface's name, which the kernel keys nothing on and which a
// record that outlives a reboot needs: an index is reused, so a record holding
// the index alone would name whichever device took it.
type writtenDefault struct {
	destination netip.Prefix
	index       int
	device      string
	gateway     netip.Addr
}

// defaultPrefixes are the two keys this writes, one per family.
var defaultPrefixes = []netip.Prefix{
	netip.PrefixFrom(netip.IPv4Unspecified(), 0),
	netip.PrefixFrom(netip.IPv6Unspecified(), 0),
}

// NewUnderlayDefaults takes a route socket of its own, so its writes are never
// interleaved with the reconciler's on one sequence number, and reclaims what
// a previous instance recorded writing before anything else happens.
//
// statePath is where that record lives; empty keeps it in memory for this
// process only. A state file that cannot be read is reported and treated as
// empty, because a node that will not start is worse than a route left behind.
func NewUnderlayDefaults(links defaultRoutes, statePath string) (*UnderlayDefaults, error) {
	if links == nil {
		return nil, errors.New("kernel: the underlay defaults need a link source")
	}
	sock, err := dialRouteSocket()
	if err != nil {
		return nil, err
	}
	u := &UnderlayDefaults{
		sock: sock, links: links, statePath: statePath,
		written:      make(map[writtenDefault]bool),
		warned:       make(map[netip.Prefix]bool),
		dump:         func() ([]byte, error) { return route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0) },
		lookupDevice: deviceIndex,
	}
	records, err := loadUnderlayState(statePath)
	if err != nil {
		slog.Warn("kernel could not read which underlay routes an earlier run wrote",
			"path", statePath, "err", err,
			"detail", "any route it left is left where it is")
	}
	u.reclaim(records)
	return u, nil
}

// Hold is called before the reconciler installs a route that would carry this
// machine's own traffic.
func (u *UnderlayDefaults) Hold() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.held = true
	return u.ensure()
}

// Release is called once the last such route is gone, and at shutdown.
func (u *UnderlayDefaults) Release() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.held = false
	return u.remove(func(writtenDefault) bool { return true })
}

// Prepare makes an interface usable by a bound socket before the socket moves
// onto it. It writes nothing while the mesh is not carrying this machine's
// traffic, because there is nothing to fall back from.
func (u *UnderlayDefaults) Prepare(index int) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.on = index
	return u.ensure()
}

// Settle removes what was written for any interface but the one the socket is
// now on. It runs after the rebind, so there is no moment in which the socket
// is on an interface whose route has already gone.
func (u *UnderlayDefaults) Settle(index int) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.on = index
	return u.remove(func(held writtenDefault) bool { return held.index != index })
}

func (u *UnderlayDefaults) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	err := u.remove(func(writtenDefault) bool { return true })
	if u.sock != nil {
		err = errors.Join(err, u.sock.Close())
		u.sock = nil
	}
	return err
}

// Written reports the routes this process currently holds in the kernel, for
// a test and for a diagnostic.
func (u *UnderlayDefaults) Written() []writtenDefault {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]writtenDefault, 0, len(u.written))
	for held := range u.written {
		out = append(out, held)
	}
	slices.SortFunc(out, func(a, b writtenDefault) int {
		return cmp.Or(comparePrefixes(a.destination, b.destination), cmp.Compare(a.index, b.index))
	})
	return out
}

// ensure brings the kernel to one scoped default per family on u.on, under the
// next hop the host's own default of that family currently uses. A family
// whose default leaves by another interface is skipped: a route scoped to the
// interface the socket is bound to, pointing at a next hop that is not on it,
// would be a black hole rather than a fallback.
func (u *UnderlayDefaults) ensure() error {
	if !u.held || u.on == 0 {
		return nil
	}
	var errs []error
	for _, destination := range defaultPrefixes {
		index, gateway, err := u.links.Default(destination.Addr())
		switch {
		case errors.Is(err, errNoDefaultRoute):
			// Nothing of this family to fall back to, which is ordinary on a
			// single-stack host.
			continue
		case err != nil:
			errs = append(errs, err)
			continue
		}
		if index != u.on || !gateway.IsValid() || gateway.Is4() != destination.Addr().Is4() {
			// Either the host reaches this family through another interface,
			// or through a link with no next hop to name. Neither can be
			// turned into a route scoped to the interface the socket is on.
			u.report(destination, "is reached another way, so no default was scoped to the underlay interface",
				"destination", destination, "host_uses", index, "socket_on", u.on)
			continue
		}
		device, err := u.deviceName(index)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		want := writtenDefault{destination: destination, index: index, device: device, gateway: gateway}
		if u.written[want] {
			continue
		}
		// Only a route the kernel keys the same way has to go first: same
		// destination, same interface, different next hop, which is a wifi
		// network renumbering under us. One on another interface is a
		// different key and stays until Settle, so a move never leaves the
		// socket on an interface whose route has already gone.
		if err := u.remove(func(held writtenDefault) bool {
			return held.destination == destination && held.index == want.index
		}); err != nil {
			errs = append(errs, err)
			continue
		}
		// Recorded before the route is written, never after. A process dying
		// between the two then leaves a record for a route that does not
		// exist, which reclaim discards on the readback; the other order
		// leaves a route with no record, which nothing may ever remove.
		u.written[want] = true
		u.persist()
		ours, err := u.write(want)
		if err != nil {
			delete(u.written, want)
			u.persist()
			errs = append(errs, err)
			continue
		}
		delete(u.warned, destination)
		if !ours {
			delete(u.written, want)
			u.persist()
			// Somebody else already holds that exact key on that interface,
			// which macOS itself does for every interface but the primary. It
			// does the job and it is not ours, so it is not recorded and will
			// never be withdrawn.
			slog.Info("kernel found the underlay interface already carried a scoped default",
				"destination", destination, "interface_index", want.index, "next_hop", want.gateway)
			continue
		}
		slog.Info("kernel wrote a default scoped to the underlay interface",
			"destination", destination, "interface_index", want.index, "next_hop", want.gateway,
			"detail", "a socket bound to that interface has no route without it once the mesh holds the address space")
	}
	return errors.Join(errs...)
}

// write installs one scoped default and reports whether this process is the
// one that created it.
//
// EEXIST is success and not ownership. Something already holds that exact key
// on that interface, which is the state this was trying to reach, and it is
// the ordinary case in two ways: macOS writes such a route itself for every
// interface but the primary, and a crashed instance of this process leaves one
// behind. Recording it either way would make the next Release delete a route
// this process did not write, which is the one thing this file must not do.
func (u *UnderlayDefaults) write(want writtenDefault) (ours bool, err error) {
	message, err := scopedDefaultMessage(unix.RTM_ADD, want)
	if err != nil {
		return false, err
	}
	switch err := u.sock.WriteRoute(message); {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.EEXIST):
		return false, nil
	default:
		return false, fmt.Errorf("kernel: write %s scoped to interface %d via %s: %w",
			want.destination, want.index, want.gateway, err)
	}
}

// remove withdraws every recorded route the predicate selects, oldest key
// first so a test reads a stable order.
func (u *UnderlayDefaults) remove(selects func(writtenDefault) bool) error {
	var errs []error
	for _, held := range u.sorted() {
		if !selects(held) {
			continue
		}
		errs = append(errs, u.removeOne(held))
	}
	return errors.Join(errs...)
}

// sorted is the record in a fixed order, since a map is not one.
func (u *UnderlayDefaults) sorted() []writtenDefault {
	out := make([]writtenDefault, 0, len(u.written))
	for held := range u.written {
		out = append(out, held)
	}
	slices.SortFunc(out, func(a, b writtenDefault) int {
		return cmp.Or(comparePrefixes(a.destination, b.destination), cmp.Compare(a.index, b.index))
	})
	return out
}

// removeOne withdraws one recorded route, and only after the kernel says it is
// still the route this process wrote.
//
// The record is dropped once the route is gone, whether this withdrew it or
// found it already replaced, and kept on a failure the next pass or the next
// start can retry. Keeping it costs nothing, because every path to a delete
// reads the kernel back first.
func (u *UnderlayDefaults) removeOne(held writtenDefault) error {
	if !u.written[held] {
		return nil
	}
	present, err := u.stillOurs(held)
	if err != nil {
		// Reported rather than deleted on a guess. A dump this process could
		// not read is not permission to send a delete for a default route.
		return fmt.Errorf("kernel: read back %s before withdrawing it: %w", held.destination, err)
	}
	if !present {
		delete(u.written, held)
		u.persist()
		slog.Warn("kernel is leaving a scoped default it no longer recognizes",
			"destination", held.destination, "interface_index", held.index, "next_hop", held.gateway,
			"detail", "something replaced it, so withdrawing would take out a route this process did not write")
		return nil
	}
	if err := u.withdraw(held); err != nil {
		return fmt.Errorf("kernel: withdraw %s scoped to interface %d: %w", held.destination, held.index, err)
	}
	delete(u.written, held)
	u.persist()
	slog.Info("kernel withdrew the default scoped to the underlay interface",
		"destination", held.destination, "interface_index", held.index, "next_hop", held.gateway)
	return nil
}

// deviceName is the name of one interface index, which the record carries so
// that a reused index cannot be mistaken for the device that was recorded.
func (u *UnderlayDefaults) deviceName(index int) (string, error) {
	device, err := net.InterfaceByIndex(index)
	if err != nil {
		return "", fmt.Errorf("kernel: name interface %d: %w", index, err)
	}
	return device.Name, nil
}

// stillOurs reports whether the kernel holds a default at this destination
// that carries RTF_IFSCOPE, leaves by the recorded interface and points at the
// recorded next hop. Every one of the three is part of the answer: the
// unscoped default at the same destination differs only in the flag, and
// taking that one out is the failure this whole file is arranged around.
func (u *UnderlayDefaults) stillOurs(held writtenDefault) (bool, error) {
	rib, err := u.dump()
	if err != nil {
		return false, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return false, err
	}
	return heldByKernel(messages, held), nil
}

// heldByKernel is that test against a dump already parsed, which reclaim needs
// once for every record rather than once each.
func heldByKernel(messages []route.Message, held writtenDefault) bool {
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Type != unix.RTM_GET || rm.Index != held.index {
			continue
		}
		if rm.Flags&unix.RTF_IFSCOPE == 0 || rm.Flags&unix.RTF_GATEWAY == 0 {
			continue
		}
		if !isDefaultKey(rm, held.destination) {
			continue
		}
		if len(rm.Addrs) <= unix.RTAX_GATEWAY {
			continue
		}
		gateway, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_GATEWAY])
		if !ok || gateway.WithZone("") != held.gateway {
			continue
		}
		return true
	}
	return false
}

// isDefaultKey reports whether one dumped route is the default of that family,
// which is a zero-length netmask over the unspecified address and never a host
// route.
func isDefaultKey(rm *route.RouteMessage, destination netip.Prefix) bool {
	if rm.Flags&unix.RTF_HOST != 0 || len(rm.Addrs) <= unix.RTAX_NETMASK {
		return false
	}
	address, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_DST])
	if !ok || !address.IsUnspecified() || address.Is4() != destination.Addr().Is4() {
		return false
	}
	mask, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_NETMASK])
	if !ok || mask.BitLen() != address.BitLen() {
		return false
	}
	bits, ok := maskBits(mask)
	return ok && bits == 0
}

// scopedDefaultMessage encodes one add or delete. It refuses to build anything
// that is not interface-scoped, which is the last line between this file and
// the host's own default route: every path here goes through it, so a delete
// that forgot the flag cannot be sent.
func scopedDefaultMessage(kind int, held writtenDefault) (*route.RouteMessage, error) {
	destination := held.destination
	if !destination.IsValid() || destination.Bits() != 0 || !destination.Addr().IsUnspecified() {
		return nil, fmt.Errorf("kernel: %s is not a default route", destination)
	}
	if held.index == 0 {
		return nil, errors.New("kernel: a scoped default needs an interface to be scoped to")
	}
	if !held.gateway.IsValid() || held.gateway.Is4() != destination.Addr().Is4() {
		return nil, fmt.Errorf("kernel: %s cannot be reached through %s", destination, held.gateway)
	}
	mask, ok := prefixMask(destination)
	if !ok {
		return nil, fmt.Errorf("kernel: %s has no netmask", destination)
	}
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = routeAddr(destination.Addr())
	addrs[unix.RTAX_GATEWAY] = routeAddr(held.gateway)
	addrs[unix.RTAX_NETMASK] = routeAddr(mask)
	return &route.RouteMessage{
		Type:  kind,
		Flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_IFSCOPE,
		Index: held.index,
		Addrs: addrs,
	}, nil
}

// report says a thing once per transition rather than once per pass.
func (u *UnderlayDefaults) report(destination netip.Prefix, message string, args ...any) {
	if u.warned[destination] {
		return
	}
	u.warned[destination] = true
	slog.Warn("kernel: "+message, args...)
}
