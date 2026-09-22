//go:build darwin && !ios

package kernel

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
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
// measured rather than assumed. A scoped lookup still finds the most specific
// route, and where that route leaves another interface the kernel falls back
// to a longest-prefix match on the family's unspecified address and requires
// that answer to be on the bound interface. So a route as small as 0.0.0.0/24
// out of the tun takes the fallback away from every destination the tun also
// covers, and the underlay is gone. See capturesTheMachine for the measured
// table, and TestDarwinBoundSocketNeedsAScopedDefault for the end to end.
//
// A default scoped to the underlay's own interface answers the scoped lookup
// directly, so the fallback is never consulted. Measured: with it in place,
// every set that stranded a bound socket reaches again.
//
// # Written whenever the socket is bound, not only under a capture
//
// It duplicates the host's own default on the interface that already carries
// it, so it costs nothing when nothing needs it, and it is idempotent. Writing
// it only when the mesh looks like it is capturing meant a set that slipped
// past the condition took the machine off the network with nothing to fall
// back on; that whole class is gone once the route is simply always there.
//
// # Ownership, which is deliberately narrower than the tun's
//
// The reconciler's rule for its own interface is that a route of the right
// shape out of it is ours, adopted and withdrawn, because nothing else writes
// routes out of a utun this process created. None of that carries to a
// physical interface the whole machine shares, so nothing here is ever adopted
// by shape:
//
//   - only a default this tool recorded writing is a candidate for deletion;
//   - a delete is sent only after reading the kernel back and finding a route
//     that still carries RTF_IFSCOPE, the recorded interface and the recorded
//     next hop, and scopedDefaultMessage refuses to encode a delete that is
//     not interface-scoped at all;
//   - an add that answers EEXIST is success and not ownership, so a route
//     macOS wrote for a secondary interface is used and never withdrawn;
//   - the record outlives the process, in the runtime directory, so an
//     instance killed while holding one is cleaned up by the next rather than
//     leaking. reclaim states the three conditions a restart applies, and a
//     record failing any of them is held where nothing else can delete it.
//
// The failure that rule exists to prevent is tailscale's #21395, where
// clearing an exit node deleted the physical default route.
//
// # Concurrency
//
// One mutex covers the record and the syscalls both, so a link change and a
// reconcile pass never write the routing table at once. That is deliberate
// rather than incidental: the two would otherwise race to move the same key.
// Every syscall under it is bounded, the route lookups by lookupTimeout.
type UnderlayDefaults struct {
	mu   sync.Mutex
	sock rtSocket
	// host is the machine this writes to and reads back, the running kernel
	// unless the caller named another; see Host.
	host Host
	// closed is set by Close. Every entry point refuses afterwards rather than
	// dereferencing a socket that is gone.
	closed bool
	// links answers which interface the host's own default leaves by and what
	// its next hop is. It is an interface so a test can drive a move between
	// two interfaces without two uplinks to move between.
	links defaultRoutes
	// on is the interface the underlay socket is using, zero for none.
	on int
	// mesh is the tun this node carries the overlay on, so Close can tell
	// whether a capture is still installed and leave the underlay covered.
	mesh int
	// written is the set of routes this process put in the kernel, each
	// identified by everything the kernel keys one on. Nothing outside it is
	// ever deleted, and a move holds two of them for one destination until the
	// socket has left the first.
	written map[writtenDefault]bool
	// refused holds what reclaim found and would not act on. It is kept apart
	// from written on purpose: every condition reclaim applies would be worth
	// nothing if the record then joined the set an ordinary withdrawal deletes
	// from on the shape check alone. Nothing here is ever deleted by this
	// process; the next start weighs the conditions again.
	refused map[writtenDefault]bool
	// statePath is where both sets are written so they survive this process,
	// and state is the lock saying this process owns that file.
	statePath string
	state     *stateLock
	// dump reads the routing table back, and lookupDevice resolves an
	// interface name. Both are fields so a test can drive reclaim against a
	// table and a set of devices it decides.
	dump         func() ([]byte, error)
	lookupDevice func(string) (int, error)
	// covered records what the last ensure found in the kernel per family,
	// whoever put it there. It is deliberately not the same fact as written:
	// one says the key is satisfied, the other says this process may delete
	// it, and conflating them made the EEXIST path repeat a lookup, two
	// atomic rewrites of the state file, a wasted add and a log line on every
	// pass forever. Recording that the key is satisfied costs nothing and
	// claims nothing.
	covered map[netip.Prefix]bool
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

var errUnderlayClosed = errors.New("kernel: the underlay defaults are closed")

// NewUnderlayDefaults takes a route socket of its own, so its writes are never
// interleaved with the reconciler's on one sequence number, and reclaims what
// a previous instance recorded writing before anything else happens.
//
// host is the machine it writes to and reads back, nil for the one this
// process is running on.
//
// statePath is where that record lives; empty keeps it in memory for this
// process only. The file is locked before it is read, so a second daemon
// starting beside a running one reclaims nothing and overwrites nothing: it
// finds the lock held, says so, and carries on with no record of its own. A
// state file that cannot be read is reported and treated as empty, because a
// node that will not start is worse than a route left behind.
func NewUnderlayDefaults(host Host, links defaultRoutes, mesh int, statePath string) (*UnderlayDefaults, error) {
	if links == nil {
		return nil, errors.New("kernel: the underlay defaults need a link source")
	}
	host = hostOr(host)
	sock, err := routeSocket(host)
	if err != nil {
		return nil, err
	}
	u := &UnderlayDefaults{
		sock: sock, host: host, links: links, mesh: mesh, statePath: statePath,
		written:      make(map[writtenDefault]bool),
		refused:      make(map[writtenDefault]bool),
		covered:      make(map[netip.Prefix]bool),
		warned:       make(map[netip.Prefix]bool),
		dump:         host.Dump,
		lookupDevice: host.InterfaceIndex,
	}
	// Before the file is read, so nothing below can act on a record another
	// live process is still keeping.
	lock, err := lockState(statePath)
	if err != nil {
		slog.Warn("kernel is not reclaiming the underlay routes an earlier run recorded",
			"path", statePath, "err", err,
			"detail", "another process holds the record, so anything it wrote is its own to withdraw")
		return u, nil
	}
	u.state = lock
	records, err := loadUnderlayState(statePath)
	if err != nil {
		slog.Warn("kernel could not read which underlay routes an earlier run wrote",
			"path", statePath, "err", err,
			"detail", "any route it left is left where it is")
	}
	u.reclaim(records)
	return u, nil
}

// Prepare makes an interface usable by a socket bound to it, and is called
// before the socket moves onto it. It reconciles rather than remembering: the
// kernel drops this route on its own, clearing IFF_UP purges it and bringing
// the interface back up does not restore it, so a record saying it was written
// says nothing about whether it is there.
func (u *UnderlayDefaults) Prepare(index int) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return errUnderlayClosed
	}
	u.on = index
	return u.ensure()
}

// Settle removes what was written for any interface but the one the socket is
// now on. It runs after the rebind, so there is no moment in which the socket
// is on an interface whose route has already gone.
func (u *UnderlayDefaults) Settle(index int) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return errUnderlayClosed
	}
	u.on = index
	return u.remove(func(held writtenDefault) bool { return held.index != index })
}

// Ready repairs the underlay's own routing and reports, per family, what it
// can fall back on. The reconciler drops from its pass every capturing route
// whose own family is uncovered, so such a route is neither installed nor left
// behind.
//
// Per family because the fallback is: a socket bound with IP_BOUND_IF resolves
// the unspecified address of the destination's own family. A host reaching
// IPv4 through the bound interface and IPv6 through another is an ordinary
// dual-stack laptop, and one answer for the machine let ::/0 install over an
// IPv6 underlay with nothing behind it.
func (u *UnderlayDefaults) Ready() (Covered, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return Covered{}, errUnderlayClosed
	}
	if u.on == 0 {
		return Covered{}, errors.New("kernel: the underlay socket is on no interface")
	}
	err := u.ensure()
	return Covered{
		V4: u.covered[netip.PrefixFrom(netip.IPv4Unspecified(), 0)],
		V6: u.covered[netip.PrefixFrom(netip.IPv6Unspecified(), 0)],
	}, err
}

// Close removes what this process wrote, unless a capture is still in the
// kernel: the underlay's route outlives the routes that depend on it, always,
// and a withdrawal that failed upstream must not be followed by this one. What
// is left stays in the record, so the next start weighs it again.
func (u *UnderlayDefaults) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	var errs []error
	if held, err := u.captureHeld(); err != nil {
		errs = append(errs, err)
	} else if held {
		slog.Warn("kernel is leaving the underlay's own default in place",
			"detail", "a route that carries this machine's own traffic is still in the kernel, and taking the fallback away under it would leave this node with no network")
	} else {
		errs = append(errs, u.remove(func(writtenDefault) bool { return true }))
	}
	u.closed = true
	if u.sock != nil {
		errs = append(errs, u.sock.Close())
		u.sock = nil
	}
	if u.state != nil {
		errs = append(errs, u.state.Close())
		u.state = nil
	}
	return errors.Join(errs...)
}

// captureHeld reports whether the mesh interface still holds a route that
// takes this machine's own traffic, which is the one thing that must outlive
// the underlay's fallback.
func (u *UnderlayDefaults) captureHeld() (bool, error) {
	if u.mesh == 0 {
		return false, nil
	}
	rib, err := u.dump()
	if err != nil {
		return false, fmt.Errorf("kernel: read the table before withdrawing the underlay route: %w", err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return false, fmt.Errorf("kernel: parse the table before withdrawing the underlay route: %w", err)
	}
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Type != unix.RTM_GET || rm.Index != u.mesh || rm.Flags&unix.RTF_IFSCOPE != 0 {
			continue
		}
		destination, ok := dumpedPrefix(rm)
		if ok && capturesTheMachine(Route{Destination: destination}) {
			return true, nil
		}
	}
	return false, nil
}

// Written reports the routes this process currently holds in the kernel, for
// a test and for a diagnostic.
func (u *UnderlayDefaults) Written() []writtenDefault {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.sorted()
}

// Refused reports what reclaim would not act on, which nothing in this process
// will delete.
func (u *UnderlayDefaults) Refused() []writtenDefault {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]writtenDefault, 0, len(u.refused))
	for held := range u.refused {
		out = append(out, held)
	}
	slices.SortFunc(out, compareWritten)
	return out
}

// ensure brings the kernel to one scoped default per family on u.on, under the
// next hop the host's own default of that family currently uses.
//
// It reads the table back rather than trusting the record. The record says
// what this process wrote and is the whole of its claim to delete anything; it
// is not evidence that the kernel still holds it, and the kernel drops this
// route on an interface going down.
//
// A family whose default leaves by another interface is skipped and said out
// loud: a route scoped to the interface the socket is bound to, pointing at a
// next hop that is not on it, would be a black hole rather than a fallback.
func (u *UnderlayDefaults) ensure() error {
	clear(u.covered)
	if u.on == 0 {
		return nil
	}
	rib, err := u.dump()
	if err != nil {
		return fmt.Errorf("kernel: read the table before covering the underlay: %w", err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return fmt.Errorf("kernel: parse the table before covering the underlay: %w", err)
	}
	var errs []error
	for _, destination := range defaultPrefixes {
		index, gateway, err := u.links.Default(destination.Addr())
		switch {
		case errors.Is(err, ErrNoDefaultRoute):
			// Nothing of this family to fall back to, which is ordinary on a
			// single-stack host and is not a failure of this family alone.
			u.report(destination, "the host has no default of this family, so the underlay socket has none scoped to it either",
				"destination", destination, "socket_on", u.on)
			continue
		case err != nil:
			errs = append(errs, err)
			continue
		}
		if index != u.on || !gateway.IsValid() || gateway.Is4() != destination.Addr().Is4() {
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
		if heldByKernel(messages, want) {
			// Already there, whoever put it there: this process on an earlier
			// pass, macOS for a secondary interface, or an instance that
			// crashed. The key is satisfied, which is recorded, and it is not
			// ours to delete, which is not. Answering from the table rather
			// than from the record is how this stops redoing the lookup, the
			// write and two rewrites of the state file on every pass.
			u.covered[destination] = true
			delete(u.warned, destination)
			continue
		}
		// Only a route the kernel keys the same way has to go first: same
		// destination, same interface, a different next hop, which is a wifi
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
		u.covered[destination] = true
		if !ours {
			// Somebody else holds that exact key, which macOS does for every
			// interface but the primary, and the readback above missed only
			// because it raced with them. Satisfied and not ours.
			delete(u.written, want)
			u.persist()
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
// behind. Recording it either way would make the next withdrawal delete a
// route this process did not write, which is the one thing this file must not
// do.
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

// remove withdraws every recorded route the predicate selects, in a fixed
// order so a test reads a stable one. Nothing in u.refused is reachable from
// here.
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
	slices.SortFunc(out, compareWritten)
	return out
}

func compareWritten(a, b writtenDefault) int {
	return cmp.Or(comparePrefixes(a.destination, b.destination), cmp.Compare(a.index, b.index))
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
	return hostOr(u.host).InterfaceName(index)
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

// heldByKernel is that test against a dump already parsed, which ensure and
// reclaim each need once for every record rather than once each.
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

// dumpedPrefix is the destination one dumped route names, masked the way a
// Route key is.
func dumpedPrefix(rm *route.RouteMessage) (netip.Prefix, bool) {
	if len(rm.Addrs) <= unix.RTAX_NETMASK {
		return netip.Prefix{}, false
	}
	destination, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_DST])
	if !ok {
		return netip.Prefix{}, false
	}
	bits := destination.BitLen()
	if rm.Flags&unix.RTF_HOST == 0 {
		mask, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_NETMASK])
		if !ok || mask.BitLen() != destination.BitLen() {
			return netip.Prefix{}, false
		}
		if bits, ok = maskBits(mask); !ok {
			return netip.Prefix{}, false
		}
	}
	return canonicalPrefix(netip.PrefixFrom(destination, bits))
}

// isDefaultKey reports whether one dumped route is the default of that family,
// which is a zero-length netmask over the unspecified address and never a host
// route.
func isDefaultKey(rm *route.RouteMessage, destination netip.Prefix) bool {
	held, ok := dumpedPrefix(rm)
	return ok && held.Bits() == 0 && held.Addr().Is4() == destination.Addr().Is4()
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
