//go:build darwin && !ios

package client

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/NickCao/ranet-lite/internal/kernel"
)

// recordedKernel is a machine with a routing table this package's tests write
// and read back: the route socket records what was sent and applies it, the
// dump renders the result the way NET_RT_DUMP would, and the interface list
// and the host's own defaults are whatever the test says they are.
//
// It stands in for kernel.Host, which is the whole of what internal/kernel
// does to a machine, so a daemon built on one touches nothing outside this
// process. The one exception is deliberate: uplink is a real interface index,
// because the transport binds its own UDP socket to it with IP_BOUND_IF and
// the running kernel is the only thing that can answer that.
type recordedKernel struct {
	mu sync.Mutex
	// uplink is where the host's own traffic leaves by and mesh is the tun
	// this node carries the overlay on, which no lookup may answer with.
	uplink, mesh int
	devices      map[int]string
	// v4 and v6 are the host's own default of each family, a zero Index
	// meaning the host has none.
	v4, v6 kernel.RouteAnswer
	// held is the table, keyed the way the darwin kernel keys one.
	held     map[recordedRoute]bool
	assigned map[int][]netip.Prefix
	// sent is every message that reached this kernel, in order, which the
	// assertions read.
	sent []recordedWrite
	// openSockets and openWatchers count how much of this machine a daemon is
	// still holding. A descriptor left open is state the machine is in rather
	// than a call this test watched for, and a node that leaks one leaks it
	// once per start.
	openSockets, openWatchers int
	changed                   chan struct{}
}

// recordedRoute is one entry, keyed by everything the kernel keys a route on:
// the destination, the interface it leaves by and whether it is scoped to
// that interface. gateway is an address for a route with a next hop and
// invalid for one that leaves through the interface itself.
type recordedRoute struct {
	destination netip.Prefix
	index       int
	scoped      bool
	gateway     netip.Addr
	reject      bool
}

// recordedWrite is one routing message, in the terms the assertions are
// written in rather than in the encoding it arrived as.
type recordedWrite struct {
	add bool
	recordedRoute
}

func newRecordedKernel(uplink, mesh int) *recordedKernel {
	return &recordedKernel{
		uplink: uplink, mesh: mesh,
		devices:  map[int]string{uplink: "uplink0", mesh: "mesh0"},
		held:     make(map[recordedRoute]bool),
		assigned: make(map[int][]netip.Prefix),
		changed:  make(chan struct{}, 1),
	}
}

// hold puts a route in the table without anybody having written it, which is
// how the host's own routing gets there.
func (k *recordedKernel) hold(r recordedRoute) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.held[r] = true
}

// writes is every message that reached this kernel so far.
func (k *recordedKernel) writes() []recordedWrite {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.sent)
}

// installed reports whether the table holds a route to destination out of the
// mesh device, and whether it is scoped. Two routes to one destination can be
// held at once, one scoped and one not, so both answers are returned.
func (k *recordedKernel) installed(destination netip.Prefix) (plain, scoped bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for held := range k.held {
		if held.index != k.mesh || held.destination != destination {
			continue
		}
		if held.scoped {
			scoped = true
		} else {
			plain = true
		}
	}
	return plain, scoped
}

// scopedDefaults is every interface-scoped default this kernel holds on an
// interface other than the mesh, which is the underlay's own fallback.
func (k *recordedKernel) scopedDefaults() []recordedRoute {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []recordedRoute
	for held := range k.held {
		if held.scoped && held.index != k.mesh && held.destination.Bits() == 0 {
			out = append(out, held)
		}
	}
	slices.SortFunc(out, func(a, b recordedRoute) int {
		return a.destination.Addr().Compare(b.destination.Addr())
	})
	return out
}

func (k *recordedKernel) addresses(index int) []netip.Prefix {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.assigned[index])
}

// RouteSocket hands out a writer that applies what it is sent, so a second
// pass sees the table the first one left.
func (k *recordedKernel) RouteSocket() (kernel.RouteWriter, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.openSockets++
	return &recordedWriter{k: k}, nil
}

// stillOpen is how much of this machine the daemon is still holding.
func (k *recordedKernel) stillOpen() (sockets, watchers int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.openSockets, k.openWatchers
}

func (k *recordedKernel) Addresses(index int) ([]netip.Prefix, error) {
	return k.addresses(index), nil
}

func (k *recordedKernel) InterfaceIndex(name string) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for index, device := range k.devices {
		if device == name {
			return index, nil
		}
	}
	return 0, fmt.Errorf("kernel: look up interface %s: no such interface", name)
}

func (k *recordedKernel) InterfaceName(index int) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if device, ok := k.devices[index]; ok {
		return device, nil
	}
	return "", fmt.Errorf("kernel: name interface %d: no such interface", index)
}

func (k *recordedKernel) Lookup(destination, _ netip.Addr) (kernel.RouteAnswer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	answer := k.v4
	if destination.Is6() {
		answer = k.v6
	}
	if answer.Index == 0 {
		return kernel.RouteAnswer{}, kernel.ErrNoDefaultRoute
	}
	return answer, nil
}

func (k *recordedKernel) Watch(int, int, bool) (kernel.Watcher, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.openWatchers++
	return &recordedWatcher{k: k, signal: k.changed}, nil
}

func (k *recordedKernel) Assign(add bool, device string, prefix netip.Prefix) error {
	index, err := k.InterfaceIndex(device)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	held := k.assigned[index]
	if !add {
		k.assigned[index] = slices.DeleteFunc(held, func(p netip.Prefix) bool { return p == prefix })
		return nil
	}
	if !slices.Contains(held, prefix) {
		k.assigned[index] = append(held, prefix)
	}
	return nil
}

// Dump renders the table the way NET_RT_DUMP reports one: every entry as an
// RTM_GET, with the flags and the sockaddrs the kernel would carry. It goes
// back through the encoder on purpose, because what the backend decides about
// ownership it decides from those bytes.
func (k *recordedKernel) Dump() ([]byte, error) {
	k.mu.Lock()
	held := make([]recordedRoute, 0, len(k.held))
	for entry := range k.held {
		held = append(held, entry)
	}
	k.mu.Unlock()
	slices.SortFunc(held, compareRecorded)
	var rib []byte
	for _, entry := range held {
		message, err := entry.message(unix.RTM_GET)
		if err != nil {
			return nil, err
		}
		message.Version = unix.RTM_VERSION
		raw, err := message.Marshal()
		if err != nil {
			return nil, err
		}
		rib = append(rib, raw...)
	}
	return rib, nil
}

func compareRecorded(a, b recordedRoute) int {
	if c := a.destination.Addr().Compare(b.destination.Addr()); c != 0 {
		return c
	}
	if c := a.destination.Bits() - b.destination.Bits(); c != 0 {
		return c
	}
	return a.index - b.index
}

// message encodes one entry the way the kernel would report or accept it.
func (r recordedRoute) message(kind int) (*route.RouteMessage, error) {
	mask, ok := maskOf(r.destination)
	if !ok {
		return nil, fmt.Errorf("%s has no netmask", r.destination)
	}
	flags := unix.RTF_UP | unix.RTF_STATIC
	if r.scoped {
		flags |= unix.RTF_IFSCOPE
	}
	if r.reject {
		flags |= unix.RTF_REJECT
	}
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = addrOf(r.destination.Addr())
	addrs[unix.RTAX_NETMASK] = addrOf(mask)
	if r.gateway.IsValid() {
		// A next hop, which is how the host's own default and the one scoped
		// to the underlay interface are written.
		flags |= unix.RTF_GATEWAY
		addrs[unix.RTAX_GATEWAY] = addrOf(r.gateway)
	} else {
		// Out of the interface itself, the shape the reconciler installs.
		addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: r.index}
	}
	return &route.RouteMessage{Type: kind, Flags: flags, Index: r.index, Addrs: addrs}, nil
}

func addrOf(address netip.Addr) route.Addr {
	if address.Is4() {
		return &route.Inet4Addr{IP: address.As4()}
	}
	return &route.Inet6Addr{IP: address.As16()}
}

func maskOf(prefix netip.Prefix) (netip.Addr, bool) {
	bits, total := prefix.Bits(), prefix.Addr().BitLen()
	if bits < 0 || bits > total {
		return netip.Addr{}, false
	}
	raw := make([]byte, total/8)
	for i := range bits {
		raw[i/8] |= 0x80 >> (i % 8)
	}
	return netip.AddrFromSlice(raw)
}

// recordedWriter applies an RTM_ADD or an RTM_DELETE to the table and keeps
// what it was sent. It answers EEXIST for a key already held and ESRCH for one
// that is not, the way the kernel does, so the backend's own handling of both
// runs here rather than being stepped over.
type recordedWriter struct {
	k      *recordedKernel
	closed bool
}

func (w *recordedWriter) Close() error {
	w.k.mu.Lock()
	defer w.k.mu.Unlock()
	if !w.closed {
		w.closed = true
		w.k.openSockets--
	}
	return nil
}

func (w *recordedWriter) WriteRoute(raw []byte) error {
	messages, err := route.ParseRIB(route.RIBTypeRoute, raw)
	if err != nil {
		return fmt.Errorf("a message this kernel cannot parse: %w", err)
	}
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok {
			return fmt.Errorf("a %T reached the route socket", message)
		}
		if err := w.apply(rm); err != nil {
			return err
		}
	}
	return nil
}

func (w *recordedWriter) apply(rm *route.RouteMessage) error {
	entry, ok := decodeRecorded(rm)
	if !ok {
		return fmt.Errorf("a routing message with no destination")
	}
	w.k.mu.Lock()
	defer w.k.mu.Unlock()
	add := rm.Type == unix.RTM_ADD
	w.k.sent = append(w.k.sent, recordedWrite{add: add, recordedRoute: entry})
	switch {
	case add && w.k.held[entry]:
		return unix.EEXIST
	case add:
		w.k.held[entry] = true
	case !w.k.held[entry]:
		return unix.ESRCH
	default:
		delete(w.k.held, entry)
	}
	return nil
}

// decodeRecorded reads one message back into the key the table is held under.
func decodeRecorded(rm *route.RouteMessage) (recordedRoute, bool) {
	if len(rm.Addrs) <= unix.RTAX_NETMASK {
		return recordedRoute{}, false
	}
	destination, ok := addrFrom(rm.Addrs[unix.RTAX_DST])
	if !ok {
		return recordedRoute{}, false
	}
	mask, ok := addrFrom(rm.Addrs[unix.RTAX_NETMASK])
	if !ok || mask.BitLen() != destination.BitLen() {
		return recordedRoute{}, false
	}
	bits := 0
	for _, octet := range mask.AsSlice() {
		for bit := range 8 {
			if octet&(0x80>>bit) == 0 {
				break
			}
			bits++
		}
	}
	prefix, err := destination.Prefix(bits)
	if err != nil {
		return recordedRoute{}, false
	}
	entry := recordedRoute{
		destination: prefix,
		index:       rm.Index,
		scoped:      rm.Flags&unix.RTF_IFSCOPE != 0,
		reject:      rm.Flags&unix.RTF_REJECT != 0,
	}
	if gateway, ok := addrFrom(rm.Addrs[unix.RTAX_GATEWAY]); ok {
		entry.gateway = gateway
	}
	return entry, true
}

func addrFrom(addr route.Addr) (netip.Addr, bool) {
	switch value := addr.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(value.IP), true
	case *route.Inet6Addr:
		return netip.AddrFrom16(value.IP), true
	}
	return netip.Addr{}, false
}

// recordedWatcher never fires. What drives the reconcile loop in these tests
// is the route source a test announces into, plus the interval the
// configuration names, so a pass follows something the test did rather than
// something the machine underneath happened to do.
type recordedWatcher struct {
	k      *recordedKernel
	signal chan struct{}
	closed bool
}

func (w *recordedWatcher) Changed() <-chan struct{} { return w.signal }

func (w *recordedWatcher) Close() error {
	w.k.mu.Lock()
	defer w.k.mu.Unlock()
	if !w.closed {
		w.closed = true
		w.k.openWatchers--
	}
	return nil
}

// loopbackIndex is a real interface index, for the one call these tests leave
// with the running kernel: the transport sets IP_BOUND_IF on its own UDP
// socket, and an index no device has is refused.
func loopbackIndex(t *testing.T) int {
	t.Helper()
	device, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skipf("this host has no lo0 to bind a socket to: %v", err)
	}
	return device.Index
}
