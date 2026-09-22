package kernel

import "net/netip"

// Host is the machine a reconciler reads and writes: the routing socket it
// sends on, the tables it reads back, the interface list it resolves names
// through, and the addresses it assigns. A nil Host is the kernel this process
// is running on, the one every deployment gets.
//
// It exists because the path from a configuration file to a route on the wire
// ran through nothing a test could stand in for. Every mechanism under it is
// exercised against a hand-built struct, and the wiring that decides which of
// them a file turns on was exercised by nothing: on darwin a reconciler built
// through New opens a route socket, resolves a utun and dumps the table before
// any of it is observable, so a test without a kernel could not reach a single
// default of that capability. A recorded Host is a routing table a test writes
// and reads back, so the daemon is built the way the command builds it and the
// assertions are about what reached the kernel.
//
// Only the darwin backend consults one. linux has its own seam a layer down,
// the netlink connection its write tests drive, and reads this never.
type Host interface {
	// RouteSocket opens a write side of the platform's routing socket. The
	// reconciler and the underlay defaults take one each, so the sequence
	// numbers of the two never interleave. The caller closes it.
	RouteSocket() (RouteWriter, error)
	// Dump reads one of the platform's tables back, in the wire form the
	// platform's own parser reads. kind and index are the platform's own.
	Dump(kind, index int) ([]byte, error)
	// Lookup asks where one destination of one family goes. An exact mask asks
	// for that key alone rather than for a longest-prefix match; see
	// Links.Default for why the difference decides the answer here.
	Lookup(destination, mask netip.Addr) (RouteAnswer, error)
	// InterfaceIndex resolves a device name, and InterfaceName the reverse. A
	// record that outlives a reboot needs both, since an index is reused.
	InterfaceIndex(name string) (int, error)
	InterfaceName(index int) (string, error)
	// Watch reports changes to the routing of one interface, or of every
	// interface when index is zero, minus the one skip names; quiet drops this
	// process's own writes. The caller closes it.
	Watch(index, skip int, quiet bool) (Watcher, error)
	// Assign puts prefix on device, or takes it off again.
	Assign(add bool, device string, prefix netip.Prefix) error
}

// RouteAnswer is the kernel's answer about one destination: the interface it
// would leave by and the next hop it points at, the address invalid where it
// leaves through a link instead.
type RouteAnswer struct {
	Index   int
	Gateway netip.Addr
}

// RouteWriter is the write side of one routing socket, taking messages the
// caller has already encoded.
type RouteWriter interface {
	WriteRoute(raw []byte) error
	Close() error
}

// Watcher carries one coalesced wake-up per batch of changes to the routing
// it was opened over.
type Watcher interface {
	Changed() <-chan struct{}
	Close() error
}
