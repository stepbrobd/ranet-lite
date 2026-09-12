//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// routePlatform is the PF_ROUTE half of the reconciler on darwin. Nothing here
// decides what the kernel should hold; it only encodes the decision and
// enforces the ownership rule on the way back in.
//
// # Ownership
//
// darwin has neither routing tables nor rt_proto, so the three-part marker the
// linux backend stamps on a route does not exist. The output interface takes
// its place: a route belongs to this reconciler when it leaves Config.Interface
// with the shape this reconciler installs, a unicast prefix route whose gateway
// is the interface itself and not a next hop. A route out of our own utun that
// this process did not install is adopted and withdrawn with the rest, which is
// how a crashed instance's routes get cleaned up. That rests on one condition:
// nothing else writes routes out of a utun ranet-lite created. Give it a device
// no other daemon writes.
//
// The kernel's own entries for the interface are excluded by shape. An address
// creates a host route whose gateway is the address, and the per-interface
// broadcast and multicast entries carry RTF_BROADCAST or RTF_MULTICAST.
// Nothing outside Config.Interface is read, written or deleted.
//
// # What the darwin FIB cannot hold
//
// There is no source-address-dependent lookup. A source prefix covering one of
// this interface's own addresses is installed as an interface-scoped route,
// see scopeOnDarwin; any other source prefix is reported once and skipped,
// because flattening it would turn an exit's "::/0 from <prefix>" into a plain
// default route out of the tun. An announced default is scoped for a different
// reason, that it would otherwise capture the ESP underlay, and the two share
// the one scoped slot a destination has.
//
// There is no per-route metric and no preferred source either, so Route.Metric
// and Route.PrefSrc are mirrored from the configuration into every dump. Both
// are diff key fields computed from that same configuration, and reporting
// anything else would make every pass add and delete the same route forever.
type routePlatform struct {
	cfg   Config
	index int

	sock     rtSocket
	control4 int
	control6 int
	monitor  *routeMonitor

	// scoped remembers the source behind each route installed with
	// RTF_IFSCOPE, which the FIB cannot store, and an invalid prefix for a
	// scoped route that has no source. The kernel keys a scoped route by
	// destination and interface, so there is at most one per destination.
	// Only successful installs go in here, so a route left by an earlier
	// process reads as ordinary, gets deleted and is reinstalled correctly
	// once, and a foreign scoped route is never adopted from its shape alone.
	scoped map[netip.Prefix]netip.Prefix

	// warned holds the source-specific routes already reported and pending
	// the ones reported under the current dump. Routes starts every reconcile
	// pass and rotates the two, so a route the mesh keeps announcing costs one
	// log line rather than one per pass and neither map outgrows a snapshot.
	warned map[Route]bool

	// occupied remembers destinations another program already holds, so a
	// route that can never install is reported once rather than every pass.
	occupied map[netip.Prefix]bool

	// addrs replaces the interface dump when set. The write side already goes
	// through the rtSocket seam; without the read side a test cannot reach the
	// scoped install at all, because sourceIsOurs would ask the host about an
	// interface index that names nothing.
	addrs func() ([]netip.Prefix, error)

	pending map[Route]bool
}

func newPlatform(cfg Config) (platform, error) {
	// a linux-shaped configuration names a table and a protocol that mean
	// nothing here. Rejecting them is the difference between a deployment that
	// is wrong at startup and one that looks like it works.
	if cfg.Table != DefaultTable {
		return nil, fmt.Errorf("kernel: darwin has no routing tables, table %d has no meaning here", cfg.Table)
	}
	if cfg.Protocol != DefaultProtocol {
		return nil, fmt.Errorf("kernel: darwin has no route protocol, protocol %d has no meaning here", cfg.Protocol)
	}
	if cfg.VRF != "" {
		return nil, fmt.Errorf("kernel: darwin has no VRF, %s cannot be enslaved to %s", cfg.Interface, cfg.VRF)
	}
	if len(cfg.Interface) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("kernel: interface name %q does not fit an ifreq", cfg.Interface)
	}
	// the index is resolved once: netstack owns the utun for the whole process
	// lifetime, so a changed index means a different device and the routes of
	// the old one went with it.
	device, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("kernel: look up interface %s: %w", cfg.Interface, err)
	}
	plat := &routePlatform{
		cfg: cfg, index: device.Index,
		control4: -1, control6: -1,
		scoped:   make(map[netip.Prefix]netip.Prefix),
		warned:   make(map[Route]bool),
		occupied: make(map[netip.Prefix]bool),
		pending:  make(map[Route]bool),
	}
	if err := plat.open(); err != nil {
		_ = plat.Close()
		return nil, err
	}
	return plat, nil
}

// open takes the descriptors the platform holds for its whole lifetime. The
// address ioctls are dispatched by the domain of the socket they arrive on, so
// IPv4 and IPv6 each need one of their own.
func (p *routePlatform) open() error {
	sock, err := dialRouteSocket()
	if err != nil {
		return err
	}
	p.sock = sock
	if p.control4, err = controlSocket(unix.AF_INET); err != nil {
		return err
	}
	if p.control6, err = controlSocket(unix.AF_INET6); err != nil {
		return err
	}
	p.monitor, err = newRouteMonitor(p.index)
	return err
}

func controlSocket(family int) (int, error) {
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return -1, fmt.Errorf("kernel: open an address control socket: %w", err)
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

func (p *routePlatform) Notify() <-chan struct{} { return p.monitor.signal }

// Close tolerates a partly opened platform, because newPlatform unwinds
// through it when one of the descriptors cannot be taken.
func (p *routePlatform) Close() error {
	var errs []error
	if p.monitor != nil {
		errs = append(errs, p.monitor.Close())
		p.monitor = nil
	}
	for _, fd := range []*int{&p.control4, &p.control6} {
		if *fd >= 0 {
			errs = append(errs, unix.Close(*fd))
			*fd = -1
		}
	}
	if p.sock != nil {
		errs = append(errs, p.sock.Close())
		p.sock = nil
	}
	return errors.Join(errs...)
}

// metric mirrors (*Reconciler).metric and prefSrc mirrors what desired puts on
// an IPv4 route. Neither is a property of a darwin route, so both are taken
// from the configuration on the way out of a dump: the diff key then matches
// what the reconciler asked for, instead of differing on every pass.
func (p *routePlatform) metric(destination netip.Prefix) uint32 {
	if p.cfg.Metric == 0 && !destination.Addr().Is4() {
		return defaultIPv6Metric
	}
	return p.cfg.Metric
}

func (p *routePlatform) prefSrc(destination netip.Prefix) netip.Addr {
	if destination.Addr().Is4() && p.cfg.PrefSrc4.IsValid() {
		return p.cfg.PrefSrc4
	}
	return netip.Addr{}
}

// rotateWarnings ends one deduplication window and starts the next. Routes is
// the first thing every reconcile pass calls, so that is the boundary.
func (p *routePlatform) rotateWarnings() {
	p.warned, p.pending = p.pending, make(map[Route]bool, len(p.pending))
}

func (p *routePlatform) Routes() ([]Route, error) {
	p.rotateWarnings()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("kernel: dump the routing table: %w", err)
	}
	return p.ownedRoutes(rib)
}

func (p *routePlatform) ownedRoutes(rib []byte) ([]Route, error) {
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("kernel: parse the route dump: %w", err)
	}
	var out []Route
	for _, message := range messages {
		if decoded, ok := p.decodeRoute(message); ok {
			out = append(out, decoded)
		}
	}
	return out, nil
}

// skipRouteFlags names every route out of our interface that this reconciler
// did not and could not have installed. RTF_LOCAL, RTF_BROADCAST and
// RTF_MULTICAST are the kernel's own entries for an address, which is how
// darwin records the per-interface broadcast and multicast plumbing.
// RTF_WASCLONED is a copy the kernel made of some other route, RTF_LLINFO a
// neighbor cache entry, and RTF_BLACKHOLE discards silently, which the mesh
// never asks for. RTF_GATEWAY says the route has a next hop, which the mesh
// never expresses. Removing any of them would break something this reconciler
// did not create.
//
// RTF_REJECT is not among them: it is the shape a held prefix is installed
// with, so a reject route out of our own interface with our own gateway shape
// is one of ours, by the same argument as every other route out of it.
const skipRouteFlags = unix.RTF_IFSCOPE | unix.RTF_MULTICAST | unix.RTF_BROADCAST |
	unix.RTF_LOCAL | unix.RTF_WASCLONED | unix.RTF_LLINFO |
	unix.RTF_BLACKHOLE | unix.RTF_GATEWAY

// decodeRoute keeps only the routes this reconciler owns. Everything else in
// the dump belongs to somebody else, so it is dropped here and can never reach
// a delete list.
func (p *routePlatform) decodeRoute(message route.Message) (Route, bool) {
	rm, ok := message.(*route.RouteMessage)
	// NET_RT_DUMP reports every entry as an RTM_GET; anything else came from
	// somewhere this function was not meant to read.
	if !ok || rm.Type != unix.RTM_GET || rm.Index != p.index {
		return Route{}, false
	}
	// RTF_IFSCOPE is handled after the destination is known: this reconciler
	// sets it on some of its own routes, but the kernel and other daemons also
	// set it on routes of theirs that are otherwise indistinguishable from
	// ours. utun7 on a machine running Tailscale
	// carries a scoped 255.255.255.255 entry with a link gateway and
	// RTF_STATIC, which is exactly the shape this reconciler installs. So a
	// scoped route counts as ours only if this process scoped that
	// destination, and one orphaned by a crash is left alone rather than
	// deleted on the strength of a guess.
	if rm.Flags&unix.RTF_UP == 0 || rm.Flags&(skipRouteFlags&^unix.RTF_IFSCOPE) != 0 {
		return Route{}, false
	}
	if len(rm.Addrs) <= unix.RTAX_NETMASK {
		return Route{}, false
	}
	// the gateway is what is left of an ownership marker on a platform with no
	// rt_proto: a route this reconciler installed leaves through the interface
	// itself, so the kernel holds a sockaddr_dl there and never an address.
	gateway, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
	if !ok || (gateway.Index != 0 && gateway.Index != p.index) {
		return Route{}, false
	}
	destination, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_DST])
	if !ok {
		return Route{}, false
	}
	// a host route carries no netmask, which is the one case where the prefix
	// length comes from the family rather than from the message.
	bits := destination.BitLen()
	if rm.Flags&unix.RTF_HOST == 0 {
		mask, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_NETMASK])
		if !ok || mask.BitLen() != destination.BitLen() {
			return Route{}, false
		}
		if bits, ok = maskBits(mask); !ok {
			return Route{}, false
		}
	}
	prefix, ok := canonicalPrefix(netip.PrefixFrom(destination, bits))
	if !ok {
		return Route{}, false
	}
	source, tracked := p.scoped[prefix]
	if rm.Flags&unix.RTF_IFSCOPE == 0 {
		// The kernel keys a scoped route separately from the unscoped route to
		// the same destination, so both can exist at once. Only the scoped one
		// carries a source; reporting the source on both would collapse them
		// into one entry in the diff and leave the unscoped route, which for
		// "::/0" is the whole machine's default, installed forever.
		source = netip.Prefix{}
	} else if !tracked {
		return Route{}, false
	}
	return Route{
		Destination: prefix,
		// The kernel keeps no source, so a scoped route's source comes back
		// from what this process installed for that destination.
		Source:      source,
		PrefSrc:     p.prefSrc(prefix),
		Metric:      p.metric(prefix),
		Unreachable: rm.Flags&unix.RTF_REJECT != 0,
	}, true
}

// sourceIsOurs reports whether a source prefix covers an address on this
// interface, which is what interface scope can stand in for. Anything else is
// a prefix belonging to some other node and cannot be expressed here.
func (p *routePlatform) sourceIsOurs(source netip.Prefix) (bool, error) {
	assigned, err := p.Addrs()
	if err != nil {
		// Distinguished from "not ours" on purpose. Reporting a dump failure
		// as a source we cannot express would skip the route, report success,
		// and never retry something a retry would fix.
		return false, err
	}
	for _, address := range assigned {
		if source.Contains(address.Addr()) {
			return true, nil
		}
	}
	return false, nil
}

// routeMessage encodes one RTM_ADD or RTM_DELETE. The gateway is the interface
// itself, a sockaddr_dl carrying only its index, which is what
// "route -interface" sends and the only thing ifa_ifwithnet reads: ranet-lite
// picks the peer after the kernel hands over the packet, so there is no next
// hop to name.
//
// RTF_IFSCOPE is set by the caller, for the routes scopeOnDarwin names. A
// scoped route is invisible to an ordinary lookup and visible to a socket
// bound to an address on this interface.
//
// RTF_HOST is not set either, even for a full-length prefix; the netmask says
// the same thing. With RTF_HOST the kernel resolves the output interface
// through ifa_ifwithdstaddr, which on a box carrying several point-to-point
// utuns can answer with somebody else's device.
func (p *routePlatform) routeMessage(kind int, r Route) (*route.RouteMessage, error) {
	mask, ok := prefixMask(r.Destination)
	if !ok {
		return nil, fmt.Errorf("%s has no netmask", r.Destination)
	}
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = routeAddr(r.Destination.Addr())
	addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: p.index}
	addrs[unix.RTAX_NETMASK] = routeAddr(mask)
	return &route.RouteMessage{
		Type:  kind,
		Flags: unix.RTF_UP | unix.RTF_STATIC,
		Index: p.index,
		Addrs: addrs,
	}, nil
}

func routeAddr(address netip.Addr) route.Addr {
	if address.Is4() {
		return &route.Inet4Addr{IP: address.As4()}
	}
	return &route.Inet6Addr{IP: address.As16()}
}

func (p *routePlatform) AddRoute(r Route) error {
	if r.Source.IsValid() {
		ours, err := p.sourceIsOurs(r.Source)
		if err != nil {
			return err
		}
		if !ours {
			// A source prefix that is not one of this interface's own
			// addresses cannot be expressed: interface scope selects on the
			// socket's bound address, so it can only stand in for "from an
			// address of ours".
			return p.skipSourceSpecific(r)
		}
	}
	if scopeOnDarwin(r) {
		if held, ok := p.scoped[r.Destination]; ok && held != r.Source {
			// Interface scope is one route per destination per interface, so a
			// second scoped route for the same destination has nowhere to go.
			// That covers a second source prefix and an announced default
			// competing with a source-specific route to the same destination.
			// Skipping says so once; installing would collide, and recording
			// it would make the two take turns being reported as installed.
			return p.skipSourceSpecific(r)
		}
	}
	message, err := p.routeMessage(unix.RTM_ADD, r)
	if err != nil {
		return err
	}
	if scopeOnDarwin(r) {
		message.Flags |= unix.RTF_IFSCOPE
	}
	if r.Unreachable {
		// A hold rather than a path, so it answers with an error instead of
		// carrying the packet out of the tun. It keeps the scope decision
		// above: a held default must no more be visible to an unbound socket
		// than a real one.
		message.Flags |= unix.RTF_REJECT
	}
	// darwin has no replace, so a route another program holds under the same
	// key stays and this add is retried on every pass. That is the same
	// tolerance the linux backend has, and the alternative is taking over a
	// route whose owner is unknown. It is reported, because otherwise a
	// prefix that can never install looks identical to one that did.
	if err := p.sock.WriteRoute(message); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
		if !p.occupied[r.Destination] {
			p.occupied[r.Destination] = true
			slog.Warn("kernel is leaving a route that another program holds",
				"destination", r.Destination, "interface", p.cfg.Interface,
				"detail", "darwin cannot replace a route, so this one was not installed")
		}
		return errRouteSkipped
	}
	delete(p.occupied, r.Destination)
	// Recorded only after the write lands, and only for a route that actually
	// carries the scope. An entry for a route that was never installed would
	// make decodeRoute report an unscoped route as carrying a source it does
	// not have, and the diff would then leave a plain route in place forever.
	if scopeOnDarwin(r) {
		p.scoped[r.Destination] = r.Source
	}
	return nil
}

// scopeOnDarwin decides whether a route is installed with RTF_IFSCOPE, which
// hides it from an ordinary lookup and shows it to a socket bound to an
// address on this interface.
//
// A source-specific route is scoped because that is the only thing on this
// platform that draws the distinction a source prefix draws at all.
//
// A default is scoped because otherwise it captures the machine. darwin has
// one FIB and Config.Table is meaningless here, so there is no equivalent of
// the fleet's table plus "ipproto udp sport <port> lookup main", and nothing
// keeps the peers' own endpoints out of an announced default: the ESP underlay
// would route into the tun carrying it. On IPv4 an unscoped mesh default
// survives today only because it collides with the box's own, and AddRoute
// retries every pass, so the first moment the Mac has no v4 default the next
// pass takes the machine. On IPv6 there is no collision to rely on, since
// every default row on a Mac is already scoped to its own interface.
//
// A half of the address space counts as a default, because that is how a
// default that does not replace the host's is written: 0.0.0.0/1 with
// 128.0.0.0/1, or ::/1 with 8000::/1, which is the spelling wg-quick and the
// tunnels on this platform use. The pair covers every destination at a longer
// prefix than the box's own /0, so unscoped it wins the lookup outright
// instead of merely colliding, and it takes the underlay with it. A neighbor
// can announce one: the Update decoder bounds a prefix length only at 32 and
// 128.
//
// Anything more specific stays unscoped, so the mesh is reachable from the Mac
// itself without every program having to bind first. That is the same split
// tailscale makes on the same machine: its exit-node default is scoped to its
// utun, its 100.64/10 is not.
func scopeOnDarwin(r Route) bool {
	return r.Source.IsValid() || r.Destination.Bits() <= 1
}

func (p *routePlatform) DelRoute(r Route) error {
	_, installed := p.scoped[r.Destination]
	if r.Source.IsValid() && !installed {
		// Nothing was installed for a source we cannot express, and deleting
		// what is left after dropping the source would take out the ordinary
		// route to the same destination. For an exit's "::/0 from <prefix>"
		// that is the box's default route.
		//
		// The answer comes from what this process recorded at install rather
		// than from asking the kernel which addresses are on the interface
		// now. An address removed between install and withdraw would otherwise
		// make this report success without deleting, and the route would then
		// be undeletable for the life of the process.
		return nil
	}
	message, err := p.routeMessage(unix.RTM_DELETE, r)
	if err != nil {
		return err
	}
	if scopeOnDarwin(r) {
		// The kernel keys a scoped route separately from the unscoped route to
		// the same destination, so the delete has to carry the flag or it
		// removes the wrong one. Asking the route rather than the record keeps
		// withdrawing an unscoped default from taking out the scoped
		// source-specific route that shares its destination.
		message.Flags |= unix.RTF_IFSCOPE
	}
	if err := p.sock.WriteRoute(message); err != nil && !gone(err) {
		return err
	}
	// Dropped only once the route is gone, so a failed delete leaves the entry
	// and the next pass decodes the route and tries again.
	if scopeOnDarwin(r) {
		delete(p.scoped, r.Destination)
	}
	delete(p.occupied, r.Destination)
	return nil
}

// skipSourceSpecific reports a route the darwin FIB cannot express, once per
// route rather than once per pass. errRouteSkipped rather than a failure is
// deliberate: the reconciler would otherwise retry with backoff forever over
// something no retry can fix, and the mesh's own table still forwards by
// source.
func (p *routePlatform) skipSourceSpecific(r Route) error {
	key := Route{Destination: r.Destination, Source: r.Source}
	if !p.warned[key] {
		slog.Warn("kernel cannot install a source-specific route on darwin",
			"destination", r.Destination, "source", r.Source)
	}
	p.pending[key] = true
	return errRouteSkipped
}

func (p *routePlatform) Addrs() ([]netip.Prefix, error) {
	if p.addrs != nil {
		return p.addrs()
	}
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, p.index)
	if err != nil {
		return nil, fmt.Errorf("kernel: dump the addresses of %s: %w", p.cfg.Interface, err)
	}
	return p.interfaceAddrs(rib)
}

// interfaceAddrs reports every address on the interface, whoever put it there,
// which is what the reconciler needs to decide that a configured address is
// already present. It removes nothing and decides nothing.
func (p *routePlatform) interfaceAddrs(rib []byte) ([]netip.Prefix, error) {
	messages, err := route.ParseRIB(route.RIBTypeInterface, rib)
	if err != nil {
		return nil, fmt.Errorf("kernel: parse the address dump: %w", err)
	}
	var out []netip.Prefix
	for _, message := range messages {
		am, ok := message.(*route.InterfaceAddrMessage)
		if !ok || am.Index != p.index || len(am.Addrs) <= unix.RTAX_IFA {
			continue
		}
		address, ok := addressFromRouteAddr(am.Addrs[unix.RTAX_IFA])
		if !ok {
			continue
		}
		mask, ok := addressFromRouteAddr(am.Addrs[unix.RTAX_NETMASK])
		if !ok || mask.BitLen() != address.BitLen() {
			continue
		}
		bits, ok := maskBits(mask)
		if !ok {
			continue
		}
		// an assigned address keeps its host bits, so the prefix is not masked.
		prefix := netip.PrefixFrom(address, bits)
		if !prefix.IsValid() {
			continue
		}
		out = append(out, prefix)
	}
	return out, nil
}

// AddAddr names the ioctl in its error, because the two families take
// different requests down different control sockets and an errno on its own
// does not say which one answered.
func (p *routePlatform) AddAddr(prefix netip.Prefix) error {
	name, fd, number := "SIOCAIFADDR", p.control4, uintptr(unix.SIOCAIFADDR)
	build := aliasRequest4
	if !prefix.Addr().Is4() {
		name, fd, number, build = "SIOCAIFADDR_IN6", p.control6, siocAIfAddrIn6, aliasRequest6
	}
	request, err := build(p.cfg.Interface, prefix)
	if err != nil {
		return err
	}
	if err := ioctlRequest(fd, number, request); err != nil {
		return fmt.Errorf("%s on %s: %w", name, p.cfg.Interface, err)
	}
	return nil
}

// DelAddr removes one address, and is reached only for an address the
// reconciler added itself in this process lifetime.
func (p *routePlatform) DelAddr(prefix netip.Prefix) error {
	// The builder is selected and then called, never called before the family
	// is known: deleteRequest4 reads the address as four bytes and panics on a
	// v6 prefix. AddAddr above has the same shape for the same reason.
	name, fd, number := "SIOCDIFADDR", p.control4, uintptr(unix.SIOCDIFADDR)
	build := deleteRequest4
	if !prefix.Addr().Is4() {
		name, fd, number, build = "SIOCDIFADDR_IN6", p.control6, siocDIfAddrIn6, deleteRequest6
	}
	if err := ioctlRequest(fd, number, build(p.cfg.Interface, prefix)); err != nil && !gone(err) {
		return fmt.Errorf("%s on %s: %w", name, p.cfg.Interface, err)
	}
	return nil
}

// Master reports no master, always. darwin has no VRF and no master device of
// any kind, so the reconciler's "leave a link somebody else owns alone" branch
// is unreachable here and Enslave is the error that says so.
func (p *routePlatform) Master() (string, error) { return "", nil }

func (p *routePlatform) Enslave(master string) error {
	return fmt.Errorf("kernel: darwin has no VRF, %s cannot be enslaved to %s", p.cfg.Interface, master)
}

// Release is unreachable: the reconciler releases only what it enslaved, and
// Enslave never succeeds.
func (p *routePlatform) Release() error { return nil }
