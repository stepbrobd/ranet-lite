//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

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
// its place: a route belongs to this reconciler when it leaves the mesh device
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
// Nothing outside the mesh device is read, written or deleted.
//
// # What the darwin FIB cannot hold
//
// There is no source-address-dependent lookup. A source prefix covering one of
// this interface's own addresses is installed as an interface-scoped route,
// see scopeRoute; any other source prefix is reported once and skipped,
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
	table Table
	rt    Runtime
	index int

	// host is the machine this writes to and reads back, the running kernel
	// unless the caller named another; see Host.
	host    Host
	sock    rtSocket
	watcher Watcher

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

	// occupied remembers the keys another program already holds, so a
	// route that can never install is reported once rather than every pass.
	occupied map[occupiedKey]bool
	// refused holds the keys this pass watched the kernel refuse, which
	// become occupied at the start of the next one.
	refused map[occupiedKey]bool
	// ours is the keys the kernel holds for this interface: what the last dump
	// reported as ours, plus what has installed since. EEXIST says only that
	// the key is taken, not by whom, and a pass that repairs a partial apply
	// re-adds a route this process installed moments earlier, so without this
	// the reconciler recorded its own route as another program's, stopped
	// reporting it in the dump, re-added it on every pass and could never
	// withdraw it.
	ours map[occupiedKey]bool

	// addrs replaces the interface dump when set. The write side already goes
	// through the rtSocket seam; without the read side a test cannot reach the
	// scoped install at all, because sourceIsOurs would ask the host about an
	// interface index that names nothing.
	addrs func() ([]netip.Prefix, error)

	pending map[Route]bool

	// underlay is Runtime.Underlay as of the current pass. Taken once in
	// Routes, so every scope decision of a pass reads the same list: a route
	// installed scoped under one answer and deleted under another leaves the
	// kernel holding a key nothing will name again.
	underlay []netip.Addr
	// assigned is this interface's own addresses as of the current pass, and
	// assignedAt says whether that answer has been taken yet.
	//
	// It is cached for the same reason underlay is, and to stop paying for it
	// repeatedly: AddRoute asks sourceIsOurs about every source-specific route
	// it is offered, a route it skips stays in the diff and is offered again
	// on the next pass, so a node hearing sixty-four of them paid for
	// sixty-four whole-interface dumps per pass, forever. Taken once and
	// shared, the pass pays for one.
	assigned   []netip.Prefix
	assignedAt bool
}

func newPlatform(t Table, rt Runtime) (platform, error) {
	// a linux-shaped configuration names a table and a protocol that mean
	// nothing here. Rejecting them is the difference between a deployment that
	// is wrong at startup and one that looks like it works.
	if uint32(t.ID) != DefaultTable {
		return nil, fmt.Errorf("kernel: darwin has no routing tables, table %d has no meaning here", uint32(t.ID))
	}
	if t.Proto != DefaultProtocol {
		return nil, fmt.Errorf("kernel: darwin has no route protocol, protocol %d has no meaning here", t.Proto)
	}
	if t.Name() != "" {
		return nil, fmt.Errorf("kernel: darwin has no VRF, %s cannot be enslaved to %s", rt.Interface, t.Name())
	}
	if t.PrefSrc4.IsValid() {
		// The same reasoning as the three above. There is no RTA_PREFSRC here,
		// and the address a route prefers is whichever one the interface
		// carries, so a configuration that names one is asking for something
		// this platform decides for itself. Put the address on the tun with
		// kernel.addresses and source selection reaches the same answer.
		return nil, fmt.Errorf("kernel: darwin has no preferred source, prefsrc4 %s has no meaning here", t.PrefSrc4)
	}
	if len(rt.Interface) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("kernel: interface name %q does not fit an ifreq", rt.Interface)
	}
	host := hostOr(rt.Host)
	// the index is resolved once: netstack owns the utun for the whole process
	// lifetime, so a changed index means a different device and the routes of
	// the old one went with it.
	index, err := host.InterfaceIndex(rt.Interface)
	if err != nil {
		return nil, err
	}
	plat := &routePlatform{
		table: t, rt: rt, index: index, host: host,
		scoped:   make(map[netip.Prefix]netip.Prefix),
		warned:   make(map[Route]bool),
		occupied: make(map[occupiedKey]bool),
		refused:  make(map[occupiedKey]bool),
		ours:     make(map[occupiedKey]bool),
		pending:  make(map[Route]bool),
	}
	if err := plat.open(); err != nil {
		_ = plat.Close()
		return nil, err
	}
	return plat, nil
}

// open takes the descriptors the platform holds for its whole lifetime: the
// route socket every install goes out of, and the watcher that says when
// somebody else changed this interface's routing.
func (p *routePlatform) open() error {
	sock, err := routeSocket(p.host)
	if err != nil {
		return err
	}
	p.sock = sock
	p.watcher, err = p.host.Watch(p.index, 0, false)
	return err
}

func (p *routePlatform) Notify() <-chan struct{} { return p.watcher.Changed() }

// Close tolerates a partly opened platform, because newPlatform unwinds
// through it when one of the descriptors cannot be taken.
func (p *routePlatform) Close() error {
	var errs []error
	if p.watcher != nil {
		errs = append(errs, p.watcher.Close())
		p.watcher = nil
	}
	if p.sock != nil {
		errs = append(errs, p.sock.Close())
		p.sock = nil
	}
	return errors.Join(errs...)
}

// prefSrc mirrors what desired puts on an IPv4 route. It is not a property of
// a darwin route, so a dump takes it from the configuration, the way
// routeMetric answers for the metric. Without that the diff key differs from
// what the reconciler asked for on every pass.
func (p *routePlatform) prefSrc(destination netip.Prefix) netip.Addr {
	if destination.Addr().Is4() && p.table.PrefSrc4.IsValid() {
		return p.table.PrefSrc4.Addr
	}
	return netip.Addr{}
}

// rotateWarnings ends one deduplication window and starts the next. A window
// is one reconcile pass, which starts with a dump, so ownedRoutes is the only
// caller on the live path: it is the one place that knows the dump both
// arrived and parsed, and every record rotated here is refilled by the
// AddRoute calls a dump is followed by. A second call inside one pass, or a
// call from a path that will not go on to install, empties them.
func (p *routePlatform) rotateWarnings() {
	p.warned, p.pending = p.pending, make(map[Route]bool, len(p.pending))
	// occupied is rebuilt by the passes that refuse, the same way warned is,
	// so a destination the mesh has stopped asking for stops being carried.
	// Without this a node that meets a hundred foreign keys over its life
	// holds a hundred records forever, and a stale one hides a route from the
	// dump.
	//
	// Rotated only for a pass that will go on to install: a dump that fails,
	// in the kernel or in the parser, returns before any AddRoute refills the
	// record, and two such passes would empty it. On this platform that also
	// clears the exception decodeRoute reads, so a foreign key could be
	// adopted and reach a delete list.
	p.occupied, p.refused = p.refused, make(map[occupiedKey]bool, len(p.refused))
}

func (p *routePlatform) Routes() ([]Route, error) {
	if p.rt.Underlay != nil {
		p.underlay = p.rt.Underlay()
	}
	rib, err := p.host.Dump()
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
	// A pass starts once its dump has parsed, so this is where the answers
	// held for one pass are dropped: the same point rotateWarnings uses, and
	// for the same reason.
	p.assigned, p.assignedAt = nil, false
	// After the parse, not before it: a dump the kernel returns and this
	// library cannot read is a pass that will not reach any AddRoute either,
	// and rotating for it would empty the record two passes later. See
	// rotateWarnings.
	p.rotateWarnings()
	var out []Route
	stillScoped := make(map[netip.Prefix]bool, len(p.scoped))
	// Rebuilt rather than added to, so a route another program took over
	// between two passes stops being claimed as ours and is reported as held
	// the next time an install of it is refused.
	p.ours = make(map[occupiedKey]bool, len(p.ours))
	for _, message := range messages {
		decoded, ok := p.decodeRoute(message)
		if !ok {
			continue
		}
		out = append(out, decoded)
		p.ours[occupiedKey{destination: decoded.Destination, scoped: decoded.Scoped}] = true
		if decoded.Scoped {
			stillScoped[decoded.Destination] = true
		}
	}
	// p.scoped stands in for a source the FIB cannot hold, so it is a cache of
	// something only the kernel knows, and the kernel can drop a route without
	// telling this process: sleep and wake, a link change, another daemon's
	// flush. A record that outlives its route makes AddRoute refuse every
	// differently shaped scoped install at that destination as a second source
	// for one slot, which is reported as skipped and retried forever, so the
	// destination becomes uninstallable for the life of the process.
	for destination := range p.scoped {
		if !stillScoped[destination] {
			delete(p.scoped, destination)
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
// Neither RTF_REJECT nor RTF_IFSCOPE is among them: both are shapes this
// reconciler installs, the first for a held prefix and the second for an
// announced default or a source-specific route, so a route out of our own
// interface carrying either is one of ours by the same argument as every other
// route out of it. RTF_IFSCOPE is then checked again once the destination is
// known, because other daemons scope routes of their own.
const skipRouteFlags = unix.RTF_MULTICAST | unix.RTF_BROADCAST |
	unix.RTF_LOCAL | unix.RTF_WASCLONED | unix.RTF_LLINFO |
	unix.RTF_BLACKHOLE | unix.RTF_GATEWAY

// occupiedKey is the pair the darwin FIB keys a route by: the destination,
// and whether it is scoped to an interface. Recording only the
// destination let an unrelated write to the other key clear the record: a
// plain route installing successfully would forget that a foreign scoped route
// holds the same destination, and the next dump would then report that route
// as ours and withdraw it.
type occupiedKey struct {
	destination netip.Prefix
	scoped      bool
}

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
	if rm.Flags&unix.RTF_UP == 0 || rm.Flags&skipRouteFlags != 0 {
		return Route{}, false
	}
	if len(rm.Addrs) <= unix.RTAX_NETMASK {
		return Route{}, false
	}
	// the gateway is all that is left of an ownership marker on a platform
	// with no rt_proto: a route this reconciler installed leaves through the interface
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
	if prefix == limitedBroadcast {
		return Route{}, false
	}
	scoped := rm.Flags&unix.RTF_IFSCOPE != 0
	if _, tracked := p.scoped[prefix]; !tracked && p.occupied[occupiedKey{destination: prefix, scoped: scoped}] {
		// An install this process watched the kernel refuse, so another writer
		// holds this key and reporting the route as ours would withdraw it on
		// the next pass. The row's own scope is the one checked, because the
		// kernel keys on it: asking about the scoped key for every
		// row hid this reconciler's own unscoped route to the same
		// destination, which it then reinstalled and warned about on every
		// pass and never withdrew.
		//
		// The p.scoped escape is keyed by destination alone, because that is
		// how the source record is keyed, so a scoped route of ours at a
		// destination also lets the unscoped row at that destination through.
		// That is deliberate: the alternative is losing the source. What
		// reaches here at all is narrow, because p.ours is rebuilt from each
		// dump and every pass dumps before it installs, so a key refused in
		// this pass is one the last dump did not report. What this then
		// catches is the foreign route moving onto this
		// interface, under this gateway, after the refusal.
		return Route{}, false
	}
	source := p.scoped[prefix]
	if !scoped {
		// The kernel keys a scoped route separately from the unscoped route to
		// the same destination, so both can exist at once. Only the scoped one
		// carries a source; reporting the source on both would collapse them
		// into one entry in the diff and leave the unscoped route, which for
		// "::/0" is the whole machine's default, installed forever.
		source = netip.Prefix{}
	}
	// A scoped route this process did not install is reported anyway, with no
	// source, so that it can be withdrawn. Requiring a record of the install
	// made it invisible instead: an instance that attached to a tun it did not
	// create inherited its predecessor's scoped routes and could neither
	// withdraw them nor install over them, because darwin has no replace.
	//
	// It does mean taking over a scoped route out of this interface that
	// belongs to somebody else, which already happens to an unscoped one. The
	// interface is this process's, and another overlay scopes to its own. The source does not survive, so an inherited source-specific route
	// is withdrawn and reinstalled rather than recognized.
	return Route{
		Destination: prefix,
		// The kernel keeps no source, so a scoped route's source comes back
		// from what this process installed for that destination.
		Source:  source,
		PrefSrc: p.prefSrc(prefix),
		Metric:  routeMetric(p.table.Metric, prefix, rm.Flags&unix.RTF_REJECT != 0),
		// Read back rather than re-derived, because the kernel keys on it: an
		// unscoped default and a scoped one are two routes, and a withdrawal
		// that guessed from the destination would take out the wrong one and
		// leave the one it was asked for.
		Scoped:      scoped,
		Unreachable: rm.Flags&unix.RTF_REJECT != 0,
	}, true
}

// sourceIsOurs reports whether a source prefix covers an address on this
// interface, which interface scope can stand in for. Anything else is
// a prefix belonging to some other node and cannot be expressed here.
func (p *routePlatform) sourceIsOurs(source netip.Prefix) (bool, error) {
	assigned, err := p.passAddrs()
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
// itself, a sockaddr_dl carrying only its index, which
// "route -interface" sends and the only thing ifa_ifwithnet reads: ranet-lite
// picks the peer after the kernel hands over the packet, so there is no next
// hop to name.
//
// RTF_IFSCOPE is set by the caller, for the routes scopeRoute names. A
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
	if r.Destination == limitedBroadcast {
		// desired refuses this destination before the diff sees it, on both
		// platforms. The backstop is here because the reason is this one's:
		// decodeRoute drops it from every dump, so an install would succeed
		// once and then be invisible, and every later pass would re-add it,
		// get EEXIST, warn that another program holds a route this reconciler
		// wrote itself, and never withdraw it.
		return p.skipRoute(r, "the limited broadcast address is not a destination")
	}
	if r.Source.IsValid() {
		ours, err := p.sourceIsOurs(r.Source)
		if err != nil {
			return err
		}
		if !ours {
			// A source prefix that is not one of this interface's own
			// addresses cannot be expressed: interface scope selects on the
			// socket's bound address, so it can only stand in for "from an
			// address of ours". Reported in its own words, because an operator
			// reading the other message would look for a competing route and
			// find none: an exit announcing a default from a prefix this node
			// holds no address in is the ordinary case, one line per exit.
			return p.skipRoute(r, "no address of ours falls inside the source prefix")
		}
	}
	if p.scopeRoute(r) {
		if held, ok := p.scoped[r.Destination]; ok && held != r.Source {
			// Interface scope is one route per destination per interface, so a
			// second scoped route for the same destination has nowhere to go.
			// That covers a second source prefix and an announced default
			// competing with a source-specific route to the same destination.
			// Skipping says so once; installing would collide, and recording
			// it would make the two take turns being reported as installed.
			//
			// Which one is held is not an accident of arrival:
			// compareSourceSpecificity offers the most specific source first,
			// so the one kept is the one RFC 9079 section 4 would select.
			return p.skipSourceSpecific(r)
		}
	}
	message, err := p.routeMessage(unix.RTM_ADD, r)
	if err != nil {
		return err
	}
	if p.scopeRoute(r) {
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
		key := occupiedKey{destination: r.Destination, scoped: p.scopeRoute(r)}
		if p.ours[key] {
			// Already installed out of this interface, so the key is taken by
			// this reconciler and nothing is wrong. It is still reported as
			// skipped, because this call installed nothing and a pass that
			// counted it would claim to have repaired what it did not touch.
			return errRouteSkipped
		}
		p.refused[key] = true
		if !p.occupied[key] {
			p.occupied[key] = true
			slog.Warn("kernel is leaving a route that another program holds",
				"destination", r.Destination, "interface", p.rt.Interface,
				"detail", "darwin cannot replace a route, so this one was not installed")
		}
		return errRouteSkipped
	}
	installed := occupiedKey{destination: r.Destination, scoped: p.scopeRoute(r)}
	delete(p.occupied, installed)
	p.ours[installed] = true
	// Recorded only after the write lands, and only for a route that actually
	// carries the scope. An entry for a route that was never installed would
	// make decodeRoute report an unscoped route as carrying a source it does
	// not have, and the diff would then leave a plain route in place forever.
	if p.scopeRoute(r) {
		p.scoped[r.Destination] = r.Source
	}
	return nil
}

// scopeRoute decides whether a route is installed with RTF_IFSCOPE, which
// hides it from an ordinary lookup and shows it to a socket bound to an
// address on this interface. Anything it leaves unscoped is reachable from the
// Mac without every program binding first, which is the split tailscale makes
// on the same machine: its exit-node default is scoped to its utun, its
// 100.64/10 is not.
func (p *routePlatform) scopeRoute(r Route) bool {
	if standsInForASource(r) || holdsAgainstTheFIB(r) {
		return true
	}
	// A socket bound with IP_BOUND_IF looks up its routes scoped to the
	// interface the host's own default leaves by, so once the transport has
	// bound its own, a default out of the tun no longer takes the underlay
	// carrying it. Keeping the underlay out is the only reason those two were
	// scoped, and a scoped default is reached by nothing that did not name
	// this interface, so leaving the scope on is a Mac that holds a mesh
	// address and cannot use a mesh exit. See Config.BoundUnderlay, set from
	// the same configuration that binds the socket, and
	// TestDarwinBoundSocketNeedsAScopedDefault for the one thing the binding
	// does not do by itself.
	if p.rt.BoundUnderlay {
		// Not capturesTheMachine: a bound socket with a default scoped to its
		// own interface is not stranded by one, and hiding it from every
		// unbound socket leaves this Mac unable to use a mesh exit at all.
		//
		// coversAny stays either way. It is a different question: a prefix
		// holding a peer's own endpoint, 2000::/3 or a provider aggregate,
		// sends this node's ESP into the tunnel carrying it however the
		// socket is bound, because the peer is reached through the tun rather
		// than past it. Dropping this arm with the other one was a hole the
		// gate does not cover, since such a prefix is neither half the space
		// nor a route containing the family's zero address.
		return coversAny(r.Destination, p.underlay)
	}
	return capturesTheMachine(r) || coversAny(r.Destination, p.underlay)
}

// interface scope is the only thing on this platform that draws the
// distinction a source prefix draws.
func standsInForASource(r Route) bool { return r.Source.IsValid() }

// a hold answers with an error rather than carrying the packet, and this FIB
// is the only one the machine has, so unscoped it shadows whatever else could
// still reach the prefix, for the life of the process if this node originates
// it.
func holdsAgainstTheFIB(r Route) bool { return r.Unreachable }

// coversAny reports a prefix that takes an address the transport needs into
// the tun it is carrying. A default is not the only one that can: nothing
// bounds what a mesh member announces, and 2000::/3 or a provider aggregate
// holding a peer's endpoint does it as surely as ::/0. An empty list falls
// back to the destination's own length.
func coversAny(prefix netip.Prefix, addresses []netip.Addr) bool {
	return slices.ContainsFunc(addresses, prefix.Contains)
}

func (p *routePlatform) DelRoute(r Route) error {
	_, installed := p.scoped[r.Destination]
	if r.Source.IsValid() && !installed {
		// Nothing was installed for a source this backend cannot express, and
		// the FIB holds no source, so deleting what is left after dropping it
		// would take out whatever else holds that destination. For the
		// announced default that is the machine's own default route.
		//
		// The reconciler's own delete list cannot reach this: it holds only
		// routes the dump reported, and the dump attaches a source only from
		// p.scoped, so installed is true for every one of them. It is here
		// because the cost of being wrong about that is the whole machine's
		// routing, and because withdraw and the tests reach DelRoute directly.
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
	// The kernel keys a scoped route separately from the unscoped route to the
	// same destination, so the delete has to carry the flag the dump reported
	// for this route. Re-deriving it from the destination would make every
	// withdrawal of an unscoped default take out the scoped route instead and
	// leave the unscoped one, which the next pass then tries to delete again.
	if r.Scoped {
		message.Flags |= unix.RTF_IFSCOPE
	}
	if err := p.sock.WriteRoute(message); err != nil && !gone(err) {
		return err
	}
	// Dropped only once the route is gone, so a failed delete leaves the entry
	// and the next pass decodes the route and tries again. The record follows
	// the scope of the route that was withdrawn rather than the scope this
	// backend would have chosen for it: an unscoped route to a destination
	// that also holds a scoped one would otherwise wipe the scoped route's
	// source, and the next pass would tear that route down and reinstall it.
	if r.Scoped {
		delete(p.scoped, r.Destination)
	}
	withdrawn := occupiedKey{destination: r.Destination, scoped: r.Scoped}
	delete(p.occupied, withdrawn)
	delete(p.ours, withdrawn)
	return nil
}

// skipRoute reports a route this backend will not install, once per route
// rather than once per pass, naming why. errRouteSkipped rather than a failure
// is deliberate: the reconciler would otherwise retry with backoff forever
// over something no retry can fix, and the mesh's own table still forwards it.
func (p *routePlatform) skipRoute(r Route, why string) error {
	key := Route{Destination: r.Destination, Source: r.Source}
	if !p.warned[key] {
		slog.Warn("kernel is leaving a route uninstalled: "+why,
			"destination", r.Destination, "source", r.Source)
	}
	p.pending[key] = true
	return errRouteSkipped
}

// skipSourceSpecific is the case that reaches skipRoute most: the darwin FIB
// holds one source per destination, so a second source or a plain route
// competing with a source-specific one at the same destination cannot be
// expressed at all.
func (p *routePlatform) skipSourceSpecific(r Route) error {
	return p.skipRoute(r, "the darwin FIB holds one source per destination")
}

// passAddrs is Addrs for one reconcile pass, read once however many routes
// ask. A failure is not cached, so the next asker retries it, which is how a
// transient dump failure recovers.
func (p *routePlatform) passAddrs() ([]netip.Prefix, error) {
	if p.assignedAt {
		return p.assigned, nil
	}
	assigned, err := p.Addrs()
	if err != nil {
		return nil, err
	}
	p.assigned, p.assignedAt = assigned, true
	return assigned, nil
}

func (p *routePlatform) Addrs() ([]netip.Prefix, error) {
	if p.addrs != nil {
		return p.addrs()
	}
	assigned, err := p.host.Addresses(p.index)
	if err != nil {
		return nil, fmt.Errorf("kernel: read the addresses of %s: %w", p.rt.Interface, err)
	}
	return assigned, nil
}

// interfaceAddrs reports every address on the interface, whoever put it there,
// which the reconciler needs to decide that a configured address is
// already present. It removes nothing and decides nothing.
func interfaceAddrs(index int, rib []byte) ([]netip.Prefix, error) {
	messages, err := route.ParseRIB(route.RIBTypeInterface, rib)
	if err != nil {
		return nil, fmt.Errorf("kernel: parse the address dump: %w", err)
	}
	var out []netip.Prefix
	for _, message := range messages {
		am, ok := message.(*route.InterfaceAddrMessage)
		if !ok || am.Index != index || len(am.Addrs) <= unix.RTAX_IFA {
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

// AddAddr puts one configured address on the device. Which ioctl that is, and
// which control socket carries it, is the host's business; see
// runningKernel.Assign.
func (p *routePlatform) AddAddr(prefix netip.Prefix) error {
	return p.host.Assign(true, p.rt.Interface, prefix)
}

// DelAddr removes one address, and is reached only for an address the
// reconciler added itself in this process lifetime. An address that is already
// gone is not a failure: the next pass would do nothing about it either.
func (p *routePlatform) DelAddr(prefix netip.Prefix) error {
	if err := p.host.Assign(false, p.rt.Interface, prefix); err != nil && !gone(err) {
		return err
	}
	return nil
}

// Master reports no master, always. darwin has no VRF and no master device of
// any kind, so the reconciler's "leave a link somebody else owns alone" branch
// is unreachable here and Enslave is the error that says so.
func (p *routePlatform) Master() (string, error) { return "", nil }

func (p *routePlatform) Enslave(master string) error {
	return fmt.Errorf("kernel: darwin has no VRF, %s cannot be enslaved to %s", p.rt.Interface, master)
}

// Release is unreachable: the reconciler releases only what it enslaved, and
// Enslave never succeeds.
func (p *routePlatform) Release() error { return nil }

// where is the interface itself: darwin has one FIB and no routing tables.
func (p *routePlatform) where(Table) string { return "interface " + p.rt.Interface }

// scopes is scopeRoute as the diff reads it.
func (p *routePlatform) scopes(r Route) bool { return p.scopeRoute(r) }
