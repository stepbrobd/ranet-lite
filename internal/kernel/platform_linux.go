//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// netlinkConn is everything this backend asks of a netlink socket. Reaching
// AddRoute, DelRoute or AddAddr without it means opening a real socket, which
// needs root, so the checks skip them and a change to what this backend writes
// goes unnoticed on the platform the fleet runs. darwin's rtSocket is the same
// seam.
type netlinkConn interface {
	execute(kind, flags uint16, body []byte) ([]nlMessage, error)
	link(name string) (index, master uint32, err error)
	linkName(index uint32) (string, error)
	Close() error
}

// netlinkPlatform is the rtnetlink half of the reconciler. Nothing here
// decides what the kernel should hold; it only encodes the decision and
// enforces the ownership marker on the way back in, so a route without the
// reconciler's protocol, table and interface never reaches the diff.
type netlinkPlatform struct {
	cfg     Config
	index   uint32
	conn    netlinkConn
	monitor *routeMonitor

	// occupied remembers routes already reported as held by another writer.
	// A foreign route on our key does not go away by itself, so every pass
	// would otherwise repeat the same warning. Only the reconcile loop touches
	// this, and it runs one pass at a time.
	occupied map[string]bool
}

func newPlatform(cfg Config) (platform, error) {
	conn, err := dialNetlink()
	if err != nil {
		return nil, err
	}
	// the index is resolved once: netstack owns the TUN for the whole
	// process lifetime, so a changed index means a different device and the
	// routes of the old one are already gone with it.
	index, _, err := conn.link(cfg.Interface)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("kernel: look up interface %s: %w", cfg.Interface, err)
	}
	monitor, err := newRouteMonitor(cfg.Table)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &netlinkPlatform{cfg: cfg, index: index, conn: conn, monitor: monitor, occupied: make(map[string]bool)}, nil
}

func (p *netlinkPlatform) Notify() <-chan struct{} { return p.monitor.signal }

func (p *netlinkPlatform) Close() error {
	return errors.Join(p.monitor.Close(), p.conn.Close())
}

func (p *netlinkPlatform) Routes() ([]Route, error) {
	var out []Route
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		body := make([]byte, unix.SizeofRtMsg)
		body[0] = family
		// the kernel honors dump filters only on a strict-check socket, so
		// the protocol, table and interface filter is applied here instead.
		replies, err := p.conn.execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP, body)
		if err != nil {
			return nil, err
		}
		for _, reply := range replies {
			if route, ok := p.decodeRoute(reply); ok {
				out = append(out, route)
			}
		}
	}
	return out, nil
}

// decodeRoute keeps only the routes this reconciler owns. Everything else in
// the dump belongs to somebody else, so it is dropped here and can never reach
// a delete list.
func (p *netlinkPlatform) decodeRoute(message nlMessage) (Route, bool) {
	if message.Kind != unix.RTM_NEWROUTE || len(message.Data) < unix.SizeofRtMsg {
		return Route{}, false
	}
	family, dstLen, srcLen := message.Data[0], message.Data[1], message.Data[2]
	table, protocol, kind := uint32(message.Data[4]), message.Data[5], message.Data[7]
	if protocol != p.cfg.Protocol || (kind != unix.RTN_UNICAST && kind != unix.RTN_UNREACHABLE) {
		return Route{}, false
	}
	if family != unix.AF_INET && family != unix.AF_INET6 {
		return Route{}, false
	}
	var destination, source, prefsrc netip.Addr
	var oif, metric uint32
	for attr, value := range message.attributes(unix.SizeofRtMsg) {
		switch attr {
		case unix.RTA_TABLE:
			// rtm_table is a byte, so a table above 255 only exists here.
			if len(value) == 4 {
				table = binary.NativeEndian.Uint32(value)
			}
		case unix.RTA_DST:
			destination, _ = addressFromBytes(value)
		case unix.RTA_SRC:
			source, _ = addressFromBytes(value)
		case unix.RTA_PREFSRC:
			prefsrc, _ = addressFromBytes(value)
		case unix.RTA_OIF:
			if len(value) == 4 {
				oif = binary.NativeEndian.Uint32(value)
			}
		case unix.RTA_PRIORITY:
			if len(value) == 4 {
				metric = binary.NativeEndian.Uint32(value)
			}
		}
	}
	// An unreachable hold names no device, so only the table and the protocol
	// identify it. Both are this reconciler's own marker.
	if table != p.cfg.Table || (kind == unix.RTN_UNICAST && oif != p.index) {
		return Route{}, false
	}
	if !destination.IsValid() {
		destination = unspecified(family) // an absent RTA_DST is the default route
	}
	if destination.Is4() != (family == unix.AF_INET) {
		return Route{}, false
	}
	prefix, ok := canonicalPrefix(netip.PrefixFrom(destination, int(dstLen)))
	if !ok {
		return Route{}, false
	}
	decoded := Route{
		Destination: prefix, PrefSrc: prefsrc, Metric: metric,
		Unreachable: kind == unix.RTN_UNREACHABLE,
	}
	if srcLen > 0 {
		if !source.IsValid() {
			return Route{}, false
		}
		if decoded.Source, ok = canonicalPrefix(netip.PrefixFrom(source, int(srcLen))); !ok {
			return Route{}, false
		}
	}
	return decoded, true
}

// routeMessage encodes one RTM_NEWROUTE or RTM_DELROUTE body. A delete carries
// rtm_protocol deliberately: the kernel then matches on it, so even a bug in
// the diff cannot remove a route belonging to another protocol.
func (p *netlinkPlatform) routeMessage(route Route, del bool) []byte {
	family, scope := uint8(unix.AF_INET6), uint8(unix.RT_SCOPE_UNIVERSE)
	if route.Destination.Addr().Is4() {
		// an IPv4 route out of a device with no gateway is link scope, which
		// is what iproute2 sends and what fib_check_nh expects.
		family, scope = unix.AF_INET, unix.RT_SCOPE_LINK
	}
	kind := uint8(unix.RTN_UNICAST)
	if route.Unreachable {
		// A hold, not a path. It has no output interface and no scope of its
		// own: fib_check_nh is not consulted for a route that resolves to an
		// error, and naming a device would make the kernel reject it.
		kind, scope = unix.RTN_UNREACHABLE, unix.RT_SCOPE_UNIVERSE
	}
	if del {
		// RT_SCOPE_NOWHERE and RTN_UNSPEC are the kernel's wildcards in a
		// delete match, the way "ip route del" leaves them.
		scope, kind = unix.RT_SCOPE_NOWHERE, unix.RTN_UNSPEC
	}
	srcLen := 0
	if route.Source.IsValid() {
		srcLen = route.Source.Bits()
	}
	table := uint8(unix.RT_TABLE_UNSPEC)
	if p.cfg.Table <= 255 {
		table = uint8(p.cfg.Table)
	}

	body := make([]byte, unix.SizeofRtMsg)
	body[0] = family
	body[1] = uint8(route.Destination.Bits())
	body[2] = uint8(srcLen)
	body[4] = table
	body[5] = p.cfg.Protocol
	body[6] = scope
	body[7] = kind
	body = putAttrU32(body, unix.RTA_TABLE, p.cfg.Table)
	if route.Destination.Bits() > 0 {
		body = putAttr(body, unix.RTA_DST, addressBytes(route.Destination.Addr()))
	}
	if srcLen > 0 {
		body = putAttr(body, unix.RTA_SRC, addressBytes(route.Source.Addr()))
	}
	if !route.Unreachable {
		body = putAttrU32(body, unix.RTA_OIF, p.index)
	}
	if route.PrefSrc.IsValid() {
		body = putAttr(body, unix.RTA_PREFSRC, addressBytes(route.PrefSrc))
	}
	// the metric is always explicit: leaving it out would let the kernel pick
	// its own, and a delete has to name the same one to match the route.
	body = putAttrU32(body, unix.RTA_PRIORITY, route.Metric)
	return body
}

func (p *netlinkPlatform) AddRoute(route Route) error {
	// EXCL rather than REPLACE. A replace takes over whatever sits first at the
	// same prefix, tos and priority no matter who wrote it: fib_table_insert
	// compares neither rtm_protocol nor the route type. In a VRF table, which
	// is what a gravity node gives this reconciler, that first entry is the
	// kernel's own RTPROT_KERNEL local and connected route for an address on an
	// enslaved link, sitting at priority 0 where an IPv4 route with no
	// configured metric also sits. Replacing it would stop the node reaching
	// its own address, and withdraw would not put it back, because DelRoute
	// matches on our protocol.
	//
	// Refusing instead costs an update that changes only a non-key attribute,
	// a preferred source at an unchanged metric. applyRoutes withdraws before
	// it installs so that case arrives here as a plain add.
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK)
	_, err := p.conn.execute(unix.RTM_NEWROUTE, flags, p.routeMessage(route, false))
	if errors.Is(err, unix.EEXIST) {
		if key := route.String(); !p.occupied[key] {
			p.occupied[key] = true
			slog.Warn("kernel is leaving a route that another writer holds",
				"route", key, "table", p.cfg.Table,
				"detail", "something else holds this prefix at this metric in this table, so it was not installed")
		}
		// Not a failure and not an install. Reported as an error it would put
		// the whole pass into backoff over a key no retry can free, once per
		// pass, forever.
		return errRouteSkipped
	}
	if errors.Is(err, unix.EINVAL) && route.PrefSrc.IsValid() {
		// The one EINVAL with a cause an operator can act on, and the reason
		// this names it rather than leaving "invalid argument" to be guessed
		// at: the kernel refuses RTA_PREFSRC that is not an address of this
		// box, and every IPv4 route this reconciler installs carries the
		// configured prefsrc4. So one wrong address in the config file takes
		// out IPv4 routing entirely, on every pass, for the life of the
		// process. It stays a retried failure rather than a startup refusal
		// because the address is normally the node's own mesh address, which
		// this same reconciler assigns, so the first passes can legitimately
		// run before it is there.
		err = fmt.Errorf("%w (prefsrc %s is not an address of this host)", err, route.PrefSrc)
	}
	if err == nil {
		delete(p.occupied, route.String())
	}
	return err
}

func (p *netlinkPlatform) DelRoute(route Route) error {
	_, err := p.conn.execute(unix.RTM_DELROUTE, unix.NLM_F_ACK, p.routeMessage(route, true))
	if gone(err) {
		err = nil
	}
	if err == nil {
		// A route that left the desired set takes its warn-once record with
		// it, or the map keeps an entry for a key nothing asks about again.
		delete(p.occupied, route.String())
	}
	return err
}

func (p *netlinkPlatform) Addrs() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		body := make([]byte, unix.SizeofIfAddrmsg)
		body[0] = family
		replies, err := p.conn.execute(unix.RTM_GETADDR, unix.NLM_F_DUMP, body)
		if err != nil {
			return nil, err
		}
		for _, reply := range replies {
			if prefix, ok := p.decodeAddr(reply); ok {
				out = append(out, prefix)
			}
		}
	}
	return out, nil
}

func (p *netlinkPlatform) decodeAddr(message nlMessage) (netip.Prefix, bool) {
	if message.Kind != unix.RTM_NEWADDR || len(message.Data) < unix.SizeofIfAddrmsg {
		return netip.Prefix{}, false
	}
	prefixLen := message.Data[1]
	if binary.NativeEndian.Uint32(message.Data[4:]) != p.index {
		return netip.Prefix{}, false
	}
	var local, address netip.Addr
	for attr, value := range message.attributes(unix.SizeofIfAddrmsg) {
		switch attr {
		case unix.IFA_LOCAL:
			local, _ = addressFromBytes(value)
		case unix.IFA_ADDRESS:
			address, _ = addressFromBytes(value)
		}
	}
	// IFA_LOCAL is the address on this end; IFA_ADDRESS is the peer's on a
	// point-to-point link, and the same value everywhere else.
	if !local.IsValid() {
		local = address
	}
	if !local.IsValid() {
		return netip.Prefix{}, false
	}
	prefix := netip.PrefixFrom(local, int(prefixLen))
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	return prefix, true
}

func (p *netlinkPlatform) addrMessage(prefix netip.Prefix) []byte {
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = unix.AF_INET6
	if prefix.Addr().Is4() {
		body[0] = unix.AF_INET
	}
	body[1] = uint8(prefix.Bits())
	body[3] = unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(body[4:], p.index)
	raw := addressBytes(prefix.Addr())
	// with no peer address the two attributes carry the same value, which is
	// what "ip addr add" sends; IPv4 reads IFA_LOCAL and IPv6 IFA_ADDRESS.
	body = putAttr(body, unix.IFA_LOCAL, raw)
	body = putAttr(body, unix.IFA_ADDRESS, raw)
	return body
}

func (p *netlinkPlatform) AddAddr(prefix netip.Prefix) error {
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_REPLACE | unix.NLM_F_ACK)
	_, err := p.conn.execute(unix.RTM_NEWADDR, flags, p.addrMessage(prefix))
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

func (p *netlinkPlatform) DelAddr(prefix netip.Prefix) error {
	_, err := p.conn.execute(unix.RTM_DELADDR, unix.NLM_F_ACK, p.addrMessage(prefix))
	if gone(err) {
		return nil
	}
	return err
}

func (p *netlinkPlatform) Master() (string, error) {
	_, master, err := p.conn.link(p.cfg.Interface)
	if err != nil {
		return "", err
	}
	if master == 0 {
		return "", nil
	}
	return p.conn.linkName(master)
}

func (p *netlinkPlatform) Enslave(master string) error {
	index, _, err := p.conn.link(master)
	if err != nil {
		return err
	}
	return p.setMaster(index)
}

func (p *netlinkPlatform) Release() error {
	if err := p.setMaster(0); err != nil && !gone(err) {
		return err
	}
	return nil
}

// setMaster is RTM_NEWLINK without NLM_F_CREATE, which the kernel treats as a
// change to the existing link, the same request "ip link set master" sends.
func (p *netlinkPlatform) setMaster(master uint32) error {
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], p.index)
	body = putAttrU32(body, unix.IFLA_MASTER, master)
	_, err := p.conn.execute(unix.RTM_NEWLINK, unix.NLM_F_ACK, body)
	return err
}

// routeMonitor turns unsolicited route notifications into one coalesced
// wake-up. It parses just enough of each message to drop notifications for
// tables the reconciler does not own, which stops another daemon's
// route churn from waking it. Its own writes still wake it once; the settle
// window in Run absorbs the burst and the following pass finds nothing to do.
type routeMonitor struct {
	file   *os.File
	table  uint32
	signal chan struct{}
	done   chan struct{}
}

func newRouteMonitor(table uint32) (*routeMonitor, error) {
	fd, err := unix.Socket(unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("kernel: open route monitor socket: %w", err)
	}
	groups := uint32(unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("kernel: join route notification groups: %w", err)
	}
	// a large receive buffer keeps a route flood from costing an ENOBUFS,
	// which is survivable but forces a full resync.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	// the socket is nonblocking, so os.NewFile registers it with the runtime
	// poller and Close unblocks the reader without racing on the descriptor.
	monitor := &routeMonitor{
		file:   os.NewFile(uintptr(fd), "rtnetlink-monitor"),
		table:  table,
		signal: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	go monitor.run()
	return monitor, nil
}

func (m *routeMonitor) run() {
	defer close(m.done)
	buf := make([]byte, 64*1024)
	for {
		n, err := m.file.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			// ENOBUFS means notifications were dropped, which is exactly when
			// a reconcile is most needed. Anything else is unexpected and
			// would spin, so it is reported and the monitor stops; the
			// periodic sweep in Run remains as the backstop.
			m.wake()
			if errors.Is(err, unix.ENOBUFS) {
				slog.Debug("kernel route notifications dropped, resyncing")
				continue
			}
			slog.Warn("kernel route monitor stopped, falling back to the periodic sweep", "err", err)
			return
		}
		messages, err := parseMessages(buf[:n])
		if err != nil {
			m.wake() // a notification we could not parse still means something changed
			continue
		}
		for _, message := range messages {
			if message.Kind != unix.RTM_NEWROUTE && message.Kind != unix.RTM_DELROUTE {
				continue
			}
			if notificationTable(message) == m.table {
				m.wake()
				break
			}
		}
	}
}

// wake never blocks: a reader that misses one coalesced signal sees the change
// on the next one, or on the periodic sweep.
func (m *routeMonitor) wake() {
	select {
	case m.signal <- struct{}{}:
	default:
	}
}

func (m *routeMonitor) Close() error {
	err := m.file.Close()
	<-m.done
	return err
}

func notificationTable(message nlMessage) uint32 {
	if len(message.Data) < unix.SizeofRtMsg {
		return 0
	}
	table := uint32(message.Data[4])
	for attr, value := range message.attributes(unix.SizeofRtMsg) {
		if attr == unix.RTA_TABLE && len(value) == 4 {
			return binary.NativeEndian.Uint32(value)
		}
	}
	return table
}

// foreignWriters names the routing protocols other than this reconciler's that
// already have unicast routes in the table it is about to take over.
//
// It exists because an install asks for the route exclusively and reports a key
// another writer already holds rather than taking it over, so a second writer
// in one table means routes the mesh wanted are silently not installed.
// Everything else on a host keeps to its own table: Tailscale
// uses 52, and BIRD on a ranet fleet node uses 200, which is exactly the table
// this reconciler is pointed at during a migration. Reporting it is the
// difference between a migration that looks fine and one that is visibly
// sharing a table.
func (p *netlinkPlatform) foreignWriters() ([]string, error) {
	seen := map[uint8]bool{}
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		body := make([]byte, unix.SizeofRtMsg)
		body[0] = family
		replies, err := p.conn.execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP, body)
		if err != nil {
			return nil, err
		}
		collectForeignWriters(replies, p.cfg.Table, p.cfg.Protocol, seen)
	}
	// Labeled here rather than by the caller, because rt_proto is a linux
	// registry and kernel.go is the portable half. Returning the numbers bare
	// also renders them unreadably: slog's text handler quotes a []uint8 as a
	// byte string, so protocols 2 and 12 reach an operator as "\x02\f".
	labels := make([]string, 0, len(seen))
	for _, protocol := range slices.Sorted(maps.Keys(seen)) {
		labels = append(labels, protocolLabel(protocol))
	}
	return labels, nil
}

// protocolLabel names a routing protocol the way iproute2 prints it, from the
// rt_protos registry, and falls back to the bare number for one nothing has
// claimed. The two a fleet node meets in table 200 are bird and the kernel's
// own entries for the links enslaved to the VRF.
func protocolLabel(protocol uint8) string {
	var name string
	switch protocol {
	case unix.RTPROT_REDIRECT:
		name = "redirect"
	case unix.RTPROT_KERNEL:
		name = "kernel"
	case unix.RTPROT_BOOT:
		name = "boot"
	case unix.RTPROT_STATIC:
		name = "static"
	case unix.RTPROT_RA:
		name = "ra"
	case unix.RTPROT_ZEBRA:
		name = "zebra"
	case unix.RTPROT_BIRD:
		name = "bird"
	case unix.RTPROT_DHCP:
		name = "dhcp"
	case unix.RTPROT_KEEPALIVED:
		name = "keepalived"
	case unix.RTPROT_BABEL:
		name = "babel"
	case unix.RTPROT_OPENR:
		name = "openr"
	case unix.RTPROT_BGP:
		name = "bgp"
	case unix.RTPROT_ISIS:
		name = "isis"
	case unix.RTPROT_OSPF:
		name = "ospf"
	case unix.RTPROT_RIP:
		name = "rip"
	case unix.RTPROT_EIGRP:
		name = "eigrp"
	default:
		return strconv.Itoa(int(protocol))
	}
	return name + " (" + strconv.Itoa(int(protocol)) + ")"
}

// collectForeignWriters is the filter half of foreignWriters, split out so the
// rule can be tested without a netlink socket.
func collectForeignWriters(replies []nlMessage, table uint32, ours uint8, seen map[uint8]bool) {
	for _, reply := range replies {
		if reply.Kind != unix.RTM_NEWROUTE || len(reply.Data) < unix.SizeofRtMsg {
			continue
		}
		routeTable, protocol, kind := uint32(reply.Data[4]), reply.Data[5], reply.Data[7]
		if kind != unix.RTN_UNICAST || protocol == ours {
			continue
		}
		for attr, value := range reply.attributes(unix.SizeofRtMsg) {
			if attr == unix.RTA_TABLE && len(value) == 4 {
				routeTable = binary.NativeEndian.Uint32(value)
			}
		}
		// RTPROT_KERNEL is excluded only in the main table, where it is the
		// kernel's own plumbing for the machine's addresses. In any other
		// table, and a VRF table is the case that matters, those same entries
		// belong to whoever put the interface in the VRF and are exactly what
		// an install must not take over.
		if routeTable != table {
			continue
		}
		if protocol == unix.RTPROT_KERNEL && table == unix.RT_TABLE_MAIN {
			continue
		}
		seen[protocol] = true
	}
}
