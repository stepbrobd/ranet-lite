//go:build darwin && !ios

package kernel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// testIndex is the interface index every test in this file pretends to own.
// Nothing here opens a socket, so it names no real device.
const testIndex = 42

// fakeRouteSocket stands in for PF_ROUTE. It keeps what the platform sent in
// the form the kernel would have seen, so the assertions below are about the
// wire encoding rather than about the structure that produced it.
type fakeRouteSocket struct {
	t    *testing.T
	sent [][]byte
	err  error
}

func (f *fakeRouteSocket) WriteRoute(message *route.RouteMessage) error {
	f.t.Helper()
	message.Version = unix.RTM_VERSION
	raw, err := message.Marshal()
	if err != nil {
		f.t.Fatalf("marshal a routing message: %v", err)
	}
	f.sent = append(f.sent, raw)
	return f.err
}

func (f *fakeRouteSocket) Close() error { return nil }

// messages parses back what was sent, which is the round trip the tests assert
// on: a message the kernel's own parser cannot read is a message the kernel
// cannot act on either.
func (f *fakeRouteSocket) messages(t *testing.T) []*route.RouteMessage {
	t.Helper()
	var out []*route.RouteMessage
	for _, raw := range f.sent {
		parsed, err := route.ParseRIB(route.RIBTypeRoute, raw)
		if err != nil {
			t.Fatalf("parse back a sent message: %v", err)
		}
		for _, message := range parsed {
			rm, ok := message.(*route.RouteMessage)
			if !ok {
				t.Fatalf("a sent message parsed back as %T", message)
			}
			out = append(out, rm)
		}
	}
	return out
}

func testPlatform(t *testing.T, cfg Config) (*routePlatform, *fakeRouteSocket) {
	t.Helper()
	if cfg.Interface == "" {
		cfg.Interface = "utun9"
	}
	sock := &fakeRouteSocket{t: t}
	return &routePlatform{
		cfg: cfg, index: testIndex, sock: sock,
		control4: -1, control6: -1,
		warned:   make(map[Route]bool),
		pending:  make(map[Route]bool),
		scoped:   make(map[netip.Prefix]netip.Prefix),
		occupied: make(map[occupiedKey]bool),
		refused:  make(map[occupiedKey]bool),
		ours:     make(map[occupiedKey]bool),
		// No address belongs to this interface unless a test says so, which
		// makes "the source is not ours" the default rather than an accident
		// of whatever the host running the suite happens to have configured.
		addrs: func() ([]netip.Prefix, error) { return nil, nil },
	}, sock
}

// dumpEntry is one route as NET_RT_DUMP would report it.
type dumpEntry struct {
	index   int
	flags   int
	dst     netip.Prefix
	gateway route.Addr
	// hostRoute drops the netmask, which is how the kernel reports a route
	// carrying RTF_HOST.
	hostRoute bool
}

// dumpRIB encodes entries as a NET_RT_DUMP snapshot. Every entry the kernel
// returns is an RTM_GET, so that is what these are.
func dumpRIB(t *testing.T, entries ...dumpEntry) []byte {
	t.Helper()
	var rib []byte
	for _, entry := range entries {
		addrs := make([]route.Addr, unix.RTAX_MAX)
		addrs[unix.RTAX_DST] = routeAddr(entry.dst.Addr())
		addrs[unix.RTAX_GATEWAY] = entry.gateway
		if !entry.hostRoute {
			mask, ok := prefixMask(entry.dst)
			if !ok {
				t.Fatalf("no netmask for %s", entry.dst)
			}
			addrs[unix.RTAX_NETMASK] = routeAddr(mask)
		}
		message := &route.RouteMessage{
			Version: unix.RTM_VERSION,
			Type:    unix.RTM_GET,
			Flags:   entry.flags,
			Index:   entry.index,
			Addrs:   addrs,
		}
		raw, err := message.Marshal()
		if err != nil {
			t.Fatalf("marshal a dump entry: %v", err)
		}
		rib = append(rib, raw...)
	}
	return rib
}

func ourGateway() route.Addr { return &route.LinkAddr{Index: testIndex} }

func TestDarwinRouteMessageNamesInterfaceAsItsGateway(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	if err := plat.AddRoute(Route{Destination: prefix("198.51.100.0/24")}); err != nil {
		t.Fatalf("add a route: %v", err)
	}
	if err := plat.DelRoute(Route{Destination: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}); err != nil {
		t.Fatalf("delete a route: %v", err)
	}

	sent := sock.messages(t)
	if len(sent) != 2 {
		t.Fatalf("sent %d messages, want 2", len(sent))
	}

	add, del := sent[0], sent[1]
	if add.Type != unix.RTM_ADD || del.Type != unix.RTM_DELETE {
		t.Fatalf("message types are %d and %d, want %d and %d",
			add.Type, del.Type, unix.RTM_ADD, unix.RTM_DELETE)
	}
	for _, message := range sent {
		if message.Flags != unix.RTF_UP|unix.RTF_STATIC {
			t.Errorf("flags are %#x, want RTF_UP|RTF_STATIC only: a scoped or host route "+
				"resolves its output interface differently", message.Flags)
		}
		if message.Index != testIndex {
			t.Errorf("rtm_index is %d, want %d", message.Index, testIndex)
		}
		// the gateway is what decides ownership on darwin: it has to be the
		// interface itself, never an address.
		gateway, ok := message.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok {
			t.Fatalf("the gateway is %T, want a link address", message.Addrs[unix.RTAX_GATEWAY])
		}
		if gateway.Index != testIndex {
			t.Errorf("the gateway names interface %d, want %d", gateway.Index, testIndex)
		}
	}

	destination, ok := addressFromRouteAddr(add.Addrs[unix.RTAX_DST])
	if !ok || destination != addr("198.51.100.0") {
		t.Errorf("the destination is %v, want 198.51.100.0", add.Addrs[unix.RTAX_DST])
	}
	mask, ok := addressFromRouteAddr(add.Addrs[unix.RTAX_NETMASK])
	if !ok || mask != addr("255.255.255.0") {
		t.Errorf("the netmask is %v, want 255.255.255.0", add.Addrs[unix.RTAX_NETMASK])
	}
	if mask6, ok := addressFromRouteAddr(del.Addrs[unix.RTAX_NETMASK]); !ok || mask6 != addr("ffff:ffff:ffff::") {
		t.Errorf("the IPv6 netmask is %v, want ffff:ffff:ffff::", del.Addrs[unix.RTAX_NETMASK])
	}
}

// The half-default pair is included because that is how a default that leaves
// the host's own in place is written, and it is the shape that captures the
// machine outright rather than merely colliding: every destination matches it
// at a longer prefix than the box's /0.
func TestDarwinScopesPlainDefaults(t *testing.T) {
	for _, destination := range []string{
		"0.0.0.0/0", "::/0",
		"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1",
	} {
		t.Run(destination, func(t *testing.T) {
			plat, sock := testPlatform(t, Config{})
			announced := Route{Destination: prefix(destination)}
			announced.Metric = plat.metric(announced.Destination)
			if err := plat.AddRoute(announced); err != nil {
				t.Fatal(err)
			}
			written := sock.messages(t)
			if len(written) != 1 {
				t.Fatalf("install wrote %d messages, want 1", len(written))
			}
			if written[0].Flags&unix.RTF_IFSCOPE == 0 || written[0].Index != testIndex {
				t.Fatalf("default %s was installed without interface scope, so it can capture the ESP underlay", destination)
			}
			rib := dumpRIB(t, dumpEntry{
				index: testIndex, flags: written[0].Flags,
				dst: announced.Destination, gateway: ourGateway(),
			})
			actual, err := plat.ownedRoutes(rib)
			if err != nil {
				t.Fatal(err)
			}
			if add, del := diffRoutes([]Route{announced}, actual, plat.scopes); len(add) != 0 || len(del) != 0 {
				t.Fatalf("installed plain default did not converge: add %v, delete %v", add, del)
			}
			if err := plat.DelRoute(actual[0]); err != nil {
				t.Fatal(err)
			}
			if deleted := sock.messages(t); len(deleted) != 2 || deleted[1].Flags&unix.RTF_IFSCOPE == 0 {
				t.Fatal("withdrawing the plain default did not select its interface scope")
			}
		})
	}
}

// An announced default is the one route that can capture this machine: darwin
// has one FIB, Config.Table is meaningless here, and nothing keeps the peers'
// own endpoints out of it, so the ESP underlay would route into the tun
// carrying it.
func TestDarwinAnnouncedDefaultDoesNotCaptureUnderlay(t *testing.T) {
	requireNetTest(t)
	device, tun := createUTUNWithFD(t)
	setInterfaceUp(t, device)
	plat, err := newPlatform(Config{
		Interface: device, Table: DefaultTable, Protocol: DefaultProtocol,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plat.Close() })
	local := prefix("198.51.100.1/32")
	if err := plat.AddAddr(local); err != nil {
		t.Fatal(err)
	}
	if err := plat.AddRoute(Route{Destination: prefix("0.0.0.0/0")}); err != nil {
		t.Fatal(err)
	}
	target := addr("203.0.113.9").As4()
	probe := func(bound bool) bool {
		t.Helper()
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if bound {
			if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: local.Addr().As4()}); err != nil {
				t.Fatal(err)
			}
		}
		drainTUN(tun)
		payload := []byte("ranet plain route scope probe")
		if err := unix.Sendto(fd, payload, 0, &unix.SockaddrInet4{Addr: target, Port: 9}); err != nil {
			if !bound && (errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH)) {
				return false
			}
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		deadline := time.Now().Add(300 * time.Millisecond)
		for time.Now().Before(deadline) {
			n, err := unix.Read(tun, buf)
			// address assignment can emit unrelated traffic on the same utun
			if err == nil && n >= 32 && buf[4]>>4 == 4 && buf[13] == unix.IPPROTO_UDP &&
				bytes.Equal(buf[20:24], target[:]) && bytes.HasSuffix(buf[:n], payload) {
				return true
			}
			if err != nil && !errors.Is(err, unix.EAGAIN) {
				t.Fatal(err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		return false
	}
	if probe(false) {
		t.Error("an unbound underlay socket reached the tun through the announced default, which is how the ESP underlay routes into its own tunnel")
	}
	if !probe(true) {
		t.Error("a socket bound to the mesh address could not reach the announced default")
	}
}

func TestDarwinDumpKeepsOnlyRoutesItOwns(t *testing.T) {
	plat, _ := testPlatform(t, Config{PrefSrc4: addr("198.51.100.1")})
	elsewhere := &route.LinkAddr{Index: testIndex + 1}
	// the host route an interface address creates: its gateway is the address,
	// so it is the kernel's record of the address rather than a route.
	addressRoute := &route.Inet4Addr{IP: [4]byte{198, 51, 100, 1}}

	rib := dumpRIB(t,
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC,
			dst: prefix("198.51.100.0/24"), gateway: ourGateway()},
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC,
			dst: prefix("2001:db8::/48"), gateway: ourGateway()},
		// a full length prefix with no netmask, which is how RTF_HOST reports.
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_HOST,
			dst: prefix("198.51.100.42/32"), gateway: ourGateway(), hostRoute: true},
		// everything below is somebody else's.
		dumpEntry{index: testIndex + 1, flags: unix.RTF_UP | unix.RTF_STATIC,
			dst: prefix("203.0.113.0/24"), gateway: elsewhere},
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_LOCAL,
			dst: prefix("198.51.100.1/32"), gateway: addressRoute, hostRoute: true},
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE,
			dst: prefix("255.255.255.255/32"), gateway: ourGateway()},
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_MULTICAST,
			dst: prefix("224.0.0.0/4"), gateway: ourGateway()},
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_GATEWAY,
			dst: prefix("192.0.2.0/24"), gateway: &route.Inet4Addr{IP: [4]byte{192, 0, 2, 254}}},
		dumpEntry{index: testIndex, flags: unix.RTF_STATIC,
			dst: prefix("192.0.2.0/25"), gateway: ourGateway()},
	)

	got, err := plat.ownedRoutes(rib)
	if err != nil {
		t.Fatalf("decode the dump: %v", err)
	}
	// the metric and the preferred source are mirrored from the configuration,
	// because the darwin FIB holds neither and the diff key needs both.
	want := []Route{
		{Destination: prefix("198.51.100.0/24"), PrefSrc: addr("198.51.100.1")},
		{Destination: prefix("198.51.100.42/32"), PrefSrc: addr("198.51.100.1")},
		{Destination: prefix("2001:db8::/48"), Metric: defaultIPv6Metric},
	}
	slices.SortFunc(got, compareRoutes)
	slices.SortFunc(want, compareRoutes)
	if !slices.Equal(got, want) {
		t.Fatalf("the dump decoded to %v, want %v", got, want)
	}
}

// The mirroring is what makes a pass converge: a dump that reported a metric
// or a preferred source the reconciler did not ask for would leave every route
// on both the add list and the delete list forever.
func TestDarwinDumpMirrorsDiffKeyFields(t *testing.T) {
	plat, _ := testPlatform(t, Config{Metric: 32, PrefSrc4: addr("198.51.100.1")})
	rib := dumpRIB(t,
		dumpEntry{index: testIndex, flags: unix.RTF_UP, dst: prefix("198.51.100.0/24"), gateway: ourGateway()},
		dumpEntry{index: testIndex, flags: unix.RTF_UP, dst: prefix("2001:db8::/48"), gateway: ourGateway()},
	)
	got, err := plat.ownedRoutes(rib)
	if err != nil {
		t.Fatalf("decode the dump: %v", err)
	}
	want := []Route{
		{Destination: prefix("198.51.100.0/24"), PrefSrc: addr("198.51.100.1"), Metric: 32},
		{Destination: prefix("2001:db8::/48"), Metric: 32},
	}
	slices.SortFunc(got, compareRoutes)
	if !slices.Equal(got, want) {
		t.Fatalf("the dump decoded to %v, want %v", got, want)
	}
}

func TestDarwinSkipsSourceSpecificRoutes(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	specific := Route{
		Destination: prefix("::/0"),
		Source:      prefix("2001:db8::/48"),
		Metric:      defaultIPv6Metric,
	}

	if err := plat.AddRoute(specific); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("a source-specific route has to report itself skipped, not %v", err)
	}
	// deleting one has to be a no-op too: dropping the source and deleting what
	// is left would take out the default route.
	if err := plat.DelRoute(specific); err != nil {
		t.Fatalf("deleting a source-specific route has to be a no-op: %v", err)
	}
	if len(sock.sent) != 0 {
		t.Fatalf("a source-specific route reached the kernel as %v", sock.messages(t))
	}

	key := Route{Destination: specific.Destination, Source: specific.Source}
	if !plat.pending[key] {
		t.Fatal("the skipped route was not recorded, so it would be reported again next pass")
	}
	// the report is deduplicated across passes, and Routes starts every pass.
	plat.rotateWarnings()
	if err := plat.AddRoute(specific); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("adding the same route again reported %v", err)
	}
	if !plat.warned[key] {
		t.Fatal("the second pass did not see the route as already reported")
	}
	if len(plat.pending) != 1 || len(plat.warned) != 1 {
		t.Fatalf("the warning sets grew to %d and %d, want one entry each", len(plat.pending), len(plat.warned))
	}
}

// ifaMessage builds one RTM_NEWADDR the way NET_RT_IFLIST delivers it: a 20
// byte struct ifa_msghdr, then the sockaddrs named by the address bitmask in
// RTAX order. golang.org/x/net/route marshals route messages only, so an
// address dump has to be written out by hand.
func ifaMessage(t *testing.T, index int, prefix netip.Prefix) []byte {
	t.Helper()
	mask, ok := prefixMask(prefix)
	if !ok {
		t.Fatalf("no netmask for %s", prefix)
	}
	size := unix.SizeofSockaddrInet4
	put := putSockaddrInet4
	if !prefix.Addr().Is4() {
		size, put = unix.SizeofSockaddrInet6, putSockaddrInet6
	}
	const header = 20 // struct ifa_msghdr
	message := make([]byte, header+2*size)
	binary.NativeEndian.PutUint16(message[0:], uint16(len(message)))
	message[2] = unix.RTM_VERSION
	message[3] = unix.RTM_NEWADDR
	binary.NativeEndian.PutUint32(message[4:], 1<<unix.RTAX_NETMASK|1<<unix.RTAX_IFA)
	binary.NativeEndian.PutUint16(message[12:], uint16(index))
	put(message[header:], mask)
	put(message[header+size:], prefix.Addr())
	return message
}

func TestDarwinInterfaceAddrsKeepsTheirHostBits(t *testing.T) {
	plat, _ := testPlatform(t, Config{})
	var rib []byte
	rib = append(rib, ifaMessage(t, testIndex, prefix("198.51.100.1/24"))...)
	rib = append(rib, ifaMessage(t, testIndex, prefix("2001:db8::1/48"))...)
	// an address on another interface is not this interface's business.
	rib = append(rib, ifaMessage(t, testIndex+1, prefix("203.0.113.1/24"))...)

	got, err := plat.interfaceAddrs(rib)
	if err != nil {
		t.Fatalf("decode the address dump: %v", err)
	}
	want := []netip.Prefix{prefix("198.51.100.1/24"), prefix("2001:db8::1/48")}
	if !slices.Equal(got, want) {
		t.Fatalf("the address dump decoded to %v, want %v", got, want)
	}
}

// The ioctl number carries the size of the request it takes, so deriving the
// two IPv6 numbers the same way x/sys/unix derived the IPv4 ones proves both
// the formula and the structure sizes this package builds to.
func TestDarwinAddressIoctlNumbers(t *testing.T) {
	const (
		add4 = iocIn | (sizeofIfAliasReq&iocParamMask)<<16 | iocGroupIf<<8 | 26
		del4 = iocIn | (sizeofIfReq&iocParamMask)<<16 | iocGroupIf<<8 | 25
	)
	if add4 != uintptr(unix.SIOCAIFADDR) {
		t.Errorf("_IOW('i', 26, struct ifaliasreq) is %#x, but SIOCAIFADDR is %#x", add4, unix.SIOCAIFADDR)
	}
	if del4 != uintptr(unix.SIOCDIFADDR) {
		t.Errorf("_IOW('i', 25, struct ifreq) is %#x, but SIOCDIFADDR is %#x", del4, unix.SIOCDIFADDR)
	}
	if siocAIfAddrIn6 != 0x8080691a || siocDIfAddrIn6 != 0x81206919 {
		t.Errorf("the IPv6 address ioctls are %#x and %#x, want 0x8080691a and 0x81206919",
			siocAIfAddrIn6, siocDIfAddrIn6)
	}
}

func TestDarwinAliasRequests(t *testing.T) {
	request, err := aliasRequest4("utun9", prefix("198.51.100.1/24"))
	if err != nil {
		t.Fatalf("build an IPv4 alias request: %v", err)
	}
	if len(request) != sizeofIfAliasReq {
		t.Fatalf("struct ifaliasreq is %d bytes, want %d", len(request), sizeofIfAliasReq)
	}
	if name := unix.ByteSliceToString(request[:unix.IFNAMSIZ]); name != "utun9" {
		t.Errorf("the request names %q, want utun9", name)
	}
	// a utun is point to point, so the destination is mandatory and is the
	// address itself.
	for _, field := range []struct {
		name   string
		offset int
		want   [4]byte
	}{
		{"ifra_addr", offIfAliasAddr, [4]byte{198, 51, 100, 1}},
		{"ifra_dstaddr", offIfAliasDstAddr, [4]byte{198, 51, 100, 1}},
		{"ifra_mask", offIfAliasMask, [4]byte{255, 255, 255, 0}},
	} {
		if request[field.offset] != unix.SizeofSockaddrInet4 || request[field.offset+1] != unix.AF_INET {
			t.Errorf("%s is not a sockaddr_in: len %d family %d",
				field.name, request[field.offset], request[field.offset+1])
		}
		if got := [4]byte(request[field.offset+offSockaddrIn4Addr:][:4]); got != field.want {
			t.Errorf("%s holds %v, want %v", field.name, got, field.want)
		}
	}

	request, err = aliasRequest6("utun9", prefix("2001:db8::1/48"))
	if err != nil {
		t.Fatalf("build an IPv6 alias request: %v", err)
	}
	if len(request) != sizeofIn6AliasReq {
		t.Fatalf("struct in6_aliasreq is %d bytes, want %d", len(request), sizeofIn6AliasReq)
	}
	address := netip.AddrFrom16([16]byte(request[offIn6AliasAddr+offSockaddrIn6Addr:][:16]))
	if address != addr("2001:db8::1") {
		t.Errorf("ifra_addr holds %s, want 2001:db8::1", address)
	}
	mask := netip.AddrFrom16([16]byte(request[offIn6AliasMask+offSockaddrIn6Addr:][:16]))
	if mask != addr("ffff:ffff:ffff::") {
		t.Errorf("ifra_prefixmask holds %s, want ffff:ffff:ffff::", mask)
	}
	// ifra_dstaddr stays AF_UNSPEC, which in6_update_ifa accepts on a point to
	// point link and which does not force the prefix to a /128.
	if request[offIn6AliasDstAddr] != 0 || request[offIn6AliasDstAddr+1] != 0 {
		t.Errorf("ifra_dstaddr is set: len %d family %d",
			request[offIn6AliasDstAddr], request[offIn6AliasDstAddr+1])
	}
	// an address nothing renews has to be permanent.
	vltime := binary.NativeEndian.Uint32(request[offIn6AliasVLTime:])
	pltime := binary.NativeEndian.Uint32(request[offIn6AliasPLTime:])
	if vltime != nd6InfiniteLifetime || pltime != nd6InfiniteLifetime {
		t.Errorf("the lifetimes are %#x and %#x, want both infinite", vltime, pltime)
	}
}

func TestDarwinDeleteRequests(t *testing.T) {
	request := deleteRequest4("utun9", prefix("198.51.100.1/24"))
	if len(request) != sizeofIfReq {
		t.Fatalf("struct ifreq is %d bytes, want %d", len(request), sizeofIfReq)
	}
	if got := [4]byte(request[offIfReqAddr+offSockaddrIn4Addr:][:4]); got != [4]byte{198, 51, 100, 1} {
		t.Errorf("ifr_addr holds %v, want 198.51.100.1", got)
	}

	request = deleteRequest6("utun9", prefix("2001:db8::1/48"))
	if len(request) != sizeofIn6IfReq {
		t.Fatalf("struct in6_ifreq is %d bytes, want %d", len(request), sizeofIn6IfReq)
	}
	address := netip.AddrFrom16([16]byte(request[offIn6IfReqAddr+offSockaddrIn6Addr:][:16]))
	if address != addr("2001:db8::1") {
		t.Errorf("ifr_addr holds %s, want 2001:db8::1", address)
	}
}

// A configuration written for the linux backend names a table, a protocol or a
// VRF, none of which exists here. Refusing at startup is the difference
// between a deployment that is wrong and one that looks like it works.
func TestDarwinPlatformRejectsLinuxConfig(t *testing.T) {
	base := Config{Interface: "utun9", Table: DefaultTable, Protocol: DefaultProtocol}
	for _, test := range []struct {
		name    string
		mutate  func(*Config)
		mention string
	}{
		{"table", func(c *Config) { c.Table = 220 }, "routing tables"},
		{"protocol", func(c *Config) { c.Protocol = 12 }, "route protocol"},
		{"vrf", func(c *Config) { c.VRF = "gravity" }, "VRF"},
		{"name", func(c *Config) { c.Interface = strings.Repeat("u", unix.IFNAMSIZ) }, "ifreq"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			test.mutate(&cfg)
			plat, err := newPlatform(cfg)
			if err == nil {
				_ = plat.Close()
				t.Fatalf("%s was accepted", test.name)
			}
			if !strings.Contains(err.Error(), test.mention) {
				t.Fatalf("the error is %q, which does not say why: want it to mention %q", err, test.mention)
			}
		})
	}
}

func TestDarwinHasNoVRF(t *testing.T) {
	plat, _ := testPlatform(t, Config{})
	if master, err := plat.Master(); master != "" || err != nil {
		t.Fatalf("Master reported %q, %v, want the empty string and no error", master, err)
	}
	err := plat.Enslave("gravity")
	if err == nil || !strings.Contains(err.Error(), "darwin") {
		t.Fatalf("Enslave reported %v, want an error naming the platform", err)
	}
	// Release is only reached for a master this reconciler set, which cannot
	// happen once Enslave always fails.
	if err := plat.Release(); err != nil {
		t.Fatalf("Release reported %v, want nothing to do", err)
	}
}

func TestDarwinPrefixMaskRoundTrip(t *testing.T) {
	for _, want := range []netip.Prefix{
		prefix("0.0.0.0/0"), prefix("10.0.0.0/8"), prefix("198.51.100.42/32"),
		prefix("::/0"), prefix("2001:db8::/48"), prefix("2001:db8::1/128"),
	} {
		mask, ok := prefixMask(want)
		if !ok {
			t.Fatalf("no netmask for %s", want)
		}
		if mask.BitLen() != want.Addr().BitLen() {
			t.Fatalf("the netmask of %s is %d bits wide, want %d", want, mask.BitLen(), want.Addr().BitLen())
		}
		bits, ok := maskBits(mask)
		if !ok || bits != want.Bits() {
			t.Fatalf("%s round tripped to /%d (ok %v)", want, bits, ok)
		}
	}
	// a mask whose ones are not contiguous denotes no prefix at all.
	if bits, ok := maskBits(addr("255.0.255.0")); ok {
		t.Fatalf("255.0.255.0 was read as /%d", bits)
	}
}

// The scoped install is what lets a Mac hold an address an exit announces, and
// until the address seam existed no fast test could reach it: sourceIsOurs
// asked the host about an interface index that names nothing, so every
// source-specific route took the refusal path.
func TestDarwinScopesSourceOfOurs(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	local := prefix("198.51.100.0/24")
	plat.addrs = func() ([]netip.Prefix, error) { return []netip.Prefix{prefix("198.51.100.1/24")}, nil }

	announced := Route{Destination: prefix("203.0.113.0/24"), Source: local}
	if err := plat.AddRoute(announced); err != nil {
		t.Fatalf("install %s: %v", announced, err)
	}
	written := sock.messages(t)
	if len(written) != 1 {
		t.Fatalf("the install wrote %d messages, want 1", len(written))
	}
	if written[0].Flags&unix.RTF_IFSCOPE == 0 {
		t.Error("a source-specific route for one of our own addresses was installed unscoped, " +
			"which would capture every socket rather than only ours")
	}
	if got, ok := plat.scoped[announced.Destination]; !ok || got != local {
		t.Errorf("the scoped route was recorded as %v (present %v), want %s", got, ok, local)
	}

	// The withdrawal has to carry the flag too, or it removes the unscoped
	// route to the same destination instead. It takes the flag from the route
	// it was handed, which a dump fills in, rather than guessing.
	sock.sent = nil
	announced.Scoped = true
	if err := plat.DelRoute(announced); err != nil {
		t.Fatalf("withdraw %s: %v", announced, err)
	}
	if withdrawn := sock.messages(t); len(withdrawn) != 1 || withdrawn[0].Flags&unix.RTF_IFSCOPE == 0 {
		t.Error("the withdrawal did not carry RTF_IFSCOPE")
	}
	if _, ok := plat.scoped[announced.Destination]; ok {
		t.Error("the scoped entry survived the withdrawal")
	}
}

// An address that goes away between install and withdraw must not strand the
// route. Deciding ownership from a live query rather than from what was
// recorded made DelRoute report success without deleting, and every later pass
// then listed the same route for deletion and deleted nothing.
func TestDarwinWithdrawsScopedRouteAfterItsAddressIsGone(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	local := prefix("198.51.100.0/24")
	plat.addrs = func() ([]netip.Prefix, error) { return []netip.Prefix{prefix("198.51.100.1/24")}, nil }
	announced := Route{Destination: prefix("203.0.113.0/24"), Source: local}
	if err := plat.AddRoute(announced); err != nil {
		t.Fatal(err)
	}

	plat.addrs = func() ([]netip.Prefix, error) { return nil, nil }
	sock.sent = nil
	if err := plat.DelRoute(announced); err != nil {
		t.Fatalf("withdraw %s: %v", announced, err)
	}
	if written := sock.messages(t); len(written) != 1 {
		t.Fatalf("the withdrawal wrote %d messages, want 1: the route is stranded", len(written))
	}
}

// A dump failure is not an answer. Reporting it as "the source is not ours"
// skipped the route, reported success, and never retried something a retry
// would have fixed.
func TestDarwinPropagatesAddressDumpFailure(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	wanted := errors.New("dump failed")
	plat.addrs = func() ([]netip.Prefix, error) { return nil, wanted }

	err := plat.AddRoute(Route{Destination: prefix("203.0.113.0/24"), Source: prefix("198.51.100.0/24")})
	if !errors.Is(err, wanted) {
		t.Fatalf("AddRoute reported %v, want the dump failure", err)
	}
	if len(sock.sent) != 0 {
		t.Error("a route was written despite the dump failing")
	}
}

// A write that fails must leave no trace in the scoped map. An entry for a
// route that was never installed makes the next dump report the unscoped route
// to the same destination as carrying a source it does not have, and the diff
// is then satisfied by a route that captures the whole machine.
func TestDarwinDoesNotRecordScopedRouteThatFailedToInstall(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	plat.addrs = func() ([]netip.Prefix, error) { return []netip.Prefix{prefix("198.51.100.1/24")}, nil }
	sock.err = unix.EPERM

	announced := Route{Destination: prefix("::/0"), Source: prefix("198.51.100.0/24")}
	if err := plat.AddRoute(announced); err == nil {
		t.Fatal("a refused write was reported as success")
	}
	if _, recorded := plat.scoped[announced.Destination]; recorded {
		t.Error("a route that was never installed is recorded as scoped")
	}
}

// darwin keys a scoped route separately from the unscoped route to the same
// destination, so both can be present. Reporting the source on both collapses
// them into one entry, and the unscoped one, which for a default route is the
// whole machine, is then never withdrawn.
func TestDarwinDoesNotAttributeSourceToUnscopedRoute(t *testing.T) {
	plat, _ := testPlatform(t, Config{})
	dest := prefix("::/0")
	plat.scoped[dest] = prefix("2001:db8::/48")

	rib := dumpRIB(t,
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC,
			dst: dest, gateway: ourGateway()},
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE,
			dst: dest, gateway: ourGateway()},
	)
	routes, err := plat.ownedRoutes(rib)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("the two routes to %s decoded as %v, want both", dest, routes)
	}
	var withSource, withoutSource int
	for _, r := range routes {
		if r.Source.IsValid() {
			withSource++
		} else {
			withoutSource++
		}
	}
	if withSource != 1 || withoutSource != 1 {
		t.Errorf("decoded %d with a source and %d without, want one of each: %v",
			withSource, withoutSource, routes)
	}
}

// A second source prefix for the same destination has nowhere to go: interface
// scope is one route per destination per interface.
func TestDarwinRefusesSecondSourceForOneDestination(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	plat.addrs = func() ([]netip.Prefix, error) {
		return []netip.Prefix{prefix("198.51.100.1/24"), prefix("203.0.113.1/24")}, nil
	}
	dest := prefix("::/0")
	if err := plat.AddRoute(Route{Destination: dest, Source: prefix("198.51.100.0/24")}); err != nil {
		t.Fatal(err)
	}
	written := len(sock.sent)
	if err := plat.AddRoute(Route{Destination: dest, Source: prefix("203.0.113.0/24")}); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("the second source reported %v rather than reporting itself skipped", err)
	}
	if len(sock.sent) != written {
		t.Error("a second source prefix for one destination was written to the kernel")
	}
	if got := plat.scoped[dest]; got != prefix("198.51.100.0/24") {
		t.Errorf("the recorded source changed to %s, so the two would take turns", got)
	}
}

// A route more specific than a default stays unscoped, so the mesh is
// reachable from the Mac itself without every program binding first. That is
// the split tailscale makes on the same machine: its exit-node default is
// scoped to its utun, its 100.64/10 is not.
func TestDarwinSpecificRouteStaysReachableWithoutBinding(t *testing.T) {
	requireNetTest(t)
	device, tun := createUTUNWithFD(t)
	setInterfaceUp(t, device)
	plat, err := newPlatform(Config{
		Interface: device, Table: DefaultTable, Protocol: DefaultProtocol,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plat.Close() })
	if err := plat.AddAddr(prefix("198.51.100.1/32")); err != nil {
		t.Fatal(err)
	}
	if err := plat.AddRoute(Route{Destination: prefix("203.0.113.0/24")}); err != nil {
		t.Fatal(err)
	}
	target := addr("203.0.113.9").As4()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	drainTUN(tun)
	payload := []byte("ranet specific route reachability probe")
	if err := unix.Sendto(fd, payload, 0, &unix.SockaddrInet4{Addr: target, Port: 9}); err != nil {
		t.Fatalf("an unbound socket could not reach a mesh prefix: %v", err)
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		n, err := unix.Read(tun, buf)
		if err == nil && n >= 32 && buf[4]>>4 == 4 && buf[13] == unix.IPPROTO_UDP &&
			bytes.Equal(buf[20:24], target[:]) && bytes.HasSuffix(buf[:n], payload) {
			return
		}
		if err != nil && !errors.Is(err, unix.EAGAIN) {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("an unbound socket did not reach a mesh prefix, so the machine cannot use the mesh it joined")
}

// The scope on a delete comes from the route, not from a record keyed by
// destination alone: an unscoped route and a scoped one can share a
// destination, and withdrawing one must not take out the other.
func TestDarwinDeleteSelectsScopeOfRouteItWithdraws(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	specific := Route{Destination: prefix("203.0.113.0/24")}
	if err := plat.DelRoute(specific); err != nil {
		t.Fatal(err)
	}
	written := sock.messages(t)
	if len(written) != 1 || written[0].Flags&unix.RTF_IFSCOPE != 0 {
		t.Fatalf("withdrawing %s carried interface scope, which deletes a different route", specific.Destination)
	}
	if err := plat.DelRoute(Route{Destination: prefix("::/0"), Scoped: true}); err != nil {
		t.Fatal(err)
	}
	written = sock.messages(t)
	if len(written) != 2 || written[1].Flags&unix.RTF_IFSCOPE == 0 {
		t.Fatal("withdrawing an announced default did not select its interface scope")
	}

	// And the unscoped default that shares that destination goes unscoped,
	// which is the pair that used to make every pass delete the wrong one and
	// leave the one it was asked for.
	if err := plat.DelRoute(Route{Destination: prefix("::/0")}); err != nil {
		t.Fatal(err)
	}
	written = sock.messages(t)
	if len(written) != 3 || written[2].Flags&unix.RTF_IFSCOPE != 0 {
		t.Fatal("withdrawing an unscoped default carried interface scope, which deletes the scoped one instead")
	}
}

// A route the kernel refuses is neither installed nor an error. Reported as
// installed it would make the reconcile line say the opposite of what the
// kernel holds, for as long as the other writer keeps the key; reported as a
// failure it would put every pass into backoff over something no retry frees.
func TestDarwinReportsOccupiedRouteAsSkipped(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	announced := Route{Destination: prefix("::/0"), Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}
	plat.addrs = func() ([]netip.Prefix, error) {
		return []netip.Prefix{prefix("2001:db8::1/128")}, nil
	}
	sock.err = unix.EEXIST
	for attempt := range 2 {
		if err := plat.AddRoute(announced); !errors.Is(err, errRouteSkipped) {
			t.Errorf("attempt %d reported %v, want the route reported as not installed", attempt, err)
		}
	}
	actual, err := plat.ownedRoutes(dumpRIB(t, dumpEntry{
		index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE,
		dst: announced.Destination, gateway: ourGateway(),
	}))
	if err != nil || len(actual) != 0 {
		t.Fatalf("refused route appeared owned: %v, error %v", actual, err)
	}
}

// A hold answers with an error rather than carrying the packet out of the tun,
// and keeps whatever scope its destination would have had: a held default must
// no more be visible to an unbound socket than a real one.
func TestDarwinHoldIsInstalledAsReject(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	held := Route{Destination: prefix("2001:db8:1::/48"), Unreachable: true, Metric: defaultIPv6Metric}
	if err := plat.AddRoute(held); err != nil {
		t.Fatal(err)
	}
	written := sock.messages(t)
	if len(written) != 1 {
		t.Fatalf("install wrote %d messages, want 1", len(written))
	}
	if written[0].Flags&unix.RTF_REJECT == 0 {
		t.Fatalf("the hold was installed as a path, flags %#x", written[0].Flags)
	}
	// It comes back from a dump as a hold too, or every pass would delete and
	// reinstall it.
	actual, err := plat.ownedRoutes(dumpRIB(t, dumpEntry{
		index: testIndex, flags: written[0].Flags, dst: held.Destination, gateway: ourGateway(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(actual) != 1 || !actual[0].Unreachable {
		t.Fatalf("the dump reported %v, want the hold", actual)
	}
	if add, del := diffRoutes([]Route{held}, actual, plat.scopes); len(add) != 0 || len(del) != 0 {
		t.Fatalf("an installed hold did not converge: add %v, delete %v", add, del)
	}
	// A real route to the same destination is a different route, so switching
	// between them is an add and a delete rather than nothing at all.
	carried := held
	carried.Unreachable = false
	if add, del := diffRoutes([]Route{carried}, actual, plat.scopes); len(add) != 1 || len(del) != 1 {
		t.Fatalf("a hold and a path to one prefix compared equal: add %v, delete %v", add, del)
	}
}

// ranet-lite attaches to a tun it did not necessarily create, so an instance
// can start on an interface that already carries its predecessor's scoped
// routes. Darwin has no replace, so a scoped route the dump does not report is
// one this process can neither withdraw nor install over: the add comes back
// EEXIST on every pass for the life of the process, and the destination it
// names is wrong for just as long.
func TestDarwinAdoptsScopedRouteItDidNotInstall(t *testing.T) {
	plat, _ := testPlatform(t, Config{})
	inherited := []dumpEntry{
		// an announced default, which this backend always scopes
		{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE,
			dst: prefix("::/0"), gateway: ourGateway()},
		// a held prefix, which is scoped for the same reason
		{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE | unix.RTF_REJECT,
			dst: prefix("2001:db8:1::/48"), gateway: ourGateway()},
		// what a source-specific route leaves behind once the source this
		// process recorded for it is gone with the process
		{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE,
			dst: prefix("2001:db8:2::/48"), gateway: ourGateway()},
	}
	got, err := plat.ownedRoutes(dumpRIB(t, inherited...))
	if err != nil {
		t.Fatalf("decode the dump: %v", err)
	}
	want := []Route{
		{Destination: prefix("::/0"), Metric: defaultIPv6Metric, Scoped: true},
		{Destination: prefix("2001:db8:1::/48"), Metric: defaultIPv6Metric, Scoped: true, Unreachable: true},
		{Destination: prefix("2001:db8:2::/48"), Metric: defaultIPv6Metric, Scoped: true},
	}
	slices.SortFunc(got, compareRoutes)
	slices.SortFunc(want, compareRoutes)
	if !slices.Equal(got, want) {
		t.Fatalf("the dump decoded to %v, want %v", got, want)
	}
	// Reported as scoped, so the withdrawal names the key the kernel filed it
	// under rather than the unscoped route to the same destination.
	for _, r := range got {
		if !r.Scoped {
			t.Errorf("%s came back unscoped, so deleting it would take out the wrong route", r.Destination)
		}
	}
}

// p.scoped stands in for a source the FIB cannot hold, so it is a cache of
// something only the kernel knows, and the kernel can drop a route without
// telling this process: sleep and wake, a link change, another daemon's flush.
// A record that outlives its route makes every differently shaped scoped
// install at that destination look like a second source for the one scoped
// slot, which is reported as skipped and retried forever, so the destination
// becomes uninstallable for the life of the process.
func TestDarwinForgetsScopedRouteThatLeftTheKernel(t *testing.T) {
	plat, _ := testPlatform(t, Config{})
	plat.addrs = func() ([]netip.Prefix, error) { return []netip.Prefix{prefix("2001:db8::1/128")}, nil }
	dest := prefix("2001:db8:1::/48")
	if err := plat.AddRoute(Route{Destination: dest, Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}); err != nil {
		t.Fatalf("install the source-specific route: %v", err)
	}
	if _, recorded := plat.scoped[dest]; !recorded {
		t.Fatal("the install did not record the scope, so this proves nothing")
	}

	// Something else removed it. The next dump has no scoped row for it.
	if _, err := plat.ownedRoutes(dumpRIB(t)); err != nil {
		t.Fatal(err)
	}
	if _, recorded := plat.scoped[dest]; recorded {
		t.Error("the record outlived the route, so this destination can never be installed again")
	}

	// And a differently shaped scoped install at the same destination now
	// works rather than being refused as a second source for one slot.
	if err := plat.AddRoute(Route{Destination: dest, Unreachable: true, Metric: defaultIPv6Metric}); err != nil {
		t.Errorf("a hold at the same destination was refused: %v", err)
	}
}

// decodeRoute drops the limited broadcast from every dump, so installing it
// would succeed once and then be invisible: every later pass would re-add it,
// get EEXIST, and warn that another program holds a route this reconciler
// wrote itself, and withdraw would never remove it.
func TestDarwinRefusesWhatItsOwnDumpWouldNeverReport(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	if err := plat.AddRoute(Route{Destination: limitedBroadcast}); !errors.Is(err, errRouteSkipped) {
		t.Errorf("installing the limited broadcast reported %v, want it reported as not installed", err)
	}
	if written := sock.messages(t); len(written) != 0 {
		t.Errorf("the install wrote %d messages for a destination the dump never reports", len(written))
	}
}

// The record of which destinations this process scoped is what the dump reads
// a scoped route's source back from, so it may only be dropped once the kernel
// has actually forgotten the route. Dropping it first loses the source of a
// route that is still installed, and the next pass withdraws and reinstalls it
// instead of recognizing it.
func TestDarwinKeepsScopedRecordWhenWithdrawalFails(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	plat.addrs = func() ([]netip.Prefix, error) { return []netip.Prefix{prefix("2001:db8::1/128")}, nil }
	specific := Route{Destination: prefix("2001:db8:1::/48"), Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}
	if err := plat.AddRoute(specific); err != nil {
		t.Fatalf("install the source-specific route: %v", err)
	}
	if _, recorded := plat.scoped[specific.Destination]; !recorded {
		t.Fatal("the install did not record the scope, so this proves nothing")
	}

	// A withdrawal the kernel refuses for a reason other than "it is already
	// gone". The route is still there.
	sock.err = unix.EBUSY
	if err := plat.DelRoute(Route{Destination: specific.Destination, Source: specific.Source, Scoped: true}); err == nil {
		t.Error("a refused withdrawal reported success")
	}
	if _, recorded := plat.scoped[specific.Destination]; !recorded {
		t.Fatal("the scope was forgotten while the route was still installed, so its source is lost")
	}

	// And once the withdrawal lands, the record goes with it: keeping it would
	// make the dump report a source on a route that no longer carries one.
	sock.err = nil
	if err := plat.DelRoute(Route{Destination: specific.Destination, Source: specific.Source, Scoped: true}); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, recorded := plat.scoped[specific.Destination]; recorded {
		t.Error("the scope outlived the route it belonged to")
	}
}

// An unbound socket does not reach a scoped route, so a scoped route standing
// where the mesh asked for an unscoped one is a black hole. The diff has to see
// the difference: it compares a desired route under the scope it would be
// installed with and a route read back under the scope the kernel holds, so
// the two agree for everything this reconciler installed and disagree for an
// inherited scoped route the mesh now wants plain. Masking scope out of the
// comparison entirely made that pair compare equal, and no later pass could
// ever notice.
func TestDarwinReplacesAnInheritedScopeTheMeshDoesNotWant(t *testing.T) {
	plat, _ := testPlatform(t, Config{})
	dest := prefix("2001:db8:1::/48")
	// What the mesh asks for: a plain route, which this backend never scopes.
	wanted := Route{Destination: dest, Metric: defaultIPv6Metric}
	// What the kernel holds: the same destination, scoped, left behind by an
	// instance whose record of the source went with it.
	inherited, err := plat.ownedRoutes(dumpRIB(t, dumpEntry{
		index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE,
		dst: dest, gateway: ourGateway(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(inherited) != 1 || !inherited[0].Scoped {
		t.Fatalf("the dump reported %v, want one scoped route", inherited)
	}
	add, del := diffRoutes([]Route{wanted}, inherited, plat.scopes)
	if len(del) != 1 || !del[0].Scoped {
		t.Fatalf("the diff withdraws %v, want the scoped route the kernel holds", del)
	}
	if len(add) != 1 || add[0].Scoped {
		t.Fatalf("the diff installs %v, want the unscoped route the mesh asked for", add)
	}

	// And a route this reconciler did install still compares equal to itself,
	// or every pass would withdraw and reinstall everything it owns.
	announced := Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}
	held, err := plat.ownedRoutes(dumpRIB(t, dumpEntry{
		index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE,
		dst: announced.Destination, gateway: ourGateway(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if add, del := diffRoutes([]Route{announced}, held, plat.scopes); len(add) != 0 || len(del) != 0 {
		t.Fatalf("an announced default is not settled: add %v, delete %v", add, del)
	}
}

// The darwin FIB keys a route by its destination and its scope, so the record
// of what another program holds has to be keyed the same way. Keyed by
// destination alone, an unrelated write to the other key clears it: the plain
// route installs, the record that a foreign scoped route holds the same
// destination is forgotten, and the next dump reports that route as ours and
// withdraws it.
func TestDarwinOccupiedRecordSurvivesTheOtherKey(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	dest := prefix("2001:db8:1::/48")
	plat.addrs = func() ([]netip.Prefix, error) { return []netip.Prefix{prefix("2001:db8::1/128")}, nil }

	// A scoped install the kernel refuses: somebody else holds that key.
	sock.err = unix.EEXIST
	scoped := Route{Destination: dest, Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}
	if err := plat.AddRoute(scoped); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("the refused install reported %v, want the route reported as not installed", err)
	}
	// The plain route to the same destination is a different key, and it
	// installs.
	sock.err = nil
	if err := plat.AddRoute(Route{Destination: dest, Metric: defaultIPv6Metric}); err != nil {
		t.Fatalf("install the plain route: %v", err)
	}

	// The foreign scoped route is still somebody else's, so the dump must not
	// report it as ours.
	got, err := plat.ownedRoutes(dumpRIB(t, dumpEntry{
		index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE,
		dst: dest, gateway: ourGateway(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("the dump claims %v, which another program holds and this process never installed", got)
	}
}

// The record of a refused install is rebuilt by the passes that refuse, the
// same way the warning set is. A node that meets a hundred foreign keys over
// its life would otherwise carry a hundred records forever, and a stale one
// hides a route from the dump that nothing can then withdraw.
func TestDarwinForgetsOccupiedKeyTheMeshStoppedAsking(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	dest := prefix("2001:db8:1::/48")
	sock.err = unix.EEXIST
	if err := plat.AddRoute(Route{Destination: dest, Metric: defaultIPv6Metric}); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("the refused install reported %v", err)
	}
	if len(plat.occupied) != 1 {
		t.Fatalf("the refusal recorded %d keys, want one", len(plat.occupied))
	}
	// The mesh stops asking for it. Two passes with no refusal at that key,
	// and the record is gone.
	sock.err = nil
	plat.rotateWarnings()
	plat.rotateWarnings()
	if len(plat.occupied) != 0 {
		t.Errorf("the record outlived the destination the mesh stopped asking for: %v", plat.occupied)
	}
}

// The record of a refused install is per key, and the kernel's key is the
// destination and its scope, so it has to be read with the scope of the row
// being decoded. Read with the scoped key for every row, one refused scoped
// add hid this reconciler's own unscoped route to the same destination: it
// installed it, could not see it on any later pass, re-added it, warned that
// another program held its own route, and never withdrew it. On a default or
// a hold that is a permanent black hole.
func TestDarwinOccupiedRecordIsReadWithTheRowsOwnScope(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	dest := prefix("2001:db8:1::/48")
	plat.addrs = func() ([]netip.Prefix, error) { return []netip.Prefix{prefix("2001:db8::1/128")}, nil }

	// A scoped install the kernel refuses, which is somebody else holding the
	// scoped key at this destination.
	sock.err = unix.EEXIST
	if err := plat.AddRoute(Route{Destination: dest, Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("the refused install reported %v", err)
	}
	sock.err = nil

	// One dump carrying both rows, which is what the kernel returns: the
	// plain route to the same destination is a different key, so it has to be
	// reported or nothing can ever withdraw it, and the scoped one is still
	// somebody else's.
	got, err := plat.ownedRoutes(dumpRIB(t,
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC,
			dst: dest, gateway: ourGateway()},
		dumpEntry{index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE,
			dst: dest, gateway: ourGateway()},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Scoped {
		t.Fatalf("the dump reported %v, want only the unscoped route this reconciler installed", got)
	}
}

// p.scoped is keyed by destination alone while the kernel keys by destination
// and scope, so withdrawing the unscoped route to a destination must not wipe
// the scoped route's source. It did, and the next pass then tore the scoped
// route down and reinstalled it.
func TestDarwinWithdrawingUnscopedKeepsTheScopedSource(t *testing.T) {
	plat, _ := testPlatform(t, Config{})
	plat.addrs = func() ([]netip.Prefix, error) { return []netip.Prefix{prefix("2001:db8::1/128")}, nil }
	announced := Route{Destination: prefix("::/0"), Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}
	if err := plat.AddRoute(announced); err != nil {
		t.Fatalf("install the announced default: %v", err)
	}
	if _, recorded := plat.scoped[announced.Destination]; !recorded {
		t.Fatal("the install did not record the scope, so this proves nothing")
	}

	// An unscoped route to the same destination goes away, which is a
	// different key in the kernel.
	if err := plat.DelRoute(Route{Destination: announced.Destination, Metric: defaultIPv6Metric}); err != nil {
		t.Fatalf("withdraw the unscoped route: %v", err)
	}
	if _, recorded := plat.scoped[announced.Destination]; !recorded {
		t.Error("withdrawing the unscoped route forgot the scoped route's source, so the next pass replaces it")
	}
}

// The space this reconciler owns is what an operator reads in the startup
// line, and on darwin it is the interface: there is one FIB and Config.Table
// means nothing here.
func TestDarwinOwnsAnInterfaceRatherThanATable(t *testing.T) {
	plat, _ := testPlatform(t, Config{Interface: "utun9", Table: DefaultTable})
	if got := plat.where(plat.cfg); got != "interface utun9" {
		t.Errorf("darwin reports %q, want the interface it owns", got)
	}
}

// EEXIST says that the key is taken, not by whom, and a pass that repairs a
// partial apply re-adds a route this process installed moments earlier. Read
// as another program's, the reconciler's own route stopped being reported by
// the dump, so every later pass saw it missing, re-added it, was refused
// again, and could never withdraw it: the route is in the kernel and the mesh
// believes it is not, for the life of the process.
func TestDarwinKnowsItsOwnRouteFromOneAnotherProgramHolds(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	dest := prefix("2001:db8:1::/48")
	installed := Route{Destination: dest, Metric: defaultIPv6Metric}
	if err := plat.AddRoute(installed); err != nil {
		t.Fatalf("install %s: %v", dest, err)
	}

	// The same route again, which is what a repair pass does. The kernel
	// refuses it because this reconciler already installed it.
	sock.err = unix.EEXIST
	if err := plat.AddRoute(installed); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("reinstalling our own route reported %v", err)
	}
	sock.err = nil

	got, err := plat.ownedRoutes(dumpRIB(t, dumpEntry{
		index: testIndex, flags: unix.RTF_UP | unix.RTF_STATIC,
		dst: dest, gateway: ourGateway(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("the dump reports %v, so this reconciler disowned the route it installed itself", got)
	}
}

// XNU broadcasts the result of every route write to every PF_ROUTE listener,
// including the writer's own monitor, and SO_USELOOPBACK is cleared only on
// the socket that writes. An install the kernel refuses stays in the diff on
// purpose, so waking on its own echo means installing, failing, waking and
// installing again, measured at four times a second for as long as the other
// writer holds the key, which on a laptop is any prefix the machine already
// has a route for.
func TestDarwinMonitorIgnoresItsOwnRefusedWrites(t *testing.T) {
	monitor := &routeMonitor{index: testIndex, self: uintptr(unix.Getpid())}
	// Marshal writes the pid but not the errno, which is the field that says
	// the write failed, so it goes in by hand at the offset the parser reads.
	const errnoOffset = 28
	echo := func(kind int, id uintptr, errno unix.Errno) []byte {
		t.Helper()
		message := &route.RouteMessage{
			Version: unix.RTM_VERSION, Type: kind, Index: testIndex, ID: id,
			Addrs: []route.Addr{unix.RTAX_DST: routeAddr(prefix("2001:db8::/48").Addr())},
		}
		raw, marshalErr := message.Marshal()
		if marshalErr != nil {
			t.Fatalf("marshal a route message: %v", marshalErr)
		}
		binary.NativeEndian.PutUint32(raw[errnoOffset:errnoOffset+4], uint32(errno))
		return raw
	}
	if monitor.interesting(echo(unix.RTM_ADD, monitor.self, unix.EEXIST)) {
		t.Error("the monitor woke on this reconciler's own refused install, which is what it made")
	}
	if !monitor.interesting(echo(unix.RTM_ADD, monitor.self, 0)) {
		t.Error("a write of ours that landed did not wake the pass that has to see it")
	}
	if !monitor.interesting(echo(unix.RTM_ADD, monitor.self+1, unix.EEXIST)) {
		t.Error("another program's failed write did not wake the reconciler")
	}
	if !monitor.interesting(echo(unix.RTM_DELETE, monitor.self+1, 0)) {
		t.Error("another program deleting a route out of this interface did not wake the reconciler")
	}
	// A message whose declared length runs past the buffer. Something changed
	// and a pass is cheap next to missing it.
	truncated := echo(unix.RTM_ADD, monitor.self+1, 0)
	if !monitor.interesting(truncated[:len(truncated)-4]) {
		t.Error("a message that will not parse must wake rather than be dropped")
	}
}

// A dump the kernel returns and this library cannot read is a pass that will
// not reach any AddRoute either, so it must not consume a rotation. Two of
// them would empty the record, and on this platform that record is also the
// exception decodeRoute reads: a foreign route out of this interface would
// then be reported as ours and reach a delete list.
func TestDarwinKeepsTheRefusalRecordThroughAnUnparseableDump(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	dest := prefix("2001:db8:1::/48")
	sock.err = unix.EEXIST
	if err := plat.AddRoute(Route{Destination: dest, Metric: defaultIPv6Metric}); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("the refused install reported %v", err)
	}
	if len(plat.occupied) != 1 {
		t.Fatalf("the refusal recorded %d keys, want one", len(plat.occupied))
	}

	// A message whose length field runs past the buffer it arrived in.
	unreadable := []byte{100, 0, unix.RTM_VERSION, unix.RTM_GET, 0, 0, 0, 0}
	for pass := range 2 {
		if _, err := plat.ownedRoutes(unreadable); err == nil {
			t.Fatalf("pass %d: an unreadable dump parsed, so this proves nothing", pass)
		}
	}
	if len(plat.occupied) != 1 {
		t.Errorf("two passes that never decoded a route emptied the record: %v", plat.occupied)
	}
}
