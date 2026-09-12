//go:build darwin && !ios

package kernel

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

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
		occupied: make(map[netip.Prefix]bool),
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

func TestDarwinRouteMessageNamesTheInterfaceAsItsGateway(t *testing.T) {
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

func TestDarwinDumpKeepsOnlyTheRoutesItOwns(t *testing.T) {
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
func TestDarwinDumpMirrorsTheDiffKeyFields(t *testing.T) {
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

	if err := plat.AddRoute(specific); err != nil {
		t.Fatalf("a source-specific route has to be skipped, not failed: %v", err)
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
	if err := plat.AddRoute(specific); err != nil {
		t.Fatalf("add the same route again: %v", err)
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
func TestDarwinPlatformRejectsALinuxConfig(t *testing.T) {
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
func TestDarwinScopesASourceOfOurs(t *testing.T) {
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
	// route to the same destination instead.
	sock.sent = nil
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
func TestDarwinWithdrawsAScopedRouteAfterItsAddressIsGone(t *testing.T) {
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
func TestDarwinPropagatesAnAddressDumpFailure(t *testing.T) {
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
func TestDarwinDoesNotRecordAScopedRouteThatFailedToInstall(t *testing.T) {
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
func TestDarwinDoesNotAttributeASourceToAnUnscopedRoute(t *testing.T) {
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
func TestDarwinRefusesASecondSourceForOneDestination(t *testing.T) {
	plat, sock := testPlatform(t, Config{})
	plat.addrs = func() ([]netip.Prefix, error) {
		return []netip.Prefix{prefix("198.51.100.1/24"), prefix("203.0.113.1/24")}, nil
	}
	dest := prefix("::/0")
	if err := plat.AddRoute(Route{Destination: dest, Source: prefix("198.51.100.0/24")}); err != nil {
		t.Fatal(err)
	}
	written := len(sock.sent)
	if err := plat.AddRoute(Route{Destination: dest, Source: prefix("203.0.113.0/24")}); err != nil {
		t.Fatalf("the second source was reported as an error rather than skipped: %v", err)
	}
	if len(sock.sent) != written {
		t.Error("a second source prefix for one destination was written to the kernel")
	}
	if got := plat.scoped[dest]; got != prefix("198.51.100.0/24") {
		t.Errorf("the recorded source changed to %s, so the two would take turns", got)
	}
}
