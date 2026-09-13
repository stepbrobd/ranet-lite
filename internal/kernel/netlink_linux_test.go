//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This is the only test that speaks to a real kernel. It refuses to run
// anywhere but inside a network namespace it created itself and proved empty,
// because the code under test writes routes, addresses and link masters, and
// the machine running the suite is usually on the mesh it is being written
// for.
func TestNetlinkPlatformInNetworkNamespace(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(t)

	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(t, conn)

	const device = "ranettest0"
	createTUN(t, device)
	index, _, err := conn.link(device)
	if err != nil {
		t.Fatalf("look up %s: %v", device, err)
	}
	setLinkFlags(t, conn, index, unix.IFF_UP)

	cfg := Config{Interface: device, Table: DefaultTable, Protocol: DefaultProtocol}
	opened, err := newPlatform(cfg)
	if err != nil {
		t.Fatalf("open the netlink platform: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*netlinkPlatform)

	if routes, err := plat.Routes(); err != nil || len(routes) != 0 {
		t.Fatalf("a fresh table holds %v (err %v)", routes, err)
	}

	// RTA_PREFSRC is only accepted for an address the box actually has, so
	// the address assignment has to land first.
	local4, local6 := prefix("10.99.0.1/32"), prefix("2602:f590:1::1/128")
	for _, address := range []netip.Prefix{local4, local6} {
		if err := plat.AddAddr(address); err != nil {
			t.Fatalf("assign %s: %v", address, err)
		}
	}
	assigned, err := plat.Addrs()
	if err != nil {
		t.Fatalf("list addresses: %v", err)
	}
	for _, address := range []netip.Prefix{local4, local6} {
		if !slices.Contains(assigned, address) {
			t.Fatalf("%s is missing from %v", address, assigned)
		}
	}

	// IPv6 carries the kernel's own default metric explicitly, so a dump
	// reports back exactly the route that was installed.
	want := []Route{
		{Destination: prefix("10.0.0.0/8"), PrefSrc: local4.Addr()},
		{Destination: prefix("::/0"), Source: prefix("2602:f590:1::/48"), Metric: defaultIPv6Metric},
		{Destination: prefix("2602:f590::/36"), Metric: defaultIPv6Metric},
	}
	slices.SortFunc(want, compareRoutes)
	for _, route := range want {
		if err := plat.AddRoute(route); err != nil {
			if route.Source.IsValid() && (errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP)) {
				t.Fatalf("source-specific route %s rejected, is CONFIG_IPV6_SUBTREES set: %v", route, err)
			}
			t.Fatalf("install %s: %v", route, err)
		}
	}
	if got, err := plat.Routes(); err != nil || !slices.Equal(got, want) {
		t.Fatalf("table holds %v, want %v (err %v)", got, want, err)
	}

	// an exclusive install must report a collision even if the route is ours,
	// so a race after the dump cannot be counted as a successful addition
	for _, route := range want {
		if err := plat.AddRoute(route); !errors.Is(err, unix.EEXIST) {
			t.Fatalf("reinstall %s: got %v, want EEXIST", route, err)
		}
	}
	if got, _ := plat.Routes(); !slices.Equal(got, want) {
		t.Fatalf("a repeated install changed the table to %v", got)
	}

	// Ownership: neither another protocol in this table nor this protocol in
	// another table may show up in a dump, because anything that does is on
	// the delete list at withdrawal.
	other := &netlinkPlatform{
		cfg:   Config{Interface: device, Table: DefaultTable, Protocol: DefaultProtocol + 1},
		index: plat.index, conn: plat.conn,
	}
	elsewhere := &netlinkPlatform{
		cfg:   Config{Interface: device, Table: DefaultTable + 1, Protocol: DefaultProtocol},
		index: plat.index, conn: plat.conn,
	}
	foreign := Route{Destination: prefix("198.51.100.0/24")}
	aside := Route{Destination: prefix("203.0.113.0/24")}
	if err := other.AddRoute(foreign); err != nil {
		t.Fatalf("install a foreign route: %v", err)
	}
	if err := elsewhere.AddRoute(aside); err != nil {
		t.Fatalf("install a route in another table: %v", err)
	}
	if got, _ := plat.Routes(); !slices.Equal(got, want) {
		t.Fatalf("dump picked up routes of other owners: %v", got)
	}

	// A notification for this table has to reach the monitor; the reconcile
	// loop has nothing else to tell it that somebody edited the table.
	drain(plat.Notify())
	if err := plat.AddRoute(Route{Destination: prefix("192.0.2.0/24")}); err != nil {
		t.Fatalf("install a route to wake the monitor: %v", err)
	}
	select {
	case <-plat.Notify():
	case <-time.After(5 * time.Second):
		t.Fatal("no route notification arrived")
	}
	if err := plat.DelRoute(Route{Destination: prefix("192.0.2.0/24")}); err != nil {
		t.Fatalf("remove the route: %v", err)
	}

	// A delete removes exactly one route and is idempotent, so a reconcile
	// that races the kernel does not fail on the second attempt.
	victim := Route{Destination: prefix("2602:f590::/36"), Metric: defaultIPv6Metric}
	for range 2 {
		if err := plat.DelRoute(victim); err != nil {
			t.Fatalf("remove %s: %v", victim, err)
		}
	}
	remaining := slices.DeleteFunc(slices.Clone(want), func(route Route) bool { return route == victim })
	if got, _ := plat.Routes(); !slices.Equal(got, remaining) {
		t.Fatalf("table holds %v, want %v", got, remaining)
	}

	for _, route := range remaining {
		if err := plat.DelRoute(route); err != nil {
			t.Fatalf("remove %s: %v", route, err)
		}
	}
	if got, _ := plat.Routes(); len(got) != 0 {
		t.Fatalf("table still holds %v", got)
	}
	if got, _ := other.Routes(); !slices.Equal(got, []Route{foreign}) {
		t.Fatalf("the foreign route did not survive, table holds %v", got)
	}
	if got, _ := elsewhere.Routes(); !slices.Equal(got, []Route{aside}) {
		t.Fatalf("the other table did not survive, it holds %v", got)
	}

	if err := plat.DelAddr(local4); err != nil {
		t.Fatalf("remove %s: %v", local4, err)
	}
	if assigned, _ := plat.Addrs(); slices.Contains(assigned, local4) {
		t.Fatalf("%s survived removal: %v", local4, assigned)
	}

	testVRFEnslavement(t, conn, plat)
}

func TestNetlinkReportsOccupiedRoute(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(t, conn)
	// the namespace's own loopback needs no optional link driver
	const device = "lo"
	index, _, err := conn.link(device)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, index, unix.IFF_UP)
	cfg := Config{Interface: device, Table: DefaultTable, Protocol: DefaultProtocol}
	opened, err := newPlatform(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*netlinkPlatform)
	cfg.Protocol++
	foreign := &netlinkPlatform{cfg: cfg, index: index, conn: conn}
	announced := Route{Destination: prefix("198.51.100.0/24")}
	if err := foreign.AddRoute(announced); err != nil {
		t.Fatal(err)
	}
	for attempt := range 2 {
		if err := plat.AddRoute(announced); !errors.Is(err, unix.EEXIST) {
			t.Errorf("attempt %d reported %v, want EEXIST for the foreign route", attempt, err)
		}
	}
	if got, err := plat.Routes(); err != nil || len(got) != 0 {
		t.Fatalf("refused route appeared owned: %v, error %v", got, err)
	}
	if got, err := foreign.Routes(); err != nil || !slices.Equal(got, []Route{announced}) {
		t.Fatalf("foreign route changed: %v, error %v", got, err)
	}
}

// testVRFEnslavement runs last: joining a VRF flushes the device's addresses
// and routes, so it must not run before the route assertions.
func testVRFEnslavement(t *testing.T, conn *nlConn, plat *netlinkPlatform) {
	t.Helper()
	const master = "vrftest0"
	data := putAttrU32(nil, unix.IFLA_VRF_TABLE, plat.cfg.Table)
	if err := createLink(conn, master, "vrf", data); err != nil {
		t.Skipf("no vrf support in this kernel: %v", err)
	}
	index, _, err := conn.link(master)
	if err != nil {
		t.Fatalf("look up %s: %v", master, err)
	}
	setLinkFlags(t, conn, index, unix.IFF_UP)

	if current, err := plat.Master(); err != nil || current != "" {
		t.Fatalf("the device already has master %q (err %v)", current, err)
	}
	for range 2 { // enslaving twice must be indistinguishable from once
		if err := plat.Enslave(master); err != nil {
			t.Fatalf("enslave to %s: %v", master, err)
		}
	}
	if current, err := plat.Master(); err != nil || current != master {
		t.Fatalf("master is %q, want %s (err %v)", current, master, err)
	}
	if err := plat.Release(); err != nil {
		t.Fatalf("release from %s: %v", master, err)
	}
	if current, err := plat.Master(); err != nil || current != "" {
		t.Fatalf("master is %q after release, want empty (err %v)", current, err)
	}
}

// enterThrowawayNamespace moves this test's thread into a fresh network
// namespace. The thread is never unlocked, so the Go runtime destroys it when
// this goroutine exits and takes the namespace with it.
func enterThrowawayNamespace(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	before := namespaceID(t)
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare a network namespace: %v", err)
	}
	if namespaceID(t) == before {
		t.Fatal("refusing to continue: the network namespace did not change")
	}
}

func namespaceID(t *testing.T) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		t.Fatalf("stat this thread's network namespace: %v", err)
	}
	return st.Ino
}

// requireEmptyNamespace is the second guard. A namespace that already holds a
// route is somebody's real one, whatever the inode said.
func requireEmptyNamespace(t *testing.T, conn *nlConn) {
	t.Helper()
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_UNSPEC
	replies, err := conn.execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP, body)
	if err != nil {
		t.Fatalf("dump every route: %v", err)
	}
	for _, reply := range replies {
		if reply.Kind == unix.RTM_NEWROUTE {
			t.Fatal("refusing to continue: this network namespace already holds routes")
		}
	}
}

func createTUN(t *testing.T, name string) {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no /dev/net/tun: %v", err)
	}
	// the device lives as long as the descriptor, so it outlives the test by
	// nothing at all.
	t.Cleanup(func() { _ = unix.Close(fd) })
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatalf("build an ifreq for %s: %v", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatalf("create tun %s: %v", name, err)
	}
}

func setLinkFlags(t *testing.T, conn *nlConn, index uint32, flags uint32) {
	t.Helper()
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], index)
	binary.NativeEndian.PutUint32(body[8:], flags)
	binary.NativeEndian.PutUint32(body[12:], flags)
	if _, err := conn.execute(unix.RTM_NEWLINK, unix.NLM_F_ACK, body); err != nil {
		t.Fatalf("set flags on link %d: %v", index, err)
	}
}

// createLink is test scaffolding, not part of the reconciler: the daemon never
// creates a link, it only ever joins one.
func createLink(conn *nlConn, name, kind string, data []byte) error {
	var info []byte
	info = putAttrString(info, unix.IFLA_INFO_KIND, kind)
	if data != nil {
		info = putAttr(info, unix.IFLA_INFO_DATA, data)
	}
	body := make([]byte, unix.SizeofIfInfomsg)
	body = putAttrString(body, unix.IFLA_IFNAME, name)
	body = putAttr(body, unix.IFLA_LINKINFO, info)
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK)
	_, err := conn.execute(unix.RTM_NEWLINK, flags, body)
	return err
}

func drain(signal <-chan struct{}) {
	for {
		select {
		case <-signal:
		default:
			return
		}
	}
}
