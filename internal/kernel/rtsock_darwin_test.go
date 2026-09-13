//go:build darwin && !ios

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// darwinNetTestEnv gates the only test in this package that speaks to the real
// routing socket. It is off by default and stays off: the machine running the
// suite is the laptop this backend was written for, and it is on the mesh.
const darwinNetTestEnv = "RANET_LITE_DARWIN_NETTEST"

// The prefixes this test is allowed to name, and the only ones it ever does.
// RFC 5737 and RFC 3849 reserve both for documentation, so neither can collide
// with a mesh prefix, a fleet prefix or anything already on the machine.
var (
	netTestRoute4 = prefix("198.51.100.0/24")
	netTestHost4  = prefix("198.51.100.42/32")
	// deliberately not the address's own prefix: assigning an IPv6 address
	// makes in6_ifinit create the connected route for it, and this reconciler
	// can only own routes it installed itself. IPv4 has no such collision on a
	// point to point link, where in_ifinit adds only the host route.
	netTestRoute6 = prefix("2001:db8:1::/48")
	netTestAddr4  = prefix("198.51.100.1/24")
	netTestAddr6  = prefix("2001:db8::1/48")
)

// guardSocket sits between the platform and the real routing socket. Every
// change the platform can make to the kernel goes through here, so refusing a
// message that does not name the interface under test turns "it did not touch
// another device" from an observation into a proof.
type guardSocket struct {
	t     *testing.T
	index int
	inner rtSocket
}

func (g *guardSocket) WriteRoute(message *route.RouteMessage) error {
	g.t.Helper()
	switch message.Type {
	case unix.RTM_ADD, unix.RTM_DELETE:
	default:
		g.t.Fatalf("the platform sent routing message type %d, which it has no business sending", message.Type)
	}
	if message.Index != g.index {
		g.t.Fatalf("a routing message named interface index %d, not %d", message.Index, g.index)
	}
	gateway, ok := message.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
	if !ok || gateway.Index != g.index {
		g.t.Fatalf("a routing message left through %v, not interface index %d",
			message.Addrs[unix.RTAX_GATEWAY], g.index)
	}
	return g.inner.WriteRoute(message)
}

func (g *guardSocket) Close() error { return g.inner.Close() }

// TestDarwinPlatformOnRealKernel exercises the routing socket, the address
// ioctls and the notification loop against the running kernel. It creates a
// utun of its own, names only documentation prefixes, and destroys the device
// again at the end, which takes every address and route on it along.
func TestDarwinPlatformOnRealKernel(t *testing.T) {
	if os.Getenv(darwinNetTestEnv) != "1" {
		t.Skipf("the real kernel path is off by default because this machine is on a live mesh; "+
			"run it with %s=1 and as root to exercise it", darwinNetTestEnv)
	}
	if os.Getuid() != 0 {
		t.Skipf("%s=1 but this process is not root; the routing socket writes and the address "+
			"ioctls both need it, so there is nothing to exercise", darwinNetTestEnv)
	}

	device := createUTUN(t)
	setInterfaceUp(t, device)
	cfg := Config{Interface: device, Table: DefaultTable, Protocol: DefaultProtocol}
	opened, err := newPlatform(cfg)
	if err != nil {
		t.Fatalf("open the darwin platform on %s: %v", device, err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)
	plat.sock = &guardSocket{t: t, index: plat.index, inner: plat.sock}

	// every route in the kernel that is not ours, so the end of the test can
	// prove none of them went away.
	foreign := foreignRoutes(t, plat.index)

	if routes, err := plat.Routes(); err != nil || len(routes) != 0 {
		t.Fatalf("a fresh utun already holds %v (err %v)", routes, err)
	}

	// Addresses first. The kernel creates entries of its own for an address on
	// a point to point link, and the next check is that none of them is
	// mistaken for a route this reconciler owns.
	for _, address := range []netip.Prefix{netTestAddr4, netTestAddr6} {
		if err := plat.AddAddr(address); err != nil {
			t.Fatalf("assign %s to %s: %v", address, device, err)
		}
	}
	assigned, err := plat.Addrs()
	if err != nil {
		t.Fatalf("list the addresses of %s: %v", device, err)
	}
	for _, address := range []netip.Prefix{netTestAddr4, netTestAddr6} {
		if !slices.Contains(assigned, address) {
			t.Fatalf("%s is missing from %v", address, assigned)
		}
	}
	if routes, err := plat.Routes(); err != nil || len(routes) != 0 {
		t.Fatalf("the kernel's own entries for an address were read as routes we own: %v (err %v)", routes, err)
	}

	// Every metric comes from routeMetric, and so does every metric the dump
	// answers with, because this FIB keeps none of its own. A hold takes a
	// different one, and a second answer for it makes the diff disagree in the
	// direction that never converges: the pass deletes and reinstalls the same
	// route forever, with a window on each one where the prefix is not held.
	hold := Route{Destination: prefix("2001:db8:dead::/48"), Unreachable: true}
	want := []Route{
		{Destination: netTestRoute4},
		{Destination: netTestHost4},
		{Destination: netTestRoute6},
		hold,
	}
	for i := range want {
		want[i].Metric = routeMetric(cfg.Metric, want[i].Destination, want[i].Unreachable)
		want[i].Scoped = plat.scopes(want[i])
	}
	slices.SortFunc(want, compareRoutes)
	for _, r := range want {
		if err := plat.AddRoute(r); err != nil {
			t.Fatalf("install %s out of %s: %v", r, device, err)
		}
	}
	if got, err := plat.Routes(); err != nil || !slices.Equal(got, want) {
		t.Fatalf("%s holds %v, want %v (err %v)", device, got, want, err)
	}

	// A repeated install reports the route as already held and changes
	// nothing, which lets a pass repair a partial apply without counting
	// what it did not do.
	for _, r := range want {
		if err := plat.AddRoute(r); !errors.Is(err, errRouteSkipped) {
			t.Fatalf("reinstall %s reported %v", r, err)
		}
	}
	if got, _ := plat.Routes(); !slices.Equal(got, want) {
		t.Fatalf("a repeated install changed %s to %v", device, got)
	}

	// A source-specific route is skipped rather than flattened. Flattening
	// this one would install a default route out of the tun.
	specific := Route{Destination: prefix("::/0"), Source: netTestRoute6, Metric: defaultIPv6Metric}
	if err := plat.AddRoute(specific); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("a source-specific route reported %v rather than reporting itself skipped", err)
	}
	if got, _ := plat.Routes(); !slices.Equal(got, want) {
		t.Fatalf("a source-specific route reached the kernel: %s now holds %v", device, got)
	}

	// The notification loop. The reconciler wakes on a change to a route out
	// of its own interface and on nothing else.
	drain(plat.Notify())
	extra := Route{Destination: prefix("198.51.100.128/25")}
	if err := plat.AddRoute(extra); err != nil {
		t.Fatalf("install %s: %v", extra, err)
	}
	select {
	case <-plat.Notify():
	case <-time.After(10 * time.Second):
		t.Fatal("installing a route did not wake the route monitor")
	}

	// The same route again, which the kernel refuses with EEXIST and echoes
	// with rtm_errno set. A refusal stays in the diff on purpose, so waking on
	// its own echo means installing, failing, waking and installing again,
	// measured at four times a second on a live machine. Only the kernel
	// writes that field where the kernel puts it, see rtmErrnoOffset.
	drain(plat.Notify())
	if err := plat.AddRoute(extra); !errors.Is(err, errRouteSkipped) {
		t.Fatalf("reinstalling our own route reported %v, want it skipped", err)
	}
	select {
	case <-plat.Notify():
		t.Error("the monitor woke on this reconciler's own refused install, so a pass that cannot install spins")
	case <-time.After(2 * time.Second):
	}

	if err := plat.DelRoute(extra); err != nil {
		t.Fatalf("withdraw %s: %v", extra, err)
	}

	for _, r := range want {
		if err := plat.DelRoute(r); err != nil {
			t.Fatalf("withdraw %s: %v", r, err)
		}
		// a route that is already gone is success, the same tolerance the
		// linux backend has, because a pass that failed halfway repeats.
		if err := plat.DelRoute(r); err != nil {
			t.Fatalf("withdrawing %s twice reported %v", r, err)
		}
	}
	if got, err := plat.Routes(); err != nil || len(got) != 0 {
		t.Fatalf("%s still holds %v after the withdrawal (err %v)", device, got, err)
	}

	for _, address := range []netip.Prefix{netTestAddr4, netTestAddr6} {
		if err := plat.DelAddr(address); err != nil {
			t.Fatalf("remove %s from %s: %v", address, device, err)
		}
	}
	assigned, err = plat.Addrs()
	if err != nil {
		t.Fatalf("list the addresses of %s: %v", device, err)
	}
	for _, address := range []netip.Prefix{netTestAddr4, netTestAddr6} {
		if slices.Contains(assigned, address) {
			t.Fatalf("%s survived its removal: %v", address, assigned)
		}
	}

	// Nothing outside the device under test may have moved. A route that
	// disappeared here was taken by something else on the machine, because the
	// guard above refused every message that could have named another device.
	remaining := foreignRoutes(t, plat.index)
	for key := range foreign {
		if !remaining[key] {
			t.Errorf("a route out of another interface is gone: %s", key)
		}
	}
}

// createUTUN opens a utun of its own and returns the name the kernel gave it.
// Closing the control descriptor destroys the interface with every address and
// route on it, so this one cleanup is total even when the test fails halfway.
func createUTUN(t *testing.T) string {
	t.Helper()
	const (
		utunControl = "com.apple.net.utun_control"
		// SYSPROTO_CONTROL and UTUN_OPT_IFNAME, neither of which
		// golang.org/x/sys/unix carries.
		sysprotoControl = 2
		utunOptIfname   = 2
	)
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		t.Fatalf("open a system control socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControl)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		t.Fatalf("look up %s: %v", utunControl, err)
	}
	// unit 0 asks for the first free utun rather than naming one, so the test
	// cannot land on a device something else is already using.
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		t.Fatalf("create a utun: %v", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		t.Fatalf("read the name of the new utun: %v", err)
	}
	t.Logf("created %s, which goes away with this test", name)
	return name
}

func setInterfaceUp(t *testing.T, name string) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("open an address control socket: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	// struct ifreq, whose union starts at the end of the name and holds a
	// short here.
	request := make([]byte, sizeofIfReq)
	copy(request[:unix.IFNAMSIZ], name)
	if err := ioctlRequest(fd, unix.SIOCGIFFLAGS, request); err != nil {
		t.Fatalf("read the flags of %s: %v", name, err)
	}
	flags := binary.NativeEndian.Uint16(request[offIfReqAddr:]) | unix.IFF_UP
	binary.NativeEndian.PutUint16(request[offIfReqAddr:], flags)
	if err := ioctlRequest(fd, unix.SIOCSIFFLAGS, request); err != nil {
		t.Fatalf("bring %s up: %v", name, err)
	}
}

// foreignRoutes identifies every route in the kernel that does not leave the
// interface under test. Nothing this backend does may remove one. The flags
// are left out of the identity because the kernel turns RTF_DONE and
// RTF_MODIFIED on and off under a route that is not going anywhere.
func foreignRoutes(t *testing.T, index int) map[string]bool {
	t.Helper()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatalf("dump the routing table: %v", err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatalf("parse the routing table: %v", err)
	}
	out := make(map[string]bool, len(messages))
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Index == index || len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		destination, _ := addressFromRouteAddr(rm.Addrs[unix.RTAX_DST])
		mask, _ := addressFromRouteAddr(rm.Addrs[unix.RTAX_NETMASK])
		out[fmt.Sprintf("index %d %s mask %s", rm.Index, destination, mask)] = true
	}
	return out
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
