//go:build linux

package kernel

import (
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeNetlink stands in for the socket so what this backend writes can be read
// back without root. Every other check of the write path needs a real netlink
// socket and /dev/net/tun, so none of them runs in the nix sandbox.
type fakeNetlink struct {
	sent []struct {
		kind, flags uint16
		body        []byte
	}
	err error
}

func (f *fakeNetlink) execute(kind, flags uint16, body []byte) ([]nlMessage, error) {
	f.sent = append(f.sent, struct {
		kind, flags uint16
		body        []byte
	}{kind, flags, body})
	return nil, f.err
}

func (f *fakeNetlink) link(string) (uint32, uint32, error) { return 0, 0, nil }
func (f *fakeNetlink) linkName(uint32) (string, error)     { return "", nil }
func (f *fakeNetlink) Close() error                        { return nil }

func writePlatform(t *testing.T) (*netlinkPlatform, *fakeNetlink) {
	t.Helper()
	conn := &fakeNetlink{}
	return &netlinkPlatform{
		cfg:      Config{Interface: "ranet0", Table: 200, Protocol: DefaultProtocol},
		index:    7,
		conn:     conn,
		occupied: map[string]bool{},
	}, conn
}

// A retracted prefix is held as an unreachable route rather than removed, so
// traffic for it is answered with an error instead of following a covering
// route somewhere else. Installing it as an ordinary path would send that
// traffic out of the tun to a peer that no longer announces it.
func TestLinuxInstallsAHoldAsAnUnreachableRoute(t *testing.T) {
	plat, conn := writePlatform(t)
	held := Route{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Unreachable: true}
	if err := plat.AddRoute(held); err != nil {
		t.Fatalf("install the hold: %v", err)
	}
	if len(conn.sent) != 1 {
		t.Fatalf("the install wrote %d messages, want 1", len(conn.sent))
	}
	sent := conn.sent[0]
	if sent.kind != unix.RTM_NEWROUTE {
		t.Errorf("wrote message type %d, want RTM_NEWROUTE", sent.kind)
	}
	if sent.flags&unix.NLM_F_EXCL == 0 || sent.flags&unix.NLM_F_CREATE == 0 {
		t.Errorf("flags %#x: a replace takes over whatever sits at the same key, whoever wrote it", sent.flags)
	}
	if got := sent.body[7]; got != unix.RTN_UNREACHABLE {
		t.Errorf("the hold was written as route type %d, want RTN_UNREACHABLE", got)
	}
	// A route that resolves to an error has no output interface: fib_check_nh
	// is not consulted for one, and naming a device makes the kernel refuse it.
	for attr := range (nlMessage{Kind: unix.RTM_NEWROUTE, Data: sent.body}).attributes(unix.SizeofRtMsg) {
		if attr == unix.RTA_OIF {
			t.Error("the hold names an output interface, which the kernel refuses")
		}
	}

	// A path to the same prefix is not a hold, and is written as one.
	plat, conn = writePlatform(t)
	if err := plat.AddRoute(Route{Destination: held.Destination}); err != nil {
		t.Fatalf("install the path: %v", err)
	}
	if got := conn.sent[0].body[7]; got != unix.RTN_UNICAST {
		t.Errorf("a path was written as route type %d, want RTN_UNICAST", got)
	}
}

// A prefix another writer already holds is reported as skipped rather than as
// a failure. Reported as a failure it would put the whole pass into backoff
// over a key no retry can free, once per pass, for the life of the process.
func TestLinuxReportsAnOccupiedRouteAsSkipped(t *testing.T) {
	plat, conn := writePlatform(t)
	conn.err = unix.EEXIST
	route := Route{Destination: netip.MustParsePrefix("2001:db8:2::/48")}
	for attempt := range 2 {
		if err := plat.AddRoute(route); !errors.Is(err, errRouteSkipped) {
			t.Errorf("attempt %d reported %v, want the route reported as not installed", attempt, err)
		}
	}
	// And it is not mistaken for an install: the next pass has to try again.
	if !plat.occupied[route.String()] {
		t.Error("the refusal was not recorded, so the warning repeats once a pass")
	}

	// Once the key frees up the record goes with it, or a later refusal is
	// silent.
	conn.err = nil
	if err := plat.AddRoute(route); err != nil {
		t.Fatalf("install after the key freed: %v", err)
	}
	if plat.occupied[route.String()] {
		t.Error("the route installed and is still recorded as held by somebody else")
	}
}

// Withdrawing matches on this reconciler's own protocol, so a route another
// writer put at the same prefix is not what goes away.
func TestLinuxWithdrawalNamesOurOwnProtocol(t *testing.T) {
	plat, conn := writePlatform(t)
	if err := plat.DelRoute(Route{Destination: netip.MustParsePrefix("2001:db8:3::/48")}); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if len(conn.sent) != 1 || conn.sent[0].kind != unix.RTM_DELROUTE {
		t.Fatalf("the withdrawal wrote %d messages", len(conn.sent))
	}
	if got := conn.sent[0].body[5]; got != DefaultProtocol {
		t.Errorf("the withdrawal named protocol %d, want this reconciler's own %d", got, DefaultProtocol)
	}
	// A route that is already gone is not an error: the reconciler and the
	// kernel disagreeing about one is ordinary and self-correcting.
	plat, conn = writePlatform(t)
	conn.err = unix.ESRCH
	if err := plat.DelRoute(Route{Destination: netip.MustParsePrefix("2001:db8:4::/48")}); err != nil {
		t.Errorf("withdrawing a route that was already gone reported %v", err)
	}
}
