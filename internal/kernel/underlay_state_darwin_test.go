//go:build darwin && !ios

package kernel

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// ourRecord is the record this tool would have written on the uplink.
func ourRecord() writtenDefault {
	return writtenDefault{
		destination: v4default, index: uplinkIndex,
		device: "en0", gateway: addr("192.168.0.1"),
	}
}

// reclaimFrom runs one reclaim against a table and a set of devices the test
// decides, and reports what reached the kernel and what survived the pass.
func reclaimFrom(t *testing.T, rib []byte, records []writtenDefault, lookup func(string) (int, error)) ([]sentRoute, []writtenDefault, string) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "underlay.json")
	if err := saveUnderlayState(state, records); err != nil {
		t.Fatal(err)
	}
	sock := &fakeRouteSocket{t: t}
	u := &UnderlayDefaults{
		sock: sock, links: &fakeDefaults{}, statePath: state,
		written:      make(map[writtenDefault]bool),
		refused:      make(map[writtenDefault]bool),
		covered:      make(map[netip.Prefix]bool),
		warned:       make(map[netip.Prefix]bool),
		dump:         func() ([]byte, error) { return rib, nil },
		lookupDevice: lookup,
	}
	loaded, err := loadUnderlayState(state)
	if err != nil {
		t.Fatalf("the state this test just wrote would not load: %v", err)
	}
	u.reclaim(loaded)
	return sent(t, sock), u.Refused(), state
}

// resolvesTo is a device lookup answering one index for every name.
func resolvesTo(index int) func(string) (int, error) {
	return func(string) (int, error) { return index, nil }
}

// A record is not permission to delete. The route the kernel holds has to
// match it on every attribute the kernel keys one on, and the scope is the one
// that separates our route from the host's own default at the same
// destination, which is the route none of this may ever touch.
func TestReclaimLeavesARouteThatDiffersOnAnyAttribute(t *testing.T) {
	// The host's own unscoped default, on the interface the record names, so
	// that the primary test passes and the attribute under test is the only
	// thing left deciding the outcome.
	primary := dumpEntry{
		index: uplinkIndex,
		flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC,
		dst:   v4default, gateway: &route.Inet4Addr{IP: [4]byte{192, 168, 0, 1}},
	}
	for name, held := range map[string]dumpEntry{
		"the destination is another family": {
			index: uplinkIndex,
			flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | unix.RTF_IFSCOPE,
			dst:   v6default, gateway: routeAddr(addr("2001:db8::1")),
		},
		"the destination is a prefix rather than a default": {
			index: uplinkIndex,
			flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | unix.RTF_IFSCOPE,
			dst:   prefix("10.0.0.0/8"), gateway: routeAddr(addr("192.168.0.1")),
		},
		"the interface index is another one": {
			index: dockIndex,
			flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | unix.RTF_IFSCOPE,
			dst:   v4default, gateway: routeAddr(addr("192.168.0.1")),
		},
		"the next hop moved": {
			index: uplinkIndex,
			flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | unix.RTF_IFSCOPE,
			dst:   v4default, gateway: routeAddr(addr("192.168.0.254")),
		},
		"it carries no interface scope, so it is the host's own": {
			index: uplinkIndex,
			flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC,
			dst:   v4default, gateway: routeAddr(addr("192.168.0.1")),
		},
	} {
		t.Run(name, func(t *testing.T) {
			rib := dumpRIB(t, primary, held)
			messages, _, _ := reclaimFrom(t, rib, []writtenDefault{ourRecord()}, resolvesTo(uplinkIndex))
			for _, message := range messages {
				t.Errorf("a record that did not match sent %+v", message)
			}
		})
	}
}

// Every attribute matching, and the interface still primary, is the one case
// that withdraws. Without it the four tests above would pass on a reclaim that
// never deletes anything at all.
func TestReclaimWithdrawsARouteThatMatchesInEveryWay(t *testing.T) {
	rib := dumpRIB(t,
		dumpEntry{
			index: uplinkIndex,
			flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC,
			dst:   v4default, gateway: routeAddr(addr("192.168.0.1")),
		},
		ourScoped(uplinkIndex, addr("192.168.0.1")),
	)
	messages, kept, state := reclaimFrom(t, rib, []writtenDefault{ourRecord()}, resolvesTo(uplinkIndex))
	if len(messages) != 1 || messages[0].kind != unix.RTM_DELETE {
		t.Fatalf("the reclaim sent %+v, want one delete", messages)
	}
	if !messages[0].scoped || messages[0].index != uplinkIndex {
		t.Errorf("the delete was %+v, want it scoped to interface %d", messages[0], uplinkIndex)
	}
	if len(kept) != 0 {
		t.Errorf("the reclaim kept %+v after withdrawing it", kept)
	}
	if recorded, err := loadUnderlayState(state); err != nil || len(recorded) != 0 {
		t.Errorf("the state file still holds %v (%v)", recorded, err)
	}
}

// The clause that makes the rest safe: macOS writes a scoped default for every
// interface except the one holding the unscoped default, so a scoped default
// on the interface that also holds the unscoped one is a shape only this tool
// produces. An interface that is no longer the primary one no longer carries
// that signature, and its route is left alone.
func TestReclaimLeavesARouteOnAnInterfaceThatIsNoLongerPrimary(t *testing.T) {
	ours := ourScoped(uplinkIndex, addr("192.168.0.1"))
	for name, rib := range map[string][]byte{
		"the host's default moved to another interface": dumpRIB(t,
			dumpEntry{
				index: dockIndex,
				flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC,
				dst:   v4default, gateway: routeAddr(addr("10.0.0.1")),
			},
			ours),
		"the host has no default of that family at all": dumpRIB(t, ours),
	} {
		t.Run(name, func(t *testing.T) {
			messages, kept, _ := reclaimFrom(t, rib, []writtenDefault{ourRecord()}, resolvesTo(uplinkIndex))
			for _, message := range messages {
				t.Errorf("a route on an interface that is no longer primary sent %+v", message)
			}
			if len(kept) != 1 {
				t.Errorf("the record was dropped rather than kept for a later start: %+v", kept)
			}
		})
	}
}

// An index is reused across a reboot and across a device reordering, which is
// why the name is recorded beside it. A name that now resolves to another
// index names a route that is not ours.
func TestReclaimLeavesARouteWhoseInterfaceWasRenumbered(t *testing.T) {
	rib := dumpRIB(t,
		dumpEntry{
			index: uplinkIndex,
			flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC,
			dst:   v4default, gateway: routeAddr(addr("192.168.0.1")),
		},
		ourScoped(uplinkIndex, addr("192.168.0.1")),
	)
	for name, lookup := range map[string]func(string) (int, error){
		"the name resolves to another index": resolvesTo(dockIndex),
		"the device is not present":          func(string) (int, error) { return 0, os.ErrNotExist },
	} {
		t.Run(name, func(t *testing.T) {
			messages, kept, _ := reclaimFrom(t, rib, []writtenDefault{ourRecord()}, lookup)
			for _, message := range messages {
				t.Errorf("a renumbered interface sent %+v", message)
			}
			if len(kept) != 1 {
				t.Errorf("the record was dropped rather than kept: %+v", kept)
			}
		})
	}
}

// A record whose route is simply gone costs nothing to forget, and remembering
// it would make the file grow for the life of the deployment.
func TestReclaimForgetsARecordWhoseRouteIsGone(t *testing.T) {
	rib := dumpRIB(t, dumpEntry{
		index: uplinkIndex,
		flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC,
		dst:   v4default, gateway: routeAddr(addr("192.168.0.1")),
	})
	messages, kept, state := reclaimFrom(t, rib, []writtenDefault{ourRecord()}, resolvesTo(uplinkIndex))
	for _, message := range messages {
		t.Errorf("a record whose route is gone sent %+v", message)
	}
	if len(kept) != 0 {
		t.Errorf("the record survived a route that is not there: %+v", kept)
	}
	if recorded, err := loadUnderlayState(state); err != nil || len(recorded) != 0 {
		t.Errorf("the state file still holds %v (%v)", recorded, err)
	}
}

// loadInto writes one body to a state file and reads it back the way a start
// does, then drives the constructor path over whatever came back. A node
// starting depends on that path surviving, and no unreadable file may ever
// reach a delete, so both are asserted for every body below.
func loadInto(t *testing.T, body string) ([]writtenDefault, error) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "underlay.json")
	if err := os.WriteFile(state, []byte(body), stateMode); err != nil {
		t.Fatal(err)
	}
	records, err := loadUnderlayState(state)
	sock := &fakeRouteSocket{t: t}
	u := &UnderlayDefaults{
		sock: sock, links: &fakeDefaults{}, statePath: state,
		written:      make(map[writtenDefault]bool),
		refused:      make(map[writtenDefault]bool),
		covered:      make(map[netip.Prefix]bool),
		warned:       make(map[netip.Prefix]bool),
		dump:         func() ([]byte, error) { return dumpRIB(t), nil },
		lookupDevice: resolvesTo(uplinkIndex),
	}
	u.reclaim(records)
	for _, message := range sent(t, sock) {
		t.Errorf("a file the load did not take whole produced %+v", message)
	}
	return records, err
}

// goodRecord is ourRecord as the file spells it, the one every case below
// pairs its bad record with.
const goodRecord = `{"destination":"0.0.0.0/0","index":16,"interface":"en0","gateway":"192.168.0.1"}`

// A state file this tool cannot read must not stop a node starting, and must
// not be turned into a delete. A daemon that will not come up is worse than a
// route left behind, and a delete built from a file that would not parse is
// worse than both.
//
// The error is asserted rather than logged: a load that swallowed it would
// report a clean first start over a file that says this node owns a route on
// the interface the whole machine shares, and the difference between the two
// is the whole of what the record is for.
func TestFileThatWillNotParseIsRefusedAndDeletesNothing(t *testing.T) {
	for name, body := range map[string]string{
		"empty":                   "",
		"truncated":               `[{"destination":"0.0.0.0/0","index":16,`,
		"not json at all":         "this is not a state file",
		"json of the wrong shape": `{"destination":"0.0.0.0/0"}`,
	} {
		t.Run(name, func(t *testing.T) {
			records, err := loadInto(t, body)
			if err == nil {
				t.Error("a file that does not parse was reported as a clean start")
			}
			if len(records) != 0 {
				t.Errorf("it yielded %+v anyway", records)
			}
		})
	}
}

// One record this tool cannot read does not discard the others, which may each
// name a route that is still there. The file holds one record per family, so
// throwing the file away over the second leaks the first for good.
//
// Each case is its bad record beside the one good one, so the cases stay
// distinguishable: a decoder that refuses a different clause than the case
// names still has to hand back exactly the good record and nothing else.
func TestRecordThatWillNotDecodeIsDroppedAndTheOthersKept(t *testing.T) {
	for name, bad := range map[string]string{
		"naming no prefix":                      `{"destination":"","index":16,"interface":"en0","gateway":"192.168.0.1"}`,
		"naming a prefix rather than a default": `{"destination":"10.0.0.0/8","index":16,"interface":"en0","gateway":"192.168.0.1"}`,
		"naming no interface index":             `{"destination":"::/0","index":0,"interface":"en1","gateway":"2001:db8::1"}`,
		// A lookup resolves the name, so a record without one can never be
		// weighed against the kernel and would be held for good.
		"naming no interface":                 `{"destination":"::/0","index":19,"interface":"","gateway":"2001:db8::1"}`,
		"naming an unparseable next hop":      `{"destination":"::/0","index":16,"interface":"en0","gateway":"not an address"}`,
		"whose next hop is of another family": `{"destination":"0.0.0.0/0","index":16,"interface":"en0","gateway":"2001:db8::1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			for order, body := range map[string]string{
				"the bad record first":  "[" + bad + "," + goodRecord + "]",
				"the good record first": "[" + goodRecord + "," + bad + "]",
			} {
				t.Run(order, func(t *testing.T) {
					records, err := loadInto(t, body)
					if err != nil {
						t.Errorf("one record this tool cannot read refused the whole file: %v", err)
					}
					if want := []writtenDefault{ourRecord()}; !slices.Equal(records, want) {
						t.Errorf("the load yielded %+v, want only %+v", records, want)
					}
				})
			}
		})
	}
}

// watchingSocket answers WriteRoute after telling the test what the state file
// held at the moment the message left, which is the only way to see an
// ordering the process that dies between the two lines cannot report.
type watchingSocket struct {
	*fakeRouteSocket
	state string
	held  [][]writtenDefault
}

func (w *watchingSocket) WriteRoute(message *route.RouteMessage) error {
	w.fakeRouteSocket.t.Helper()
	records, _ := loadUnderlayState(w.state)
	w.held = append(w.held, records)
	return w.fakeRouteSocket.WriteRoute(message)
}

// The record is on disk before the route is in the kernel, never after. A
// process dying between the two leaves a record for a route that does not
// exist, which the next start's readback discards; the other order leaves a
// route on the interface the whole machine shares with no record, and rule one
// says nothing may ever remove that.
func TestRecordIsOnDiskBeforeTheRouteReachesTheKernel(t *testing.T) {
	state := filepath.Join(t.TempDir(), "underlay.json")
	sock := &watchingSocket{fakeRouteSocket: &fakeRouteSocket{t: t}, state: state}
	u := &UnderlayDefaults{
		sock: sock, host: namedDevices{}, statePath: state,
		links:        &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}},
		written:      make(map[writtenDefault]bool),
		refused:      make(map[writtenDefault]bool),
		covered:      make(map[netip.Prefix]bool),
		warned:       make(map[netip.Prefix]bool),
		dump:         func() ([]byte, error) { return hostRIB(t), nil },
		lookupDevice: resolvesTo(uplinkIndex),
	}
	if err := u.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	if len(sock.held) != 1 {
		t.Fatalf("the pass sent %d messages, want the one route it had to write", len(sock.held))
	}
	want := writtenDefault{
		destination: v4default, index: uplinkIndex,
		device: "uplink0", gateway: addr("192.168.0.1"),
	}
	if got := sock.held[0]; !slices.Contains(got, want) {
		t.Errorf("the file held %+v when the route was written, want %+v already in it", got, want)
	}
}

// A table that will not read back says nothing about whether the recorded
// routes are still there, so the records are kept rather than forgotten.
// Dropping them would leak one scoped default per start on an interface no
// later run has any claim to, which is the leak the file exists to close.
func TestReclaimKeepsItsRecordsWhenTheTableWillNotReadBack(t *testing.T) {
	for name, dump := range map[string]func() ([]byte, error){
		"the dump fails": func() ([]byte, error) { return nil, errors.New("no route socket") },
		// A message declaring more bytes than the buffer holds, as a read cut
		// short by a full socket buffer leaves.
		"the dump will not parse": func() ([]byte, error) { return []byte{0x20, 0x00, 0x05, 0x01, 0x00, 0x00}, nil },
	} {
		t.Run(name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "underlay.json")
			if err := saveUnderlayState(state, []writtenDefault{ourRecord()}); err != nil {
				t.Fatal(err)
			}
			sock := &fakeRouteSocket{t: t}
			u := &UnderlayDefaults{
				sock: sock, links: &fakeDefaults{}, statePath: state,
				written:      make(map[writtenDefault]bool),
				refused:      make(map[writtenDefault]bool),
				covered:      make(map[netip.Prefix]bool),
				warned:       make(map[netip.Prefix]bool),
				dump:         dump,
				lookupDevice: resolvesTo(uplinkIndex),
			}
			u.reclaim([]writtenDefault{ourRecord()})

			for _, message := range sent(t, sock) {
				t.Errorf("a table that would not read back produced %+v", message)
			}
			if want := []writtenDefault{ourRecord()}; !slices.Equal(u.Refused(), want) {
				t.Errorf("the pass kept %+v, want %+v held for the next start", u.Refused(), want)
			}
			// And on disk, which is where the next start reads it.
			got, err := loadUnderlayState(state)
			if err != nil {
				t.Fatal(err)
			}
			if want := []writtenDefault{ourRecord()}; !slices.Equal(got, want) {
				t.Errorf("the file holds %+v, want %+v", got, want)
			}
		})
	}
}

// The file is replaced rather than rewritten, so a process dying mid-write
// leaves the previous record rather than a truncated one, which loads as no
// record at all and leaks whatever it named. A rename gives the path a new
// inode and a write in place does not, which is the difference read here.
func TestStateFileIsReplacedRatherThanRewrittenInPlace(t *testing.T) {
	state := filepath.Join(t.TempDir(), "underlay.json")
	inode := func() uint64 {
		t.Helper()
		info, err := os.Stat(state)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("stat answered %T, which names no inode", info.Sys())
		}
		return stat.Ino
	}
	if err := saveUnderlayState(state, []writtenDefault{ourRecord()}); err != nil {
		t.Fatal(err)
	}
	first := inode()
	if err := saveUnderlayState(state, []writtenDefault{
		ourRecord(),
		{destination: v6default, index: uplinkIndex, device: "en0", gateway: addr("2001:db8::1")},
	}); err != nil {
		t.Fatal(err)
	}
	if second := inode(); second == first {
		t.Errorf("both writes landed on inode %d, so the second truncated the file the first had left", second)
	}
	// And the temporary file it renamed over is not left beside it.
	entries, err := os.ReadDir(filepath.Dir(state))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != filepath.Base(state) {
			t.Errorf("the replacement left %s behind", entry.Name())
		}
	}
}

// A state file that is missing is the ordinary first start.
func TestMissingStateStartsClean(t *testing.T) {
	records, err := loadUnderlayState(filepath.Join(t.TempDir(), "underlay.json"))
	if err != nil {
		t.Errorf("a first start reported %v", err)
	}
	if len(records) != 0 {
		t.Errorf("a first start found %+v", records)
	}
}

// The record has to survive the round trip exactly, or a restart withdraws
// nothing: every attribute of it is part of the test a delete has to pass.
func TestStateRoundTripsEveryAttribute(t *testing.T) {
	state := filepath.Join(t.TempDir(), "underlay.json")
	want := []writtenDefault{
		{destination: v4default, index: uplinkIndex, device: "en0", gateway: addr("192.168.0.1")},
		{destination: v6default, index: dockIndex, device: "en1", gateway: addr("2001:db8::1")},
	}
	if err := saveUnderlayState(state, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadUnderlayState(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("the round trip produced %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("record %d round-tripped as %+v, want %+v", i, got[i], want[i])
		}
	}
	// Owner only, like the control socket's lock beside it.
	info, err := os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != stateMode {
		t.Errorf("the state file is mode %o, want %o", mode, stateMode)
	}
}

// The load refuses a file holding more records than this writes, rather than
// acting on a list something else produced.
func TestStateRefusesMoreRecordsThanItWrites(t *testing.T) {
	state := filepath.Join(t.TempDir(), "underlay.json")
	many := make([]writtenDefault, 0, maxStateRecords+1)
	for i := range maxStateRecords + 1 {
		many = append(many, writtenDefault{
			destination: v4default, index: uplinkIndex + i,
			device: "en0", gateway: addr("192.168.0.1"),
		})
	}
	if err := saveUnderlayState(state, many); err == nil {
		t.Error("the save wrote more records than it bounds")
	}
	// Written by something else, so the load has to refuse it too.
	raw := "["
	for i := range maxStateRecords + 1 {
		if i > 0 {
			raw += ","
		}
		raw += `{"destination":"0.0.0.0/0","index":16,"interface":"en0","gateway":"192.168.0.1"}`
	}
	raw += "]"
	if err := os.WriteFile(state, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := loadUnderlayState(state)
	if err == nil {
		t.Error("the load accepted more records than the save writes")
	}
	if len(records) != 0 {
		t.Errorf("it yielded %+v anyway", records)
	}
}

// The premise the reclaim's last condition rests on, asserted on whatever
// machine the suite runs on rather than taken on trust: no interface holds
// both an unscoped default and a scoped one, so a scoped default on the
// interface that also holds the unscoped one is a shape only this tool
// produces. It reads the table and writes nothing.
func TestNoOtherProgramScopesADefaultToThePrimaryInterface(t *testing.T) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatal(err)
	}
	// One subtest per family, so a family the host cannot answer for reports
	// itself untested rather than passing. This host carries nine scoped ::/0
	// routes on utuns and no unscoped one, and a single-bodied test skipped
	// quietly on it while claiming the premise held for IPv6.
	for _, destination := range defaultPrefixes {
		t.Run(destination.String(), func(t *testing.T) {
			primary, ok := unscopedDefaultIndex(messages, destination)
			if !ok {
				t.Skipf("this host has no default of this family, so the premise is untested for it")
			}
			scoped := 0
			for _, message := range messages {
				rm, ok := message.(*route.RouteMessage)
				if !ok || rm.Type != unix.RTM_GET || rm.Flags&unix.RTF_IFSCOPE == 0 {
					continue
				}
				if isDefaultKey(rm, destination) && rm.Index == primary {
					scoped++
				}
			}
			t.Logf("the host's default is on index %d, which carries %d scoped defaults", primary, scoped)
			if scoped != 0 {
				t.Errorf("interface %d holds both the unscoped default and %d scoped ones, so the reclaim's last condition does not tell this tool's route from another program's on this host",
					primary, scoped)
			}
		})
	}
}

// A record reclaim refused must not be reachable by an ordinary withdrawal.
// Every condition reclaim weighs is worth nothing if the record then joins the
// set a later Close deletes from on the shape check alone: measured before
// this split, the refusal was logged and the same route was withdrawn
// milliseconds later on the first pass of every start.
func TestRefusedRecordsAreNotReachableByAWithdrawal(t *testing.T) {
	// The host's default has moved to another interface, so clause three
	// refuses the record and the route stays.
	ours := ourScoped(uplinkIndex, addr("192.168.0.1"))
	rib := dumpRIB(t,
		dumpEntry{
			index: dockIndex,
			flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC,
			dst:   v4default, gateway: routeAddr(addr("10.0.0.1")),
		},
		ours)
	state := filepath.Join(t.TempDir(), "underlay.json")
	if err := saveUnderlayState(state, []writtenDefault{ourRecord()}); err != nil {
		t.Fatal(err)
	}
	sock := &fakeRouteSocket{t: t}
	u := &UnderlayDefaults{
		sock: sock, links: &fakeDefaults{}, statePath: state,
		written:      make(map[writtenDefault]bool),
		refused:      make(map[writtenDefault]bool),
		covered:      make(map[netip.Prefix]bool),
		warned:       make(map[netip.Prefix]bool),
		dump:         func() ([]byte, error) { return rib, nil },
		lookupDevice: resolvesTo(uplinkIndex),
	}
	records, err := loadUnderlayState(state)
	if err != nil {
		t.Fatal(err)
	}
	u.reclaim(records)

	if len(u.Refused()) != 1 {
		t.Fatalf("the refusal did not keep the record: %+v", u.Refused())
	}
	if len(u.Written()) != 0 {
		t.Fatalf("a refused record joined the set a withdrawal deletes from: %+v", u.Written())
	}
	// The withdrawal every start makes, which is where the record used to go.
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	for _, message := range sent(t, sock) {
		if message.kind == unix.RTM_DELETE {
			t.Errorf("a record the clauses refused was withdrawn anyway: %+v", message)
		}
	}
	// And it survives to the next start, which is the only thing that can
	// weigh the clauses again.
	kept, err := loadUnderlayState(state)
	if err != nil || len(kept) != 1 {
		t.Errorf("the refused record was forgotten: %v (%v)", kept, err)
	}
}

// A second daemon must not touch the record a running one owns. It reaches
// reclaim before the control socket's lock and before the port is bound, so
// without a lock of its own it withdrew the first process's live route, which
// passes every clause because it is real, resolvable and on the primary, and
// then wrote an empty record over it.
func TestSecondProcessReclaimsNothing(t *testing.T) {
	state := filepath.Join(t.TempDir(), "underlay.json")
	if err := saveUnderlayState(state, []writtenDefault{ourRecord()}); err != nil {
		t.Fatal(err)
	}
	first, err := lockState(state)
	if err != nil {
		t.Fatalf("the first process could not take the record: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	second, err := lockState(state)
	if err == nil {
		_ = second.Close()
		t.Fatal("a second process took a record the first one holds")
	}

	// And the constructor carries on rather than refusing to start, with no
	// record of its own to act on.
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	u, err := NewUnderlayDefaults(nil, links, 0, state)
	if err != nil {
		t.Fatalf("a second process refused to start: %v", err)
	}
	t.Cleanup(func() { _ = u.Close() })
	if got := len(u.Written()) + len(u.Refused()); got != 0 {
		t.Errorf("a second process took %d records it does not own", got)
	}
	kept, err := loadUnderlayState(state)
	if err != nil || len(kept) != 1 {
		t.Errorf("a second process overwrote the record: %v (%v)", kept, err)
	}
}
