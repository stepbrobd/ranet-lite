//go:build darwin && !ios

package kernel

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// The two interfaces every test here moves between, and the next hops on them.
const (
	uplinkIndex = 16
	dockIndex   = 19
)

var (
	v4default = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	v6default = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
)

// hostDefault is one family's answer from the host's own routing.
type hostDefault struct {
	index   int
	gateway netip.Addr
}

// fakeDefaults is the host's own routing as a test decides it.
type fakeDefaults struct {
	v4 hostDefault
	v6 hostDefault
}

func (f *fakeDefaults) Default(family netip.Addr) (int, netip.Addr, error) {
	held := f.v4
	if family.Is6() {
		held = f.v6
	}
	if held.index == 0 {
		return 0, netip.Addr{}, errNoDefaultRoute
	}
	return held.index, held.gateway, nil
}

// testUnderlay wires the owner onto a fake route socket and a routing table
// the test writes, so every assertion is about the messages that reached the
// kernel rather than about the bookkeeping beside them.
func testUnderlay(t *testing.T, links defaultRoutes, rib func() []byte) (*UnderlayDefaults, *fakeRouteSocket) {
	t.Helper()
	sock := &fakeRouteSocket{t: t}
	return &UnderlayDefaults{
		sock: sock, links: links,
		written:      make(map[writtenDefault]bool),
		refused:      make(map[writtenDefault]bool),
		covered:      make(map[netip.Prefix]bool),
		warned:       make(map[netip.Prefix]bool),
		dump:         func() ([]byte, error) { return rib(), nil },
		lookupDevice: func(string) (int, error) { return uplinkIndex, nil },
	}, sock
}

// hostRIB is a routing table holding the host's own unscoped default, the one
// route none of this may ever touch, plus whatever else the test adds.
func hostRIB(t *testing.T, extra ...dumpEntry) []byte {
	t.Helper()
	entries := []dumpEntry{{
		index: uplinkIndex,
		flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC,
		dst:   v4default, gateway: &route.Inet4Addr{IP: [4]byte{192, 168, 0, 1}},
	}}
	return dumpRIB(t, append(entries, extra...)...)
}

// ourScoped is the entry the kernel would report for a route this process
// wrote, which the withdrawal has to find before it sends a delete.
func ourScoped(index int, gateway netip.Addr) dumpEntry {
	destination := v4default
	if gateway.Is6() {
		destination = v6default
	}
	return dumpEntry{
		index: index,
		flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | unix.RTF_IFSCOPE,
		dst:   destination, gateway: routeAddr(gateway),
	}
}

// deletes is every RTM_DELETE that reached the kernel, described the way rule
// one is stated: the destination, the interface and whether it was scoped.
type sentRoute struct {
	kind    int
	scoped  bool
	index   int
	isV4    bool
	gateway netip.Addr
}

func sent(t *testing.T, sock *fakeRouteSocket) []sentRoute {
	t.Helper()
	var out []sentRoute
	for _, message := range sock.messages(t) {
		entry := sentRoute{kind: message.Type, scoped: message.Flags&unix.RTF_IFSCOPE != 0, index: message.Index}
		if len(message.Addrs) > unix.RTAX_DST {
			if address, ok := addressFromRouteAddr(message.Addrs[unix.RTAX_DST]); ok {
				entry.isV4 = address.Is4()
			}
		}
		if len(message.Addrs) > unix.RTAX_GATEWAY {
			if address, ok := addressFromRouteAddr(message.Addrs[unix.RTAX_GATEWAY]); ok {
				entry.gateway = address
			}
		}
		out = append(out, entry)
	}
	return out
}

// Rule one, the one that matters: the host's own unscoped default is never
// named by a delete, through any sequence of holds, releases and moves.
// Tailscale shipped the opposite as #21395, where clearing an exit node
// deleted the physical default route.
func TestUnderlayDefaultsNeverDeletesAnUnscopedDefault(t *testing.T) {
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	scoped := []dumpEntry{ourScoped(uplinkIndex, addr("192.168.0.1"))}
	underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t, scoped...) })

	for _, step := range []struct {
		name string
		run  func() error
	}{
		{"prepare", func() error { return underlay.Prepare(uplinkIndex) }},
		{"cover", func() error { _, err := underlay.Ready(); return err }},
		{"settle", func() error { return underlay.Settle(uplinkIndex) }},
		{"move to the dock", func() error { return underlay.Prepare(dockIndex) }},
		{"settle on the dock", func() error { return underlay.Settle(dockIndex) }},
		{"close", underlay.Close},
	} {
		if err := step.run(); err != nil {
			t.Logf("%s: %v", step.name, err)
		}
	}

	for _, message := range sent(t, sock) {
		if message.kind != unix.RTM_DELETE {
			continue
		}
		// Every one of the three, because the unscoped default differs from
		// ours only in the flag and in nothing else the kernel keys on.
		if !message.scoped {
			t.Errorf("a delete was sent without interface scope, which names the host's own default: %+v", message)
		}
		if message.index == 0 {
			t.Errorf("a delete was sent naming no interface: %+v", message)
		}
		if !message.gateway.IsValid() {
			t.Errorf("a delete was sent naming no next hop: %+v", message)
		}
	}
}

// A process that crashed left its scoped default behind. The next one records
// nothing, so it deletes nothing: adopting a route by its shape is exactly
// what this refuses to do on an interface the whole machine shares.
func TestUnderlayDefaultsLeavesWhatAnEarlierProcessWrote(t *testing.T) {
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	// The table as a crashed instance left it: the host's own default, and a
	// scoped one that looks exactly like what this process would write.
	orphan := ourScoped(uplinkIndex, addr("192.168.0.1"))
	underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t, orphan) })

	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	if err := underlay.Close(); err != nil {
		t.Fatal(err)
	}
	if err := underlay.Close(); err != nil {
		t.Fatal(err)
	}
	for _, message := range sent(t, sock) {
		if message.kind == unix.RTM_DELETE {
			t.Errorf("a fresh process deleted a route it never wrote: %+v", message)
		}
	}
}

// A next hop that moved under a route this process wrote makes the readback
// stop matching. The route is left alone rather than deleted on the strength
// of a record, because what is there now is somebody else's.
func TestUnderlayDefaultsLeavesARouteItNoLongerRecognizes(t *testing.T) {
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	// The kernel reports a scoped default on the right interface under a next
	// hop this process never wrote.
	replaced := ourScoped(uplinkIndex, addr("192.168.0.254"))
	underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t, replaced) })

	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	if got := len(underlay.Written()); got != 1 {
		t.Fatalf("the hold recorded %d routes, want 1", got)
	}
	if err := underlay.Close(); err != nil {
		t.Fatal(err)
	}
	for _, message := range sent(t, sock) {
		if message.kind == unix.RTM_DELETE {
			t.Errorf("a route whose readback did not match was deleted anyway: %+v", message)
		}
	}
	if got := len(underlay.Written()); got != 0 {
		t.Errorf("the record survived a route that is no longer ours, so it would be retried forever")
	}
}

// The route is written as soon as the socket is bound, and written once. Only
// writing it when the mesh looked like it was capturing left every set that
// slipped past that condition with nothing to fall back on; always writing it
// removes the class. Writing it repeatedly would be the other defect, so the
// second and third bindings have to be silent.
func TestUnderlayDefaultsWritesOnceWhenTheSocketBinds(t *testing.T) {
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	held := []dumpEntry{}
	underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t, held...) })

	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	first := sent(t, sock)
	if len(first) != 1 || first[0].kind != unix.RTM_ADD {
		t.Fatalf("binding wrote %+v, want one add", first)
	}
	// The kernel now reports it, which every later pass reads.
	held = append(held, ourScoped(uplinkIndex, addr("192.168.0.1")))
	for range 3 {
		if err := underlay.Prepare(uplinkIndex); err != nil {
			t.Fatal(err)
		}
		if err := underlay.Settle(uplinkIndex); err != nil {
			t.Fatal(err)
		}
	}
	if got := sent(t, sock); len(got) != 1 {
		t.Errorf("a route already in the table was written again: %+v", got)
	}
}

// And the repair: the kernel drops this route on its own, clearing IFF_UP
// purges it, so a record saying it was written says nothing about whether it
// is there. A pass that finds it gone puts it back.
func TestUnderlayDefaultsRewritesARouteTheKernelDropped(t *testing.T) {
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	held := []dumpEntry{}
	underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t, held...) })

	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	held = append(held, ourScoped(uplinkIndex, addr("192.168.0.1")))
	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	if got := sent(t, sock); len(got) != 1 {
		t.Fatalf("the second pass wrote %+v, want nothing", got)
	}

	// The interface goes down and comes back: the kernel purged the route and
	// did not restore it, while this process still holds the record.
	held = nil
	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	got := sent(t, sock)
	if len(got) != 2 || got[1].kind != unix.RTM_ADD {
		t.Errorf("the route the kernel dropped was not put back: %+v", got)
	}
}

// Rule three, the move: the interface the socket is going to is made usable
// before the socket moves onto it, and the one it left is cleared only after.
// Any other order leaves a moment with no route the bound socket can use.
func TestUnderlayDefaultsPreparesTheNewInterfaceBeforeClearingTheOld(t *testing.T) {
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	// The table as the kernel would report it, which the test moves under the
	// code the way the kernel does.
	var held []dumpEntry
	underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t, held...) })

	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	held = append(held, ourScoped(uplinkIndex, addr("192.168.0.1")))
	if err := underlay.Settle(uplinkIndex); err != nil {
		t.Fatal(err)
	}

	// The dock arrives: the host's default moves, and the transport calls
	// Prepare before it rebinds and Settle after.
	links.v4 = hostDefault{index: dockIndex, gateway: addr("10.0.0.1")}
	if err := underlay.Prepare(dockIndex); err != nil {
		t.Fatal(err)
	}
	held = append(held, ourScoped(dockIndex, addr("10.0.0.1")))
	if err := underlay.Settle(dockIndex); err != nil {
		t.Fatal(err)
	}

	messages := sent(t, sock)
	addDock := slices.IndexFunc(messages, func(m sentRoute) bool {
		return m.kind == unix.RTM_ADD && m.index == dockIndex
	})
	delUplink := slices.IndexFunc(messages, func(m sentRoute) bool {
		return m.kind == unix.RTM_DELETE && m.index == uplinkIndex
	})
	if addDock < 0 {
		t.Fatalf("the interface the socket moved to was never made usable: %+v", messages)
	}
	if delUplink < 0 {
		t.Fatalf("the interface the socket left kept its route: %+v", messages)
	}
	if addDock > delUplink {
		t.Errorf("the old interface was cleared before the new one was ready: %+v", messages)
	}
	if got := underlay.Written(); len(got) != 1 || got[0].index != dockIndex {
		t.Errorf("after the move the record holds %+v, want one route on the dock", got)
	}
}

// A family the host reaches through another interface gets no scoped default:
// a route on the interface the socket is bound to, pointing at a next hop that
// is not on it, is a black hole rather than a fallback. This is the ordinary
// case, because a host with no IPv6 default at all is ordinary.
func TestUnderlayDefaultsSkipsAFamilyTheHostReachesElsewhere(t *testing.T) {
	links := &fakeDefaults{
		v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")},
		v6: hostDefault{index: dockIndex, gateway: addr("2001:db8::1")},
	}
	underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t) })
	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	messages := sent(t, sock)
	if len(messages) != 1 || messages[0].kind != unix.RTM_ADD || !messages[0].isV4 {
		t.Fatalf("wrote %+v, want one IPv4 add", messages)
	}
	for _, held := range underlay.Written() {
		if held.destination == v6default {
			t.Error("a v6 default was written on an interface the host does not reach v6 through")
		}
	}
}

// The next hop on one interface can change without the interface changing, on
// a wifi network that renumbers. The route has to follow, and the old one has
// to go first or the add collides with it.
func TestUnderlayDefaultsRewritesWhenTheNextHopMoves(t *testing.T) {
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	var held []dumpEntry
	underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t, held...) })
	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	held = []dumpEntry{ourScoped(uplinkIndex, addr("192.168.0.1"))}

	// The wifi network renumbers: the host's next hop moves while the
	// interface does not, so the key collides and the old one has to go first.
	links.v4 = hostDefault{index: uplinkIndex, gateway: addr("192.168.1.1")}
	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	messages := sent(t, sock)
	if len(messages) != 3 {
		t.Fatalf("a renumbered next hop wrote %+v, want an add, a delete and an add", messages)
	}
	if messages[1].kind != unix.RTM_DELETE || messages[1].gateway != addr("192.168.0.1") {
		t.Errorf("the old next hop was not withdrawn first: %+v", messages)
	}
	if messages[2].kind != unix.RTM_ADD || messages[2].gateway != addr("192.168.1.1") {
		t.Errorf("the new next hop was not written: %+v", messages)
	}
}

// The encoder is the last line between this file and the host's own default,
// so it refuses anything that is not an interface-scoped default rather than
// trusting every path through the file to have got it right.
func TestScopedDefaultMessageRefusesAnythingElse(t *testing.T) {
	good := writtenDefault{destination: v4default, index: uplinkIndex, gateway: addr("192.168.0.1")}
	for name, bad := range map[string]writtenDefault{
		"a prefix rather than a default": {destination: prefix("10.0.0.0/8"), index: uplinkIndex, gateway: addr("192.168.0.1")},
		"no destination at all":          {index: uplinkIndex, gateway: addr("192.168.0.1")},
		"a default with no interface":    {destination: v4default, gateway: addr("192.168.0.1")},
		"a default with no next hop":     {destination: v4default, index: uplinkIndex},
		"a next hop of another family":   {destination: v4default, index: uplinkIndex, gateway: addr("2001:db8::1")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scopedDefaultMessage(unix.RTM_DELETE, bad); err == nil {
				t.Error("the encoder built a message for it")
			}
		})
	}
	for _, kind := range []int{unix.RTM_ADD, unix.RTM_DELETE} {
		message, err := scopedDefaultMessage(kind, good)
		if err != nil {
			t.Fatal(err)
		}
		if message.Flags&unix.RTF_IFSCOPE == 0 {
			t.Error("the encoder built a default without interface scope")
		}
		if message.Flags&unix.RTF_GATEWAY == 0 {
			t.Error("the encoder built a next-hop route without RTF_GATEWAY")
		}
		if message.Index != uplinkIndex {
			t.Errorf("the message names interface %d, want %d", message.Index, uplinkIndex)
		}
	}
}

// A dump the process cannot read is not permission to send a delete for a
// default route. It is reported and the route is left where it is.
func TestUnderlayDefaultsRefusesToWithdrawOnAnUnreadableDump(t *testing.T) {
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	var held []dumpEntry
	underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t, held...) })
	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	if len(underlay.Written()) != 1 {
		t.Fatalf("the route was not recorded, so this measures nothing: %+v", underlay.Written())
	}
	// The table stops reading back after the route is recorded, which is the
	// state a withdrawal must refuse to act in.
	underlay.dump = func() ([]byte, error) { return nil, errors.New("the kernel would not answer") }
	if _, err := underlay.Ready(); err == nil {
		t.Error("a pass over an unreadable dump reported the underlay covered")
	}
	if err := underlay.Close(); err == nil {
		t.Error("a withdrawal over an unreadable dump reported success")
	}
	for _, message := range sent(t, sock) {
		if message.kind == unix.RTM_DELETE {
			t.Errorf("a delete was sent without reading the kernel back: %+v", message)
		}
	}
}

// An add that answers EEXIST is success and not ownership. macOS writes a
// scoped default itself for every interface but the primary, and a crashed
// instance of this process leaves one behind; recording either as ours would
// make the next release delete a route this process did not write.
func TestUnderlayDefaultsDoesNotOwnARouteThatWasAlreadyThere(t *testing.T) {
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	existing := ourScoped(uplinkIndex, addr("192.168.0.1"))
	underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t, existing) })
	sock.err = unix.EEXIST

	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	if covered, err := underlay.Ready(); err != nil || !covered.V4 {
		t.Fatalf("an add that found the route already there was reported as a failure: %+v %v", covered, err)
	}
	if got := underlay.Written(); len(got) != 0 {
		t.Fatalf("a route that was already there was recorded as ours: %+v", got)
	}
	sock.err = nil
	if err := underlay.Close(); err != nil {
		t.Fatal(err)
	}
	for _, message := range sent(t, sock) {
		if message.kind == unix.RTM_DELETE {
			t.Errorf("a route this process did not create was deleted: %+v", message)
		}
	}
}

// Close leaves the socket gone, so every entry point afterwards has to say so
// rather than dereference it. Nothing reaches this from the daemon today,
// because the reconciler always withdraws first and the hub's follower is not
// joined, which is exactly the kind of invariant that holds until a refactor.
func TestUnderlayDefaultsRefusesEverythingAfterClose(t *testing.T) {
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	underlay, _ := testUnderlay(t, links, func() []byte { return hostRIB(t) })
	if err := underlay.Close(); err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"prepare": func() error { return underlay.Prepare(uplinkIndex) },
		"settle":  func() error { return underlay.Settle(uplinkIndex) },
		"ready":   func() error { _, err := underlay.Ready(); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, errUnderlayClosed) {
				t.Errorf("answered %v, want the closed error", err)
			}
		})
	}
	// And closing twice is not a second withdrawal.
	if err := underlay.Close(); err != nil {
		t.Errorf("a second close reported %v", err)
	}
}

// The underlay's own route outlives the routes that depend on it. A
// withdrawal that failed upstream leaves a capture in the kernel, and taking
// the fallback away under it is the window the ordering exists to close.
func TestCloseLeavesTheRouteWhileACaptureIsStillInstalled(t *testing.T) {
	const meshIndex = 77
	links := &fakeDefaults{v4: hostDefault{index: uplinkIndex, gateway: addr("192.168.0.1")}}
	var held []dumpEntry
	sock := &fakeRouteSocket{t: t}
	underlay := &UnderlayDefaults{
		sock: sock, links: links, mesh: meshIndex,
		written:      make(map[writtenDefault]bool),
		refused:      make(map[writtenDefault]bool),
		covered:      make(map[netip.Prefix]bool),
		warned:       make(map[netip.Prefix]bool),
		dump:         func() ([]byte, error) { return hostRIB(t, held...), nil },
		lookupDevice: resolvesTo(uplinkIndex),
	}
	if err := underlay.Prepare(uplinkIndex); err != nil {
		t.Fatal(err)
	}
	held = append(held, ourScoped(uplinkIndex, addr("192.168.0.1")))
	if len(underlay.Written()) != 1 {
		t.Fatalf("the route was not recorded: %+v", underlay.Written())
	}

	// A capture the reconciler could not withdraw, still out of the mesh
	// device.
	held = append(held, dumpEntry{
		index: meshIndex,
		flags: unix.RTF_UP | unix.RTF_STATIC,
		dst:   prefix("0.0.0.0/1"), gateway: &route.LinkAddr{Index: meshIndex},
	})
	if err := underlay.Close(); err != nil {
		t.Fatal(err)
	}
	for _, message := range sent(t, sock) {
		if message.kind == unix.RTM_DELETE {
			t.Errorf("the fallback was withdrawn under a capture that is still installed: %+v", message)
		}
	}
}

// Prepare covers what it can and moves the socket either way. An interface
// whose family the host reaches another way, or reaches through a link with no
// next hop to name, is still where this node's own traffic goes, so the socket
// belongs there; refusing the move would leave it bound to an interface that
// may be gone. What must not happen is a capture installing over it, and Ready
// answers that, per family.
//
// The comment on moveUnderlay used to claim the opposite, that a Prepare which
// covered nothing stopped the move. It did not, and holding it would have been
// the worse behaviour.
func TestPrepareMovesOntoAnInterfaceItCannotCover(t *testing.T) {
	for name, links := range map[string]*fakeDefaults{
		"the host reaches this family another way": {
			v4: hostDefault{index: dockIndex, gateway: addr("10.0.0.1")},
		},
		"the host reaches it through a link with no next hop": {
			v4: hostDefault{index: uplinkIndex},
		},
		"the host has no default at all": {},
	} {
		t.Run(name, func(t *testing.T) {
			underlay, sock := testUnderlay(t, links, func() []byte { return hostRIB(t) })
			if err := underlay.Prepare(uplinkIndex); err != nil {
				t.Errorf("preparing an interface it cannot cover refused the move: %v", err)
			}
			if got := sent(t, sock); len(got) != 0 {
				t.Errorf("it wrote %+v on an interface it cannot cover", got)
			}
			// And the separate question gets the honest answer.
			covered, err := underlay.Ready()
			if err != nil {
				t.Fatal(err)
			}
			if covered.V4 || covered.V6 {
				t.Errorf("an interface it covered nothing on reports %+v", covered)
			}
		})
	}
}
