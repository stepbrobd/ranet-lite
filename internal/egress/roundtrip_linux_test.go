//go:build linux && !android

package egress

import (
	"net/netip"
	"os"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// This is the only test here that speaks to a real kernel. Everything else in
// the package is checked against a fake, which can only ever agree with the
// encoder it was written beside; what nf_tables accepts, and what it hands
// back afterwards, is the half a fake cannot answer for.
//
// It refuses to run anywhere but inside a network namespace it created itself
// and proved empty, because the code under test writes into the host's packet
// filter and the machine running the suite may well be translating real
// traffic. internal/kernel's netlink round trips take the same two guards, and
// the netlink VM check runs both as root.
func TestNftablesRoundTripInNetworkNamespace(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)

	cfg := Config{
		Enable: true, Return: true,
		Advertise: prefixes(t, "198.51.100.0/24", "2001:db8:1::/48", "0.0.0.0/0"),
	}
	rt := Runtime{
		Interface:     "ranet0",
		MeshAddresses: []netip.Addr{netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("2001:db8::2")},
		Forwarding:    func() (bool, bool) { return true, true },
	}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)

	tr := &Translator{cfg: cfg, rt: rt, be: be}
	desired := tr.desired()
	if len(desired) != 5 {
		t.Fatalf("the configuration asks for %d rules, want two out and three in", len(desired))
	}
	if err := be.Apply(desired); err != nil {
		t.Fatalf("install %d rules: %v", len(desired), err)
	}

	// The whole round trip in one assertion: the kernel took every expression,
	// kept the rules in the order they were written, and handed back the
	// spelling this package wrote into each one's comment. A mismatch here is
	// a ruleset the reconcile loop would rewrite on every pass forever.
	held, err := be.Rules()
	if err != nil {
		t.Fatalf("read the rules back: %v", err)
	}
	want := make([]string, 0, len(desired))
	for _, rule := range desired {
		want = append(want, rule.String())
	}
	got := make([]string, 0, len(held))
	for _, rule := range held {
		got = append(got, rule.Spec)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("the kernel holds %q, want %q", got, want)
	}
	if !sameRules(held, desired) {
		t.Error("a pass would rewrite rules the kernel already holds")
	}

	// A counter in every rule, at zero, since nothing has crossed this
	// namespace. Reading it back at all is the part that can break: it is a
	// 64-bit attribute the kernel aligns with a padding attribute of its own.
	for i, rule := range held {
		if rule.Packets != 0 || rule.Bytes != 0 {
			t.Errorf("rule %d came back with %d flows and %d bytes in an empty namespace", i, rule.Packets, rule.Bytes)
		}
	}

	// This tool's own tables are the only ones here, so nothing can be
	// reported as another writer's.
	conflicts, err := be.Conflicts()
	if err != nil {
		t.Fatalf("look for other translation: %v", err)
	}
	if len(conflicts) != 0 {
		t.Errorf("reported %q in a namespace holding nothing else", conflicts)
	}

	// Applying the same rules again replaces the chain rather than appending
	// to it, the path a changed configuration takes on a running node.
	if err := be.Apply(desired); err != nil {
		t.Fatalf("reinstall the rules: %v", err)
	}
	if held, err = be.Rules(); err != nil || len(held) != len(desired) {
		t.Fatalf("a second install left %d rules (%v), want %d", len(held), err, len(desired))
	}

	if err := be.Withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	requireEmptyRuleset(t, be)
	// And a withdrawal of nothing is not an error, which every shutdown on a
	// node that never installed anything depends on.
	if err := be.Withdraw(); err != nil {
		t.Errorf("withdrawing an empty host failed: %v", err)
	}
}

// requireEmptyRuleset is the second guard, and the assertion after a
// withdrawal. A namespace already holding a table is somebody's real one,
// whatever the inode said.
func requireEmptyRuleset(t *testing.T, be backend) {
	t.Helper()
	tables, err := be.(*nftables).ownTables()
	if err != nil {
		t.Fatalf("list this tool's tables: %v", err)
	}
	if len(tables) != 0 {
		t.Fatalf("the namespace holds %d tables named %s", len(tables), TableName)
	}
	rules, err := be.Rules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("the namespace holds %d rules of this tool's", len(rules))
	}
}

// enterThrowawayNamespace moves this thread into a network namespace of its
// own and refuses to continue if it did not move, the same pair of guards
// internal/kernel's netlink test takes.
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
