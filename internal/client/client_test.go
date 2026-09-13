package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
	yaml "gopkg.in/yaml.v3"
)

func TestInboundBatchOrderMergesConsecutiveCompletedBatches(t *testing.T) {
	const first, second = 0, 1

	firstResult := inboundDecrypted{Err: errors.New("first")}
	secondResult := inboundDecrypted{Err: errors.New("second")}
	completed := make(chan *inboundBatch, 2)
	recycled := make(chan *inboundBatch, 2)
	delivered := make(chan byte, 2)
	emitterDone := make(chan struct{})
	calls := 0
	go func() {
		emitInboundBatches(completed, recycled, func(results []inboundDecrypted) {
			calls++
			for _, result := range results {
				if result.Err == firstResult.Err {
					delivered <- 1
				} else {
					delivered <- 2
				}
			}
		})
		close(emitterDone)
	}()
	completed <- &inboundBatch{ticket: second, results: []inboundDecrypted{secondResult}}
	select {
	case got := <-delivered:
		t.Fatalf("later batch %d delivered before the first batch", got)
	default:
	}
	completed <- &inboundBatch{ticket: first, results: []inboundDecrypted{firstResult}}
	close(completed)
	<-emitterDone
	close(delivered)

	var got []byte
	for value := range delivered {
		got = append(got, value)
	}
	if !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("delivery order = %v, want [1 2]", got)
	}
	if calls != 1 {
		t.Fatalf("emit called %d times, want one merged call", calls)
	}
}

func runtimeFixture(t *testing.T) (*config.Config, ed25519.PrivateKey, registry.Registry) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	reg := registry.Registry{{
		Organization: "example", PublicKey: publicPEM,
		Nodes: []registry.Node{
			{CommonName: "local", Endpoints: []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Port: 13000}}},
			{CommonName: "gateway", Endpoints: []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip4", Port: 13000}}},
		},
	}}
	cfg := &config.Config{
		Organization: "example", CommonName: "local",
		Endpoints: []config.Endpoint{{SerialNumber: "0", AddressFamily: "ip4"}},
		Peers:     []config.Peer{{Organization: "example", CommonName: "gateway", SerialNumber: "1"}},
	}
	return cfg, privateKey, reg
}

func TestValidateRuntimeConfig(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	if err := validateRuntimeConfig(cfg, privateKey, reg); err != nil {
		t.Fatal(err)
	}
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeConfig(cfg, wrongKey, reg); err == nil {
		t.Fatal("accepted a private key from another organization")
	}
	cfg.Peers[0].SerialNumber = "missing"
	if err := validateRuntimeConfig(cfg, privateKey, reg); err == nil {
		t.Fatal("accepted a peer endpoint missing from the registry")
	}
}

func TestValidateESPTunnelPayload(t *testing.T) {
	ipv4 := make([]byte, 20)
	ipv4[0], ipv4[3] = 0x45, 20
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	for _, test := range []struct {
		name    string
		plain   []byte
		nh      byte
		deliver bool
		wantErr bool
	}{
		{name: "IPv4", plain: ipv4, nh: esp.NextHeaderIPv4, deliver: true},
		{name: "IPv6", plain: ipv6, nh: esp.NextHeaderIPv6, deliver: true},
		{name: "dummy", plain: ipv6, nh: esp.NextHeaderNone},
		{name: "version mismatch", plain: ipv6, nh: esp.NextHeaderIPv4, wantErr: true},
		{name: "unsupported", plain: ipv4, nh: 6, wantErr: true},
		{name: "IPv4 trailing data", plain: append(append([]byte(nil), ipv4...), 0), nh: esp.NextHeaderIPv4, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			deliver, err := validateESPTunnelPayload(test.plain, test.nh)
			if (err != nil) != test.wantErr || deliver != test.deliver {
				t.Fatalf("got deliver=%v err=%v; want deliver=%v err=%v", deliver, err, test.deliver, test.wantErr)
			}
		})
	}
}

func TestSyncPeersStartsAndStopsDialers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, dialers: make(map[string]*dialer)}
	c.cfg.Store(&config.Config{
		Organization: "example",
		CommonName:   "node",
		Endpoints:    []config.Endpoint{{SerialNumber: "0", AddressFamily: "ip4"}},
		Peers: []config.Peer{
			{Organization: "example", CommonName: "a"},
			{Organization: "example", CommonName: "b"},
		},
	})
	// Both nodes are in the registry, with an endpoint that never resolves, so
	// each dialer stays in its retry loop rather than giving up and taking
	// itself out of the map. What is under test is the bookkeeping, not the
	// dialing.
	reg := registry.Registry{{Organization: "example", Nodes: []registry.Node{
		{CommonName: "a", Endpoints: []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Port: 13000}}},
		{CommonName: "b", Endpoints: []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Port: 13000}}},
	}}}
	c.reg.Store(&reg)

	c.syncPeers()
	if got := dialerCount(c); got != 2 {
		t.Fatalf("started %d dialers, want 2", got)
	}
	if !hasDialer(c, "example/a/@0") {
		t.Fatal("no dialer for the first peer")
	}

	// Dropping one peer stops exactly that dialer and leaves the other alone.
	c.cfg.Store(&config.Config{
		Organization: "example",
		CommonName:   "node",
		Endpoints:    []config.Endpoint{{SerialNumber: "0", AddressFamily: "ip4"}},
		Peers:        []config.Peer{{Organization: "example", CommonName: "a"}},
	})
	c.syncPeers()
	if got := dialerCount(c); got != 1 {
		t.Fatalf("after removing a peer there are %d dialers, want 1", got)
	}
	if !hasDialer(c, "example/a/@0") {
		t.Fatal("the surviving peer's dialer was replaced or removed")
	}
	if hasDialer(c, "example/b/@0") {
		t.Fatal("the removed peer's dialer is still tracked")
	}
	cancel()
	c.peers.Wait()
}

// The dialer map is written by every dialer that ends on its own, so a test
// reads it the way syncPeers does.
func dialerCount(c *Client) int {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	return len(c.dialers)
}

func hasDialer(c *Client, path string) bool {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	return c.dialers[path] != nil
}

func TestReloadRefusesChangesItCannotApply(t *testing.T) {
	base := &config.Config{
		Organization: "example", CommonName: "node", Port: 13000,
		Endpoints: []config.Endpoint{{SerialNumber: "0", AddressFamily: "ip4"}},
	}
	for name, next := range map[string]*config.Config{
		"identity": {Organization: "example", CommonName: "other", Port: 13000, Endpoints: base.Endpoints},
		"port":     {Organization: "example", CommonName: "node", Port: 14000, Endpoints: base.Endpoints},
		"tun":      {Organization: "example", CommonName: "node", Port: 13000, Endpoints: base.Endpoints, TUN: "ranet9"},
		"endpoints": {Organization: "example", CommonName: "node", Port: 13000,
			Endpoints: []config.Endpoint{{SerialNumber: "1", AddressFamily: "ip6"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := reloadable(base, next); err == nil {
				t.Fatal("a change that needs a restart was accepted")
			}
		})
	}
	unchanged := *base
	unchanged.Peers = []config.Peer{{Organization: "example", CommonName: "a"}}
	if err := reloadable(base, &unchanged); err != nil {
		t.Fatalf("adding a peer was refused: %v", err)
	}
}

func TestReloadRefusesAssignedAddressChanges(t *testing.T) {
	for name, change := range map[string]func(*config.Config){
		"top-level addition": func(c *config.Config) {
			c.Originate = []string{"fd00:1::1/64", "fd00:2::1/64"}
		},
		"top-level removal": func(c *config.Config) { c.Originate = nil },
		"babel addition": func(c *config.Config) {
			c.Babel.Originate = []config.OriginatePrefix{{
				Prefix: netip.MustParsePrefix("fd00:2::1/64"), From: netip.MustParsePrefix("fd00:3::/64"),
			}}
		},
		"host address change": func(c *config.Config) { c.Originate = []string{"fd00:1::2/64"} },
	} {
		t.Run(name, func(t *testing.T) {
			c, path := reloadFixture(t)
			old := c.config()
			old.Kernel = config.Kernel{Enabled: true, AssignOriginated: true}
			old.Originate = []string{"fd00:1::1/64"}
			next := *old
			change(&next)
			writeConfig(t, path, &next)
			if _, err := config.Load(path); err != nil {
				t.Fatalf("invalid reload fixture: %v", err)
			}
			if err := c.Reload(path); err == nil {
				t.Fatal("reload accepted an assigned address change")
			}
			if !slices.Equal(c.config().Originate, old.Originate) ||
				!slices.Equal(c.config().Babel.Originate, old.Babel.Originate) {
				t.Error("refused reload changed the active originations")
			}
		})
	}
}

func TestReloadAllowsUnchangedAssignedAddresses(t *testing.T) {
	base := &config.Config{
		Kernel:    config.Kernel{Enabled: true, AssignOriginated: true},
		Originate: []string{"fd00:1::1/64", "fd00:2::1/64"},
	}
	for name, change := range map[string]func(*config.Config){
		"reorder and duplicate": func(c *config.Config) {
			c.Originate = []string{"fd00:2::1/64", "fd00:1::1/64", "fd00:2::1/64"}
		},
		"move into babel": func(c *config.Config) {
			c.Originate = []string{"fd00:1::1/64"}
			c.Babel.Originate = []config.OriginatePrefix{{
				Prefix: netip.MustParsePrefix("fd00:2::1/64"), From: netip.MustParsePrefix("fd00:3::/64"),
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			next := *base
			change(&next)
			if err := reloadable(base, &next); err != nil {
				t.Fatalf("unchanged assigned addresses were refused: %v", err)
			}
		})
	}
	for _, kernel := range []config.Kernel{
		{Enabled: true},
		{AssignOriginated: true},
	} {
		old := &config.Config{Kernel: kernel}
		next := *old
		next.Originate = []string{"fd00:4::/64"}
		if err := reloadable(old, &next); err != nil {
			t.Fatalf("announcement-only change was refused: %v", err)
		}
	}
}

func reloadFixture(t *testing.T) (*Client, string) {
	t.Helper()
	cfg, privateKey, reg := runtimeFixture(t)
	dir := t.TempDir()
	cfg.Port = 13000
	cfg.PrivateKey = filepath.Join(dir, "key.pem")
	cfg.Registry = filepath.Join(dir, "registry.json")
	writeKey(t, cfg.PrivateKey, privateKey)
	writeRegistry(t, cfg.Registry, reg)
	speaker, err := babel.New(cfg.Babel.SpeakerConfig(), &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		ctx: ctx, cancel: cancel, privateKey: privateKey,
		speaker: speaker, dialers: make(map[string]*dialer),
	}
	c.cfg.Store(cfg)
	c.reg.Store(&reg)
	t.Cleanup(func() { cancel(); c.peers.Wait() })
	return c, filepath.Join(dir, "config.yaml")
}

func TestMetricsExposesBabelAndSessionState(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := babel.New(babel.Config{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	speaker.Originate(netip.MustParsePrefix("10.66.0.5/32"))
	c := &Client{speaker: speaker, sessions: newSessionSet()}
	c.countInbound(7, 2)

	var out bytes.Buffer
	c.Metrics(&out)
	text := out.String()
	for _, want := range []string{
		"ranet_lite_babel_routes_originated 1",
		"ranet_lite_babel_routes_selected 0",
		"ranet_lite_sessions 0",
		"ranet_lite_esp_inbound_packets_total 7",
		"ranet_lite_esp_inbound_dropped_total 2",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output is missing %q:\n%s", want, text)
		}
	}
	// Every series needs its HELP and TYPE, or a scrape rejects the sample.
	for _, name := range []string{"ranet_lite_sessions", "ranet_lite_esp_inbound_packets_total"} {
		if !strings.Contains(text, "# HELP "+name+" ") || !strings.Contains(text, "# TYPE "+name+" ") {
			t.Errorf("metric %s has no HELP or TYPE", name)
		}
	}
}

// Two nodes that dial each other at once land both sessions on the same path
// name at both ends. They have to pick the same survivor whichever order the
// two handshakes finish in locally, or each keeps the SA the other tore down
// and nothing crosses until dead peer detection notices.
func TestSimultaneousOpenConvergesOnSameSession(t *testing.T) {
	a := ike.Identity{Organization: "example", CommonName: "alpha", SerialNumber: "1"}
	b := ike.Identity{Organization: "example", CommonName: "bravo", SerialNumber: "1"}
	if preferInitiator(a, b) == preferInitiator(b, a) {
		t.Fatal("both ends think the same one should dial, so there is no tie-break at all")
	}

	// One session per direction, named by who opened it. Both nodes see both.
	const dialedByA, dialedByB = "dialed-by-a", "dialed-by-b"
	allAlive := func(*ike.Session) bool { return true }
	noneAlive := func(*ike.Session) bool { return false }
	// resolve replays one node's arrival order and reports which session it
	// keeps. local is that node's own identity.
	// alive is what this node believes about each session. The two ends read
	// their own clocks, so they are not obliged to agree, and the rule has to
	// converge anyway.
	resolve := func(local, remote ike.Identity, order []string, alive func(*ike.Session) bool) string {
		set := newSessionSet()
		set.close = func(*ike.Session) {}
		set.active = alive
		sessions := map[string]*ike.Session{dialedByA: {}, dialedByB: {}}
		for _, which := range order {
			// The roles of the SA itself, not this node's point of view: who
			// opened it and who answered. Both ends pass the same pair.
			initiator, responder := a, b
			if which == dialedByB {
				initiator, responder = b, a
			}
			set.adopt("path", sessions[which], initiator, responder, nil)
		}
		for name, sess := range sessions {
			if live := set.live["path"]; live != nil && live.session == sess {
				return name
			}
		}
		return ""
	}

	orders := [][]string{{dialedByA, dialedByB}, {dialedByB, dialedByA}}
	for _, orderA := range orders {
		for _, orderB := range orders {
			for _, liveness := range []struct {
				name string
				a, b func(*ike.Session) bool
			}{
				{"both alive", allAlive, allAlive},
				{"alpha sees its incumbent as dead", noneAlive, allAlive},
				{"bravo sees its incumbent as dead", allAlive, noneAlive},
				{"both see theirs as dead", noneAlive, noneAlive},
			} {
				keptByA := resolve(a, b, orderA, liveness.a)
				keptByB := resolve(b, a, orderB, liveness.b)
				if keptByA == "" || keptByB == "" {
					t.Fatalf("a node kept no session at all (%s, a=%v b=%v)", liveness.name, orderA, orderB)
				}
				if keptByA != keptByB {
					t.Fatalf("%s: alpha kept %s and bravo kept %s (a=%v b=%v), so each closes the one the other kept",
						liveness.name, keptByA, keptByB, orderA, orderB)
				}
			}
		}
	}
}

// Losing the resolution must not send the dialer straight back in. Without a
// stand-down the two ends take turns replacing each other's session every
// reconnect delay for as long as the process runs, and every replacement
// withdraws the routes learned through that peer.
func TestSessionSetReportsEstablishedPath(t *testing.T) {
	set := newSessionSet()
	set.close = func(*ike.Session) {}
	set.active = func(*ike.Session) bool { return true }
	if set.holds("path") {
		t.Fatal("an empty set reports a session, so neither end would ever dial")
	}
	sess := &ike.Session{}
	release, adopted := set.adoptPreferred("path", sess, true, nil)
	if !adopted {
		t.Fatal("the first session was not adopted")
	}
	if !set.holds("path") {
		t.Error("a live session is not reported, so the peer's dialer keeps opening more")
	}
	release()
	if set.holds("path") {
		t.Error("the path is still held after the session ended, so nothing would redial")
	}
}

// A peer that reboots leaves an SA on this side that looks established until
// dead peer detection reaps it, a minute or more later. Declining its fresh
// handshake in favor of that one locks it out for the whole of that minute,
// and because the stale entry also stops our own dialer, neither end opens
// anything at all.
// A peer that rebooted leaves an SA on this side that looks established until
// dead peer detection reaps it a minute later. That entry must not stand this
// node's dialer down, or neither end opens anything for the whole of that
// minute: the peer has no session, and we are waiting behind one that is gone.
func TestStaleIncumbentDoesNotStandDialerDown(t *testing.T) {
	set := newSessionSet()
	set.close = func(*ike.Session) {}
	stale, fresh := &ike.Session{}, &ike.Session{}
	set.active = func(sess *ike.Session) bool { return sess != stale }

	if _, adopted := set.adoptPreferred("path", stale, true, nil); !adopted {
		t.Fatal("the first session was not adopted")
	}
	if set.holds("path") {
		t.Fatal("a session that has stopped proving the peer is there still stops our dialer")
	}
	// The dialer then opens one, and this end prefers it because it is the one
	// both ends agree should be dialed, so it takes over from the stale entry.
	if _, adopted := set.adoptPreferred("path", fresh, true, nil); !adopted {
		t.Fatal("the dialer's own session was declined")
	}
	if live := set.live["path"]; live == nil || live.session != fresh {
		t.Error("the stale session is still the live one")
	}
	if !set.holds("path") {
		t.Error("the replacement does not stand the dialer down")
	}
}

// The preference rule still has to hold when the incumbent really is alive, or
// two nodes dialing each other at once keep different sessions.
func TestSessionSetKeepsActivePreferredSession(t *testing.T) {
	set := newSessionSet()
	set.close = func(*ike.Session) {}
	set.active = func(*ike.Session) bool { return true }
	winner, loser := &ike.Session{}, &ike.Session{}
	set.adoptPreferred("path", winner, true, nil)
	if _, adopted := set.adoptPreferred("path", loser, false, nil); adopted {
		t.Error("the session neither end prefers replaced the one both do")
	}
	if live := set.live["path"]; live == nil || live.session != winner {
		t.Error("the preferred session was not kept")
	}
}

// A dialer that gives up on its own must not leave its entry behind. The
// registry is rewritten whenever any node joins the mesh, so a peer that is
// briefly not in it is ordinary, and an entry that still says "running"
// makes every later reload skip that peer until the process restarts.
func TestSyncPeersRestartsDialerThatGaveUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, dialers: make(map[string]*dialer)}
	// A serial number sends runPeer through the pre-checks, which fail against
	// an empty registry and return rather than looping.
	c.cfg.Store(&config.Config{
		Organization: "example",
		CommonName:   "node",
		Endpoints:    []config.Endpoint{{SerialNumber: "0", AddressFamily: "ip4"}},
		Peers:        []config.Peer{{Organization: "example", CommonName: "a", SerialNumber: "1"}},
	})
	reg := registry.Registry{}
	c.reg.Store(&reg)

	c.syncPeers()
	c.peers.Wait()
	c.dialersMu.Lock()
	remaining := len(c.dialers)
	c.dialersMu.Unlock()
	if remaining != 0 {
		t.Fatalf("a dialer that returned left %d entries behind", remaining)
	}

	// The registry now names the node, and a reload has to pick it up.
	c.syncPeers()
	c.dialersMu.Lock()
	started := len(c.dialers)
	c.dialersMu.Unlock()
	if started != 1 {
		t.Errorf("a reload started %d dialers for a peer that had given up, want 1", started)
	}
	cancel()
	c.peers.Wait()
}

// Repointing a peer at a different endpoint is a change a reload has to apply.
// While the serial number was missing from the dialer's name it looked like no
// change at all, and Reload reported success while the old dialer kept using
// the value it captured when it started.
func TestSyncPeersNoticesChangedSerialNumber(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, dialers: make(map[string]*dialer)}
	base := func(serial string) *config.Config {
		return &config.Config{
			Organization: "example",
			CommonName:   "node",
			Endpoints:    []config.Endpoint{{SerialNumber: "0", AddressFamily: "ip4"}},
			Peers:        []config.Peer{{Organization: "example", CommonName: "a", SerialNumber: serial}},
		}
	}
	// The peer is in the registry with no address yet, so each dialer retries
	// rather than giving up. A dialer that gives up drops its own entry, which
	// would race this test's read of the map it just filled.
	reg := registry.Registry{{
		Organization: "example",
		Nodes: []registry.Node{{
			CommonName: "a",
			Endpoints: []registry.Endpoint{
				{SerialNumber: "1", AddressFamily: "ip4"},
				{SerialNumber: "2", AddressFamily: "ip4"},
			},
		}},
	}}
	c.reg.Store(&reg)
	c.cfg.Store(base("1"))
	c.syncPeers()

	c.cfg.Store(base("2"))
	c.syncPeers()
	c.dialersMu.Lock()
	_, old := c.dialers["example/a/1@0"]
	_, updated := c.dialers["example/a/2@0"]
	c.dialersMu.Unlock()
	if old {
		t.Error("the dialer for the old endpoint serial is still running")
	}
	if !updated {
		t.Error("no dialer was started for the new endpoint serial, so the change was dropped")
	}
	cancel()
	c.peers.Wait()
}

// A node joining the mesh must cost one dialer rather than a restart of every
// other node's dataplane, which Reload exists for. This drives it through
// a file on disk, the way SIGHUP does.
func TestReloadAppliesRegistryPeersAndOriginations(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	dir := t.TempDir()
	registryPath := filepath.Join(dir, "registry.json")
	writeRegistry(t, registryPath, reg)
	cfg.Registry = registryPath
	cfg.Originate = []string{"fd00:1::/64"}
	// Load validates the whole file, so the fixture has to be a config a node
	// could actually run.
	cfg.Port = 13000
	cfg.PrivateKey = filepath.Join(dir, "key.pem")
	writeKey(t, cfg.PrivateKey, privateKey)

	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := babel.New(babel.Config{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{
		ctx: ctx, cancel: cancel, privateKey: privateKey,
		speaker: speaker, dialers: make(map[string]*dialer),
	}
	c.cfg.Store(cfg)
	c.reg.Store(&reg)
	c.syncPeers()
	defer func() { cancel(); c.peers.Wait() }()

	// A second node joins and this node starts announcing another prefix,
	// which is exactly what a registry rewrite plus a config edit looks like.
	next := *cfg
	next.Peers = append(slices.Clone(cfg.Peers),
		config.Peer{Organization: "example", CommonName: "third", SerialNumber: "1"})
	next.Originate = []string{"fd00:1::/64", "fd00:2::/64"}
	grown := slices.Clone(reg)
	grown[0].Nodes = append(slices.Clone(reg[0].Nodes), registry.Node{
		CommonName: "third",
		Endpoints:  []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip4", Port: 13000}},
	})
	writeRegistry(t, registryPath, grown)
	configPath := filepath.Join(dir, "config.yaml")
	writeConfig(t, configPath, &next)

	if err := c.Reload(configPath); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := len(c.config().Peers); got != 2 {
		t.Errorf("the reloaded config has %d peers, want 2", got)
	}
	if _, _, ok := c.registry().FindNode("example", "third"); !ok {
		t.Error("the reloaded registry does not have the node that just joined")
	}
	c.dialersMu.Lock()
	dialers := len(c.dialers)
	c.dialersMu.Unlock()
	if dialers != 2 {
		t.Errorf("%d dialers after the reload, want one per peer", dialers)
	}
}

func writeRegistry(t *testing.T, path string, reg registry.Registry) {
	t.Helper()
	body, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeKey(t *testing.T, path string, key ed25519.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

// The responder decides whether this node answers at all, and acceptPeers is
// started once by Run. Accepting the change would report a reload that turned
// the responder on while nobody answered.
func TestReloadRefusesResponderChange(t *testing.T) {
	base := &config.Config{Organization: "example", CommonName: "node", Port: 13000}
	next := *base
	next.Responder = !base.Responder
	if err := reloadable(base, &next); err == nil {
		t.Error("a responder change was accepted, and nothing applies it")
	}
}

// A field written out as its own default is the same configuration as an
// omitted one. Comparing them as written refuses a reload that changes
// nothing, so writing "rxcost: 96" into the file, the value the speaker
// already uses, would have been enough to make every later SIGHUP fail.
func TestReloadAcceptsDefaultWrittenOutInFull(t *testing.T) {
	base := &config.Config{
		Organization: "example", CommonName: "node", Port: 13000,
		Endpoints: []config.Endpoint{{SerialNumber: "0", AddressFamily: "ip4"}},
	}
	defaults := base.Babel.SpeakerConfig()
	rxcost, rttCost := defaults.Cost.RxCost, defaults.Cost.RTTCost
	rttMin, rttMax := config.Duration(defaults.Cost.RTTMin), config.Duration(defaults.Cost.RTTMax)
	reconcile := config.Duration(kernel.DefaultReconcileInterval)

	for name, next := range map[string]*config.Config{
		"babel costs": {
			Organization: "example", CommonName: "node", Port: 13000, Endpoints: base.Endpoints,
			Babel: config.Babel{RxCost: &rxcost, RTTCost: &rttCost, RTTMin: &rttMin, RTTMax: &rttMax},
		},
		"reconcile interval": {
			Organization: "example", CommonName: "node", Port: 13000, Endpoints: base.Endpoints,
			Kernel: config.Kernel{ReconcileInterval: &reconcile},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := reloadable(base, next); err != nil {
				t.Errorf("writing a default out in full was refused: %v", err)
			}
		})
	}

	// A real change is still refused, or the comparison would be useless.
	louder := uint16(rxcost + 1)
	changed := *base
	changed.Babel = config.Babel{RxCost: &louder}
	if err := reloadable(base, &changed); err == nil {
		t.Error("a changed link cost was accepted, which the speaker would never see")
	}
}

// Whatever a session registers under the path's name has to go in under the
// same decision that hands it the path. Two sessions resolving against each
// other reach adopt in one order and everything after it in another, so a
// session already replaced would otherwise take the babel neighbor away from
// the one that replaced it: the speaker would hold a peer whose mux is closed
// and the adjacency would stay down until that session unwound.
func TestRegistrationCannotOutliveItsSession(t *testing.T) {
	set := newSessionSet()
	set.close = func(*ike.Session) {}
	loser, winner := &ike.Session{}, &ike.Session{}

	var mu sync.Mutex
	registered := ""
	attach := func(name string) func() func() {
		return func() func() {
			mu.Lock()
			defer mu.Unlock()
			registered = name
			return func() {
				mu.Lock()
				defer mu.Unlock()
				if registered == name {
					registered = ""
				}
			}
		}
	}

	releaseLoser, adopted := set.adoptPreferred("path", loser, false, attach("loser"))
	if !adopted {
		t.Fatal("the first session was not adopted")
	}
	if _, adopted := set.adoptPreferred("path", winner, true, attach("winner")); !adopted {
		t.Fatal("the session both ends prefer was declined")
	}
	// The loser now unwinds, which is the ordering that used to clobber.
	releaseLoser()

	mu.Lock()
	defer mu.Unlock()
	if registered != "winner" {
		t.Errorf("the path is registered to %q, want the session that holds it", registered)
	}
}

// The registry is rewritten every time any node joins the mesh, and the peers
// list is local and edited by hand, so the two drift: a node decommissioned
// elsewhere leaves an entry behind here. Refusing the whole reload over it
// would mean this node never sees another registry, and every node that joins
// afterwards is unreachable from here, over a peer that is unreachable either
// way.
func TestReloadSkipsAPeerTheRegistryNoLongerNames(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	dir := t.TempDir()
	registryPath := filepath.Join(dir, "registry.json")
	cfg.Registry = registryPath
	cfg.Port = 13000
	cfg.PrivateKey = filepath.Join(dir, "key.pem")
	writeKey(t, cfg.PrivateKey, privateKey)
	// Two peers to start with, so the reload below can be seen to keep one.
	cfg.Peers = append(slices.Clone(cfg.Peers),
		config.Peer{Organization: "example", CommonName: "third", SerialNumber: "1"})
	joined := slices.Clone(reg)
	joined[0].Nodes = append(slices.Clone(reg[0].Nodes), registry.Node{
		CommonName: "third",
		Endpoints:  []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip4", Port: 13000}},
	})
	writeRegistry(t, registryPath, joined)

	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := babel.New(babel.Config{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{
		ctx: ctx, cancel: cancel, privateKey: privateKey,
		speaker: speaker, dialers: make(map[string]*dialer),
	}
	c.cfg.Store(cfg)
	c.reg.Store(&joined)
	c.syncPeers()
	defer func() { cancel(); c.peers.Wait() }()

	// "third" is decommissioned and a fourth node joins in the same rewrite.
	// Nothing about this node's own configuration changed.
	shrunk := slices.Clone(reg)
	shrunk[0].Nodes = append(slices.Clone(reg[0].Nodes), registry.Node{
		CommonName: "fourth",
		Endpoints:  []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip4", Port: 13000}},
	})
	writeRegistry(t, registryPath, shrunk)
	configPath := filepath.Join(dir, "config.yaml")
	writeConfig(t, configPath, cfg)

	if err := c.Reload(configPath); err != nil {
		t.Fatalf("one stale peer refused the whole reload: %v", err)
	}
	if _, _, ok := c.registry().FindNode("example", "fourth"); !ok {
		t.Error("the node that joined in the same rewrite never reached this node")
	}
	if _, _, ok := c.registry().FindNode("example", "third"); ok {
		t.Error("the decommissioned node is still in the registry this node holds")
	}
}
