package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
	"github.com/NickCao/ranet-lite/internal/transport"
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
	// A payload length of zero is the jumbogram encoding, which this tunnel
	// does not carry, so the padded case needs a packet with a real payload.
	ipv6Payload := make([]byte, 48)
	ipv6Payload[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Payload[4:6], 8)
	for _, test := range []struct {
		name    string
		plain   []byte
		nh      byte
		deliver bool
		wantErr bool
		want    []byte
	}{
		{name: "IPv4", plain: ipv4, nh: esp.NextHeaderIPv4, deliver: true},
		{name: "IPv6", plain: ipv6, nh: esp.NextHeaderIPv6, deliver: true},
		{name: "dummy", plain: ipv6, nh: esp.NextHeaderNone},
		{name: "version mismatch", plain: ipv6, nh: esp.NextHeaderIPv4, wantErr: true},
		{name: "unsupported", plain: ipv4, nh: 6, wantErr: true},
		// RFC 4303 section 2.7: a sender may append Traffic Flow
		// Confidentiality padding after the payload in tunnel mode, and the
		// IP length field is what lets the receiver discard it. Refusing the
		// packet instead dropped every packet from a peer with tfcpad set,
		// silently, since nothing above ESP reads the length.
		{name: "IPv4 with TFC padding", plain: append(append([]byte(nil), ipv4...), 0, 0, 0), nh: esp.NextHeaderIPv4, deliver: true, want: ipv4},
		{name: "IPv6 with TFC padding", plain: append(append([]byte(nil), ipv6Payload...), 7, 7), nh: esp.NextHeaderIPv6, deliver: true, want: ipv6Payload},
		{name: "IPv4 shorter than its header claims", plain: ipv4[:len(ipv4)-1], nh: esp.NextHeaderIPv4, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner, deliver, err := validateESPTunnelPayload(test.plain, test.nh)
			if (err != nil) != test.wantErr || deliver != test.deliver {
				t.Fatalf("got deliver=%v err=%v; want deliver=%v err=%v", deliver, err, test.deliver, test.wantErr)
			}
			if test.want != nil && !bytes.Equal(inner, test.want) {
				t.Errorf("the delivered packet is %x, want %x", inner, test.want)
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
	rxcost := uint16(64)
	window := uint32(8192)
	// Every refusal, not a sample of them. Each of these is read once at
	// startup by something a reload cannot reach, so accepting one would
	// report a reload that changed nothing, or leave the node running two
	// policies at the same time.
	for name, change := range map[string]func(*config.Config){
		"identity":  func(c *config.Config) { c.CommonName = "other" },
		"port":      func(c *config.Config) { c.Port = 14000 },
		"tun":       func(c *config.Config) { c.TUN = "ranet9" },
		"responder": func(c *config.Config) { c.Responder = !c.Responder },
		"endpoints": func(c *config.Config) { c.Endpoints = []config.Endpoint{{SerialNumber: "1", AddressFamily: "ip6"}} },
		"babel":     func(c *config.Config) { c.Babel.RxCost = &rxcost },
		"kernel":    func(c *config.Config) { c.Kernel.Table = 201 },
		"rekey":     func(c *config.Config) { c.ReplayWindow = &window },
	} {
		t.Run(name, func(t *testing.T) {
			next := *base
			change(&next)
			if err := reloadable(base, &next); err == nil {
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
	// A neighbor and a session, or every per-peer and per-path line below is
	// a loop over nothing and only the scalars are ever written.
	// A reserved peer whose transport never returns, so its drop counter is
	// something other than zero: a per-neighbor line asserted at zero cannot
	// tell the count from no counting at all.
	blocked := make(chan struct{})
	var drain sync.Once
	peer := netstack.NewPeerReserved("gateway",
		func(int) (netstack.BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { <-blocked; return nil })
	defer func() { drain.Do(func() { close(blocked) }); peer.Close() }()
	handle := speaker.AddPeer(peer)
	defer handle.Close()
	for {
		place, err := peer.ReserveRawOrDrop([]byte("bulk"), 41)
		if err != nil {
			break
		}
		place.Send()
	}
	if _, err := peer.ReserveRawOrDrop([]byte("one more"), 41); err == nil {
		t.Fatal("the peer took a packet past its budget, so its drop counter proves nothing")
	}
	// A real hub with its unclaimed queue filled, so the inbound drop counter
	// reads something: nothing else in this test would give it a value other
	// than the zero it has with the counting deleted.
	hub, err := transport.NewHub("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	c := &Client{speaker: speaker, sessions: newSessionSet(), hub: hub}
	if fillUnclaimedQueue(t, hub) == 0 {
		t.Fatal("the queue refused nothing, so the counter would read zero either way")
	}
	// Closed before anything reads the counter: the receive loops are still
	// draining the socket backlog of the last burst, and every datagram in it
	// raises the count, so a snapshot taken while they run is smaller than
	// what Metrics renders a moment later. The count that matters is the one
	// that stops moving, not the one fillUnclaimedQueue saw on its way out.
	hub.Close()
	var refused uint64
	for deadline := time.Now().Add(20 * time.Second); refused == 0; {
		settled := hub.Dropped()
		time.Sleep(10 * time.Millisecond)
		if hub.Dropped() == settled {
			refused = settled
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the drop counter never settled, so the metric would be read mid-flight")
		}
	}
	c.sessions.close = func(*ike.Session) {}
	c.sessions.active = func(*ike.Session) bool { return true }
	release, adopted := c.sessions.adoptPreferred("example/gateway/1@0", &ike.Session{}, true, nil)
	if !adopted {
		t.Fatal("the session was not adopted, so the per-path lines would be empty")
	}
	defer release()
	c.countInbound(7, 2)

	// A hello, an IHU and one route, so every per-neighbor line below reads
	// something other than the zero it would read with the counting deleted.
	speaker.Receive(peer, babelPacket(t,
		babel.EncodeHello(babel.Hello{Seqno: 1, Interval: 1000}),
		babel.EncodeIHU(babel.IHU{RxCost: 96, Interval: 1000}),
		babel.EncodeRouterID([8]byte{1}),
		babel.EncodeUpdate(babel.Update{AE: 2, Plen: 64, Prefix: netip.MustParseAddr("fd00:1::").AsSlice(),
			Seqno: 1, Metric: 20, Interval: 1000}),
	))

	stats := speaker.Stats()
	if len(stats.Neighbors) != 1 || stats.Neighbors[0].Cost == 0 || stats.Neighbors[0].Dropped == 0 ||
		stats.Neighbors[0].Routes == 0 || !stats.Neighbors[0].Alive {
		t.Fatalf("the fixture leaves %+v, so asserting the per-neighbor lines proves nothing", stats.Neighbors)
	}
	var out bytes.Buffer
	c.Metrics(&out)
	text := out.String()
	for _, want := range []string{
		"ranet_lite_babel_routes_originated 1",
		fmt.Sprintf("ranet_lite_babel_routes_selected %d", stats.Selected),
		fmt.Sprintf("ranet_lite_receive_dropped_total %d", refused),
		"ranet_lite_sessions 1",
		"ranet_lite_esp_inbound_packets_total 7",
		"ranet_lite_esp_inbound_dropped_total 2",
		`ranet_lite_session_up{path="example/gateway/1@0"} 1`,
		fmt.Sprintf(`ranet_lite_babel_neighbor_up{peer="gateway"} %d`, boolValue(stats.Neighbors[0].Alive)),
		fmt.Sprintf(`ranet_lite_babel_routes_received{peer="gateway"} %d`, stats.Neighbors[0].Routes),
		// A neighbor that has said nothing costs infinity, and the peer above
		// refused at least one packet, so neither line is zero either way.
		fmt.Sprintf(`ranet_lite_babel_neighbor_cost{peer="gateway"} %d`, stats.Neighbors[0].Cost),
		fmt.Sprintf(`ranet_lite_peer_send_dropped_total{peer="gateway"} %d`, stats.Neighbors[0].Dropped),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output is missing %q:\n%s", want, text)
		}
	}
	// Every series needs its HELP and TYPE, or a scrape rejects the sample.
	for _, name := range []string{
		"ranet_lite_sessions", "ranet_lite_esp_inbound_packets_total",
		"ranet_lite_session_up", "ranet_lite_babel_neighbor_up",
		"ranet_lite_babel_neighbor_cost", "ranet_lite_babel_routes_received",
		"ranet_lite_peer_send_dropped_total", "ranet_lite_receive_dropped_total",
	} {
		if !strings.Contains(text, "# HELP "+name+" ") || !strings.Contains(text, "# TYPE "+name+" ") {
			t.Errorf("metric %s has no HELP or TYPE", name)
		}
	}

	// The handler is what a scrape actually reaches, and it is the only place
	// the content type is set.
	recorder := httptest.NewRecorder()
	c.MetricsHandler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("the handler served %q, which prometheus will not parse", got)
	}
	if recorder.Body.String() != text {
		t.Error("the handler served something other than what Metrics writes")
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
			set.adopt("path", sessions[which], initiator, responder, responder, nil)
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
	// A source-specific announcement too, which only the babel block can
	// express and which reaches the speaker through its own loop.
	next.Babel.Originate = []config.OriginatePrefix{{
		Prefix: netip.MustParsePrefix("fd00:3::/64"),
		From:   netip.MustParsePrefix("fd00:a::/64"),
	}}
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
	// And the announcements reached the speaker, rather than only the copy of
	// the configuration the client holds. A reload that stored the new set and
	// never applied it would report success and announce the old one forever.
	if got := speaker.Stats().Originated; got != 3 {
		t.Errorf("the speaker announces %d prefixes after the reload, want the two plain ones and the source-specific one", got)
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

// A node decommissioned elsewhere leaves an entry behind in this node's peers
// list. Refusing the whole reload over it would mean this node never sees
// another registry, and every node that joins afterwards is unreachable from
// here, over a peer that is unreachable either way.
func TestReloadSkipsPeerRegistryNoLongerNames(t *testing.T) {
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
	// A live session for the node the rewrite below drops. The registry is the
	// trust root, so a reload has to close it: refusing the next handshake
	// leaves the tunnel it already holds carrying traffic until every other
	// node restarts.
	c.sessions = newSessionSet()
	var revoked []*ike.Session
	c.sessions.close = func(sess *ike.Session) { revoked = append(revoked, sess) }
	c.sessions.active = func(*ike.Session) bool { return true }
	third := &ike.Session{}
	thirdID := ike.Identity{Organization: "example", CommonName: "third", SerialNumber: "1"}
	if _, ok := c.sessions.adopt("example/third/1@1", third, thirdID, thirdID, thirdID, nil); !ok {
		t.Fatal("the session for the node about to be dropped was not adopted")
	}
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
	if len(revoked) != 1 || revoked[0] != third {
		t.Errorf("the reload closed %d sessions, want the one whose node it dropped", len(revoked))
	}
	if _, held := c.sessions.live["example/third/1@1"]; held {
		t.Error("the decommissioned node's session is still live, so it still carries traffic")
	}
}

// closeAll shuts the set so a handshake that finished behind the sweep is told
// to go rather than installed with nothing left to serve it. Without the door
// the peer carries a session this node has already forgotten until its own
// dead peer detection expires, which is over a minute.
func TestSessionLandingAfterSweepIsToldToGo(t *testing.T) {
	set := newSessionSet()
	var closed []*ike.Session
	set.close = func(sess *ike.Session) { closed = append(closed, sess) }
	set.active = func(*ike.Session) bool { return true }
	set.closeAll()

	late := &ike.Session{}
	attached := false
	release, adopted := set.adoptPreferred("path", late, true, func() func() {
		attached = true
		return func() {}
	})
	defer release()
	if adopted {
		t.Error("a handshake that finished after the sweep was installed anyway")
	}
	if attached {
		t.Error("the late session registered a babel neighbor with nothing left to remove it")
	}
	if len(closed) != 1 || closed[0] != late {
		t.Errorf("the late session was dropped without telling its peer: closed %d", len(closed))
	}
	if set.holds("path") {
		t.Error("the set holds a path after the node has gone")
	}
}

// holds is only worth anything where it is consulted. The peer reached us over
// this same pair of endpoints, so dialing anyway opens a second SA that one end
// has to resolve away, and doing that on every reconnect delay is how two nodes
// spend a whole mesh replacing each other's sessions.
func TestDialerStandsDownForSessionPeerOpened(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	loopback := "127.0.0.1"
	// A port nothing listens on, so a dial that happens anyway cannot succeed
	// and cannot be mistaken for the stand-down.
	reg[0].Nodes[1].Endpoints[0].Address = &loopback
	hub, err := transport.NewHub("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, privateKey: privateKey, hub: hub, sessions: newSessionSet()}
	c.cfg.Store(cfg)
	c.reg.Store(&reg)
	c.sessions.close = func(*ike.Session) {}
	c.sessions.active = func(*ike.Session) bool { return true }

	local := cfg.Endpoints[0]
	peer := cfg.Peers[0]
	name := "example/gateway/1@0"
	if _, adopted := c.sessions.adoptPreferred(name, &ike.Session{}, false, nil); !adopted {
		t.Fatal("the session the peer opened was not adopted")
	}

	start := time.Now()
	err = c.connectPeer(ctx, local, peer, name)
	if !errors.Is(err, errSessionEstablished) {
		t.Fatalf("the dialer reported %v, want the stand-down", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the stand-down took %s, so it happened after the dial rather than instead of it", elapsed)
	}
}

// A peer this local endpoint cannot reach must not be dialed, whether that is
// because the registry no longer names the node or because the node has no
// endpoint in this address family, and whether or not the peer pins a serial.
// Without the check the dialer enters the retry loop and logs the same failure
// every reconnect delay for the life of the process.
func TestDialerGivesUpOnAPeerItCannotReach(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, privateKey: privateKey, sessions: newSessionSet()}
	c.cfg.Store(cfg)
	c.reg.Store(&reg)

	// "wrong family" is a node that exists and simply cannot be reached from
	// this local endpoint, which on a dual-stack node with single-stack peers
	// is the ordinary configuration rather than a mistake.
	reg[0].Nodes = append(reg[0].Nodes, registry.Node{
		CommonName: "v6only",
		Endpoints:  []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip6", Port: 13000}},
	})
	for name, peer := range map[string]config.Peer{
		"pinned to a serial":  {Organization: "example", CommonName: "gone", SerialNumber: "1"},
		"pinned to none":      {Organization: "example", CommonName: "gone"},
		"wrong family":        {Organization: "example", CommonName: "v6only"},
		"wrong family pinned": {Organization: "example", CommonName: "v6only", SerialNumber: "1"},
	} {
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})
			go func() { defer close(done); c.runPeer(ctx, cfg.Endpoints[0], peer) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("the dialer is still retrying a node the registry does not name")
			}
		})
	}
}

// babelPacket frames TLVs the way the speaker's own senders do: an IPv6
// link-local source, the multicast group, and the UDP checksum IPv6 makes
// mandatory. The framing lives in internal/babel and is not exported, so a
// test outside that package builds it here.
func babelPacket(t *testing.T, tlvs ...babel.RawTLV) []byte {
	t.Helper()
	src := netip.MustParseAddr("fe80::2")
	dst := netip.MustParseAddr("ff02::1:6")
	payload := babel.EncodePacket(tlvs)
	raw := make([]byte, 40+8+len(payload))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:6], uint16(8+len(payload)))
	raw[6], raw[7] = 17, 1
	copy(raw[8:24], src.AsSlice())
	copy(raw[24:40], dst.AsSlice())
	udp := raw[40:]
	binary.BigEndian.PutUint16(udp[0:2], babel.Port)
	binary.BigEndian.PutUint16(udp[2:4], babel.Port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(raw[8:40])
	var meta [8]byte
	binary.BigEndian.PutUint32(meta[0:4], uint32(len(udp)))
	meta[7] = 17
	add(meta[:])
	add(udp)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	if checksum := ^uint16(sum); checksum == 0 {
		binary.BigEndian.PutUint16(udp[6:8], 0xffff)
	} else {
		binary.BigEndian.PutUint16(udp[6:8], checksum)
	}
	return raw
}

// fillUnclaimedQueue sends IKE_SA_INIT-shaped datagrams at a hub nobody is
// listening on until its queue refuses one, which is the ordinary way an
// inbound receive queue fills: the SPIs belong to no Mux, so every datagram
// lands in the queue Listen drains and nothing drains it.
func fillUnclaimedQueue(t *testing.T, hub *transport.Hub) uint64 {
	t.Helper()
	// The queue exists only once somebody asks to listen, and nothing drains
	// it here, which is what a responder under load looks like from the
	// receive loop's side.
	_ = hub.Listen()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: hub.LocalAddr().(*net.UDPAddr).Port}
	const marker = 4
	datagram := make([]byte, marker+28)
	header := datagram[marker:]
	binary.BigEndian.PutUint64(header[0:8], 1) // an initiator SPI no Mux has registered
	header[17] = 0x20                          // version 2.0
	header[18] = 34                            // IKE_SA_INIT
	header[19] = 0x08                          // initiator
	binary.BigEndian.PutUint32(header[24:28], uint32(len(header)))

	deadline := time.Now().Add(20 * time.Second)
	for hub.Dropped() < 64 {
		if time.Now().After(deadline) {
			t.Fatal("the unclaimed queue never filled, so the drop counter proves nothing")
		}
		for range 64 {
			if _, err := peer.WriteToUDP(datagram, dst); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(time.Millisecond)
	}
	return hub.Dropped()
}

// The Prometheus text exposition format defines three escape sequences inside
// a label value and no others, and a record carrying anything else is refused
// whole rather than in part: one tab or non-breaking space pasted into an
// organization or common name would take every series on this node out of
// monitoring, with nothing in its own log. Go's %q writes \t and  .
func TestMetricsLabelsUseOnlyTheEscapesTheFormatDefines(t *testing.T) {
	for name, test := range map[string]struct{ in, want string }{
		"plain":                 {"example/gateway/0@0", "example/gateway/0@0"},
		"backslash":             {`a\b`, `a\\b`},
		"quote":                 {`a"b`, `a\"b`},
		"newline":               {"a\nb", `a\nb`},
		"tab":                   {"a\tb", "a\tb"},
		"non-breaking space":    {"a b", "a b"},
		"printable non-ascii":   {"orgé", "orgé"},
		"carriage return alone": {"a\rb", "a\rb"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := label(test.in); got != test.want {
				t.Errorf("label(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}

	// And the rendered line carries it, so nothing above the helper reaches
	// for %q again.
	speaker, err := babel.New(babel.Config{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		t.Fatal(err)
	}
	peer := netstack.NewPeer("gate\tway", func(raw []byte, _ byte) ([]byte, error) { return raw, nil },
		func([]byte) error { return nil })
	handle := speaker.AddPeer(peer)
	defer handle.Close()
	c := &Client{speaker: speaker, sessions: newSessionSet()}
	// A live session too: the path label is the other value built from a name
	// a peer chooses, and with no sessions its line is never rendered.
	c.sessions.close = func(*ike.Session) {}
	c.sessions.active = func(*ike.Session) bool { return true }
	if _, adopted := c.sessions.adoptPreferred("example/gate\tway/0@0", &ike.Session{}, true, nil); !adopted {
		t.Fatal("the session was not adopted, so the path line would be empty")
	}
	var out bytes.Buffer
	c.Metrics(&out)
	for _, want := range []string{"{peer=\"gate\tway\"}", "{path=\"example/gate\tway/0@0\"}"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the rendered line does not carry %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), `\t`) {
		t.Error("a label value carries an escape the format does not define")
	}
}

// The registry is what a handshake is checked against, so it is what decides
// who may stay. A node taken out of it kept every tunnel it already held,
// because the handshake check only refuses the next one and nothing revisited
// the sessions already running. A reload is the only moment this node learns
// that a node is gone.
func TestReloadClosesASessionTheRegistryNoLongerNames(t *testing.T) {
	set := newSessionSet()
	var closed []*ike.Session
	set.close = func(sess *ike.Session) { closed = append(closed, sess) }
	set.active = func(*ike.Session) bool { return true }

	stays := ike.Identity{Organization: "example", CommonName: "keeper", SerialNumber: "0"}
	goes := ike.Identity{Organization: "example", CommonName: "gone", SerialNumber: "0"}
	keeper, gone := &ike.Session{}, &ike.Session{}
	for _, adopted := range []struct {
		path string
		sess *ike.Session
		peer ike.Identity
	}{{"example/keeper/0@0", keeper, stays}, {"example/gone/0@0", gone, goes}} {
		if _, ok := set.adopt(adopted.path, adopted.sess, adopted.peer, adopted.peer, adopted.peer, nil); !ok {
			t.Fatalf("%s was not adopted", adopted.path)
		}
	}

	// A session whose handshake has not named a peer yet is not evidence of
	// anything, and closing it would drop a tunnel still coming up.
	anonymous := &ike.Session{}
	set.mu.Lock()
	set.live["example/anonymous/0@0"] = &liveSession{session: anonymous}
	set.mu.Unlock()

	// Trusted by name rather than "anything but goes", so the anonymous entry
	// is untrusted too and only the guard above keeps it.
	revoked := set.revoke(func(peer ike.Identity) bool { return peer == stays })
	if len(revoked) != 1 || revoked[0] != "example/gone/0@0" {
		t.Fatalf("the sweep closed %v, want only the path the registry dropped", revoked)
	}
	if len(closed) != 1 || closed[0] != gone {
		t.Errorf("the sweep told %d sessions, and not the one that went", len(closed))
	}
	if _, held := set.live["example/gone/0@0"]; held {
		t.Error("the revoked session is still live, so it still carries traffic")
	}
	if _, held := set.live["example/keeper/0@0"]; !held {
		t.Error("the sweep took a session the registry still names")
	}
	if _, held := set.live["example/anonymous/0@0"]; !held {
		t.Error("the sweep took a session whose handshake had not named a peer yet")
	}
}

// A node taken out of the registry while its dialer is running stops being
// dialed. The check before the loop covers a node that was already gone;
// this one covers the reload that removes it afterwards, and without it the
// dialer logs the same lookup failure every reconnect delay for the life of
// the process while Reload's "so nothing will dial it" is not true.
func TestDialerGivesUpOnANodeAReloadRemoved(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, privateKey: privateKey,
		dialers: make(map[string]*dialer), dialRetry: time.Millisecond}
	c.cfg.Store(cfg)
	c.reg.Store(&reg)

	local, named := cfg.Endpoints[0], cfg.Peers[0]
	if _, _, ok := reg.FindNode(named.Organization, named.CommonName); !ok {
		t.Fatal("the fixture's own peer is not in its registry, so this proves nothing")
	}
	done := make(chan struct{})
	go func() { c.runPeer(ctx, local, named); close(done) }()

	// Still dialing while the registry names it.
	select {
	case <-done:
		t.Fatal("the dialer gave up on a node the registry still names")
	case <-time.After(100 * time.Millisecond):
	}

	// The reload takes the node out, and the next pass of the loop notices.
	empty := registry.Registry{}
	c.reg.Store(&empty)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("the dialer kept retrying a node the registry no longer names")
	}
}
