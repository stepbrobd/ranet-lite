//go:build darwin && !ios

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
	"github.com/NickCao/ranet-lite/internal/transport"
)

// This file runs one configuration file all the way to a running daemon and
// asks what reached the kernel. Everything else in this package builds a
// Client by hand and drives one mechanism, which is why two reviews and two
// audits found fifteen call sites wiring the darwin underlay together that
// could each be deleted with the whole suite green: every mechanism was
// tested and nothing tested that a file turns them on.
//
// Nothing here needs privilege or a second machine. internal/kernel names the
// machine it reads and writes, see kernel.Host, and recordedKernel is a
// routing table this test writes and reads back. The one thing still left
// with the running kernel is IP_BOUND_IF on the transport's own UDP socket,
// which is why the uplink below is lo0's index.

// meshDeviceIndex is the tun this node carries the overlay on. No socket is
// bound to it, so it names a device that need not exist.
const meshDeviceIndex = 424

// What the mesh announces to this node, what this node announces back, and
// where the machine under it reaches the world. capturingPrefix takes the
// machine and ordinaryPrefix does not, which is the distinction the whole
// capture gate rests on.
var (
	capturingPrefix = netip.MustParsePrefix("::/0")
	ordinaryPrefix  = netip.MustParsePrefix("2001:db8:2::/64")
	// witnessPrefix is announced beside a route the daemon should hold back,
	// so that its arrival says a pass has run over both; see daemon.heldBack.
	witnessPrefix = netip.MustParsePrefix("2001:db8:3::/64")
	// announcedAddress is the prefix this node originates, which
	// assign_announced puts on the mesh device.
	announcedAddress = netip.MustParsePrefix("2001:db8:1::1/128")
	// hostGateways are the next hops the recorded host reaches the world
	// through, one per family.
	hostGateway4 = netip.MustParseAddr("192.0.2.1")
	hostGateway6 = netip.MustParseAddr("2001:db8:ff::1")
	// peerEndpoint is where the trust document says this node's peer answers,
	// which is an address the transport has to keep reaching past the mesh.
	peerEndpoint = netip.MustParseAddr("198.51.100.7")
)

// daemon is one node built the way the command builds one, on a recorded
// machine.
type daemon struct {
	node   *Client
	routes *kernel.Reconciler
	host   *recordedKernel
	// uplink is the interface the recorded host's own traffic leaves by.
	uplink int
	// stop ends the reconcile loop and waits for it to withdraw, the way the
	// command waits for it before closing the node.
	stop func()
}

// recordedHost is the machine a daemon in this file starts on: one uplink
// carrying the host's own default of both families, and a mesh device. A test
// that wants a different machine changes it before handing it to startDaemon.
func recordedHost(t *testing.T) *recordedKernel {
	t.Helper()
	uplink := loopbackIndex(t)
	host := newRecordedKernel(uplink, meshDeviceIndex)
	host.v4 = kernel.RouteAnswer{Index: uplink, Gateway: hostGateway4}
	host.v6 = kernel.RouteAnswer{Index: uplink, Gateway: hostGateway6}
	// The host's own two defaults, the routes none of this may ever touch.
	host.hold(recordedRoute{destination: netip.MustParsePrefix("0.0.0.0/0"), index: uplink, gateway: hostGateway4})
	host.hold(recordedRoute{destination: capturingPrefix, index: uplink, gateway: hostGateway6})
	return host
}

// startDaemon builds one node and its reconciler, retrying the port. A
// configuration file has to name a port, since link.port is required, and the
// only way to name a free one is to bind zero, read it back and give it up, so
// anything else on the machine can take it in between. newLoopbackMesh in this
// package retries for the same reason; the wait makes a run of losses unlikely
// rather than merely improbable.
func startDaemon(t *testing.T, bind bool, host *recordedKernel) *daemon {
	t.Helper()
	// The record of what this process wrote is an ownership claim over routes
	// on a shared interface, so it goes somewhere of this test's own rather
	// than into the runtime directory a daemon on this machine may be holding.
	state := underlayStatePath
	underlayStatePath = filepath.Join(t.TempDir(), "underlay.json")
	t.Cleanup(func() { underlayStatePath = state })

	const attempts = 10
	for attempt := range attempts {
		d, err := tryDaemon(t, bind, host)
		if err == nil {
			return d
		}
		t.Logf("attempt %d could not bind the port the kernel had just handed back: %v", attempt, err)
		time.Sleep(time.Duration(attempt+1) * 20 * time.Millisecond)
	}
	t.Fatalf("%d attempts in a row could not bind a port the kernel had just handed back", attempts)
	return nil
}

// tryDaemon writes a configuration, loads it through the loader the daemon
// uses, builds the node around a mesh with no TUN, and builds the route
// reconciler out of what the node says about itself. The last step is the one
// under test: main does exactly this and nothing more.
//
// Only the port it could not take comes back as an error; anything else is
// this test being wrong about the tree and ends it.
func tryDaemon(t *testing.T, bind bool, host *recordedKernel) (*daemon, error) {
	t.Helper()
	cfg := loadDaemonConfig(t, bind)
	privateKey := daemonIdentity(t, cfg)
	reg, err := registry.Load(cfg.Auth.Trust)
	if err != nil {
		t.Fatal(err)
	}
	mesh := netstack.NewRoutesOnly()
	// The device the mesh actually got, which the file cannot say and which
	// the reconciler is handed rather than told.
	mesh.Name = "mesh0"
	t.Cleanup(mesh.Close)

	node, err := newClient(cfg, privateKey, reg, mesh, host)
	if err != nil {
		return nil, err
	}
	t.Cleanup(node.Close)
	// A session counts as live only when the set says so, and standing up two
	// real SAs measures something else.
	node.sessions.active = func(*ike.Session) bool { return true }

	routes, err := kernel.New(*cfg.Cap.Table, node.KernelRuntime(), mesh.Routes)
	if err != nil {
		t.Fatalf("the reconciler this node described was refused: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = routes.Run(ctx)
	}()
	stop := sync.OnceFunc(func() { cancel(); <-done })
	t.Cleanup(stop)
	return &daemon{node: node, routes: routes, host: host, uplink: host.uplink, stop: stop}, nil
}

// announce puts a prefix in the mesh's forwarding table, which is where the
// reconciler reads what to install from, and wakes the reconcile loop.
func (d *daemon) announce(prefix netip.Prefix) {
	d.node.Mesh.Routes.Set(netip.Prefix{}, prefix, &netstack.Peer{ID: "peer"})
}

// live adopts one session that has proved its peer is there, the one thing
// that opens the capture gate.
func (d *daemon) live(t *testing.T) {
	t.Helper()
	if _, adopted := d.node.sessions.adoptPreferred("example/gateway/1@0", &ike.Session{}, true, nil); !adopted {
		t.Fatal("the session was not adopted")
	}
	d.announce(ordinaryPrefix)
}

// waitFor polls until the condition holds, because a reconcile pass is a
// goroutine rather than a call. The budget is generous: a failure here is a
// route that never arrives, not one that arrives late.
func waitForKernel(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting until %s", what)
}

// heldBack announces prefix together with a witness the daemon has no reason
// to hold back, waits for the witness to arrive, and then reports whether
// prefix is in the kernel. The witness turns a wait into an assertion: its
// arrival proves a pass ran over a set carrying both, so an absent prefix is
// one the reconciler decided against rather than one that had not reached it
// yet.
func (d *daemon) heldBack(t *testing.T, prefix, witness netip.Prefix) bool {
	t.Helper()
	d.announce(prefix)
	d.announce(witness)
	waitForKernel(t, "a pass over an announcement carrying both has run", func() bool {
		plain, scoped := d.host.installed(witness)
		return plain || scoped
	})
	plain, scoped := d.host.installed(prefix)
	return !plain && !scoped
}

// A configuration that sets link.underlay.bind produces a daemon whose
// transport socket is bound to the interface the host's own traffic leaves by,
// whose underlay has a default scoped to that interface, and whose reconciler
// holds an announced default out of the kernel until a session is live. Every
// one of those is a different call site, and each of them was removable.
//
// The assertions are about routes and sockets rather than about which
// functions ran, so a rearrangement that keeps the behavior keeps the test.
func TestBoundUnderlayConfigurationInstallsACaptureOnlyOnceASessionIsLive(t *testing.T) {
	d := startDaemon(t, true, recordedHost(t))

	// The socket is where the configuration said it should be. Nothing else
	// in this package can tell a node that asked to bind and could not from
	// one that never asked, and the reconciler reads exactly that distinction
	// before it hands this machine's traffic to the mesh.
	if !d.node.hub.UnderlayReady() {
		t.Fatal("the transport did not bind its underlay socket, so no capture can ever install")
	}

	// An ordinary prefix installs at once: the gate holds back what would
	// carry this machine's own traffic and nothing else.
	d.announce(ordinaryPrefix)
	waitForKernel(t, "the ordinary prefix reaches the kernel", func() bool {
		plain, _ := d.host.installed(ordinaryPrefix)
		return plain
	})

	// And the address the file announces is assigned to the device the mesh
	// got, which is the only thing cap.route's announcements do to the kernel.
	waitForKernel(t, "the announced address is assigned to the mesh device", func() bool {
		for _, held := range d.host.addresses(meshDeviceIndex) {
			if held == announcedAddress {
				return true
			}
		}
		return false
	})

	// The default the mesh is announcing is not installed, because no session
	// has proved a peer is there. A node coming up beside a stale
	// announcement must not take it.
	if got := d.node.LiveSessions(); got != 0 {
		t.Fatalf("a node with no session counts %d live, so this measures nothing", got)
	}
	if !d.heldBack(t, capturingPrefix, witnessPrefix) {
		t.Fatal("the mesh took this machine's own traffic before a session was live")
	}

	// One live session opens it.
	d.live(t)
	if got := d.node.LiveSessions(); got != 1 {
		t.Fatalf("a bound node with one live session counts %d", got)
	}
	waitForKernel(t, "the announced default reaches the kernel", func() bool {
		plain, _ := d.host.installed(capturingPrefix)
		return plain
	})

	// Unscoped, which is the whole of why the socket is bound: a default
	// scoped to the tun is reached by nothing that did not name the tun, so
	// this Mac would hold a mesh address and still not use a mesh exit.
	if _, scoped := d.host.installed(capturingPrefix); scoped {
		t.Error("the announced default was scoped to the tun although the underlay socket is bound")
	}

	// And the underlay has something to fall back on, which is the condition
	// making the route above safe: a socket bound with IP_BOUND_IF still reads
	// the shared table, so its own interface needs a default of its own.
	fallback := d.host.scopedDefaults()
	if len(fallback) != 2 {
		t.Fatalf("%d defaults were scoped to the underlay interface, want one per family: %+v", len(fallback), fallback)
	}
	for _, held := range fallback {
		if held.index != d.uplink {
			t.Errorf("a default was scoped to interface %d, want the uplink %d", held.index, d.uplink)
		}
		if !held.gateway.IsValid() {
			t.Errorf("the default scoped to the underlay names no next hop: %+v", held)
		}
	}
	// The host's own unscoped defaults are untouched, always. Tailscale
	// shipped the opposite as #21395.
	for _, write := range d.host.writes() {
		if !write.add && write.index == d.uplink && !write.scoped {
			t.Errorf("an unscoped route on the uplink was withdrawn: %+v", write)
		}
	}
}

// The same file without link.underlay.bind produces a daemon that binds
// nothing, writes nothing on the uplink, and scopes its announced default to
// the tun so that no ordinary socket follows it. Without the scope this node's
// own ESP would leave through the tunnel it is carrying.
func TestUnboundUnderlayConfigurationScopesItsCaptureToTheTun(t *testing.T) {
	d := startDaemon(t, false, recordedHost(t))

	// Nothing asked for a binding, so the hub reports ready and the socket is
	// on no interface. The two answers together tell this apart from a node
	// that asked to bind and could not.
	if !d.node.hub.UnderlayReady() {
		t.Fatal("a node that asked for no binding reports its underlay as not where it should be")
	}
	if d.node.CaptureRoutes() != nil {
		t.Error("a node that binds nothing opened routing for a socket it does not have")
	}

	d.live(t)
	d.announce(capturingPrefix)
	waitForKernel(t, "the announced default reaches the kernel", func() bool {
		_, scoped := d.host.installed(capturingPrefix)
		return scoped
	})
	if plain, _ := d.host.installed(capturingPrefix); plain {
		t.Error("the announced default is reachable from every socket on this machine, underlay included")
	}
	for _, write := range d.host.writes() {
		if write.index != meshDeviceIndex {
			t.Errorf("a node that binds no socket wrote %+v, which is not on its own tun", write)
		}
	}
}

// A capture is held back per family, and the family it is held back for is
// decided by what the underlay itself can fall back on rather than by what the
// mesh is announcing. A laptop reaching IPv4 through the interface its socket
// is bound to and IPv6 through another is ordinary, and answering "covered"
// for the machine put an announced default in the kernel over an IPv6 underlay
// with nothing behind it.
func TestCaptureIsHeldBackForAFamilyTheUnderlayCannotFallBackOn(t *testing.T) {
	host := recordedHost(t)
	// The host reaches IPv6 nowhere, so nothing can be scoped to the
	// underlay's interface for that family.
	host.v6 = kernel.RouteAnswer{}
	d := startDaemon(t, true, host)

	d.live(t)
	// The IPv4 half is covered, so a capturing route of that family installs.
	// It arrives scoped, because it also covers this node's own peer endpoint,
	// the separate question TestPrefixCoveringAPeerEndpointIsScopedEvenWithABoundSocket
	// asks; this one measures only that it arrives.
	v4capture := netip.MustParsePrefix("0.0.0.0/0")
	d.announce(v4capture)
	waitForKernel(t, "the IPv4 default reaches the kernel", func() bool {
		plain, scoped := d.host.installed(v4capture)
		return plain || scoped
	})

	// The IPv6 half is not, so a capturing route of that family never does.
	// Installing it would take this node off IPv6 entirely with no fallback.
	if !d.heldBack(t, capturingPrefix, witnessPrefix) {
		t.Error("an IPv6 default was installed over an underlay with no IPv6 route of its own")
	}
	if got := d.host.scopedDefaults(); len(got) != 1 || got[0].destination != v4capture {
		t.Errorf("the underlay's own routing is %+v, want the IPv4 default alone", got)
	}
}

// A prefix covering a peer's own endpoint takes this node's ESP into the
// tunnel carrying it, however the socket is bound, because the peer is then
// reached through the tun rather than past it. It is scoped for that reason
// alone, and neither half the address space nor a route containing the
// family's zero address, so the capture gate does not cover it.
func TestPrefixCoveringAPeerEndpointIsScopedEvenWithABoundSocket(t *testing.T) {
	d := startDaemon(t, true, recordedHost(t))
	d.live(t)

	covering := netip.MustParsePrefix("198.51.100.0/24")
	if !covering.Contains(peerEndpoint) {
		t.Fatalf("%s does not hold the peer endpoint %s, so this measures nothing", covering, peerEndpoint)
	}
	d.announce(covering)
	waitForKernel(t, "the prefix covering the peer endpoint reaches the kernel", func() bool {
		plain, scoped := d.host.installed(covering)
		return plain || scoped
	})
	plain, scoped := d.host.installed(covering)
	if plain || !scoped {
		t.Error("a prefix holding this node's own peer endpoint is reachable from the underlay socket, which sends its ESP into the tunnel carrying it")
	}
}

// Shutdown takes down what this node opened, in the order the routing demands:
// the underlay's own fallback outlives every route depending on it, and then
// goes. A node that left the fallback behind leaks one scoped default per
// start onto an interface the whole machine shares.
func TestShutdownWithdrawsTheUnderlayRoutingAndLeavesTheMachineAsItFoundIt(t *testing.T) {
	d := startDaemon(t, true, recordedHost(t))
	d.live(t)
	d.announce(capturingPrefix)
	waitForKernel(t, "the announced default reaches the kernel", func() bool {
		plain, _ := d.host.installed(capturingPrefix)
		return plain
	})
	if len(d.host.scopedDefaults()) == 0 {
		t.Fatal("the underlay wrote no routing, so this measures nothing")
	}

	// The command waits for the reconciler before it closes the node, so the
	// capture is gone by the time the fallback under it is.
	d.stop()
	if plain, scoped := d.host.installed(capturingPrefix); plain || scoped {
		t.Fatal("the reconciler left the route carrying this machine's traffic in the kernel")
	}
	d.node.Close()
	if got := d.host.scopedDefaults(); len(got) != 0 {
		t.Errorf("shutdown left %+v scoped to an interface this node does not own", got)
	}
	// And nothing of this machine is still held. A route socket or a link
	// watcher left open is one per start, for the life of the process.
	if sockets, watchers := d.host.stillOpen(); sockets != 0 || watchers != 0 {
		t.Errorf("shutdown left %d route sockets and %d link watchers open", sockets, watchers)
	}
}

// And the other order, which is the one the ordering rule exists for: a
// withdrawal that failed upstream, or a shutdown that ran out of order, must
// not take the fallback out from under a route that is still in the kernel.
// Doing so leaves this node with no network at all rather than with a mesh
// that is down.
func TestUnderlayRoutingOutlivesACaptureStillInTheKernel(t *testing.T) {
	d := startDaemon(t, true, recordedHost(t))
	d.live(t)
	d.announce(capturingPrefix)
	waitForKernel(t, "the announced default reaches the kernel", func() bool {
		plain, _ := d.host.installed(capturingPrefix)
		return plain
	})

	// Closed while the capture is still installed, the state a failed
	// withdrawal leaves behind.
	d.node.Close()
	if got := d.host.scopedDefaults(); len(got) == 0 {
		t.Fatal("the underlay's own routing went while a route carrying this machine's traffic was still in the kernel")
	}

	// Which is why the record outlives the process: what this start could not
	// take down is taken down by the next one. The reconciler withdraws the
	// capture on its way out, and a second node on the same machine, reading
	// the same record, reclaims what the first left.
	d.stop()
	_, _, closeUnderlay, err := underlayRuntime(transport.Underlay{Bind: true}, "mesh0", d.host)
	if err != nil {
		t.Fatalf("a second node could not open the underlay: %v", err)
	}
	t.Cleanup(closeUnderlay)
	if got := d.host.scopedDefaults(); len(got) != 0 {
		t.Errorf("the next start left %+v behind, so a node killed holding one leaks it for good", got)
	}
}

// loadDaemonConfig writes one node's file and reads it back through the loader
// the daemon uses, so the capability defaults and the refusals are the ones a
// deployment gets.
func loadDaemonConfig(t *testing.T, bind bool) *config.Config {
	t.Helper()
	dir := t.TempDir()
	keyPath, trustPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "registry.json")
	// A port of this run's own, because the hub below binds it for real and
	// two of these tests in flight at once would otherwise collide.
	port := freeUDPPort(t)
	underlay := ""
	if bind {
		underlay = "  underlay:\n    bind: true\n"
	}
	body := fmt.Sprintf(`node:
  org: example
  name: laptop
auth:
  key: %s
  trust: %s
link:
  port: %d
  endpoints:
    - serial: "0"
      family: ip4
%sdial:
  to:
    - name: gateway
      serial: "1"
cap:
  route:
    announce:
      - %q
  table:
    assign_announced: true
    reconcile: 50ms
    capture_grace: 1s
`, keyPath, trustPath, port, underlay, announcedAddress.String())
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	writeDaemonIdentity(t, keyPath, trustPath, port)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the configuration this test writes does not load: %v", err)
	}
	if cfg.Cap.Table == nil {
		t.Fatal("the configuration carries no cap.table, so there is no reconciler to build")
	}
	return cfg
}

// writeDaemonIdentity writes the key and the trust document the file names.
// The peer's endpoint carries an address, because the transport has to keep
// reaching it past whatever the mesh announces and the reconciler reads that
// set once a pass. Nothing dials it: these tests never call Run, so no dialer
// is ever started and nothing here reaches the network.
func writeDaemonIdentity(t *testing.T, keyPath, trustPath string, port uint16) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := peerEndpoint.String()
	reg := registry.Registry{{
		Organization: "example",
		PublicKey:    string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		Nodes: []registry.Node{
			{CommonName: "laptop", Endpoints: []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Port: port}}},
			{CommonName: "gateway", Endpoints: []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip4", Address: &endpoint, Port: port}}},
		},
	}}
	raw, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// daemonIdentity reads back the key the file names, the way client.New does.
func daemonIdentity(t *testing.T, cfg *config.Config) ed25519.PrivateKey {
	t.Helper()
	privateKey, err := registry.LoadPrivateKey(cfg.Auth.Key)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}
