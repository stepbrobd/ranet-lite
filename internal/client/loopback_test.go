package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
)

var meshCounter atomic.Uint64

// loopbackNode is one end of a two-node mesh standing on 127.0.0.1.
type loopbackNode struct {
	name       string
	port       uint16
	prefix     netip.Prefix
	client     *Client
	cfg        *config.Config
	configPath string
}

// freeUDPPort asks the kernel for a port and gives it straight back, which is
// the only way to name one in a config before the hub binds it.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// newLoopbackMesh builds two clients that know about each other, each on its
// own UDP port, sharing one organization key. Neither owns a TUN: babel
// intercepts its own traffic before delivery, so nothing reaches one.
func newLoopbackMesh(t *testing.T) (*loopbackNode, *loopbackNode) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	// Names are unique per mesh, not per role. A port the kernel handed back
	// can be handed out again once a hub closes, and a node another test left
	// retransmitting would otherwise authenticate against its replacement:
	// same organization key, same common name, same port.
	mesh := meshCounter.Add(1)
	nodes := []*loopbackNode{
		{name: fmt.Sprintf("alpha-%d", mesh), port: freeUDPPort(t), prefix: netip.MustParsePrefix("fd00:a::/64")},
		{name: fmt.Sprintf("bravo-%d", mesh), port: freeUDPPort(t), prefix: netip.MustParsePrefix("fd00:b::/64")},
	}
	loopback := "127.0.0.1"
	org := registry.Organization{PublicKey: publicPEM, Organization: "example"}
	for _, node := range nodes {
		org.Nodes = append(org.Nodes, registry.Node{
			CommonName: node.name,
			Endpoints: []registry.Endpoint{{
				SerialNumber: "0", AddressFamily: "ip4", Address: &loopback, Port: node.port,
			}},
		})
	}
	reg := registry.Registry{org}

	// Written to disk as well, because Reload reads the file rather than
	// taking a struct, and that is the path a SIGHUP takes.
	dir := t.TempDir()
	registryPath := filepath.Join(dir, "registry.json")
	raw, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	for i, node := range nodes {
		peer := nodes[1-i]
		node.configPath = filepath.Join(dir, node.name+".yaml")
		node.cfg = writeLoopbackConfig(t, node, peer, keyPath, registryPath, []string{node.prefix.String()})
		client, err := newClient(node.cfg, private, reg, netstack.NewRoutesOnly())
		if err != nil {
			t.Fatalf("%s: %v", node.name, err)
		}
		node.client = client
	}
	return nodes[0], nodes[1]
}

// writeLoopbackConfig writes one node's config file and loads it back, so the
// running client and the file a reload reads can never drift apart.
func writeLoopbackConfig(t *testing.T, node, peer *loopbackNode, keyPath, registryPath string, originate []string) *config.Config {
	t.Helper()
	body := fmt.Sprintf(`organization: example
common_name: %s
port: %d
endpoints:
  - serial_number: "0"
    address_family: ip4
private_key: %s
registry: %s
# Both ends answer as well as dial, which is the full-mesh shape and the one
# that produces a simultaneous open.
responder: true
peers:
  - common_name: %s
    serial_number: "0"
babel:
  hello_interval: 200ms
  update_interval: 400ms
originate:
`, node.name, node.port, keyPath, registryPath, peer.name)
	for _, prefix := range originate {
		body += fmt.Sprintf("  - %q\n", prefix)
	}
	if err := os.WriteFile(node.configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(node.configPath)
	if err != nil {
		t.Fatalf("%s: %v", node.name, err)
	}
	return cfg
}

// Two nodes dialing and answering each other is the shape a full mesh has, and
// no other test in this package executes Run, acceptPeers, connectPeer,
// serveSession or closeSession at all: the resolution rules are exercised
// against a model of sessionSet with its own close and liveness stubbed out.
func TestTwoNodesConvergeOverLoopback(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	_, stop := run(t, alpha, bravo)

	// Both ends settle on exactly one session, which is the thing the
	// preference rule decides and which diverges if the two ends disagree.
	waitFor(t, 20*time.Second, "one established session at each end", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})

	// And the route each announces reaches the other, which means the session
	// is carrying ESP, babel is running inside it and the forwarding table was
	// written.
	reaches := func(from, to *loopbackNode) bool {
		peer, ok := from.client.Mesh.Routes.Lookup(netip.Addr{}, to.prefix.Addr().Next())
		return ok && peer != nil
	}
	waitFor(t, 20*time.Second, "each node forwarding to the other's prefix", func() bool {
		return reaches(alpha, bravo) && reaches(bravo, alpha)
	})

	stop()
}

func isCanceled(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}

// run starts each node and returns a stop that cancels and waits for every one
// of them. Waiting matters: a client left unwinding keeps its dialers retrying
// and its hub bound, and the next test would then be sharing a port with it.
func run(t *testing.T, nodes ...*loopbackNode) (context.Context, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, len(nodes))
	for _, node := range nodes {
		go func() { stopped <- node.client.Run(ctx) }()
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			for range nodes {
				select {
				case err := <-stopped:
					if err != nil && !isCanceled(err) {
						t.Errorf("a node stopped with %v", err)
					}
				case <-time.After(30 * time.Second):
					t.Error("a node did not stop after its context was canceled")
				}
			}
		})
	}
	t.Cleanup(stop)
	return ctx, stop
}

func waitFor(t *testing.T, limit time.Duration, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// SIGHUP announcing a new prefix has to reach the peer's forwarding table.
// The existing reload test sets Originate and asserts peer and registry
// counts, so deleting the SetOriginated call passes it.
func TestReloadAnnouncesANewPrefixToThePeer(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	run(t, alpha, bravo)
	added := netip.MustParsePrefix("fd00:aa::/64")
	waitFor(t, 20*time.Second, "the initial route", func() bool {
		peer, ok := bravo.client.Mesh.Routes.Lookup(netip.Addr{}, alpha.prefix.Addr().Next())
		return ok && peer != nil
	})

	writeLoopbackConfig(t, alpha, bravo, alpha.cfg.PrivateKey, alpha.cfg.Registry,
		[]string{alpha.prefix.String(), added.String()})
	if err := alpha.client.Reload(alpha.configPath); err != nil {
		t.Fatalf("adding an originated prefix was refused: %v", err)
	}

	waitFor(t, 20*time.Second, "the reloaded prefix to reach the peer", func() bool {
		peer, ok := bravo.client.Mesh.Routes.Lookup(netip.Addr{}, added.Addr().Next())
		return ok && peer != nil
	})
}

// Shutdown tells every peer the SA is gone rather than leaving it sending ESP
// into an SPI we no longer accept until its own dead peer detection expires,
// which is over a minute. closeAll and the Delete inside closeSession are both
// unreachable from anything else in this package.
func TestShutdownTellsThePeerBeforeGoing(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	run(t, bravo)
	_, stopAlpha := run(t, alpha)

	waitFor(t, 20*time.Second, "both ends established", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})

	// Only alpha goes. bravo has to notice through the Delete rather than
	// through its own liveness timer, which is far slower than this.
	stopAlpha()
	deadline := time.Now().Add(15 * time.Second)
	for len(bravo.client.sessions.paths()) != 0 {
		if time.Now().After(deadline) {
			bravo.client.sessions.mu.Lock()
			for path, live := range bravo.client.sessions.live {
				t.Logf("bravo still holds %s: mux closed=%v preferred=%v active=%v",
					path, live.session.Mux().IsClosed(), live.preferred, live.session.Active())
			}
			bravo.client.sessions.mu.Unlock()
			t.Fatal("the peer kept a session it was told to drop")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
