package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/ike"
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
//
// It retries. freeUDPPort asks the kernel for a port and gives it straight
// back, because naming one in a config file is the only way these nodes can
// find each other, so anything else on the machine can take it in the gap.
// Retrying with fresh ports is the difference between a rare unexplained
// failure somewhere in this package and none.
// newLoopbackMesh retries, because the ports are chosen by binding to zero,
// reading the port back and binding it again: anything else on the machine can
// take it in between, and on a loaded one several tests are doing this at
// once. The wait between attempts makes a run of losses unlikely
// rather than merely improbable; without it a busy machine lost every attempt
// in the same handful of microseconds.
func newLoopbackMesh(t *testing.T) (*loopbackNode, *loopbackNode) {
	t.Helper()
	const attempts = 10
	for attempt := range attempts {
		alpha, bravo, err := tryLoopbackMesh(t)
		if err == nil {
			return alpha, bravo
		}
		t.Logf("attempt %d could not bind the ports it was given: %v", attempt, err)
		time.Sleep(time.Duration(attempt+1) * 20 * time.Millisecond)
	}
	t.Fatalf("%d attempts in a row could not bind a port the kernel had just handed back", attempts)
	return nil, nil
}

func tryLoopbackMesh(t *testing.T) (_, _ *loopbackNode, err error) {
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
			for _, built := range nodes[:i] {
				built.client.Close()
			}
			return nil, nil, fmt.Errorf("%s: %w", node.name, err)
		}
		node.client = client
	}
	return nodes[0], nodes[1], nil
}

// writeLoopbackConfig writes one node's config file and loads it back, so the
// running client and the file a reload reads can never drift apart.
func writeLoopbackConfig(t *testing.T, node, peer *loopbackNode, keyPath, registryPath string, originate []string) *config.Config {
	t.Helper()
	body := fmt.Sprintf(`node:
  org: example
  name: %s
auth:
  key: %s
  trust: %s
link:
  port: %d
  endpoints:
    - serial: "0"
      family: ip4
  # Both ends answer as well as dial, which is the full mesh shape and the one
  # that produces a simultaneous open.
  listen: true
dial:
  to:
    - name: %s
      serial: "0"
cap:
  babel:
    hello: 200ms
    update: 400ms
  route:
    announce:
`, node.name, keyPath, registryPath, node.port, peer.name)
	for _, prefix := range originate {
		body += fmt.Sprintf("      - %q\n", prefix)
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
	waitFor(t, convergeBudget, "one established session at each end", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})

	// And the route each announces reaches the other, which means the session
	// is carrying ESP, babel is running inside it and the forwarding table was
	// written.
	reaches := func(from, to *loopbackNode) bool {
		peer, ok := from.client.Mesh.Routes.Lookup(netip.Addr{}, to.prefix.Addr().Next())
		return ok && peer != nil
	}
	waitFor(t, convergeBudget, "each node forwarding to the other's prefix", func() bool {
		return reaches(alpha, bravo) && reaches(bravo, alpha)
	})

	// One session at each end is not the same thing as the same session at
	// both ends. Two nodes evicting each other hold one apiece and still carry
	// traffic, so neither check above can tell that apart from convergence.
	// The preference bit is a property of the SA rather than of the node that
	// holds it, so the two ends agree on it exactly when they are holding the
	// same SA.
	waitFor(t, convergeBudget, "both ends holding the same session", func() bool {
		a, aok := preferenceOf(alpha)
		b, bok := preferenceOf(bravo)
		return aok && bok && a == b
	})

	stop()
}

// preferenceOf reads the preference bit of the one session a node is holding.
func preferenceOf(node *loopbackNode) (bool, bool) {
	set := node.client.sessions
	set.mu.Lock()
	defer set.mu.Unlock()
	if len(set.live) != 1 {
		return false, false
	}
	for _, live := range set.live {
		return live.preferred, true
	}
	return false, false
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
				case <-time.After(convergeBudget):
					t.Error("a node did not stop after its context was canceled")
				}
			}
		})
	}
	t.Cleanup(stop)
	return ctx, stop
}

// convergeBudget is how long these tests wait for something they expect to
// happen. It is generous because a loaded machine is not a failing
// implementation: a convergence that never happens still fails the test, just
// later, while a budget tuned to an idle machine turns load into a false red.
// Every one of these is a positive assertion, so nothing is weakened by
// waiting longer.
const convergeBudget = 60 * time.Second

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
func TestReloadAnnouncesNewPrefixToPeer(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	run(t, alpha, bravo)
	added := netip.MustParsePrefix("fd00:aa::/64")
	waitFor(t, convergeBudget, "the initial route", func() bool {
		peer, ok := bravo.client.Mesh.Routes.Lookup(netip.Addr{}, alpha.prefix.Addr().Next())
		return ok && peer != nil
	})

	writeLoopbackConfig(t, alpha, bravo, alpha.cfg.Auth.Key, alpha.cfg.Auth.Trust,
		[]string{alpha.prefix.String(), added.String()})
	if err := alpha.client.Reload(alpha.configPath); err != nil {
		t.Fatalf("adding an originated prefix was refused: %v", err)
	}

	waitFor(t, convergeBudget, "the reloaded prefix to reach the peer", func() bool {
		peer, ok := bravo.client.Mesh.Routes.Lookup(netip.Addr{}, added.Addr().Next())
		return ok && peer != nil
	})
}

// Shutting down closes the hub, which ends every dialed session at once. See
// Client.stopping for what the dialers have to read that as.
func TestShutdownSaysNothingAboutReconnecting(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// closeAll runs before c.cancel, deliberately, and on a full mesh it takes
	// long enough for a dialer to reach its own check while the context is
	// still alive. Held open here so the window is the same size every time
	// rather than whatever the scheduler gives, and set before either node
	// runs because adoptFor reads this outside the set's own lock.
	closeSession := alpha.client.sessions.close
	alpha.client.sessions.close = func(sess *ike.Session) {
		closeSession(sess)
		time.Sleep(200 * time.Millisecond)
	}
	run(t, bravo)
	_, stopAlpha := run(t, alpha)

	waitFor(t, convergeBudget, "both ends established", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})

	written := &syncBuffer{}
	previous := log.Writer()
	log.SetOutput(written)
	t.Cleanup(func() { log.SetOutput(previous) })
	stopAlpha()
	// Only alpha is stopping, and both nodes write to the one logger this
	// captures, so the lines that count are the ones naming alpha's own peer.
	// bravo stays up, loses the node it was dialing and says it will retry,
	// which is the correct thing for a node whose peer went away: counting its
	// line as well failed this test in about one run in thirty.
	dialingBravo := fmt.Sprintf("peer %s/%s", alpha.cfg.Node.Org, bravo.name)
	var got []string
	for _, line := range written.lines("reconnecting in") {
		if strings.Contains(line, dialingBravo) {
			got = append(got, line)
		}
	}
	if len(got) != 0 {
		t.Errorf("shutdown wrote %d reconnect lines, want none: %s", len(got), strings.Join(got, " | "))
	}
}

// Shutdown tells every peer the SA is gone rather than leaving it sending ESP
// into an SPI we no longer accept until its own dead peer detection expires,
// which is over a minute. closeAll and the Delete inside closeSession are both
// unreachable from anything else in this package.
//
// closeAll is driven directly rather than through the whole client stop,
// because a node that is canceled while it is dialing leaves the other end
// holding a session it was never told about: the responder commits at
// IKE_AUTH and the initiator confirms a message later, so an initiator that
// goes between the two has nothing to send a Delete on. That is the exchange's
// own shape, not this sweep's, and the peer clears it on liveness. Driving the
// sweep makes this deterministic; the redial that follows a resolved
// simultaneous open is otherwise in flight whenever the machine is slow.
func TestShutdownTellsPeerBeforeGoing(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	run(t, bravo)
	_, stopAlpha := run(t, alpha)
	t.Cleanup(stopAlpha)

	waitFor(t, convergeBudget, "both ends established", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})

	// Only alpha's sessions go, while its hub is still open to carry the
	// Delete. bravo has to notice through that rather than through its own
	// liveness timer, which is far slower than this.
	alpha.client.sessions.closeAll()
	deadline := time.Now().Add(convergeBudget)
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
