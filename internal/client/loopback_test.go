package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
)

// loopbackNode is one end of a two-node mesh standing on 127.0.0.1.
type loopbackNode struct {
	name   string
	port   uint16
	prefix netip.Prefix
	client *Client
	cfg    *config.Config
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

	nodes := []*loopbackNode{
		{name: "alpha", port: freeUDPPort(t), prefix: netip.MustParsePrefix("fd00:a::/64")},
		{name: "bravo", port: freeUDPPort(t), prefix: netip.MustParsePrefix("fd00:b::/64")},
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

	for i, node := range nodes {
		peer := nodes[1-i]
		node.cfg = &config.Config{
			Organization: "example", CommonName: node.name, Port: node.port,
			Endpoints: []config.Endpoint{{SerialNumber: "0", AddressFamily: "ip4"}},
			Peers:     []config.Peer{{Organization: "example", CommonName: peer.name, SerialNumber: "0"}},
			Originate: []string{node.prefix.String()},
			// Both ends answer as well as dial, which is the full-mesh shape
			// and the one that produces a simultaneous open.
			Responder: true,
			Babel:     config.Babel{HelloInterval: 200 * time.Millisecond, UpdateInterval: 400 * time.Millisecond},
		}
		client, err := newClient(node.cfg, private, reg, netstack.NewRoutesOnly())
		if err != nil {
			t.Fatalf("%s: %v", node.name, err)
		}
		node.client = client
	}
	return nodes[0], nodes[1]
}

// Two nodes dialing and answering each other is the shape a full mesh has, and
// no other test in this package executes Run, acceptPeers, connectPeer,
// serveSession or closeSession at all: the resolution rules are exercised
// against a model of sessionSet with its own close and liveness stubbed out.
func TestTwoNodesConvergeOverLoopback(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stopped := make(chan error, 2)
	for _, node := range []*loopbackNode{alpha, bravo} {
		go func() { stopped <- node.client.Run(ctx) }()
	}

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

	cancel()
	for range 2 {
		select {
		case err := <-stopped:
			if err != nil && !isCanceled(err) {
				t.Errorf("a node stopped with %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("a node did not stop after its context was canceled")
		}
	}
}

func isCanceled(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
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
