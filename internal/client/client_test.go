package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/registry"
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

// Two nodes that dial each other at once land both sessions on the same path
// name at both ends. They have to pick the same survivor whichever order the
// two handshakes finish in locally, or each keeps the SA the other tore down
// and nothing crosses until dead peer detection notices.
func TestSimultaneousOpenConvergesOnTheSameSession(t *testing.T) {
	a := ike.Identity{Organization: "example", CommonName: "alpha", SerialNumber: "1"}
	b := ike.Identity{Organization: "example", CommonName: "bravo", SerialNumber: "1"}
	if preferInitiator(a, b) == preferInitiator(b, a) {
		t.Fatal("both ends think the same one should dial, so there is no tie-break at all")
	}

	// One session per direction, named by who opened it. Both nodes see both.
	const dialedByA, dialedByB = "dialed-by-a", "dialed-by-b"
	// resolve replays one node's arrival order and reports which session it
	// keeps. local is that node's own identity.
	resolve := func(local, remote ike.Identity, order []string) string {
		set := newSessionSet()
		set.close = func(*ike.Session) {}
		set.active = func(*ike.Session) bool { return true }
		sessions := map[string]*ike.Session{dialedByA: {}, dialedByB: {}}
		weDial := local == a
		for _, which := range order {
			// A session is preferred when it runs in the direction both ends
			// agree should be dialed.
			dialedByUs := (which == dialedByA) == weDial
			preferred := dialedByUs == preferInitiator(local, remote)
			set.adopt("path", sessions[which], preferred)
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
			keptByA := resolve(a, b, orderA)
			keptByB := resolve(b, a, orderB)
			if keptByA == "" || keptByB == "" {
				t.Fatalf("a node kept no session at all (a=%v b=%v)", orderA, orderB)
			}
			if keptByA != keptByB {
				t.Errorf("alpha (order %v) kept %s while bravo (order %v) kept %s, which is a blackhole in both directions",
					orderA, keptByA, orderB, keptByB)
			}
		}
	}
}

// Losing the resolution must not send the dialer straight back in. Without a
// stand-down the two ends take turns replacing each other's session every
// reconnect delay for as long as the process runs, and every replacement
// withdraws the routes learned through that peer.
func TestAnEstablishedSessionStopsTheDialer(t *testing.T) {
	set := newSessionSet()
	set.close = func(*ike.Session) {}
	set.active = func(*ike.Session) bool { return true }
	if set.holds("path") {
		t.Fatal("an empty set reports a session, so neither end would ever dial")
	}
	sess := &ike.Session{}
	release, adopted := set.adopt("path", sess, true)
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
func TestAStaleSessionDoesNotLockOutTheReconnectingPeer(t *testing.T) {
	set := newSessionSet()
	set.close = func(*ike.Session) {}
	stale, fresh := &ike.Session{}, &ike.Session{}
	// The incumbent is the one both ends prefer, and it is no longer carrying
	// traffic. The peer dialing us is the proof of that.
	set.active = func(sess *ike.Session) bool { return sess != stale }

	if _, adopted := set.adopt("path", stale, true); !adopted {
		t.Fatal("the first session was not adopted")
	}
	if set.holds("path") {
		t.Error("a session that has stopped proving the peer is there still stops our dialer")
	}
	if _, adopted := set.adopt("path", fresh, false); !adopted {
		t.Fatal("a fresh handshake was declined in favor of a session that is not carrying traffic")
	}
	if live := set.live["path"]; live == nil || live.session != fresh {
		t.Error("the stale session is still the live one")
	}
}

// The preference rule still has to hold when the incumbent really is alive, or
// two nodes dialing each other at once keep different sessions.
func TestAnActivePreferredSessionStillWins(t *testing.T) {
	set := newSessionSet()
	set.close = func(*ike.Session) {}
	set.active = func(*ike.Session) bool { return true }
	winner, loser := &ike.Session{}, &ike.Session{}
	set.adopt("path", winner, true)
	if _, adopted := set.adopt("path", loser, false); adopted {
		t.Error("the session neither end prefers replaced the one both do")
	}
	if live := set.live["path"]; live == nil || live.session != winner {
		t.Error("the preferred session was not kept")
	}
}
