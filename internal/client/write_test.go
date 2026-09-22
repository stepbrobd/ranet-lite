package client

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/control"
	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
	"github.com/NickCao/ranet-lite/internal/srv6"
	"github.com/NickCao/ranet-lite/schema"
)

// writable builds a node with all three subsystems configured, so a test below
// asks about the verb rather than about which blocks the file happens to
// carry.
func writable(t *testing.T) *Client {
	t.Helper()
	steering, err := srv6.NewSteerTable([]srv6.Steer{{
		To:  schema.MustPrefix("3fff:1::/48"),
		Via: []schema.Addr{schema.MustAddr("3fff:1:69c:98d6::1")},
	}}, schema.MustAddr("3fff:1:69c:8c0::1"))
	if err != nil {
		t.Fatal(err)
	}
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	mesh.SetSteering(steering)
	// A speaker and a registry, because a test below reads the whole status
	// rather than the stopped set alone: a subsystem stopped and not reported
	// is a node running less than its file says with nothing saying so.
	speaker, err := babel.New(babel.Config{}, babel.Routes{}, babel.Runtime{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{
		Mesh:     mesh,
		speaker:  speaker,
		sessions: newSessionSet(),
		dialers:  make(map[string]*dialer),
		running:  startedSubsystems(),
	}
	c.cfg.Store(&config.Config{Link: config.Link{Listen: true}})
	c.reg.Store(&registry.Registry{})
	c.SetReconcilerEnable(func(bool) {})
	return c
}

// Each verb stops its own subsystem and starts it again, and a status reports
// what it leaves. Steering is read off the mesh rather than off the record:
// the record holds what a write remembered and the mesh holds what a packet
// meets.
func TestSubsystemStopsAndStartsWhatItNames(t *testing.T) {
	c := writable(t)
	var reconciler []bool
	c.SetReconcilerEnable(func(on bool) { reconciler = append(reconciler, on) })

	if _, err := c.SetSubsystem(control.SubsystemSteering, false); err != nil {
		t.Fatal(err)
	}
	if c.Mesh.SteeringEnabled() {
		t.Error("steering was stopped and the mesh is still acting on its policies")
	}
	if c.Mesh.Steering() == nil {
		t.Error("stopping steering unloaded the table, so a diagnostic can no longer report what was stopped")
	}
	if _, err := c.SetSubsystem(control.SubsystemReconciler, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetSubsystem(control.SubsystemResponder, false); err != nil {
		t.Fatal(err)
	}
	if got := c.Status().Disabled; len(got) != 3 {
		t.Errorf("the status reports %v stopped, want all three", got)
	}
	if len(reconciler) != 1 || reconciler[0] {
		t.Errorf("the reconciler was told %v, want one stop", reconciler)
	}

	result, err := c.SetSubsystem(control.SubsystemSteering, true)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Mesh.SteeringEnabled() {
		t.Error("steering was started again and the mesh is not acting on its policies")
	}
	if !strings.Contains(result.Detail, "running") {
		t.Errorf("starting answered %q", result.Detail)
	}
	// A second ask is answered as the no-op it is rather than reported as a
	// change somebody then goes looking for in the logs.
	again, err := c.SetSubsystem(control.SubsystemSteering, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(again.Detail, "already") {
		t.Errorf("a repeated start answered %q, want it to say nothing moved", again.Detail)
	}
}

// A subsystem outside the closed set, and one this node's file never turned
// on, are both refused by name. Reporting either as stopped tells an operator
// their node is in a state it was never in.
func TestSubsystemRefusesWhatThisNodeDoesNotRun(t *testing.T) {
	c := writable(t)
	if _, err := c.SetSubsystem("dataplane", false); err == nil {
		t.Error("a subsystem outside the set was accepted")
	} else if !strings.Contains(err.Error(), "reconciler") {
		t.Errorf("the refusal reads %q, want it to name the set", err)
	}

	bare := &Client{Mesh: &netstack.Mesh{}, running: startedSubsystems()}
	bare.cfg.Store(&config.Config{})
	for name, want := range map[control.Subsystem]string{
		control.SubsystemReconciler: "cap.table",
		control.SubsystemSteering:   "cap.segment",
		control.SubsystemResponder:  "link.listen",
	} {
		if _, err := bare.SetSubsystem(name, false); err == nil {
			t.Errorf("%s was stopped on a node that does not run it", name)
		} else if !strings.Contains(err.Error(), want) {
			t.Errorf("the %s refusal reads %q, want it to name %s", name, err, want)
		}
	}
	if got := bare.disabledSubsystems(); got != nil {
		t.Errorf("a refused stop still recorded %v", got)
	}
}

// Stopping the responder leaves the sessions this node already holds alone,
// dialed and answered alike: it refuses the next handshake and is not a way to
// drop the mesh. TestStoppedResponderRefusesLiveHandshakes covers the refusal
// itself, against a peer actually dialing in.
func TestStoppedResponderKeepsTheSessionsItHolds(t *testing.T) {
	c := writable(t)
	if !c.subsystemRunning(control.SubsystemResponder) {
		t.Fatal("the fixture node does not answer dials, so this proves nothing")
	}
	c.sessions.close = func(*ike.Session) { t.Error("stopping the responder closed a live session") }
	c.sessions.active = func(*ike.Session) bool { return true }
	c.sessions.adoptPreferred("example/gateway/1@0", &ike.Session{}, true, nil)

	if _, err := c.SetSubsystem(control.SubsystemResponder, false); err != nil {
		t.Fatal(err)
	}
	if c.subsystemRunning(control.SubsystemResponder) {
		t.Error("a stopped responder still serves what it answers")
	}
	if !c.sessions.holds("example/gateway/1@0") {
		t.Error("stopping the responder dropped a session this node already held")
	}
}

// Redial drops what this node holds for the peer and cuts the reconnect delay
// short, which is the half of the butte finding this side can act on. The
// session leaves the set before the dialer is woken, or the dialer stands down
// behind a session that is already going.
func TestRedialDropsSessionsAndWakesDialers(t *testing.T) {
	c := writable(t)
	var closedMu sync.Mutex
	var closed []*ike.Session
	c.sessions.close = func(sess *ike.Session) {
		closedMu.Lock()
		defer closedMu.Unlock()
		closed = append(closed, sess)
	}
	c.sessions.active = func(*ike.Session) bool { return true }
	held := &ike.Session{}
	if _, adopted := c.sessions.adoptPreferred("example/gateway/1@0", held, true, nil); !adopted {
		t.Fatal("the fixture session was not adopted")
	}
	woken := &dialer{cancel: func() {}, wake: make(chan struct{}, 1)}
	c.dialers["example/gateway/1@0"] = woken
	other := &dialer{cancel: func() {}, wake: make(chan struct{}, 1)}
	c.dialers["example/elsewhere/1@0"] = other

	result, err := c.Redial("gateway")
	if err != nil {
		t.Fatal(err)
	}
	closedMu.Lock()
	if len(closed) != 1 || closed[0] != held {
		t.Errorf("redial closed %d sessions, want the one held for the peer", len(closed))
	}
	closedMu.Unlock()
	if c.sessions.holds("example/gateway/1@0") {
		t.Error("the session is still in the set, so the woken dialer stands down behind it")
	}
	select {
	case <-woken.wake:
	default:
		t.Error("the peer's dialer was not woken, so it waits out the whole reconnect delay")
	}
	select {
	case <-other.wake:
		t.Error("a dialer for another peer was woken")
	default:
	}
	if !strings.Contains(result.Detail, "1 session") {
		t.Errorf("redial answered %q", result.Detail)
	}

	if _, err := c.Redial("nobody"); err == nil {
		t.Error("redialing a peer this node neither dials nor holds was accepted")
	}
}

// A peer this node only answers has no dialer, and dropping its session is
// still the useful half: the peer opens a new one.
func TestRedialDropsResponderOnlySession(t *testing.T) {
	c := writable(t)
	c.sessions.close = func(*ike.Session) {}
	c.sessions.active = func(*ike.Session) bool { return true }
	c.sessions.adoptPreferred("example/inbound/1@0", &ike.Session{}, true, nil)
	result, err := c.Redial("example/inbound")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Detail, "1 session") || !strings.Contains(result.Detail, "0 dialer") {
		t.Errorf("redial answered %q, want one session and no dialer", result.Detail)
	}
}

// A dialer waiting out its reconnect delay comes round as soon as it is woken
// rather than at the end of it, which is the difference between a redial that
// acts now and one that acts in ten seconds. The loop under test is the real
// one, because a wake that never reaches its select is a redial that reports
// success and changes nothing.
func TestDialerWakesBeforeItsReconnectDelay(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{ctx: ctx, cancel: cancel, privateKey: privateKey,
		dialers: make(map[string]*dialer), dialRetry: time.Hour}
	c.cfg.Store(cfg)
	c.reg.Store(&reg)

	// A name the dialer takes and the resolver refuses, so each pass is one
	// attempt and then the wait this test is about. RFC 6761 reserves
	// .invalid for it.
	unresolvable := "gateway.invalid"
	reg[0].Nodes[1].Endpoints[0].Address = &unresolvable
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		c.runPeer(ctx, cfg.Link.Endpoints[0], cfg.Dial.To[0], wake)
		close(done)
	}()

	// Taking the node out of the registry ends the loop on its next pass, so
	// whether the loop came round is observable without a counter.
	time.Sleep(100 * time.Millisecond)
	empty := registry.Registry{}
	c.reg.Store(&empty)
	select {
	case <-done:
		t.Fatal("the dialer came round with no wake, so this measures nothing about one")
	case <-time.After(200 * time.Millisecond):
	}

	wake <- struct{}{}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("a woken dialer waited out its reconnect delay")
	}
}

// rekey reaches one peer's sessions, --all reaches every one, and neither
// reaches a session it did not name.
func TestRekeyAsksTheSessionsItNames(t *testing.T) {
	c := writable(t)
	c.sessions.close = func(*ike.Session) {}
	c.sessions.active = func(*ike.Session) bool { return true }
	asked := make(chan *ike.Session, 4)
	c.sessions.rekey = func(sess *ike.Session) error {
		asked <- sess
		return nil
	}
	gateway, elsewhere := &ike.Session{}, &ike.Session{}
	c.sessions.adoptPreferred("example/gateway/1@0", gateway, true, nil)
	c.sessions.adoptPreferred("example/elsewhere/1@0", elsewhere, true, nil)

	result, err := c.Rekey("gateway", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Acted) != 1 || result.Acted[0] != "example/gateway/1@0" {
		t.Errorf("rekey acted on %v, want the one peer", result.Acted)
	}
	select {
	case sess := <-asked:
		if sess != gateway {
			t.Error("rekey reached a session it did not name")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no session was asked to rekey")
	}

	if _, err := c.Rekey("", true); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case <-asked:
		case <-time.After(5 * time.Second):
			t.Fatal("--all left a session unasked")
		}
	}

	if _, err := c.Rekey("gateway", true); err == nil {
		t.Error("a peer and --all together were accepted")
	}
	if _, err := c.Rekey("", false); err == nil {
		t.Error("a rekey naming neither a peer nor --all was accepted")
	}
	if _, err := c.Rekey("nobody", false); err == nil {
		t.Error("rekeying a peer this node holds no session with was accepted")
	}
}

// The reload verb re-reads the file the daemon was started with. A node that
// was never told says so, rather than guessing at the default path and
// re-reading a file this process is not running.
func TestReloadUsesThePathTheDaemonWasStartedWith(t *testing.T) {
	c := writable(t)
	if _, err := c.Reload(); err == nil {
		t.Error("a node that was never told where its file is reloaded anyway")
	} else if !strings.Contains(err.Error(), "never told") {
		t.Errorf("the refusal reads %q", err)
	}
	c.SetConfigPath("/nonexistent/ranet-lite.toml")
	if _, err := c.Reload(); err == nil {
		t.Error("a reload of a file that does not exist reported success")
	} else if !strings.Contains(err.Error(), "/nonexistent/ranet-lite.toml") {
		t.Errorf("the failure reads %q, want it to name the file it read", err)
	}
}

// A peer is named by the whole path, by organization and name, or by the name
// alone, and two nodes sharing a name across organizations stay apart.
func TestPeerMatchingTakesEveryShapeOfTheName(t *testing.T) {
	const path = "example/gateway/1@0"
	for name, want := range map[string]bool{
		"gateway":             true,
		"example/gateway":     true,
		"example/gateway/1@0": true,
		"other/gateway":       false,
		"gate":                false,
		"example":             false,
		"":                    false,
	} {
		if got := matchesPeer(path, name); got != want {
			t.Errorf("matchesPeer(%q, %q) = %v, want %v", path, name, got, want)
		}
	}
}
