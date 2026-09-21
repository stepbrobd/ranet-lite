package control

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSource answers with one distinguishable value per read, so a handler
// that wires two paths to the same reader is caught rather than passing.
type fakeSource struct{}

func (fakeSource) Status() Status {
	return Status{Organization: "example", CommonName: "node", Port: 13000}
}

func (fakeSource) Neighbors() []Neighbor {
	return []Neighbor{{Peer: "example/gateway@0", Alive: true, Cost: 116, Routes: 7}}
}

func (fakeSource) Routes() []Route {
	return []Route{{Destination: netip.MustParsePrefix("2001:db8::/32"), Via: "example/gateway@0", Metric: 212}}
}

func (fakeSource) Sessions() []Session {
	return []Session{{Path: "example/gateway/0@0", Peer: "example/gateway", Active: true}}
}

func (fakeSource) Peers() []Peer {
	return []Peer{{Path: "example/gateway/@0", Organization: "example", CommonName: "gateway", Generated: true}}
}

// Every path answers, and each answers with its own subsystem rather than
// with whatever the previous registration happened to close over.
func TestHandlerServesEveryReadAsJSON(t *testing.T) {
	server := httptest.NewServer(Handler(fakeSource{}))
	defer server.Close()
	for path, want := range map[string]string{
		PathStatus:    `"common_name":"node"`,
		PathNeighbors: `"peer":"example/gateway@0"`,
		PathRoutes:    `"destination":"2001:db8::/32"`,
		PathSessions:  `"path":"example/gateway/0@0"`,
		PathPeers:     `"generated":true`,
	} {
		t.Run(path, func(t *testing.T) {
			response, err := http.Get(server.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("%s answered %s", path, response.Status)
			}
			if got := response.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("%s served as %q", path, got)
			}
			body := make([]byte, 4096)
			n, _ := response.Body.Read(body)
			if !strings.Contains(string(body[:n]), want) {
				t.Errorf("%s answered %q, want it to carry %q", path, body[:n], want)
			}
		})
	}
}

// The socket is read-only, and the rule is enforced rather than left implied
// by there being no route that writes: a POST falling through to a reader
// answers 200 and reads as a write that took effect.
func TestHandlerRefusesWrites(t *testing.T) {
	server := httptest.NewServer(Handler(fakeSource{}))
	defer server.Close()
	response, err := http.Post(server.URL+PathStatus, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("a POST answered %s, want 405", response.Status)
	}
	if allow := response.Header.Get("Allow"); !strings.Contains(allow, "GET") {
		t.Errorf("the refusal advertises %q, want it to name GET", allow)
	}
}

// A socket an instance left behind is removed and a socket a live daemon is
// listening on is not, because taking the second away would leave the running
// node unreachable while reporting a clean start.
func TestListenClearsStaleSocketAndRefusesLiveOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")

	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	// A killed process leaves the inode behind, which closing the listener
	// without unlinking reproduces.
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()

	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("a stale socket was not cleared: %v", err)
	}
	defer listener.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != socketMode {
		t.Errorf("the socket is mode %o, want %o so the daemon's group can read it", mode, socketMode)
	}

	if _, err := Listen(path); err == nil {
		t.Fatal("a second daemon took over a socket the first is listening on")
	} else if !strings.Contains(err.Error(), "already listening") {
		t.Errorf("the refusal reads %q, want it to name the live daemon", err)
	}
}

// Anything at the path that is not a socket belongs to somebody else, so it is
// named rather than unlinked.
func TestListenRefusesPathThatIsNotSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("an ordinary file at the socket path was removed")
	} else if !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("the refusal reads %q, want it to say what is in the way", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the file was removed anyway: %v", err)
	}
}

// sun_path is 104 bytes on darwin and 108 on linux, and a bind over either
// fails as "invalid argument", which names neither the path nor the limit.
func TestListenRefusesOverlongPath(t *testing.T) {
	path := "/tmp/" + strings.Repeat("d", maxSocketPath) + "/control.sock"
	_, err := Listen(path)
	if err == nil {
		t.Fatal("an overlong socket path was accepted")
	}
	if !strings.Contains(err.Error(), "unix socket holds") {
		t.Errorf("the refusal reads %q, want it to name the limit", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); err == nil {
		t.Error("the refusal created the directory on its way out")
	}
}

// Every read decodes into its own type across a real socket, which is the
// check that the client and the handler agree about field names as well as
// about paths.
func TestClientRoundTripsEveryRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() { done <- Serve(listener, fakeSource{}) }()

	client := Dial(path)
	status, err := client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.CommonName != "node" || status.Port != 13000 {
		t.Errorf("status decoded as %+v", status)
	}
	neighbors, err := client.Neighbors()
	if err != nil {
		t.Fatal(err)
	}
	if len(neighbors) != 1 || neighbors[0].Cost != 116 {
		t.Errorf("neighbors decoded as %+v", neighbors)
	}
	routes, err := client.Routes()
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Metric != 212 {
		t.Errorf("routes decoded as %+v", routes)
	}
	sessions, err := client.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || !sessions[0].Active {
		t.Errorf("sessions decoded as %+v", sessions)
	}
	peers, err := client.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || !peers[0].Generated {
		t.Errorf("peers decoded as %+v", peers)
	}

	listener.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("an ordinary close reported %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return after its listener closed")
	}
}

// "connect: no such file or directory" names neither the daemon nor the flag
// that would have created the socket.
func TestClientExplainsMissingDaemon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	_, err := Dial(path).Status()
	if err == nil {
		t.Fatal("reading a socket that does not exist succeeded")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "daemon") {
		t.Errorf("the failure reads %q, want it to name the path and the daemon", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Error("the failure is still the bare syscall error")
	}
}

// A duration on the wire reads as "4s" rather than as a count of nanoseconds,
// and survives the round trip either way.
func TestDurationRoundTripsAsText(t *testing.T) {
	body, err := Duration(90 * time.Second).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `"1m30s"` {
		t.Fatalf("encoded as %s, want a duration string", body)
	}
	var back Duration
	if err := back.UnmarshalJSON(body); err != nil {
		t.Fatal(err)
	}
	if time.Duration(back) != 90*time.Second {
		t.Errorf("decoded as %s", back)
	}
}

// A live daemon owns its socket even when nothing can dial it. Deciding
// staleness by dialing unlinks a running node's socket whenever the dial fails
// for any reason but a refused connection, and a daemon out of descriptors,
// one whose backlog is full and one whose socket this user cannot open all
// fail that way.
func TestListenRefusesALiveSocketItCannotDial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// connect needs write permission on a unix socket, so this is one a live
	// daemon is serving and nothing can reach.
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("a second daemon took over a live socket it could not dial")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the live daemon's socket was unlinked: %v", err)
	}
}

// An idle connection costs the daemon a goroutine and a descriptor until
// something closes it. net/http clears the read deadline between requests, so
// ReadHeaderTimeout does not bound one that has finished a request and gone
// quiet.
func TestIdleConnectionsAreBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for an idle timeout")
	}
	server := newServer(&fakeSource{})
	if server.IdleTimeout == 0 {
		t.Fatal("an idle connection is bounded by IdleTimeout and by nothing else")
	}
	server.IdleTimeout = 100 * time.Millisecond
	client, daemon := net.Pipe()
	defer client.Close()
	go server.Serve(&onePipe{daemon: daemon})

	if _, err := client.Write([]byte("GET " + PathStatus + " HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(client).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(client); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("an idle connection was not closed: %v", err)
	}
}

// onePipe hands a server one connection and then blocks, which is enough to
// watch what the server does with that one.
type onePipe struct {
	daemon net.Conn
	done   bool
}

func (p *onePipe) Accept() (net.Conn, error) {
	if p.done {
		select {}
	}
	p.done = true
	return p.daemon, nil
}
func (p *onePipe) Close() error   { return nil }
func (p *onePipe) Addr() net.Addr { return p.daemon.LocalAddr() }

// A client that accumulates connections costs the daemon a goroutine and a
// descriptor apiece, and a node out of descriptors cannot be asked anything at
// all, the silence this socket was built to end. Past the bound a connection is
// closed as it is accepted rather than queued, so a client holding every place
// cannot hold up the accept loop or a shutdown either.
func TestConnectionsPastTheBoundAreRefusedRatherThanQueued(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- Serve(listener, fakeSource{}) }()

	// One request each, then held open, the state the idle timeout would
	// otherwise be the only bound on.
	held := make([]net.Conn, 0, maxConnections)
	defer func() {
		for _, conn := range held {
			conn.Close()
		}
	}()
	for len(held) < maxConnections {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("connection %d of %d was refused: %v", len(held)+1, maxConnections, err)
		}
		if _, err := conn.Write([]byte("GET " + PathStatus + " HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
			t.Fatalf("connection %d was not answered: %v", len(held)+1, err)
		}
		held = append(held, conn)
	}

	// The next one is accepted and closed rather than left waiting.
	over, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("a connection past the bound was refused at dial: %v", err)
	}
	defer over.Close()
	over.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(over); err != nil {
		t.Errorf("a connection past the bound was left open: %v", err)
	}

	// And the listener still answers its own close while every place is held.
	listener.Close()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("an ordinary close reported %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return while the bound was full")
	}
}

// A duration inside a sentence is written out, and the unit is chosen after
// rounding: a pass 59.5 seconds ago is a minute, not sixty seconds. A
// timestamp ahead of this clock is said rather than rendered as a negative.
func TestKernelLineWritesItsDurationOut(t *testing.T) {
	for name, test := range map[string]struct {
		since time.Duration
		want  string
	}{
		"one second":          {time.Second, "last pass 1 second ago"},
		"under a minute":      {45 * time.Second, "last pass 45 seconds ago"},
		"rounding to one":     {59500 * time.Millisecond, "last pass 1 minute ago"},
		"rounding to an hour": {3599 * time.Second, "last pass 1 hour ago"},
		"a clock ahead":       {-3 * time.Second, "last pass timestamped ahead of this clock"},
	} {
		t.Run(name, func(t *testing.T) {
			line := kernelLine(KernelStatus{Enabled: true, PassAt: time.Now().Add(-test.since)})
			if !strings.Contains(line, test.want) {
				t.Errorf("the line reads %q, want it to carry %q", line, test.want)
			}
		})
	}
}
