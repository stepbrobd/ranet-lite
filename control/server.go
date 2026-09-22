package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// MaxSocketPath is the shortest of the platform limits this tree builds for:
// linux allows 108 bytes in sun_path and darwin 104, both including the
// terminator. Binding a longer one fails as "invalid argument", which names
// neither the path nor the limit, so the check is here instead.
const MaxSocketPath = 103

// socketMode is the permission the socket is left at. Group reachable rather
// than owner only, so an operator in the daemon's group runs the subcommands
// without root: the unit names that group, since nothing here changes the
// socket's owner. This mode is the whole authorization story, the verbs
// included, because no verb reaches past what the node's own file already
// decides; see the package doc. dirMode lets that same group traverse the
// directory holding it, and lockMode is owner-only because only the daemon
// takes the lock.
const (
	socketMode = 0o660
	dirMode    = 0o750
	lockMode   = 0o600
)

// lockSuffix names the file whose lock says which process owns the socket.
const lockSuffix = ".lock"

// Listen binds the control socket at path, creating its parent directory and
// clearing a socket a previous instance left behind.
//
// Which process owns the path is settled by an exclusive lock on a sibling
// file rather than by dialing the socket to see whether anything answers.
// Dialing answers "is something accepting at this instant", which is a
// different question: a live daemon out of descriptors, one whose backlog is
// full, and one whose socket this user cannot open all fail to answer, and
// unlinking on any of those takes a running node's socket away. The lock also
// closes the window between deciding a socket is stale and binding the
// replacement, where two starting instances could each remove the other's.
//
// A path that is not a socket is refused by name rather than removed: it is
// not this daemon's to take away from whoever put it there.
//
// The lock file outlives the process on purpose. Unlinking it at exit races:
// a second instance can open it and block on the lock, and an unlink between
// those two steps leaves that instance holding a lock on an unlinked inode
// while a third creates the path afresh and locks that, so both believe they
// own the socket. An empty file is the cheaper end of that trade, and a unit
// with RuntimeDirectory set clears it anyway.
func Listen(path string) (net.Listener, error) {
	if len(path) > MaxSocketPath {
		return nil, fmt.Errorf("control: socket path is %d bytes, over the %d a unix socket holds: %s", len(path), MaxSocketPath, path)
	}
	if err := makeParent(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := takeOwnership(path)
	if err != nil {
		return nil, err
	}
	if err := clearStale(path); err != nil {
		lock.Close()
		return nil, err
	}
	socket, err := net.Listen("unix", path)
	if err != nil {
		lock.Close()
		return nil, fmt.Errorf("control: %w", err)
	}
	// After the bind rather than through a umask: the umask is the process's
	// and belongs to whoever started it, and a socket left at 0755 by one is a
	// socket the group cannot read.
	if err := os.Chmod(path, socketMode); err != nil {
		socket.Close()
		lock.Close()
		return nil, fmt.Errorf("control: %w", err)
	}
	return &ownedListener{Listener: socket, lock: lock}, nil
}

// makeParent creates the socket's directory at a mode the daemon's group can
// traverse. MkdirAll takes the process umask off the mode it is given, so a
// unit with a restrictive one would otherwise leave a directory nobody but the
// daemon can enter and a socket inside it that says it is group readable. A
// directory that already exists is left exactly as it is.
func makeParent(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	return nil
}

// takeOwnership holds the lock that says this process owns the socket path,
// for as long as it holds the descriptor. A lock another process holds is
// reported rather than waited for, because a second daemon on one path is a
// configuration mistake rather than a queue to join.
func takeOwnership(path string) (*os.File, error) {
	lock, err := os.OpenFile(path+lockSuffix, os.O_CREATE|os.O_RDWR, lockMode)
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("control: another daemon is already listening on %s, which is why it holds %s", path, lock.Name())
		}
		return nil, fmt.Errorf("control: locking %s: %w", lock.Name(), err)
	}
	return lock, nil
}

// clearStale removes the socket a dead instance left behind, and refuses
// anything else at that path. Its caller holds the lock, so nothing is serving
// this path and a socket here is nobody's.
func clearStale(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("control: %s exists and is not a socket, so it is not this daemon's to remove", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("control: removing the stale socket: %w", err)
	}
	return nil
}

// ownedListener ties the lock to the socket. Closing unlinks the socket first
// and releases the lock after, so the path is never free for another daemon to
// bind while this one is still unlinking.
type ownedListener struct {
	net.Listener
	lock *os.File
}

func (l *ownedListener) Close() error {
	return errors.Join(l.Listener.Close(), l.lock.Close())
}

// Handler serves src. Every answer is built whole before anything reaches the
// socket, JSON and the scrape alike, because a slow reader must not be able to
// hold the dataplane's lock open.
//
// The reads are always served. The writes are served when src also implements
// [Sink], and refused by name when it does not, rather than answering 404 on a
// path this build does have.
func Handler(src Source) http.Handler {
	mux := http.NewServeMux()
	answer(mux, PathStatus, func() any { return src.Status() })
	answer(mux, PathNeighbors, func() any { return src.Neighbors() })
	answer(mux, PathRoutes, func() any { return src.Routes() })
	answer(mux, PathSessions, func() any { return src.Sessions() })
	answer(mux, PathPeers, func() any { return src.Peers() })
	scrape(mux, PathMetrics, src)
	sink, _ := src.(Sink)
	act(mux, PathDisable, sink, func(s Sink, r Request) (Result, error) { return s.SetSubsystem(r.Subsystem, false) })
	act(mux, PathEnable, sink, func(s Sink, r Request) (Result, error) { return s.SetSubsystem(r.Subsystem, true) })
	act(mux, PathRedial, sink, func(s Sink, r Request) (Result, error) { return s.Redial(r.Peer) })
	act(mux, PathRekey, sink, func(s Sink, r Request) (Result, error) { return s.Rekey(r.Peer, r.All) })
	act(mux, PathReload, sink, func(s Sink, r Request) (Result, error) { return s.Reload() })
	return mux
}

// answer registers one read. The method check is explicit rather than implied
// by there being nothing on this path to write: a POST that falls through to a
// reader looks like a write that succeeded.
func answer(mux *http.ServeMux, path string, read func() any) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "this is a read, so it takes a GET", http.StatusMethodNotAllowed)
			return
		}
		body, err := json.Marshal(read())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(append(body, '\n'))
	})
}

// scrape registers the one read that is not JSON. A scrape belongs on this
// socket because a node nobody can ask is a node nobody can diagnose, and
// binding a port to read one's own counters is a listener a fleet then has to
// firewall. The render goes into a buffer before anything reaches the socket,
// for the reason [Source] gives.
func scrape(mux *http.ServeMux, path string, src Source) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "this is a read, so it takes a GET", http.StatusMethodNotAllowed)
			return
		}
		var body bytes.Buffer
		src.Metrics(&body)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Write(body.Bytes())
	})
}

// maxRequest bounds a write's body. A [Request] is four short fields, so
// anything near this is a client that has lost track of what it is sending and
// should be told rather than allocated for.
const maxRequest = 64 << 10

// act registers one write.
//
// POST rather than GET, and the method carries the whole separation between
// the two halves of this surface: a reader that reaches one of these paths
// with a GET is refused instead of acting, and none of the reads answers
// anything but GET and HEAD. POST rather than PUT because none of the verbs is
// idempotent, a second rekey being a second exchange rather than the same one
// restated.
//
// The authorization story is the socket's mode and stays that way: nothing
// here inspects a credential, because every verb acts on state the node's own
// file already decides. See the package doc for the line that keeps a verb
// from needing one.
func act(mux *http.ServeMux, path string, sink Sink, run func(Sink, Request) (Result, error)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "this is a write, so it takes a POST", http.StatusMethodNotAllowed)
			return
		}
		if sink == nil {
			http.Error(w, "this node serves the reads only, so there is nothing here to ask", http.StatusNotImplemented)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequest))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var request Request
		// An empty body is the zero request rather than a decode failure, so
		// reload, which reads no field, is asked with nothing at all.
		if len(body) > 0 {
			if err := json.Unmarshal(body, &request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		result, err := run(sink, request)
		if err != nil {
			// The caller named something this node does not run, which is a
			// request to correct rather than a failure on this side.
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		answered, err := json.Marshal(result)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(append(answered, '\n'))
	})
}

// maxConnections bounds how many connections are open at once. A diagnostic
// makes one request and exits, so a client past a handful is one accumulating
// them, and each costs the daemon a goroutine and a descriptor. Running out of
// descriptors is how a node stops being able to answer at all, which is the
// one thing this socket exists to prevent.
const maxConnections = 32

// Serve runs the control surface on listener until it is closed. It returns
// nil for an ordinary close so a caller can tell a shutdown from a failure.
func Serve(listener net.Listener, src Source) error {
	server := newServer(src)
	err := server.Serve(&boundedListener{Listener: listener, places: make(chan struct{}, maxConnections)})
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// newServer is the configured server, apart so that a test can assert on the
// bounds rather than wait out the ones a live node needs.
func newServer(src Source) *http.Server {
	return &http.Server{
		Handler: Handler(src),
		// A unix socket has no network in front of it, so these bound a local
		// client that stops reading rather than an attacker.
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		// A connection that finished a request and went quiet is bounded by
		// this and by nothing else. net/http clears the read deadline between
		// requests and starts ReadHeaderTimeout only once the next request's
		// first byte has arrived, so without this a client holds a goroutine
		// and a descriptor for as long as it likes.
		IdleTimeout: 30 * time.Second,
	}
}

// boundedListener hands out at most cap(places) connections at a time and
// closes the rest as it accepts them.
//
// Closing rather than waiting for a place keeps the accept loop answering
// its own listener: waiting for one would park this goroutine on a
// channel that closing the listener does not wake, so a client holding every
// place would hold up the shutdown for as long as the idle timeout. It is also
// the better answer to give, since a diagnostic that is refused says so at
// once where one that waits looks like a node that has stopped responding.
type boundedListener struct {
	net.Listener
	places chan struct{}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.places <- struct{}{}:
			return &boundedConn{Conn: conn, places: l.places}, nil
		default:
			conn.Close()
		}
	}
}

type boundedConn struct {
	net.Conn
	places chan struct{}
	closed sync.Once
}

func (c *boundedConn) Close() error {
	err := c.Conn.Close()
	c.closed.Do(func() { <-c.places })
	return err
}
