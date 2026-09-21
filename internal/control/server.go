package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// maxSocketPath is the shortest of the platform limits this tree builds for:
// linux allows 108 bytes in sun_path and darwin 104, both including the
// terminator. Binding a longer one fails as "invalid argument", which names
// neither the path nor the limit, so the check is here instead.
const maxSocketPath = 103

// socketMode is the permission the socket is left at. Group readable rather
// than owner only, so an operator in the daemon's group runs the subcommands
// without root. Nothing here writes, so read access is the whole grant.
const socketMode = 0o660

// Listen binds the control socket at path, creating its parent directory and
// clearing a socket a previous instance left behind.
//
// A stale socket is removed only when it is a socket and nothing answers on
// it. A path that is an ordinary file, or one a live daemon is already
// listening on, is refused by name: removing either would take something away
// from whoever put it there, and a second daemon silently stealing the first
// one's socket is worse than failing to start.
func Listen(path string) (net.Listener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("control: socket path is %d bytes, over the %d a unix socket holds: %s", len(path), maxSocketPath, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if err := clearStale(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	// After the bind rather than through a umask: the umask is the process's
	// and belongs to whoever started it, and a socket left at 0755 by one is a
	// socket the group cannot read.
	if err := os.Chmod(path, socketMode); err != nil {
		listener.Close()
		return nil, fmt.Errorf("control: %w", err)
	}
	return listener, nil
}

// clearStale removes a socket no daemon is listening on, and refuses anything
// else at that path.
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
	// A refused connection is the definition of stale here: a live daemon
	// accepts, and an abandoned inode does not. Any other error is reported
	// rather than treated as an invitation to unlink.
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		conn.Close()
		return fmt.Errorf("control: another daemon is already listening on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("control: removing the stale socket: %w", err)
	}
	return nil
}

// Handler serves src. Every route is a GET returning JSON, and the answer is
// built and encoded outside whatever lock src took, because a slow reader must
// not be able to hold the dataplane's lock open.
func Handler(src Source) http.Handler {
	mux := http.NewServeMux()
	answer(mux, PathStatus, func() any { return src.Status() })
	answer(mux, PathNeighbors, func() any { return src.Neighbors() })
	answer(mux, PathRoutes, func() any { return src.Routes() })
	answer(mux, PathSessions, func() any { return src.Sessions() })
	answer(mux, PathPeers, func() any { return src.Peers() })
	return mux
}

// answer registers one read. The method check is explicit rather than implied
// by there being nothing to write: a POST that falls through to a reader looks
// like a write that succeeded.
func answer(mux *http.ServeMux, path string, read func() any) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "the control socket is read-only", http.StatusMethodNotAllowed)
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

// Serve runs the control surface on listener until it is closed. It returns
// nil for an ordinary close so a caller can tell a shutdown from a failure.
func Serve(listener net.Listener, src Source) error {
	server := &http.Server{
		Handler: Handler(src),
		// A unix socket has no network in front of it, so these bound a local
		// client that stops reading rather than an attacker.
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}
