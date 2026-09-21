package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// Client reads one daemon's control socket. It is the other half of Handler,
// in the same package so the two cannot drift apart on a field name.
type Client struct {
	path string
	http *http.Client
}

// Dial prepares a client. Nothing is opened until a read, so a command that
// only prints its usage never touches the socket.
func Dial(path string) *Client {
	return &Client{
		path: path,
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", path)
				},
			},
		},
	}
}

func (c *Client) Path() string { return c.path }

// Status, Neighbors, Routes, Sessions and Peers each read one path. They are
// written out rather than generated so that the type a caller gets is the type
// the compiler checked.
func (c *Client) Status() (Status, error) { return read[Status](c, PathStatus) }

func (c *Client) Neighbors() ([]Neighbor, error) { return read[[]Neighbor](c, PathNeighbors) }

func (c *Client) Routes() ([]Route, error) { return read[[]Route](c, PathRoutes) }

func (c *Client) Sessions() ([]Session, error) { return read[[]Session](c, PathSessions) }

func (c *Client) Peers() ([]Peer, error) { return read[[]Peer](c, PathPeers) }

// read fetches and decodes one path. A body is bounded, because a client
// reading a daemon it cannot verify still should not be made to allocate
// without limit.
func read[T any](c *Client, path string) (T, error) {
	var out T
	response, err := c.http.Get("http://control" + path)
	if err != nil {
		return out, c.explain(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		return out, fmt.Errorf("control: reading %s: %w", path, err)
	}
	if response.StatusCode != http.StatusOK {
		return out, fmt.Errorf("control: %s: %s: %s", path, response.Status, trimLine(body))
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("control: decoding %s: %w", path, err)
	}
	return out, nil
}

// explain turns a dial failure into the sentence an operator can act on. The
// two that happen are a socket that was never created and one left behind by a
// daemon that is gone, and "connect: connection refused" names neither the
// daemon nor the flag that would have created it.
func (c *Client) explain(err error) error {
	switch {
	case len(c.path) > MaxSocketPath:
		// The kernel answers a bind and a connect over the limit the same
		// way, as "invalid argument", so the reader is told what the daemon
		// would have been told rather than left with an errno.
		return fmt.Errorf("control: socket path is %d bytes, over the %d a unix socket holds: %s", len(c.path), MaxSocketPath, c.path)
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("control: no socket at %s: the daemon creates it unless it was started with -control \"\"", c.path)
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("control: nothing is listening at %s, so the daemon is not running", c.path)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("control: %s cannot be opened by this user: the socket is mode 0660 and owned by the daemon", c.path)
	}
	return fmt.Errorf("control: %w", err)
}

// trimLine keeps a server error to its first line, since http.Error appends a
// newline and a multi-line body would break the one-error-per-line rule the
// rest of the command output follows.
func trimLine(body []byte) string {
	for i, b := range body {
		if b == '\n' {
			return string(body[:i])
		}
	}
	return string(body)
}
