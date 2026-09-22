//go:build darwin && !ios

package client

import (
	"errors"
	"testing"

	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/transport"
)

// noLinks is a host with no default route, the state a laptop is in for the
// first seconds after it wakes and for as long as it sits between two
// networks.
type noLinks struct{ signal chan struct{} }

func (noLinks) DefaultInterface() (int, error) { return 0, errors.New("no default route") }
func (l noLinks) Changed() <-chan struct{}     { return l.signal }

// A node configured to bind its underlay socket and unable to is a node whose
// sessions must not count, whatever they are doing. The reconciler installs a
// real default out of the tun once a session is live, and over a socket that
// is still following the forwarding table that default carries this node's own
// ESP into the tunnel the ESP is carrying.
func TestLiveSessionsCountsNothingWhileTheUnderlayIsNotBound(t *testing.T) {
	hub, err := transport.NewHub(":0", transport.Underlay{Bind: true},
		transport.Runtime{Links: noLinks{signal: make(chan struct{})}})
	if err != nil {
		t.Fatalf("a hub on a host with no default route was refused: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	c := &Client{hub: hub, sessions: newSessionSet()}
	c.sessions.active = func(*ike.Session) bool { return true }
	if _, adopted := c.sessions.adoptPreferred("example/gateway/0@0", &ike.Session{}, true, nil); !adopted {
		t.Fatal("the session was not adopted")
	}
	if got := c.LiveSessions(); got != 0 {
		t.Errorf("a live session over an unbound underlay counted %d, want 0", got)
	}
}
