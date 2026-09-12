// Package client owns the mesh runtime: peer reconnection, IKE/ESP lifetimes,
// and Babel registration. The command only handles flags, signals and logging.
package client

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
	"github.com/NickCao/ranet-lite/internal/transport"
)

type Client struct {
	Mesh *netstack.Mesh

	// cfg and reg are replaced wholesale by a reload, never mutated, so every
	// reader sees one consistent pair even while one is being installed.
	cfg        atomic.Pointer[config.Config]
	reg        atomic.Pointer[registry.Registry]
	privateKey ed25519.PrivateKey
	speaker    *babel.Speaker
	hub        *transport.Hub
	sessions   *sessionSet
	workers    int
	ctx        context.Context
	cancel     context.CancelFunc

	// dialers is one cancel per running peer loop, keyed by the same path name
	// sessions uses, so a reload can start and stop them individually.
	dialersMu sync.Mutex
	dialers   map[string]*dialer
	// stopped closes the door on new dialers. Run sets it under dialersMu
	// before waiting, so a reload arriving at the same moment cannot add to
	// the WaitGroup after the wait has begun, which panics.
	stopped bool
	peers   sync.WaitGroup
}

func (c *Client) config() *config.Config      { return c.cfg.Load() }
func (c *Client) registry() registry.Registry { return *c.reg.Load() }

func New(cfg *config.Config) (_ *Client, err error) {
	privateKey, err := registry.LoadPrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	reg, err := registry.Load(cfg.Registry)
	if err != nil {
		return nil, err
	}
	if err := validateRuntimeConfig(cfg, privateKey, reg); err != nil {
		return nil, err
	}
	mesh, err := netstack.NewNamed(0, cfg.TUN)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			mesh.Close()
		}
	}()
	hub, err := transport.NewHub(fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = hub.Close()
		}
	}()
	speaker, err := babel.New(cfg.Babel.SpeakerConfig(), mesh)
	if err != nil {
		return nil, err
	}
	// The plain list and babel.originate together. The latter carries the
	// source-specific announcements the former cannot express, which is how an
	// exit announces a default from a prefix.
	originated, err := originatedRoutes(cfg)
	if err != nil {
		return nil, err
	}
	speaker.SetOriginated(originated)
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		Mesh: mesh, privateKey: privateKey,
		speaker: speaker, hub: hub, sessions: newSessionSet(),
		workers: max(1, runtime.GOMAXPROCS(0)),
		ctx:     ctx, cancel: cancel,
		dialers: make(map[string]*dialer),
	}
	c.cfg.Store(cfg)
	c.reg.Store(&reg)
	return c, nil
}

// Run is called once. It returns only after peer handshakes, IKE sessions, ESP
// workers and Babel timers have stopped, including cancellation during dialing.
func (c *Client) Run(ctx context.Context) error {
	// Tell every peer before the sessions go, rather than leaving each of them
	// sending ESP into an SPI we no longer accept until its own dead peer
	// detection expires. It runs before c.cancel because a cancelled session
	// has no loop left to carry the Delete.
	stop := context.AfterFunc(ctx, func() {
		c.sessions.closeAll()
		c.cancel()
	})
	defer stop()
	defer c.Close()
	if ctx.Err() != nil {
		c.cancel()
	}
	c.syncPeers()
	if c.config().Responder {
		c.peers.Go(func() {
			if err := c.acceptPeers(c.ctx); err != nil && c.ctx.Err() == nil {
				log.Printf("responder: %v", err)
			}
		})
	}
	err := c.speaker.Run(c.ctx)
	_ = c.hub.Close()
	c.stopDialers()
	c.peers.Wait()
	return err
}

// Close is idempotent and can interrupt Run.
func (c *Client) Close() {
	c.cancel()
	_ = c.hub.Close()
	c.Mesh.Close()
}

// dialer is one running peer loop. It is a pointer so an entry has an identity
// a later goroutine can compare against, which a func value cannot provide.
type dialer struct{ cancel context.CancelFunc }

// stopDialers refuses any further dialer before the wait below begins. It is
// the write half of the check syncPeers makes under the same lock: without it
// a SIGHUP that reaches syncPeers as Run is shutting down can call Go on a
// WaitGroup whose counter has already reached zero and whose Wait has already
// started, which is a panic rather than a race the scheduler smooths over.
func (c *Client) stopDialers() {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	c.stopped = true
}
