// Package client owns the mesh runtime: peer reconnection, IKE/ESP lifetimes,
// and Babel registration. The command only handles flags, signals and logging.
package client

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/netip"
	"runtime"
	"sync"

	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
	"github.com/NickCao/ranet-lite/internal/transport"
)

type Client struct {
	Mesh *netstack.Mesh

	cfg        *config.Config
	privateKey ed25519.PrivateKey
	registry   registry.Registry
	speaker    *babel.Speaker
	hub        *transport.Hub
	sessions   *sessionSet
	workers    int
	ctx        context.Context
	cancel     context.CancelFunc
}

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
	speaker, err := babel.New(babel.Config{
		HelloInterval: cfg.Babel.HelloInterval, UpdateInterval: cfg.Babel.UpdateInterval,
	}, mesh)
	if err != nil {
		return nil, err
	}
	for _, raw := range cfg.Originate {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("config: originate %q: %w", raw, err)
		}
		speaker.Originate(prefix)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		Mesh: mesh, cfg: cfg, privateKey: privateKey, registry: reg,
		speaker: speaker, hub: hub, sessions: newSessionSet(),
		workers: max(1, runtime.GOMAXPROCS(0)),
		ctx:     ctx, cancel: cancel,
	}, nil
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
	var peers sync.WaitGroup
	for _, local := range c.cfg.Endpoints {
		for _, peer := range c.cfg.Peers {
			peers.Go(func() { c.runPeer(c.ctx, local, peer) })
		}
	}
	if c.cfg.Responder {
		peers.Go(func() {
			if err := c.acceptPeers(c.ctx); err != nil && c.ctx.Err() == nil {
				log.Printf("responder: %v", err)
			}
		})
	}
	err := c.speaker.Run(c.ctx)
	_ = c.hub.Close()
	peers.Wait()
	return err
}

// Close is idempotent and can interrupt Run.
func (c *Client) Close() {
	c.cancel()
	_ = c.hub.Close()
	c.Mesh.Close()
}
