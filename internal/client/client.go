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
	"sync/atomic"
	"time"

	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/control"
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
	underlay   atomic.Pointer[[]netip.Addr]
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
	// dialRetry overrides defaultReconnectDelay; zero means the default.
	dialRetry time.Duration
	// stopped closes the door on new dialers. Run sets it under dialersMu
	// before waiting, so a reload arriving at the same moment cannot add to
	// the WaitGroup after the wait has begun, which panics.
	stopped bool
	peers   sync.WaitGroup

	// regReadAt is when the registry now installed was read, in unix
	// nanoseconds, so a diagnostic can tell a registry that reloaded from one
	// that has been the same since startup.
	regReadAt atomic.Int64
	// kernelStatus is the route reconciler's own view, supplied by the command
	// that built it. Nil until then, and nil forever on a node whose routes
	// are configured externally.
	kernelStatus atomic.Pointer[func() control.KernelStatus]

	inboundPackets atomic.Uint64
	inboundDropped atomic.Uint64
	// dropReported is nanoseconds since started, read through time.Since so it
	// comes off the monotonic clock, and primed one interval in the past so
	// the first refused batch is still said out loud. See noteInboundDropped.
	dropReported atomic.Int64
	started      time.Time
}

func (c *Client) config() *config.Config      { return c.cfg.Load() }
func (c *Client) registry() registry.Registry { return *c.reg.Load() }

// storeRegistry installs a registry and the underlay set derived from it.
// Nothing reads both, so the two need no common pointer: a reconciler asking
// between the stores gets the previous addresses and asks again next pass.
func (c *Client) storeRegistry(reg registry.Registry) {
	addresses := underlayAddrs(reg)
	c.reg.Store(&reg)
	c.underlay.Store(&addresses)
	c.regReadAt.Store(time.Now().UnixNano())
}

// Underlay is every endpoint address in the registry this node could have to
// reach, which the route reconciler consults so that a route covering one is
// not installed where the transport would then follow it into its own tunnel.
// A hostname endpoint is not in it, because resolving one is a network call.
func (c *Client) Underlay() []netip.Addr {
	if addresses := c.underlay.Load(); addresses != nil {
		return *addresses
	}
	return nil
}

// underlayAddrs takes the literals out of every endpoint a dialer would accept,
// so the set and the dialers agree on what this node may have to reach.
func underlayAddrs(reg registry.Registry) []netip.Addr {
	var out []netip.Addr
	for _, organization := range reg {
		for _, node := range organization.Nodes {
			for _, endpoint := range node.Endpoints {
				if !endpoint.Dialable() {
					continue
				}
				if address, err := netip.ParseAddr(*endpoint.Address); err == nil {
					out = append(out, address)
				}
			}
		}
	}
	return out
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
	warnUnforwardableTransit(cfg)
	// Before the tun exists, so a segment this node could not answer for
	// refuses the startup without a device to clean up.
	segments, err := localSegments(cfg)
	if err != nil {
		return nil, err
	}
	mesh, err := netstack.NewNamed(0, cfg.TUN)
	if err != nil {
		return nil, err
	}
	mesh.SetSegments(segments)
	defer func() {
		if err != nil {
			mesh.Close()
		}
	}()
	return newClient(cfg, privateKey, reg, mesh)
}

// newClient is New with the loading done, so a test can stand up a client
// around a mesh it built itself rather than a privileged TUN.
func newClient(cfg *config.Config, privateKey ed25519.PrivateKey, reg registry.Registry, mesh *netstack.Mesh) (_ *Client, err error) {
	hub, err := transport.NewHub(fmt.Sprintf(":%d", cfg.Port), cfg.FWMark)
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
		started: time.Now(),
	}
	c.dropReported.Store(-int64(espDropReportInterval))
	c.cfg.Store(cfg)
	c.storeRegistry(reg)
	return c, nil
}

// Run is called once. It returns only after peer handshakes, IKE sessions, ESP
// workers and Babel timers have stopped, including cancellation during dialing.
func (c *Client) Run(ctx context.Context) error {
	// Tell every peer before the sessions go, rather than leaving each of them
	// sending ESP into an SPI we no longer accept until its own dead peer
	// detection expires. It runs before c.cancel because a canceled session
	// has no loop left to carry the Delete.
	stop := context.AfterFunc(ctx, func() {
		c.stopDialers()
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
	// Canceled before the hub closes, so a dialer reads the session ending as
	// this node stopping. See stopping.
	c.cancel()
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

// stopping lets a dialer tell this node going down from a peer worth retrying.
// The context does not: closeAll runs before c.cancel, deliberately, so a
// Delete still has a loop to carry it, and every dialer whose session ends in
// that window would otherwise say "reconnecting in 10s" at the one moment none
// of them will.
func (c *Client) stopping() bool {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	return c.stopped
}
