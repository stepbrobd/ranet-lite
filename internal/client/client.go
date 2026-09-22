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

	"github.com/NickCao/ranet-lite/control"
	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
	"github.com/NickCao/ranet-lite/srv6"
	"github.com/NickCao/ranet-lite/transport"
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
	// closeUnderlay releases whatever the transport's underlay setting had to
	// open, which on darwin is the route socket the binding follows. Nil on a
	// Client built by hand in a test.
	closeUnderlay func()
	// capture holds whatever the route reconciler needs in the kernel before
	// it hands this machine's own traffic to the mesh, nil where the platform
	// needs nothing. It lives here rather than in main because it shares the
	// link watcher the transport binds through, and the two have to agree
	// about which interface the underlay is on.
	capture kernel.CaptureRoutes
	// host is the machine the underlay and the route reconciler read and
	// write, nil for the one this process is running on. It is kept so the
	// reconciler this client hands the command is built against the same
	// machine the underlay was opened on.
	host     kernel.Host
	sessions *sessionSet
	workers  int
	ctx      context.Context
	cancel   context.CancelFunc

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
	// egressStatus and egressAnnounce are the egress capability's, supplied
	// the same way. The second is read on every republication rather than
	// captured, because an exit withholds its advertisement whenever its rule
	// is not installed and the set it may announce changes under a running
	// node.
	egressStatus   atomic.Pointer[func() control.EgressStatus]
	egressAnnounce atomic.Pointer[func() []netip.Prefix]

	// running is the control socket's write path state: whether each named
	// subsystem is acting. It is the record rather than the mechanism, since
	// each subsystem keeps its own flag where its hot path can read it. A
	// status reports this map and a second write compares against it.
	runningMu sync.Mutex
	running   map[control.Subsystem]bool
	// reconcilerEnable stops and starts the route reconciler, supplied by the
	// command that built it as SetKernelStatus is. Nil on a node with no
	// cap.table, where the verb is refused by name rather than reported as
	// having stopped something.
	reconcilerEnable atomic.Pointer[func(bool)]
	// configPath is where the daemon read this node's configuration, so the
	// reload verb re-reads the same file SIGHUP does. Empty on a client a test
	// built by hand, where the verb says so rather than guessing at a path.
	configPath atomic.Pointer[string]

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
	privateKey, err := registry.LoadPrivateKey(cfg.Auth.Key)
	if err != nil {
		return nil, err
	}
	reg, err := registry.Load(cfg.Auth.Trust)
	if err != nil {
		return nil, err
	}
	if err := validateRuntimeConfig(cfg, privateKey, reg); err != nil {
		return nil, err
	}
	warnUnforwardableTransit(cfg)
	warnVRFWithoutL3mdev(cfg)
	// Before the tun exists, so a segment this node could not answer for
	// refuses the startup without a device to clean up.
	segments, steering, err := cfg.Segments().Tables()
	if err != nil {
		return nil, err
	}
	// Every steered packet carries its segment list inside the tunnel, so the
	// device has to hand over packets small enough to still fit once it is
	// there. Taking it off the MTU is ordinary tunnel behavior, and the
	// alternative is a large packet arriving that cannot be encapsulated and
	// going out unsteered, which is a silent hole in the steering rather than
	// a smaller MSS.
	mtu, err := steeredMTU(steering)
	if err != nil {
		return nil, err
	}
	mesh, err := netstack.NewNamed(mtu, cfg.Link.TUN)
	if err != nil {
		return nil, err
	}
	mesh.SetSegments(segments)
	mesh.SetSteering(steering)
	defer func() {
		if err != nil {
			mesh.Close()
		}
	}()
	return newClient(cfg, privateKey, reg, mesh, nil)
}

// steeredMTU is the device MTU once the largest configured segment list has
// been taken off it, and zero for a node that steers nothing, which leaves the
// device's own default. The arithmetic and the refusal are the capability's
// own, and config.Validate makes the same call with the same device, so a file
// the loader took is a file this will start on.
func steeredMTU(steering *srv6.SteerTable) (int, error) {
	return steering.CheckMTU(netstack.DefaultMTU)
}

// newClient is New with the loading done, so a test can stand up a client
// around a mesh it built itself rather than a privileged TUN. host is the
// machine the underlay reads and writes, nil for the one this process is
// running on, as New passes and as a deployment gets.
func newClient(cfg *config.Config, privateKey ed25519.PrivateKey, reg registry.Registry, mesh *netstack.Mesh, host kernel.Host) (_ *Client, err error) {
	underlay, capture, closeUnderlay, err := underlayRuntime(cfg.Link.Underlay, mesh.Name, host)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			closeUnderlay()
		}
	}()
	hub, err := transport.NewHub(fmt.Sprintf(":%d", cfg.Link.Port), cfg.Link.Underlay, underlay)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = hub.Close()
		}
	}()
	// Two capabilities configure the speaker: cap.babel is the protocol's own
	// timers and cost, and cap.route the prefixes this node puts into the mesh.
	speaker, err := babel.New(cfg.Babel(), cfg.Routes(), babel.Runtime{}, mesh)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		Mesh: mesh, privateKey: privateKey,
		speaker: speaker, hub: hub, closeUnderlay: closeUnderlay, capture: capture,
		host:     host,
		sessions: newSessionSet(),
		workers:  max(1, runtime.GOMAXPROCS(0)),
		ctx:      ctx, cancel: cancel,
		dialers: make(map[string]*dialer),
		running: startedSubsystems(),
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
	if c.config().Link.Listen {
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
	if c.closeUnderlay != nil {
		c.closeUnderlay()
	}
	c.Mesh.Close()
}

// CaptureRoutes holds the routing the reconciler needs while the mesh carries
// this machine's own traffic, or nil where the platform needs nothing. The
// command that builds the reconciler hands it to kernel.Config.
func (c *Client) CaptureRoutes() kernel.CaptureRoutes { return c.capture }

// KernelRuntime is everything cap.table is handed rather than told: the device
// the mesh actually got, the addresses the transport has to keep reaching, the
// prefixes cap.route announces, and the two halves of link.underlay that only
// a running node knows. None of it is a fact an operator writes down, which is
// why none of it is in the capability.
//
// It is assembled here rather than in the command because five of the seven
// are this client's own and the other two are the settings it opened them
// under. The command builds the reconciler from it; see kernel.Runtime for
// what each field decides.
func (c *Client) KernelRuntime() kernel.Runtime {
	cfg := c.config()
	return kernel.Runtime{
		Interface: c.Mesh.Name,
		Underlay:  c.Underlay,
		Announced: cfg.Routes().Announced(),
		Sessions:  c.LiveSessions,
		// One setting decides both halves, so they cannot be set against each
		// other: the transport binds its socket off the forwarding table, and
		// the reconciler stops hiding an announced default from every socket
		// that did not ask for the tun by name.
		BoundUnderlay: cfg.Link.Underlay.Bind,
		Capture:       c.CaptureRoutes(),
		Host:          c.host,
	}
}

// LiveSessions is how many of this node's sessions have recently proved their
// peer is there. The route reconciler reads it before it hands this machine's
// own traffic to the mesh, so the answer is deliberately the narrow one: a
// session that is merely installed proves nothing, and a peer that rebooted
// leaves one looking established for over a minute.
//
// A node whose underlay socket is not where its configuration says it should
// be reports none, whatever its sessions are doing. On darwin the socket is
// bound to the interface the host's own default leaves by, and a default route
// out of the tun over an unbound socket is the tunnel inside itself that the
// binding exists to prevent.
func (c *Client) LiveSessions() int {
	if !c.hub.UnderlayReady() {
		return 0
	}
	return c.sessions.liveCount()
}

// dialer is one running peer loop. It is a pointer so an entry has an identity
// a later goroutine can compare against, which a func value cannot provide.
//
// wake cuts short the reconnect delay, and is buffered so a redial arriving
// while the loop is dialing rather than waiting is not lost and does not block
// the caller. One place is enough: two asks that land before the loop comes
// round are one attempt either way.
type dialer struct {
	cancel context.CancelFunc
	wake   chan struct{}
}

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
