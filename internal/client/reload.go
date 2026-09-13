package client

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/netip"
	"reflect"
	"slices"
	"time"

	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/internal/registry"
)

// peerPath names one dialer, and is the same name the session it establishes is
// adopted under, so a reload can reason about both with one key.
// The serial number is part of the name because it selects which of the peer's
// endpoints we dial. Leaving it out made a reload that repointed a peer look
// like no change at all, and report success while the old dialer kept using
// the value it captured at startup.
func peerPath(peer config.Peer, local config.Endpoint) string {
	return fmt.Sprintf("%s/%s/%s@%s", peer.Organization, peer.CommonName, peer.SerialNumber, local.SerialNumber)
}

// syncPeers starts a dialer for every (local endpoint, peer) pair the current
// configuration names and stops the ones it no longer does. Stopping one
// cancels its context, which ends the session it holds.
//
// It runs once at startup and again on every reload, so a node joining or
// leaving the mesh costs one dialer rather than a restart, which would drop
// every SA on this node.
func (c *Client) syncPeers() {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	// Read inside the lock. Two calls can be in flight, since Run makes one at
	// startup and every SIGHUP makes another, and a set computed before the
	// lock is a set that may already be stale when it is installed: the later
	// caller would then cancel every dialer the earlier one started and
	// nothing would run again to correct it.
	cfg := c.config()
	peers := effectivePeers(cfg, c.registry())
	wanted := make(map[string]struct{}, len(cfg.Endpoints)*len(peers))
	if c.stopped || c.ctx.Err() != nil {
		return
	}
	for _, local := range cfg.Endpoints {
		for _, peer := range peers {
			path := peerPath(peer, local)
			wanted[path] = struct{}{}
			if _, running := c.dialers[path]; running {
				continue
			}
			ctx, cancel := context.WithCancel(c.ctx)
			running := &dialer{cancel: cancel}
			c.dialers[path] = running
			c.peers.Go(func() {
				defer cancel()
				// A dialer that gives up on its own, because the registry does
				// not name the node yet, has to leave the map or the entry
				// says "running" forever and every later reload skips it. The
				// registry is rewritten whenever any node joins, so a peer
				// briefly absent from it is ordinary.
				defer c.forgetDialer(path, running)
				c.runPeer(ctx, local, peer)
			})
		}
	}
	for path, running := range c.dialers {
		if _, keep := wanted[path]; keep {
			continue
		}
		log.Printf("peer %s: no longer configured", path)
		running.cancel()
		delete(c.dialers, path)
	}
}

// Reload re-reads the configuration and the registry and applies what can be
// applied without dropping the tunnels this node is carrying: the registry
// itself, the peers we dial, and the prefixes we originate. ranet reconciles
// the same way rather than restarting, and it matters here because the
// registry is rewritten every time any node joins the mesh.
//
// Everything a reload cannot reach is refused rather than applied, because
// each such change alters what peers have already authenticated or
// what the dataplane is attached to, so a restart is the honest way to change
// them and a half-applied reload would be worse than none.
// registryPath and privateKeyPath are the command line's, repeated here
// because the file may name neither: ranet's own config has nowhere to put
// them, and a node started that way would otherwise fail every reload it ever
// saw. fullMesh is repeated for the same reason. The registry is rewritten whenever any node joins the mesh, so that is
// every reload that matters.
func (c *Client) Reload(path, registryPath, privateKeyPath string, fullMesh bool) error {
	cfg, err := config.Load(path, registryPath, privateKeyPath, fullMesh)
	if err != nil {
		return err
	}
	reg, err := registry.Load(cfg.Registry)
	if err != nil {
		return err
	}
	if err := c.sameIdentityKey(cfg.PrivateKey); err != nil {
		return err
	}
	families, err := validateLocalConfig(cfg, c.privateKey, reg)
	if err != nil {
		return err
	}
	if err := reloadable(c.config(), cfg); err != nil {
		return err
	}
	// A peer the registry cannot support is reported and skipped rather than
	// refused. The two drift, so one entry left behind by a decommissioned
	// node would otherwise freeze every later reload on this node: the
	// registry every other peer needs would never be applied, over a peer that
	// is unreachable whatever happens here. The dialer already gives up on a
	// node the registry does not name and is started again by the next
	// reload.
	// Both halves are advisory here, but appending one to the other would
	// write into whichever backing array had the room.
	refuse, skip := validatePeers(cfg, reg, families)
	for _, problems := range [][]error{refuse, skip} {
		for _, problem := range problems {
			log.Printf("reload: %v, so nothing will dial it", problem)
		}
	}

	c.storeRegistry(reg)
	c.cfg.Store(cfg)
	// The registry decides who may connect, so it decides who may stay. A node
	// taken out of it keeps every tunnel it already holds until somebody says
	// otherwise, and this is the only moment anybody does.
	for _, path := range c.sessions.revoke(c.stillTrusted) {
		log.Printf("reload: %s is no longer in the registry, session closed", path)
	}
	originated, err := originatedRoutes(cfg)
	if err != nil {
		return err
	}
	c.speaker.SetOriginated(originated)
	c.syncPeers()
	nodes := 0
	for _, organization := range reg {
		nodes += len(organization.Nodes)
	}
	log.Printf("reloaded %s: %d peers, %d nodes in the registry", path, len(effectivePeers(cfg, reg)), nodes)
	return nil
}

// sameIdentityKey refuses a reload that would change the key this node signs
// with. LoadPrivateKey runs once, in New, and the responder captured the
// result when Run built it, so a new key here would reach the dialers and
// leave every accepted session signing with the old one. The file is read
// rather than the path compared, because a rotation is staged by writing the
// new key where the old one was.
func (c *Client) sameIdentityKey(path string) error {
	key, err := registry.LoadPrivateKey(path)
	if err != nil {
		return err
	}
	if !key.Public().(ed25519.PublicKey).Equal(c.privateKey.Public()) {
		return fmt.Errorf("config: private key changed, restart to apply")
	}
	return nil
}

// reloadable reports why a change cannot be applied in place, or nil.
func reloadable(old, next *config.Config) error {
	switch {
	case old.Organization != next.Organization || old.CommonName != next.CommonName:
		return fmt.Errorf("config: identity changed, restart to apply")
	case old.FWMark != next.FWMark:
		// The mark is set on the one socket when it is opened, so a change
		// here would be read back from the file and reach nothing.
		return fmt.Errorf("config: fwmark changed, restart to apply")
	case old.Port != next.Port:
		return fmt.Errorf("config: port changed, restart to apply")
	case old.TUN != next.TUN:
		return fmt.Errorf("config: tun device changed, restart to apply")
	case old.Responder != next.Responder:
		// acceptPeers is started once by Run, so turning the responder on or
		// off here would report success and change nothing.
		return fmt.Errorf("config: responder changed, restart to apply")
	case !sameEndpoints(old.Endpoints, next.Endpoints):
		// The responder answers to one identity per local endpoint and builds
		// that set once, and each endpoint runs its own dialers.
		return fmt.Errorf("config: local endpoints changed, restart to apply")
	case !sameBabelSettings(old.Babel, next.Babel):
		// The speaker is built once, so a changed interval or cost would be
		// read back from the file and never reach it. Refusing says so instead
		// of reporting a reload that did nothing. Originate is the exception:
		// SetOriginated applies it, and it is the field an exit changes.
		return fmt.Errorf("config: babel settings changed, restart to apply")
	case !sameKernelSettings(old.Kernel, next.Kernel) || !sameKernelAddresses(old, next):
		// The reconciler is configured once in main, including the addresses
		// assign_originated expands into, so none of this block can be applied
		// here.
		return fmt.Errorf("config: kernel settings changed, restart to apply")
	case !sameRekeySettings(old, next):
		// Accepted sessions take these from the responder built at startup, so
		// applying them to newly dialed sessions alone would leave the node
		// running two different policies at once.
		return fmt.Errorf("config: rekey or replay settings changed, restart to apply")
	}
	return nil
}

// sameKernelSettings compares the reconciler block, which is read once at
// startup, by what it was given rather than by how the file was written. An
// omitted list and an empty one mean the same thing, and so do an omitted
// interval and one written out as its own default; comparing them as written
// refuses a reload that changes nothing, which writing "reconcile_interval:
// 30s" into the file would have been enough to cause.
func sameKernelSettings(old, next config.Kernel) bool {
	normalize := func(k *config.Kernel) {
		if len(k.Addresses) == 0 {
			k.Addresses = nil
		}
		interval := kernel.DefaultReconcileInterval
		if k.ReconcileInterval != nil {
			interval = time.Duration(*k.ReconcileInterval)
		}
		effective := config.Duration(interval)
		k.ReconcileInterval = &effective
	}
	normalize(&old)
	normalize(&next)
	return reflect.DeepEqual(old, next)
}

func sameKernelAddresses(old, next *config.Config) bool {
	if !old.Kernel.Enabled || !old.Kernel.AssignOriginated {
		return true
	}
	before, err := old.KernelAddresses()
	if err != nil {
		return false
	}
	after, err := next.KernelAddresses()
	if err != nil {
		return false
	}
	compare := func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return a.Bits() - b.Bits()
	}
	slices.SortFunc(before, compare)
	slices.SortFunc(after, compare)
	return slices.Equal(before, after)
}

// sameBabelSettings compares everything in the babel block that a reload
// cannot apply, which is everything except the originated prefixes. The
// comparison is on the speaker each one would run rather than on the fields as
// written: an omitted cost or interval and one spelled out as its own default
// are the same speaker, and comparing them as written refuses a reload that
// changes nothing. The intervals default inside babel rather than in
// SpeakerConfig, so WithDefaults is where the two spellings meet.
func sameBabelSettings(old, next config.Babel) bool {
	return old.SpeakerConfig().WithDefaults() == next.SpeakerConfig().WithDefaults()
}

// sameRekeySettings compares the timers and the replay window that a session
// captures when it is created.
func sameRekeySettings(old, next *config.Config) bool {
	return old.ChildRekeyIntervalValue() == next.ChildRekeyIntervalValue() &&
		old.IKERekeyIntervalValue() == next.IKERekeyIntervalValue() &&
		old.RekeyMarginValue() == next.RekeyMarginValue() &&
		old.RekeyJitterValue() == next.RekeyJitterValue() &&
		old.RekeyRetryInitialValue() == next.RekeyRetryInitialValue() &&
		old.RekeyRetryMaxValue() == next.RekeyRetryMaxValue() &&
		old.ReplayWindowSize() == next.ReplayWindowSize()
}

func sameEndpoints(old, next []config.Endpoint) bool {
	if len(old) != len(next) {
		return false
	}
	for i := range old {
		// Only what this node runs on. An Endpoint also carries ranet's own
		// fields: the port and the mark are compared at the top level, having
		// been adopted into it, and the address and the updown path change
		// nothing here, so refusing a reload over one would force a restart
		// for a field that was never read.
		if old[i].SerialNumber != next[i].SerialNumber || old[i].AddressFamily != next[i].AddressFamily {
			return false
		}
	}
	return true
}

// originatedRoutes is every announcement the configuration asks for, the plain
// list and the source-specific one together. The parse is reported rather than
// skipped: a caller that built a Config by hand has not been through Load.
func originatedRoutes(cfg *config.Config) ([]babel.OriginatedRoute, error) {
	routes := make([]babel.OriginatedRoute, 0, len(cfg.Originate)+len(cfg.Babel.Originate))
	for _, raw := range cfg.Originate {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("config: originate %q: %w", raw, err)
		}
		routes = append(routes, babel.OriginatedRoute{Destination: prefix})
	}
	for _, entry := range cfg.Babel.Originate {
		routes = append(routes, babel.OriginatedRoute{Destination: entry.Prefix, Source: entry.From})
	}
	return routes, nil
}

// forgetDialer drops a dialer that ended by itself, and only if the map still
// holds this one, so a dialer stopped and immediately restarted by a reload
// cannot delete its own replacement.
func (c *Client) forgetDialer(path string, running *dialer) {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	if c.dialers[path] == running {
		delete(c.dialers, path)
	}
}
