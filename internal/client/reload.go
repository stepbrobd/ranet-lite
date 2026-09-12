package client

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"reflect"

	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
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
	cfg := c.config()
	wanted := make(map[string]struct{}, len(cfg.Endpoints)*len(cfg.Peers))
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	if c.stopped || c.ctx.Err() != nil {
		return
	}
	for _, local := range cfg.Endpoints {
		for _, peer := range cfg.Peers {
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
func (c *Client) Reload(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	reg, err := registry.Load(cfg.Registry)
	if err != nil {
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
	// refused. The registry is rewritten every time any node joins the mesh
	// while the peers list is local and edited by hand, so one entry left
	// behind by a decommissioned node would otherwise freeze every later
	// reload on this node: the registry every other peer needs would never be
	// applied, over a peer that is unreachable whatever happens here. The
	// dialer already gives up on a node the registry does not name and is
	// started again by the next reload.
	for _, problem := range validatePeers(cfg, reg, families) {
		log.Printf("reload: %v, skipping it", problem)
	}

	c.reg.Store(&reg)
	c.cfg.Store(cfg)
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
	log.Printf("reloaded %s: %d peers, %d nodes in the registry", path, len(cfg.Peers), nodes)
	return nil
}

// reloadable reports why a change cannot be applied in place, or nil.
func reloadable(old, next *config.Config) error {
	switch {
	case old.Organization != next.Organization || old.CommonName != next.CommonName:
		return fmt.Errorf("config: identity changed, restart to apply")
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
	case !sameKernelSettings(old.Kernel, next.Kernel):
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
// startup. An omitted list and an empty one mean the same thing, and
// reflect.DeepEqual does not, so they are normalized first: refusing a reload
// over "addresses: []" against no key at all would be a refusal over nothing.
func sameKernelSettings(old, next config.Kernel) bool {
	normalize := func(k *config.Kernel) {
		if len(k.Addresses) == 0 {
			k.Addresses = nil
		}
	}
	normalize(&old)
	normalize(&next)
	return reflect.DeepEqual(old, next)
}

// sameBabelSettings compares everything in the babel block that a reload
// cannot apply, which is everything except the originated prefixes.
func sameBabelSettings(old, next config.Babel) bool {
	old.Originate, next.Originate = nil, nil
	return reflect.DeepEqual(old, next)
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
		if old[i] != next[i] {
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
