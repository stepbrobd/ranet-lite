package client

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/netip"
	"reflect"
	"slices"

	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/egress"
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/internal/registry"
	"github.com/NickCao/ranet-lite/internal/schema"
	"github.com/NickCao/ranet-lite/internal/srv6"
)

// peerPath names one dialer, and is the same name the session it establishes is
// adopted under, so a reload can reason about both with one key.
// The serial number is part of the name because it selects which of the peer's
// endpoints we dial. Leaving it out made a reload that repointed a peer look
// like no change at all, and report success while the old dialer kept using
// the value it captured at startup.
func peerPath(peer config.Peer, local config.Endpoint) string {
	return fmt.Sprintf("%s/%s/%s@%s", peer.Org, peer.Name, peer.Serial, local.Serial)
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
	wanted := make(map[string]struct{}, len(cfg.Link.Endpoints)*len(peers))
	if c.stopped || c.ctx.Err() != nil {
		return
	}
	for _, local := range cfg.Link.Endpoints {
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
				// A dialer that gives up on its own, because the trust
				// document does not name the node yet, has to leave the map or
				// the entry says "running" forever and every later reload
				// skips it. The document is rewritten whenever any node joins,
				// so a peer briefly absent from it is ordinary.
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

// Reload re-reads the configuration and the trust document and applies what
// can be applied without dropping the tunnels this node is carrying: the
// document itself, the peers we dial, and the prefixes we announce. ranet
// reconciles the same way rather than restarting, and it matters here because
// the document is rewritten every time any node joins the mesh.
//
// Everything a reload cannot reach is refused rather than applied, because
// each such change alters what peers have already authenticated or what the
// dataplane is attached to, so a restart is the honest way to change them and
// a half-applied reload would be worse than none.
func (c *Client) Reload(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	reg, err := registry.Load(cfg.Auth.Trust)
	if err != nil {
		return err
	}
	if err := c.sameIdentityKey(cfg.Auth.Key); err != nil {
		return err
	}
	families, err := validateLocalConfig(cfg, c.privateKey, reg)
	if err != nil {
		return err
	}
	if err := reloadable(c.config(), cfg); err != nil {
		return err
	}
	// A peer the trust document cannot support is reported and skipped rather
	// than refused. The two drift, so one entry left behind by a decommissioned
	// node would otherwise freeze every later reload on this node: the document
	// every other peer needs would never be applied, over a peer that is
	// unreachable whatever happens here. The dialer already gives up on a node
	// the document does not name and is started again by the next reload.
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
	// The trust document decides who may connect, so it decides who may stay.
	// A node taken out of it keeps every tunnel it already holds until
	// somebody says otherwise, and this is the only moment anybody does.
	for _, path := range c.sessions.revoke(c.stillTrusted) {
		log.Printf("reload: %s is no longer in the trust document, session closed", path)
	}
	c.republish(cfg)
	c.syncPeers()
	nodes := 0
	for _, organization := range reg {
		nodes += len(organization.Nodes)
	}
	log.Printf("reloaded %s: %d peers, %d nodes in the trust document", path, len(effectivePeers(cfg, reg)), nodes)
	return nil
}

// sameIdentityKey refuses a reload that would change the key this node signs
// with. LoadPrivateKey runs once, in New, and the listener captured the
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
		return fmt.Errorf("config: auth.key changed, restart to apply")
	}
	return nil
}

// reloadable reports why a change cannot be applied in place, or nil. The
// capability is the unit: a block this node reads once at startup is compared
// whole, rather than field by field, so a capability that grows a field does
// not grow a check here as well.
func reloadable(old, next *config.Config) error {
	switch {
	case old.Node != next.Node:
		return fmt.Errorf("config: node changed, restart to apply")
	case old.Link.Mark != next.Link.Mark:
		// The mark is set on the one socket when it is opened, so a change
		// here would be read back from the file and reach nothing.
		return fmt.Errorf("config: link.mark changed, restart to apply")
	case old.Link.Port != next.Link.Port:
		return fmt.Errorf("config: link.port changed, restart to apply")
	case old.Link.TUN != next.Link.TUN:
		return fmt.Errorf("config: link.tun changed, restart to apply")
	case old.Link.Listen != next.Link.Listen:
		// acceptPeers is started once by Run, so turning the listener on or
		// off here would report success and change nothing.
		return fmt.Errorf("config: link.listen changed, restart to apply")
	case !slices.Equal(old.Link.Endpoints, next.Link.Endpoints):
		// The listener answers to one identity per local endpoint and builds
		// that set once, and each endpoint runs its own dialers.
		return fmt.Errorf("config: link.endpoints changed, restart to apply")
	case old.Babel().WithDefaults() != next.Babel().WithDefaults():
		// The speaker is built once, so a changed interval or cost would be
		// read back from the file and never reach it. Refusing says so instead
		// of reporting a reload that did nothing. The comparison is on the
		// speaker each one would run rather than on the fields as written: an
		// omitted cost and one spelled out as its own default are the same
		// speaker.
		return fmt.Errorf("config: cap.babel changed, restart to apply")
	case old.Routes().Transits() != next.Routes().Transits():
		// The announcements are the reloadable half of cap.route, and
		// SetRoutes applies them. Whether this node relays is read while a
		// packet is being built and is fixed for the speaker's life.
		return fmt.Errorf("config: cap.route transit changed, restart to apply")
	case !reflect.DeepEqual(normalize(old.Segments()), normalize(next.Segments())):
		// The table is built once, before the tun exists, and the inbound
		// path reads it without asking whether it changed. Applying a new one
		// here would leave packets already in flight acted on under the old.
		return fmt.Errorf("config: cap.segment changed, restart to apply")
	case !sameTable(old, next):
		// The reconciler is configured once in main, including the addresses
		// assign_announced expands into, so none of this block can be applied
		// here.
		return fmt.Errorf("config: cap.table changed, restart to apply")
	case !sameCrypto(old, next):
		// Accepted sessions take these from the listener built at startup, so
		// applying them to newly dialed sessions alone would leave the node
		// running two different policies at once.
		return fmt.Errorf("config: cap.crypto changed, restart to apply")
	case !sameEgress(old, next):
		// The translator is built once in main and owns the tables it created
		// under the families the old block named, so a new one applied here
		// would leave the host holding rules from a configuration nothing is
		// running any more.
		return fmt.Errorf("config: cap.egress changed, restart to apply")
	}
	return nil
}

// sameEgress compares the capability by what it was given rather than by how
// the file was written, as sameTable does: an omitted list and an empty one
// ask for the same thing, and so do an omitted sweep and one written out as
// its own default.
func sameEgress(old, next *config.Config) bool {
	normalize := func(e *egress.Egress) *egress.Egress {
		if e == nil {
			return nil
		}
		copied := *e
		if len(copied.Advertise) == 0 {
			copied.Advertise = nil
		}
		if copied.Sweep == 0 {
			copied.Sweep = schema.Duration(egress.DefaultSweep)
		}
		return &copied
	}
	return reflect.DeepEqual(normalize(old.Egress()), normalize(next.Egress()))
}

// sameCrypto compares the timers and the window a session captures when it is
// created, rather than the block as written: an omitted interval and one
// spelled out as its own default describe the same session.
func sameCrypto(old, next *config.Config) bool {
	a, b := old.Crypto(), next.Crypto()
	return a.ChildInterval() == b.ChildInterval() &&
		a.IKEInterval() == b.IKEInterval() &&
		a.Margin() == b.Margin() &&
		a.Jitter() == b.Jitter() &&
		a.RetryFirst() == b.RetryFirst() &&
		a.RetryMax() == b.RetryMax() &&
		a.ReplayWindow() == b.ReplayWindow()
}

// sameTable compares the reconciler's capability, which is read once at
// startup, by what it was given rather than by how the file was written. An
// omitted list and an empty one mean the same thing, and so do an omitted
// interval and one written out as its own default. Comparing them as written
// refuses a reload that changes nothing, which writing "reconcile = 30s" into
// the file would have been enough to cause. The addresses are compared as the
// reconciler resolves them, since assign_announced expands cap.route into
// them.
func sameTable(old, next *config.Config) bool {
	if (old.Cap.Table == nil) != (next.Cap.Table == nil) {
		return false
	}
	if old.Cap.Table == nil {
		return true
	}
	before, after := *old.Cap.Table, *next.Cap.Table
	normalizeTable(&before)
	normalizeTable(&after)
	if !reflect.DeepEqual(before, after) {
		return false
	}
	return slices.Equal(
		sortedPrefixes(old.Cap.Table.Assigned(old.Routes().Announced())),
		sortedPrefixes(next.Cap.Table.Assigned(next.Routes().Announced())))
}

// sortedPrefixes puts an address set in one order, so two of them compare as
// sets rather than as the lists two files happened to write.
func sortedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	out := slices.Clone(prefixes)
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return a.Bits() - b.Bits()
	})
	return out
}

func normalizeTable(t *kernel.Table) {
	if len(t.Addresses) == 0 {
		t.Addresses = nil
	}
	if len(t.Rules) == 0 {
		t.Rules = nil
	}
	if t.Reconcile == 0 {
		t.Reconcile = schema.Duration(kernel.DefaultReconcileInterval)
	}
}

// normalize compares the segment capability by what it was given rather than
// by how the file was written, so an omitted list and an empty one are the
// same.
func normalize(segments srv6.Segments) srv6.Segments {
	if len(segments.Local) == 0 {
		segments.Local = nil
	}
	// Cloned before the entries are touched: the struct is a shallow copy, so
	// normalizing in place would reach through the shared backing array and
	// edit the configuration this comparison is only supposed to read.
	if len(segments.Steer) == 0 {
		segments.Steer = nil
	} else {
		segments.Steer = slices.Clone(segments.Steer)
		for i := range segments.Steer {
			if len(segments.Steer[i].Via) == 0 {
				segments.Steer[i].Via = nil
			}
		}
	}
	return segments
}

// announced is every prefix this node is putting into the mesh right now: the
// ones cap.route asks for unconditionally, plus the ones cap.egress is
// currently willing to stand behind. The second set is read from the
// translator on every call rather than from the file, because an exit withholds
// a prefix whose rule is not installed and that answer changes under a running
// node.
func (c *Client) announced(cfg *config.Config) []babel.OriginatedRoute {
	routes := cfg.Routes().Originated()
	for _, prefix := range c.egressAdvertised() {
		routes = append(routes, babel.OriginatedRoute{Destination: prefix})
	}
	return routes
}

// SetEgressAnnounce hands the runtime cap.egress's own view of what it may
// advertise. See announced.
func (c *Client) SetEgressAnnounce(read func() []netip.Prefix) {
	c.egressAnnounce.Store(&read)
}

func (c *Client) egressAdvertised() []netip.Prefix {
	if read := c.egressAnnounce.Load(); read != nil {
		return (*read)()
	}
	return nil
}

// Republish rebuilds the announcement set and hands it to the speaker.
// cap.egress calls it whenever the prefixes it may advertise change, which is
// how an exit whose rule stopped being installed retracts rather than going on
// attracting traffic it would have to drop.
func (c *Client) Republish() { c.republish(c.config()) }

func (c *Client) republish(cfg *config.Config) {
	c.speaker.SetOriginated(c.announced(cfg))
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
