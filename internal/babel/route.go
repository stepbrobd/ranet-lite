package babel

import (
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"time"
)

// An invalid source denotes an ordinary route. Source-specific routes are
// independent entries, resolved by destination first at the forwarding table.
type routeKey struct {
	source netip.Prefix
	dest   netip.Prefix
}

// advertisement is the (router-id, seqno, metric) triple an Update TLV carries
// for one prefix, RFC 8966 section 3.7.
type advertisement struct {
	routerID [8]byte
	seqno    uint16
	metric   uint16
}

// routeInfo is one route table entry, RFC 8966 section 3.2.6, indexed by
// (routeKey, neighbor). rxMetric is the metric the neighbor advertised, the
// one the feasibility condition compares; the link cost is added only when
// computing this route's own metric.
type routeInfo struct {
	routerID  [8]byte
	seqno     uint16
	rxMetric  uint16
	hold      time.Duration
	expiresAt time.Time
	// smoothed is ms(R) of RFC 8966 Appendix A.3. It only damps selection and
	// is never advertised.
	smoothed   float64
	smoothedAt time.Time
}

// A selection is a value, independent of mutable candidate and neighbor state.
type routeSelection struct {
	neighbor *neighborState
	cost     uint16
	routerID [8]byte
	seqno    uint16
}

type keyEntry struct {
	routes   map[*neighborState]*routeInfo
	selected routeSelection
	// The origin of the last selected route, so a withdrawal can be advertised
	// as an explicit retraction instead of going silent.
	retractID    [8]byte
	retractSeqno uint16
}

// maxRouteKeys caps how many distinct prefixes this node will hold at once.
// It is well above any plausible mesh: the fleet announces two prefixes from
// sixteen nodes, and a full internet table is not something a Babel mesh
// carries. It exists so the number is ours rather than a peer's.
const maxRouteKeys = 16384

// starveRequest is one seqno request the route table wants sent, RFC 8966
// sections 3.8.2.1 and 3.8.2.2. The Speaker owns transmission and duplicate
// suppression.
type starveRequest struct {
	key      routeKey
	neighbor *neighborState
	routerID [8]byte
	seqno    uint16
}

// Speaker.mu owns the route table, the source table AND forwarding-table
// publication. No selection may escape that critical section and later
// overwrite a newer one.
//
// Selected routes are re-advertised, so this is no longer the loop-free-by-
// construction stub of RFC 8966 Appendix E: the feasibility condition in
// source.go keeps the mesh loop free, and every advertisement this node
// sends must pass through observe.
type routeTable struct {
	entries map[routeKey]*keyEntry
	sources map[sourceKey]*sourceEntry
	// retracted is the neighbors whose routes are all at infinity already, so
	// a repeated wildcard retraction costs a map lookup rather than a walk of
	// the whole table. Bounded by the neighbor count, and cleared wherever one
	// advertises a finite metric again.
	retracted map[*neighborState]bool
	// originsPerKey is how many distinct origins each prefix has spent of
	// maxOriginsPerPrefix, so one prefix cannot fill the whole source table.
	originsPerKey map[routeKey]int
	// originsBy is one neighbor's share of that, and sourcesByPeer its share
	// of the whole table. See maxOriginsPerPrefixPerNeighbor.
	originsBy     map[originShare]int
	sourcesByPeer map[string]int
	// dirty collects keys whose advertisement changed, for the triggered
	// updates of RFC 8966 section 3.7.2; starved collects seqno requests.
	// Both are drained by the Speaker, which owns all transmission.
	dirty   map[routeKey]struct{}
	starved []starveRequest
	// tau is the hysteresis time constant of Appendix A.3. Zero disables
	// hysteresis, leaving plain lowest-metric selection. trigger is how much
	// worse a selected route must get before it is worth a triggered update.
	tau     time.Duration
	trigger uint16
	// cost carries the round-trip parameters into selection, since RFC 9616
	// section 4.2 feeds its penalty to the metric computation a node runs on
	// its own routes rather than to what it advertises.
	cost    CostParams
	install func(routeKey, routeSelection)
	// forget drops the forwarding entry entirely, ending the
	// unreachable hold install leaves behind for a retracted prefix.
	forget func(routeKey)
	// warnedOverfull keeps a refused flood from becoming a log flood, and
	// warnedOrigins does the same for the source table.
	warnedOverfull bool
	warnedOrigins  bool
	// nextExpiryAt is the earliest route.expiresAt in the table, the deadline
	// the run loop sleeps on, kept rather than recomputed: the walk that
	// derived it was one route read per route in the table, 1.8 ms at
	// maxRouteKeys prefixes over eight neighbors, paid on every pass. Only
	// ever moved earlier between sweeps, so dropping a route leaves it early
	// rather than late: one pass that finds nothing due, where late would miss
	// an expiry. sweepExpired recomputes it exactly.
	nextExpiryAt time.Time
}

func newRouteTable(install func(routeKey, routeSelection)) *routeTable {
	return &routeTable{
		entries:       make(map[routeKey]*keyEntry),
		sources:       make(map[sourceKey]*sourceEntry),
		retracted:     make(map[*neighborState]bool),
		originsPerKey: make(map[routeKey]int),
		originsBy:     make(map[originShare]int),
		sourcesByPeer: make(map[string]int),
		dirty:         make(map[routeKey]struct{}),
		install:       install,
	}
}

// update applies the route acquisition procedure of RFC 8966 section 3.5.3 to
// one advertised route and reruns selection.
func (rt *routeTable) update(n *neighborState, key routeKey, adv advertisement, hold time.Duration, now time.Time) {
	if adv.metric != MetricInfinity {
		rt.forgetRetraction(n)
	}
	feasible := rt.feasible(key, adv, n.peer.ID)
	entry := rt.entries[key]
	var route *routeInfo
	if entry != nil {
		route = entry.routes[n]
	}
	if route == nil {
		// An unfeasible update, a retraction for a route we do not know about,
		// and an update that expires on arrival all create nothing.
		if !feasible || adv.metric == MetricInfinity || hold <= 0 {
			return
		}
		if entry == nil {
			if len(rt.entries) >= maxRouteKeys {
				// A peer chooses how many prefixes it sends, and each key
				// costs a map of its own plus a trie node and a source entry.
				// Without a ceiling one misbehaving or compromised neighbor
				// decides how much memory this node uses, and the per-wake
				// selection sweep is linear in the same number.
				rt.overfull(key)
				return
			}
			entry = &keyEntry{routes: make(map[*neighborState]*routeInfo)}
			rt.entries[key] = entry
		}
		route = &routeInfo{}
		entry.routes[n] = route
	}
	selected := entry.selected.neighbor == n
	// The hold of section 3.5.4 starts when the route is retracted, and runs
	// for the interval of the update it replaces. Reading the retraction's own
	// would let the neighbor choose how long this node answers with an error,
	// section 4.6.9 forbidding a zero one of a finite update only, and running
	// it again on each retraction would let a neighbor repeating one pin the
	// prefix for as long as it likes. Without any of it a retraction arriving
	// a moment before the old deadline holds for that moment, and the packet
	// falls through to the ::/0 an exit announces and bounces until its hop
	// limit is spent.
	retracting := adv.metric == MetricInfinity && route.rxMetric != MetricInfinity
	route.routerID, route.seqno, route.rxMetric = adv.routerID, adv.seqno, adv.metric
	switch {
	case adv.metric != MetricInfinity:
		route.hold, route.expiresAt = hold, now.Add(hold)
	case retracting && route.hold > 0:
		route.expiresAt = now.Add(route.hold)
	}
	// Section 3.8.2.2: an unfeasible update for the selected route unselects
	// it, so ask its origin for a sequence number that makes it usable again
	// rather than waiting for the route to expire.
	if !feasible && selected {
		rt.starve(key, n, adv)
	}
	rt.selectRoute(key, entry, now)
}

// Every change uses the same selection procedure, including a metric increase
// on the selected route, a link-cost change, expiry, and neighbor removal.
func (rt *routeTable) selectRoute(key routeKey, entry *keyEntry, now time.Time) {
	var best, incumbent *neighborState
	var bestCost, incumbentCost uint16
	var bestSmoothed, incumbentSmoothed float64
	var unfeasible []*neighborState
	for n, route := range entry.routes {
		if !now.Before(route.expiresAt) {
			// Section 3.5.3: a route expires to infinity first, which holds the
			// prefix (section 3.5.4); the next expiry flushes it.
			if route.rxMetric == MetricInfinity {
				delete(entry.routes, n)
				continue
			}
			route.rxMetric = MetricInfinity
			route.expiresAt = now.Add(route.hold)
		}
		// Every route that survives the pass contributes to the table's
		// minimum, whether or not it can be selected: a retracted one still
		// has to be flushed when its hold runs out.
		rt.noteExpiry(route.expiresAt)
		cost := route.cost(n, now, rt.cost)
		if cost == MetricInfinity {
			// Deliberately not smoothed. ms(R) follows an increase
			// immediately, so feeding it infinity pins it there, and a link
			// that comes back after a few seconds then stays unselected for
			// several time constants while the smoothed value decays from
			// 65535. A retracted or expired route is absent, not merely
			// expensive, and Appendix A.3 is about how good a route has been
			// while it existed.
			continue // retain the candidate until its Update expires
		}
		route.smooth(cost, now, rt.tau)
		if !rt.feasible(key, route.advertised(), n.peer.ID) {
			// Section 3.6: an unfeasible route is never selected. A stored
			// route can turn unfeasible after the fact, either through a
			// metric fluctuation or because this node has since advertised a
			// better distance, so the condition is rechecked here and not only
			// on receipt.
			unfeasible = append(unfeasible, n)
			continue
		}
		if n == entry.selected.neighbor {
			incumbent, incumbentCost, incumbentSmoothed = n, cost, route.smoothed
		}
		// Break ties by peer ID so map iteration cannot affect the choice.
		if best == nil || cost < bestCost || (cost == bestCost && n.peer.ID < best.peer.ID) {
			best, bestCost, bestSmoothed = n, cost, route.smoothed
		}
	}

	var selected routeSelection
	switch {
	case best == nil:
	case incumbent == nil || best == incumbent:
		selected = entry.selectionFor(best, bestCost)
	case bestCost < incumbentCost && bestSmoothed < incumbentSmoothed:
		// Appendix A.3: leave the selected route only when the challenger is
		// better on both the instantaneous and the smoothed metric. Equal cost
		// therefore keeps the current next hop.
		selected = entry.selectionFor(best, bestCost)
	default:
		selected = entry.selectionFor(incumbent, incumbentCost)
	}

	previous := entry.selected
	// Only a changed next hop changes the forwarding table: the cost is
	// something this node advertises, which significant below decides, and is
	// not part of the entry. Reinstalling on a cost change alone logged a line, wrote
	// the same entry and woke the kernel reconciler for every prefix through
	// a neighbor whose measured RTT moved, which under RFC 9616 costing is
	// most IHUs.
	if selected.neighbor != previous.neighbor {
		rt.install(key, selected)
	}
	if rt.significant(previous, selected) {
		rt.dirty[key] = struct{}{}
	}
	if selected.neighbor != nil {
		entry.retractID, entry.retractSeqno = selected.routerID, selected.seqno
	}
	entry.selected = selected
	// Section 3.8.2.1: the last feasible route is gone while unfeasible ones
	// remain, so ask their origins for a new sequence number. Only the
	// transition asks: a prefix that stays starved would otherwise repeat the
	// request on every pass for as long as the unfeasible routes are retained.
	if selected.neighbor == nil && previous.neighbor != nil {
		for _, n := range unfeasible {
			rt.starve(key, n, entry.routes[n].advertised())
		}
	}
	if len(entry.routes) == 0 {
		delete(rt.entries, key)
		rt.dirty[key] = struct{}{} // a flushed prefix may still need retracting
		// The entry is gone, so the section 3.5.4 hold goes with it and a
		// covering route may serve this destination again.
		rt.flush(key)
	}
}

// significant decides whether a selection change earns a triggered update,
// RFC 8966 section 3.7.2. A different next hop, origin or sequence number does,
// as does any move to or from unreachable; a metric fluctuation does not. An
// improvement is deliberately left to the periodic dump: advertising a smaller
// metric lowers this node's feasibility distance, which can make routes it
// already holds unselectable.
func (rt *routeTable) significant(old, new routeSelection) bool {
	switch {
	case (old.neighbor == nil) != (new.neighbor == nil):
		return true
	case new.neighbor == nil:
		return false
	case old.neighbor != new.neighbor || old.routerID != new.routerID || old.seqno != new.seqno:
		return true
	default:
		return new.cost > old.cost && uint32(new.cost)-uint32(old.cost) >= uint32(rt.trigger)
	}
}

func (entry *keyEntry) selectionFor(n *neighborState, cost uint16) routeSelection {
	route := entry.routes[n]
	return routeSelection{neighbor: n, cost: cost, routerID: route.routerID, seqno: route.seqno}
}

func (r *routeInfo) advertised() advertisement {
	return advertisement{routerID: r.routerID, seqno: r.seqno, metric: r.rxMetric}
}

// cost is M(c, m) of RFC 8966 section 3.5.2 with the recommended additive
// metric. The link cost is clamped to one so that M stays strictly monotonic
// even when a neighbor reports an rxcost of zero; without M(c, m) > m,
// persistent routing loops are possible.
func (r *routeInfo) cost(n *neighborState, now time.Time, cost CostParams) uint16 {
	return saturatingAdd(max(1, n.linkCost(now, cost)), r.rxMetric)
}

// smooth maintains ms(R) of RFC 8966 Appendix A.3 as an exponentially smoothed
// average of the route's metric. It runs on every selection pass, so the sample
// interval is irregular and the decay is taken from elapsed time rather than
// from a sample count.
//
// The one deviation from A.3 is that an increase is not smoothed: ms(R) is the
// worst this route has been over the last few time constants. A plain average
// makes ms(R) lag a real degradation of the selected route, which keeps traffic
// on a link that has already gone bad for as long as it takes ms(R) to catch
// up. Damping only improvements still gives A.3 what it asks for, that a route
// be consistently good before it is switched to.
func (r *routeInfo) smooth(cost uint16, now time.Time, tau time.Duration) {
	elapsed := now.Sub(r.smoothedAt)
	switch {
	// A cost at or above the running average is the unsmoothed increase the
	// paragraph above describes, and the max on the last line already settles
	// it at cost: with (smoothed - cost) <= 0 the damped value cannot exceed
	// cost whatever the decay works out to. Taking it here is the same number
	// without math.Exp, which selectRoute would otherwise run once per route
	// per pass -- and a converged mesh reports the same cost every time, so
	// that is the steady state rather than a corner.
	case r.smoothedAt.IsZero() || tau <= 0 || float64(cost) >= r.smoothed:
		r.smoothed = float64(cost)
	case elapsed > 0:
		r.smoothed = float64(cost) + (r.smoothed-float64(cost))*math.Exp(-float64(elapsed)/float64(tau))
	}
	r.smoothed, r.smoothedAt = max(r.smoothed, float64(cost)), now
}

func (rt *routeTable) starve(key routeKey, n *neighborState, adv advertisement) {
	rt.starved = append(rt.starved, starveRequest{
		key: key, neighbor: n, routerID: adv.routerID, seqno: rt.requestSeqno(key, adv),
	})
}

func (rt *routeTable) route(n *neighborState, key routeKey) *routeInfo {
	entry := rt.entries[key]
	if entry == nil {
		return nil
	}
	return entry.routes[n]
}

func (rt *routeTable) recomputeNeighbor(n *neighborState, now time.Time) {
	for key, entry := range rt.entries {
		if _, ok := entry.routes[n]; ok {
			rt.selectRoute(key, entry, now)
		}
	}
}

// expireNeighbor discards a neighbor's routes outright. It is for a peer that
// is gone, not for one that merely stopped answering: an unreachable neighbor
// keeps its routes, which an infinite link cost already makes unselectable,
// until their own expiry timers run out.
func (rt *routeTable) expireNeighbor(n *neighborState, now time.Time) {
	delete(rt.retracted, n)
	for key, entry := range rt.entries {
		if _, ok := entry.routes[n]; ok {
			delete(entry.routes, n)
			rt.selectRoute(key, entry, now)
		}
	}
}

// retractNeighbor applies a wildcard retraction, RFC 8966 section 4.6.9 read
// with RFC 9079 section 5.2: every route from this neighbor,
// whatever its source prefix, goes to infinity through the ordinary
// acquisition path, so the prefixes are held rather than vanishing.
//
// It is a walk of the whole route table, and a neighbor can put a hundred and
// twelve wildcard retractions in one packet: the TLV is twelve bytes. After
// the first, every route from that neighbor is already at infinity and the
// walk finds nothing to do, so the repeat is remembered rather than redone.
// Measured at 403 ms of the speaker lock per packet at maxRouteKeys routes,
// which is every neighbor's receive path, the hello emitter and route
// selection held behind one peer.
func (rt *routeTable) retractNeighbor(n *neighborState, now time.Time) {
	if rt.retracted[n] {
		return
	}
	rt.retracted[n] = true
	for key, entry := range rt.entries {
		if route, ok := entry.routes[n]; ok {
			// The same rule as update's: the hold starts at the retraction
			// and runs for the interval of the update it replaces.
			if route.rxMetric != MetricInfinity && route.hold > 0 {
				route.expiresAt = now.Add(route.hold)
			}
			route.rxMetric = MetricInfinity
			rt.selectRoute(key, entry, now)
		}
	}
}

// forgetRetraction is called wherever a neighbor advertises a finite metric
// again, which makes the next wildcard retraction from it real work.
func (rt *routeTable) forgetRetraction(n *neighborState) {
	delete(rt.retracted, n)
}

func (rt *routeTable) sweepExpired(now time.Time) {
	// Cleared first and rebuilt by the walk: this is the one pass that reads
	// every route, so it is the one place the minimum can be made exact again
	// after the removals that left it early.
	rt.nextExpiryAt = time.Time{}
	for key, entry := range rt.entries {
		rt.selectRoute(key, entry, now)
	}
	rt.sweepSources(now)
}

// noteExpiry folds one route's expiry into the table's minimum.
func (rt *routeTable) noteExpiry(at time.Time) {
	rt.nextExpiryAt = earlier(rt.nextExpiryAt, at)
}

func (rt *routeTable) nextExpiry() time.Time { return rt.nextExpiryAt }

// takeDirty returns the keys whose advertisement changed since the last call.
func (rt *routeTable) takeDirty() []routeKey {
	if len(rt.dirty) == 0 {
		return nil
	}
	keys := make([]routeKey, 0, len(rt.dirty))
	for key := range rt.dirty {
		keys = append(keys, key)
	}
	clear(rt.dirty)
	return keys
}

func (rt *routeTable) takeStarved() []starveRequest {
	requests := rt.starved
	rt.starved = nil
	return requests
}

func earlier(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// Babel sequence numbers wrap at 16 bits (RFC 8966 section 3.2.1).
func seqnoGT(a, b uint16) bool { return int16(a-b) > 0 }

// overfull reports a refused prefix once rather than once per update, which
// would otherwise turn a flood into a second flood in the log.
func (rt *routeTable) overfull(key routeKey) {
	if rt.warnedOverfull {
		return
	}
	rt.warnedOverfull = true
	slog.Warn("babel route table is full, refusing new prefixes",
		"limit", maxRouteKeys, "refused", key.dest)
}

// tooManyOrigins reports a refused origin once rather than once per update,
// for the same reason overfull does.
func (rt *routeTable) tooManyOrigins(key routeKey, routerID [8]byte, why string, limit int) {
	if rt.warnedOrigins {
		return
	}
	rt.warnedOrigins = true
	slog.Warn("babel is refusing a new origin: "+why,
		"limit", limit, "prefix", key.dest, "refused", fmt.Sprintf("%x", routerID))
}

func (rt *routeTable) flush(key routeKey) {
	if rt.forget != nil {
		rt.forget(key)
	}
}
