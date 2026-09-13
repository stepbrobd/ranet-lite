package babel

import "time"

// sourceKey indexes the source table: the (prefix, plen, router-id) triple of
// RFC 8966 section 3.2.5, extended by RFC 9079 section 3.1 with the source
// prefix that routeKey already carries. "Source" is the RFC's name for the
// origin of a prefix and has nothing to do with routeKey.source, which is the
// SADR source prefix.
type sourceKey struct {
	route    routeKey
	routerID [8]byte
}

// sourceEntry holds one feasibility distance, RFC 8966 section 3.5.1: the best
// (seqno, metric) this node has ever advertised for that source, plus the
// garbage-collection timer of section 3.2.5.
type sourceEntry struct {
	seqno  uint16
	metric uint16
	gcAt   time.Time
	// owner is the neighbor whose route last caused this node to advertise
	// the distance, or empty for a prefix this node originates. The
	// per-neighbor shares are charged to it. It follows the latest
	// advertisement rather than the first, because the latest also keeps
	// refreshing gcAt. It is the peer's name rather than its state, so
	// an entry cannot pin a retired neighbor.
	owner string
}

// Source GC time, RFC 8966 Appendix B.
const sourceGCTime = 3 * time.Minute

// maxSources bounds the source table and maxOriginsPerPrefix bounds what any
// one prefix can spend of it. The index is a prefix and a router id: this
// node's route table bounds the prefixes, nothing bounds the router ids, and a
// neighbor that names a new origin for one prefix on every packet adds an
// entry on every packet that lives for sourceGCTime.
//
// Past a cap an origin this node has never advertised is unfeasible. Refusing
// a route can never close a loop, so routes already selected keep working and
// the prefixes this node originates still record their distance. The
// per-prefix share keeps the damage local: a global cap alone is first
// come, so one neighbor churning the origin of one prefix would stop this node
// learning any new origin anywhere, including a peer that restarted and drew a
// new router id, which a node that lost its sequence number state does.
//
// The numbers sit far above what a legitimate prefix or a restarting neighbor
// produces and far below what a flood needs; see maxOriginsPerPrefixPerNeighbor
// for why the first version of them was too small.
const (
	maxSources          = 1 << 16
	maxOriginsPerPrefix = 1 << 10
	// maxOriginsPerPrefixPerNeighbor is one neighbor's share of one prefix's
	// budget, and maxSourcesPerNeighbor is its share of the whole table. The
	// first stops one neighbor denying another the same prefix; the second
	// stops one neighbor spending the global budget and denying every other
	// neighbor every prefix.
	//
	// Both are far above what a restart produces, which the first version of
	// this bound got wrong. A node draws a new router id every time
	// it starts, so every restart is a new origin for every prefix it
	// announces, charged to whichever neighbor this node reaches it through.
	// At eight, nine restarts inside sourceGCTime made the prefix unfeasible,
	// and since selectRoute rechecks feasibility for stored routes that
	// dropped the route already selected: the prefix was held unreachable,
	// mesh-wide, for three minutes after the churn stopped. A cap that refuses
	// an origin refuses a route, so it has to sit above anything a supervisor
	// restarting a peer can produce.
	maxOriginsPerPrefixPerNeighbor = 1 << 8
	maxSourcesPerNeighbor          = 1 << 13
)

// originShare indexes what one neighbor has spent of one prefix's budget.
type originShare struct {
	route routeKey
	peer  string
}

// better reports whether (seqno, metric) is strictly better than the stored
// distance, the lexicographic order of RFC 8966 section 3.5.1 with the
// sequence number inverted.
func (e *sourceEntry) better(seqno, metric uint16) bool {
	return seqnoGT(seqno, e.seqno) || (seqno == e.seqno && metric < e.metric)
}

// feasible applies the feasibility condition of RFC 8966 section 3.5.1.
// Retractions are always feasible: they cannot close a loop.
func (rt *routeTable) feasible(key routeKey, adv advertisement, from string) bool {
	if adv.metric == MetricInfinity {
		return true
	}
	entry := rt.sources[sourceKey{route: key, routerID: adv.routerID}]
	if entry == nil {
		// A distance we have never recorded is feasible by definition, and
		// recording it is the cost of selecting the route, so this is also
		// where the table is bounded. See maxSources.
		switch {
		case len(rt.sources) >= maxSources:
			rt.tooManyOrigins(key, adv.routerID, "the source table is full", maxSources)
			return false
		case rt.originsPerKey[key] >= maxOriginsPerPrefix:
			rt.tooManyOrigins(key, adv.routerID, "this prefix has too many origins", maxOriginsPerPrefix)
			return false
		case rt.sourcesByPeer[from] >= maxSourcesPerNeighbor:
			rt.tooManyOrigins(key, adv.routerID, "this neighbor has spent its share of the source table", maxSourcesPerNeighbor)
			return false
		case rt.originsBy[originShare{route: key, peer: from}] >= maxOriginsPerPrefixPerNeighbor:
			rt.tooManyOrigins(key, adv.routerID, "this neighbor has spent its share of this prefix", maxOriginsPerPrefixPerNeighbor)
			return false
		}
		return true
	}
	return entry.better(adv.seqno, adv.metric)
}

// observe records a feasibility distance before an update leaves this node,
// RFC 8966 section 3.7.3. Every finite advertisement must pass through here:
// loop freedom rests on the source table bounding what we have already told
// our neighbors. Retractions neither update the distance nor reset the
// garbage-collection timer.
func (rt *routeTable) observe(key routeKey, adv advertisement, from string, now time.Time) {
	if adv.metric == MetricInfinity {
		return
	}
	index := sourceKey{route: key, routerID: adv.routerID}
	entry := rt.sources[index]
	if entry == nil {
		entry = &sourceEntry{seqno: adv.seqno, metric: adv.metric, owner: from}
		rt.sources[index] = entry
		rt.originsPerKey[key]++
		rt.originsBy[originShare{route: key, peer: from}]++
		rt.sourcesByPeer[from]++
	} else {
		if entry.better(adv.seqno, adv.metric) {
			entry.seqno, entry.metric = adv.seqno, adv.metric
		}
		// The charge follows whoever is keeping the entry alive. It was
		// frozen at whoever created it, and gcAt is refreshed by every
		// advertisement, so a neighbor that advertised one origin once and
		// went quiet stayed charged for it as long as any other neighbor kept
		// announcing the same prefix, and could then be refused a share it
		// was not using.
		if entry.owner != from {
			rt.releaseOrigin(key, entry.owner)
			rt.originsBy[originShare{route: key, peer: from}]++
			rt.sourcesByPeer[from]++
			entry.owner = from
		}
	}
	entry.gcAt = now.Add(sourceGCTime)
}

// requestSeqno is the sequence number that would make an unfeasible route
// feasible again, RFC 8966 section 3.8.2.1: the source table's value plus one,
// modulo 2^16. The advertised sequence number is the fallback for a source we
// have never advertised ourselves.
func (rt *routeTable) requestSeqno(key routeKey, adv advertisement) uint16 {
	if entry := rt.sources[sourceKey{route: key, routerID: adv.routerID}]; entry != nil {
		return entry.seqno + 1
	}
	return adv.seqno + 1
}

// sweepSources drops feasibility distances whose garbage-collection timer has
// expired, unconditionally. RFC 8966 section 3.7.3: "When the garbage-collection
// timer expires, the entry is removed from the source table", with no exception
// for an entry a route still references, and Appendix B deliberately sets the
// source GC time longer than the route expiry time so that removal is safe.
//
// Keeping a referenced entry instead made an unreachable prefix permanent. A
// neighbor whose path genuinely worsens advertises a metric this node has
// already bettered, so the route is unfeasible and unselectable; the node asks
// the origin for a new sequence number, and if every request and reply is lost
// it stops asking. The neighbor keeps refreshing the unfeasible route, so the
// distance stays referenced, so it is never collected, so the route stays
// unfeasible for the life of the process. Expiring it lets the path come
// back.
func (rt *routeTable) sweepSources(now time.Time) {
	for index, entry := range rt.sources {
		if now.Before(entry.gcAt) {
			continue
		}
		delete(rt.sources, index)
		if rt.originsPerKey[index.route] <= 1 {
			delete(rt.originsPerKey, index.route)
		} else {
			rt.originsPerKey[index.route]--
		}
		rt.releaseOrigin(index.route, entry.owner)
	}
}

// releaseOrigin gives one neighbor back the share it holds of one prefix and
// of the whole source table.
func (rt *routeTable) releaseOrigin(key routeKey, owner string) {
	share := originShare{route: key, peer: owner}
	if rt.originsBy[share] <= 1 {
		delete(rt.originsBy, share)
	} else {
		rt.originsBy[share]--
	}
	if rt.sourcesByPeer[owner] <= 1 {
		delete(rt.sourcesByPeer, owner)
	} else {
		rt.sourcesByPeer[owner]--
	}
}
