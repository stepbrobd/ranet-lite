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
// per-prefix share is what keeps the damage local: a global cap alone is first
// come, so one neighbor churning the origin of one prefix would stop this node
// learning any new origin anywhere, including a peer that restarted and drew a
// new router id as RFC 8966 section 3.2.2 requires.
//
// A prefix legitimately has a handful of origins, so thirty-two is far above
// anycast and far below what a flood needs.
const (
	maxSources          = 1 << 16
	maxOriginsPerPrefix = 32
)

// better reports whether (seqno, metric) is strictly better than the stored
// distance, the lexicographic order of RFC 8966 section 3.5.1 with the
// sequence number inverted.
func (e *sourceEntry) better(seqno, metric uint16) bool {
	return seqnoGT(seqno, e.seqno) || (seqno == e.seqno && metric < e.metric)
}

// feasible applies the feasibility condition of RFC 8966 section 3.5.1.
// Retractions are always feasible: they cannot close a loop.
func (rt *routeTable) feasible(key routeKey, adv advertisement) bool {
	if adv.metric == MetricInfinity {
		return true
	}
	entry := rt.sources[sourceKey{route: key, routerID: adv.routerID}]
	if entry == nil {
		// A distance we have never recorded is feasible by definition, but
		// recording it is what selecting the route would cost, so this is
		// also where the table is bounded. See maxSources.
		if len(rt.sources) >= maxSources || rt.originsPerKey[key] >= maxOriginsPerPrefix {
			rt.tooManyOrigins(key, adv.routerID)
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
func (rt *routeTable) observe(key routeKey, adv advertisement, now time.Time) {
	if adv.metric == MetricInfinity {
		return
	}
	index := sourceKey{route: key, routerID: adv.routerID}
	entry := rt.sources[index]
	if entry == nil {
		entry = &sourceEntry{seqno: adv.seqno, metric: adv.metric}
		rt.sources[index] = entry
		rt.originsPerKey[key]++
	} else if entry.better(adv.seqno, adv.metric) {
		entry.seqno, entry.metric = adv.seqno, adv.metric
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
// unfeasible for the life of the process. Expiring it is what lets the path
// come back.
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
	}
}
