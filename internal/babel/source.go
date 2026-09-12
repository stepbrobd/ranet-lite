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

// maxSources bounds the source table. Its index is a prefix and a router id.
// The prefix dimension is bounded by this node's own route table; the router
// id dimension is bounded by nothing, because the origin of a route is chosen
// by whoever originated it and merely relayed by the neighbor that hands it
// over. A neighbor that names a new origin for one prefix on every packet adds
// an entry on every packet, and each survives sourceGCTime after the last time
// this node advertised it.
//
// Past the cap an origin this node has never advertised is treated as
// unfeasible. Refusing a route can never close a loop, so the bound costs
// nothing in correctness: routes already selected keep working, and the
// prefixes this node originates itself still record their distance, which is
// one entry each. A real mesh never comes near this. Its live set is one entry
// per prefix per origin that was actually selected, and sixty-five thousand of
// those is a mesh far larger than any this carries.
const maxSources = 1 << 16

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
		return len(rt.sources) < maxSources
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
// expired. An entry still backing a route table entry is kept regardless:
// forgetting it would make updates feasible that selection has already
// rejected, which is the one direction that can close a loop.
func (rt *routeTable) sweepSources(now time.Time) {
	for index, entry := range rt.sources {
		if now.Before(entry.gcAt) || rt.referenced(index) {
			continue
		}
		delete(rt.sources, index)
	}
}

func (rt *routeTable) referenced(index sourceKey) bool {
	entry := rt.entries[index.route]
	if entry == nil {
		return false
	}
	for _, route := range entry.routes {
		if route.routerID == index.routerID {
			return true
		}
	}
	return false
}
