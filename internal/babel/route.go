package babel

import (
	"net/netip"
	"time"
)

// An invalid source denotes an ordinary route. Source-specific routes are
// independent entries, resolved by destination first at the forwarding table.
type routeKey struct {
	source netip.Prefix
	dest   netip.Prefix
}

type routeInfo struct {
	rxMetric  uint16
	expiresAt time.Time
}

// A selection is a value, independent of mutable candidate and neighbor state.
type routeSelection struct {
	neighbor *neighborState
	cost     uint16
}

type keyEntry struct {
	routes   map[*neighborState]routeInfo
	selected routeSelection
}

// Speaker.mu owns the candidate table AND forwarding-table publication. No
// selection may escape that critical section and later overwrite a newer one.
//
// This is an RFC 8966 Appendix E stub: learned routes are never advertised,
// and local prefixes always take precedence. Consequently feasibility state
// and comparisons between different origins' sequence numbers are unnecessary.
type routeTable struct {
	entries map[routeKey]*keyEntry
	install func(routeKey, routeSelection)
}

func newRouteTable(install func(routeKey, routeSelection)) *routeTable {
	return &routeTable{entries: make(map[routeKey]*keyEntry), install: install}
}

func (rt *routeTable) update(n *neighborState, key routeKey, metric uint16, ttl time.Duration, now time.Time) {
	entry := rt.entries[key]
	if entry == nil {
		if metric == MetricInfinity || ttl <= 0 {
			return
		}
		entry = &keyEntry{routes: make(map[*neighborState]routeInfo)}
		rt.entries[key] = entry
	}
	if metric == MetricInfinity {
		delete(entry.routes, n)
	} else {
		entry.routes[n] = routeInfo{rxMetric: metric, expiresAt: now.Add(ttl)}
	}
	rt.selectRoute(key, entry, now)
}

// Every change uses the same selection procedure, including a metric increase
// on the selected route, a link-cost change, expiry, and neighbor removal.
func (rt *routeTable) selectRoute(key routeKey, entry *keyEntry, now time.Time) {
	best := routeSelection{}
	for n, r := range entry.routes {
		if !now.Before(r.expiresAt) {
			delete(entry.routes, n)
			continue
		}
		cost := saturatingAdd(n.linkCost(now), r.rxMetric)
		if cost == MetricInfinity {
			continue // retain the candidate until its Update expires
		}
		// Keep the existing next hop on equal cost. Otherwise break ties by
		// peer ID so map iteration cannot affect the initial choice.
		if best.neighbor == nil || cost < best.cost || (cost == best.cost &&
			(n == entry.selected.neighbor || (best.neighbor != entry.selected.neighbor && n.peer.ID < best.neighbor.peer.ID))) {
			best = routeSelection{neighbor: n, cost: cost}
		}
	}
	if best != entry.selected {
		entry.selected = best
		rt.install(key, best)
	}
	if len(entry.routes) == 0 {
		delete(rt.entries, key)
	}
}

func (rt *routeTable) recomputeNeighbor(n *neighborState, now time.Time) {
	for key, entry := range rt.entries {
		if _, ok := entry.routes[n]; ok {
			rt.selectRoute(key, entry, now)
		}
	}
}

func (rt *routeTable) expireNeighbor(n *neighborState, now time.Time) {
	for key, entry := range rt.entries {
		if _, ok := entry.routes[n]; ok {
			delete(entry.routes, n)
			rt.selectRoute(key, entry, now)
		}
	}
}

func (rt *routeTable) sweepExpired(now time.Time) {
	for key, entry := range rt.entries {
		rt.selectRoute(key, entry, now)
	}
}

func (rt *routeTable) nextExpiry() time.Time {
	var deadline time.Time
	for _, entry := range rt.entries {
		for _, route := range entry.routes {
			deadline = earlier(deadline, route.expiresAt)
		}
	}
	return deadline
}

func earlier(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// Babel sequence numbers wrap at 16 bits (RFC 8966 section 3.2.2).
func seqnoGT(a, b uint16) bool { return int16(a-b) > 0 }
