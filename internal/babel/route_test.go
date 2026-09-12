package babel

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

func TestRouteTableExpiryAndRecovery(t *testing.T) {
	now := time.Now()
	n := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	makeNeighborReachable(n)
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	var selected routeSelection
	calls := 0
	rt := newRouteTable(func(got routeKey, sel routeSelection) {
		if got != key {
			t.Fatalf("installed unexpected key %v", got)
		}
		selected = sel
		calls++
	})
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, time.Minute, now)
	if selected.neighbor != n {
		t.Fatal("live route was not installed")
	}
	n.ihuExpiry = now.Add(time.Second)
	rt.sweepExpired(now.Add(time.Second))
	if selected.neighbor != nil {
		t.Fatal("expired IHU did not retract route")
	}
	if len(rt.entries) != 1 {
		t.Fatal("candidate was discarded before its Update expired")
	}
	n.ihuExpiry = now.Add(time.Hour)
	rt.recomputeNeighbor(n, now.Add(2*time.Second))
	if selected.neighbor != n {
		t.Fatal("fresh IHU did not restore retained candidate")
	}
	// RFC 8966 section 3.5.3: the first expiry retracts the route to infinity
	// and holds the prefix; only the second one flushes it.
	rt.sweepExpired(now.Add(time.Minute))
	if selected.neighbor != nil || len(rt.entries) != 1 || calls != 4 {
		t.Fatalf("expired Update left selection=%+v entries=%d callbacks=%d", selected, len(rt.entries), calls)
	}
	rt.sweepExpired(now.Add(3 * time.Minute))
	if len(rt.entries) != 0 || calls != 4 {
		t.Fatalf("held retraction left entries=%d callbacks=%d", len(rt.entries), calls)
	}
}

func TestRouteTableNeighborExpiryDeletesEmptyEntry(t *testing.T) {
	rt := newRouteTable(func(routeKey, routeSelection) {})
	n := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, time.Minute, time.Now())
	rt.expireNeighbor(n, time.Now())
	if len(rt.entries) != 0 {
		t.Fatalf("neighbor expiry retained %d empty entries", len(rt.entries))
	}
}

func TestInfiniteLinkCostNeverBecomesReachable(t *testing.T) {
	if got := saturatingAdd(MetricInfinity, 1); got != MetricInfinity {
		t.Fatalf("infinity + 1 = %d, want infinity", got)
	}
	rt := newRouteTable(func(routeKey, routeSelection) { t.Fatal("installed route without live Hello/IHU") })
	n := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, time.Minute, time.Now())
}

func TestSelectedMetricChangeIsPublished(t *testing.T) {
	now := time.Now()
	n := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	makeNeighborReachable(n)
	var got routeSelection
	rt := newRouteTable(func(_ routeKey, sel routeSelection) { got = sel })
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 10}, time.Minute, now)
	n.reportedCost = 100
	rt.recomputeNeighbor(n, now)
	if got.neighbor != n || got.cost != 110 {
		t.Fatalf("new metric was not published: %+v", got)
	}
}

// A link that goes down and comes back must be selectable again promptly. The
// smoothed metric follows an increase immediately, so feeding it infinity when
// a route is retracted pins ms(R) at 65535, and the cheap path then stays
// unselected while that decays over several time constants.
func TestRetractionDoesNotPoisonTheSmoothedMetric(t *testing.T) {
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.tau = time.Minute
	good := &neighborState{peer: netstack.NewPeer("good", nil, nil)}
	backup := &neighborState{peer: netstack.NewPeer("backup", nil, nil)}
	makeNeighborReachable(good)
	makeNeighborReachable(backup)
	key := routeKey{dest: netip.MustParsePrefix("fd00:1::/64")}
	now := time.Now()

	adv := advertisement{routerID: [8]byte{1}, seqno: 1, metric: 8}
	rt.update(good, key, adv, time.Hour, now)
	rt.update(backup, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 200}, time.Hour, now)
	if got := rt.entries[key].selected.neighbor; got != good {
		t.Fatalf("the cheap route was not selected, got %v", got)
	}

	// The good link retracts, then returns ten seconds later.
	now = now.Add(time.Second)
	rt.update(good, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: MetricInfinity}, time.Hour, now)
	if rt.entries[key].selected.neighbor != backup {
		t.Fatal("traffic did not fail over to the backup")
	}
	now = now.Add(10 * time.Second)
	rt.update(good, key, adv, time.Hour, now)

	if got := rt.entries[key].selected.neighbor; got != good {
		name := "nothing"
		if got != nil {
			name = got.peer.ID
		}
		t.Errorf("after a ten second outage the cheap link is still not selected, got %q, "+
			"so its smoothed metric was poisoned by the retraction", name)
	}
}

// A peer decides how many prefixes it sends. Each one costs a map, a trie node
// and a source entry, and the per-wake selection sweep is linear in the count,
// so the ceiling has to be ours rather than theirs.
func TestRouteTableRefusesMorePrefixesThanItsLimit(t *testing.T) {
	rt := newRouteTable(func(routeKey, routeSelection) {})
	peer := &neighborState{peer: netstack.NewPeer("flood", nil, nil)}
	makeNeighborReachable(peer)
	now := time.Now()
	adv := advertisement{routerID: [8]byte{1}, seqno: 1, metric: 64}

	for i := range maxRouteKeys + 64 {
		key := routeKey{dest: netip.PrefixFrom(netip.AddrFrom16([16]byte{
			0xfd, 0, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i),
		}), 64)}
		rt.update(peer, key, adv, time.Hour, now)
	}
	if got := len(rt.entries); got > maxRouteKeys {
		t.Errorf("one peer installed %d prefixes against a limit of %d", got, maxRouteKeys)
	}
	if len(rt.entries) == 0 {
		t.Error("the limit refused everything, so no route is ever learned")
	}
}

// The fast path in smooth has to be the same number as the arithmetic it
// skips, not merely close to it: ms(R) decides which route is selected, so a
// disagreement anywhere changes routing. Driven over the shapes a selection
// pass produces -- a first sample, a decay with no elapsed time, an
// improvement, a degradation, and a zero tau -- against the arithmetic written
// out in full.
func TestSmoothTakesTheShortcutOnlyWhereItAgrees(t *testing.T) {
	reference := func(r routeInfo, cost uint16, now time.Time, tau time.Duration) float64 {
		elapsed := now.Sub(r.smoothedAt)
		switch {
		case r.smoothedAt.IsZero() || tau <= 0:
			r.smoothed = float64(cost)
		case elapsed > 0:
			r.smoothed = float64(cost) + (r.smoothed-float64(cost))*math.Exp(-float64(elapsed)/float64(tau))
		}
		return max(r.smoothed, float64(cost))
	}
	base := time.Now()
	for _, tau := range []time.Duration{0, -time.Second, time.Millisecond, 12 * time.Second} {
		for _, elapsed := range []time.Duration{-time.Second, 0, time.Nanosecond, time.Second, time.Hour} {
			for _, smoothed := range []float64{0, 1, 41.5, 96, 65535} {
				for _, cost := range []uint16{0, 1, 42, 96, 65535} {
					for _, zero := range []bool{false, true} {
						start := routeInfo{smoothed: smoothed, smoothedAt: base}
						if zero {
							start.smoothedAt = time.Time{}
						}
						now := base.Add(elapsed)
						want := reference(start, cost, now, tau)
						got := start
						got.smooth(cost, now, tau)
						if got.smoothed != want {
							t.Fatalf("smooth(cost=%d, elapsed=%v, tau=%v, smoothed=%v, unset=%v) = %v, want %v",
								cost, elapsed, tau, smoothed, zero, got.smoothed, want)
						}
						if !got.smoothedAt.Equal(now) {
							t.Fatalf("smooth did not stamp the sample time")
						}
					}
				}
			}
		}
	}
}
