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

func TestFeasibilityCondition(t *testing.T) {
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	origin := [8]byte{1}
	for _, test := range []struct {
		name       string
		advertised *advertisement // the distance this node has already sent
		received   advertisement
		want       bool
	}{
		{"no distance for the source", nil, advertisement{origin, 1, 100}, true},
		{"retraction", &advertisement{origin, 1, 10}, advertisement{origin, 1, MetricInfinity}, true},
		{"better metric at the same seqno", &advertisement{origin, 1, 10}, advertisement{origin, 1, 9}, true},
		{"equal metric at the same seqno", &advertisement{origin, 1, 10}, advertisement{origin, 1, 10}, false},
		{"worse metric at the same seqno", &advertisement{origin, 1, 10}, advertisement{origin, 1, 11}, false},
		{"newer seqno with a worse metric", &advertisement{origin, 1, 10}, advertisement{origin, 2, 1000}, true},
		{"older seqno with a better metric", &advertisement{origin, 1, 10}, advertisement{origin, 0, 1}, false},
		{"newer seqno across the wrap", &advertisement{origin, 0xffff, 10}, advertisement{origin, 0, 1000}, true},
		{"another origin for the same prefix", &advertisement{origin, 1, 10}, advertisement{[8]byte{2}, 1, 1000}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt := newRouteTable(func(routeKey, routeSelection) {})
			if test.advertised != nil {
				rt.observe(key, *test.advertised, time.Now())
			}
			if got := rt.feasible(key, test.received); got != test.want {
				t.Fatalf("feasible = %v, want %v", got, test.want)
			}
		})
	}
}

func TestUnfeasibleUpdateIsNeverSelected(t *testing.T) {
	now := time.Now()
	origin := [8]byte{1}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	n := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	makeNeighborReachable(n)
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.observe(key, advertisement{routerID: origin, seqno: 1, metric: 40}, now)

	rt.update(n, key, advertisement{routerID: origin, seqno: 1, metric: 40}, time.Minute, now)
	if len(rt.entries) != 0 {
		t.Fatal("an unfeasible update created a route")
	}
	rt.update(n, key, advertisement{routerID: origin, seqno: 1, metric: 39}, time.Minute, now)
	if rt.entries[key].selected.neighbor != n {
		t.Fatal("a feasible update was not selected")
	}
	// A metric increase can take the selected route past the distance this
	// node has already advertised, which is exactly the case the feasibility
	// condition exists to refuse.
	rt.update(n, key, advertisement{routerID: origin, seqno: 1, metric: 41}, time.Minute, now)
	if sel := rt.entries[key].selected; sel.neighbor != nil {
		t.Fatalf("an unfeasible update stayed selected via %q", sel.neighbor.peer.ID)
	}
	if len(rt.starved) == 0 {
		t.Fatal("losing the only feasible route asked nobody for a new seqno")
	}
	if got := rt.starved[0]; got.routerID != origin || got.seqno != 2 {
		t.Fatalf("starvation request = %+v, want seqno 2 for the origin", got)
	}
}

// A stored route can turn unfeasible without any update arriving, because this
// node advertised a better distance in the meantime. Selection has to notice.
func TestSelectionRechecksFeasibility(t *testing.T) {
	now := time.Now()
	origin := [8]byte{1}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	n := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	makeNeighborReachable(n)
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.update(n, key, advertisement{routerID: origin, seqno: 1, metric: 39}, time.Minute, now)
	if rt.entries[key].selected.neighbor != n {
		t.Fatal("the only route was not selected")
	}

	rt.observe(key, advertisement{routerID: origin, seqno: 1, metric: 20}, now)
	rt.sweepExpired(now)
	if sel := rt.entries[key].selected; sel.neighbor != nil {
		t.Fatalf("a route that is no longer feasible stayed selected via %q", sel.neighbor.peer.ID)
	}
	if len(rt.starved) == 0 {
		t.Fatal("no seqno request went out for the route that became unusable")
	}
}

func TestHysteresisIgnoresFlappingChallenger(t *testing.T) {
	now := time.Now()
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	steady := &neighborState{peer: netstack.NewPeer("steady", nil, nil)}
	flappy := &neighborState{peer: netstack.NewPeer("flappy", nil, nil)}
	makeNeighborReachable(steady)
	makeNeighborReachable(flappy)
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.tau = 4 * time.Second

	rt.update(steady, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 60}, time.Hour, now)
	rt.update(flappy, key, advertisement{routerID: [8]byte{2}, seqno: 1, metric: 500}, time.Hour, now)
	if rt.entries[key].selected.neighbor != steady {
		t.Fatal("the cheaper route was not selected")
	}
	rt.update(flappy, key, advertisement{routerID: [8]byte{2}, seqno: 1, metric: 1}, time.Hour, now.Add(time.Second))
	if got := rt.entries[key].selected.neighbor; got != steady {
		t.Fatalf("a route that was bad a second ago took over at once, now via %q", got.peer.ID)
	}
	// Consistently good for several time constants is the bar Appendix A.3
	// sets, and it is met here.
	rt.sweepExpired(now.Add(15 * time.Second))
	if got := rt.entries[key].selected.neighbor; got != flappy {
		t.Fatal("a consistently better route never took over")
	}
}

// A link that goes down and comes back must be selectable again promptly. The
// smoothed metric follows an increase immediately, so feeding it infinity when
// a route is retracted pins ms(R) at 65535, and the cheap path then stays
// unselected while that decays over several time constants.
func TestRetractionDoesNotPoisonSmoothedMetric(t *testing.T) {
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
