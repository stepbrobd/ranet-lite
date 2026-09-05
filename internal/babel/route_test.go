package babel

import (
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
	rt.update(n, key, 1, time.Minute, now)
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
	rt.sweepExpired(now.Add(time.Minute))
	if selected.neighbor != nil || len(rt.entries) != 0 || calls != 4 {
		t.Fatalf("expired Update left selection=%+v entries=%d callbacks=%d", selected, len(rt.entries), calls)
	}
}

func TestRouteTableNeighborExpiryDeletesEmptyEntry(t *testing.T) {
	rt := newRouteTable(func(routeKey, routeSelection) {})
	n := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt.update(n, key, 1, time.Minute, time.Now())
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
	rt.update(n, key, 1, time.Minute, time.Now())
}

func TestSelectedMetricChangeIsPublished(t *testing.T) {
	now := time.Now()
	n := &neighborState{peer: netstack.NewPeer("peer", nil, nil)}
	makeNeighborReachable(n)
	var got routeSelection
	rt := newRouteTable(func(_ routeKey, sel routeSelection) { got = sel })
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt.update(n, key, 10, time.Minute, now)
	n.reportedCost = 100
	rt.recomputeNeighbor(n, now)
	if got.neighbor != n || got.cost != 110 {
		t.Fatalf("new metric was not published: %+v", got)
	}
}
