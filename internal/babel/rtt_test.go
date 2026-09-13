package babel

import (
	"testing"
	"time"
)

func TestCostFormula(t *testing.T) {
	p := CostParams{RxCost: 32, RTTMin: 0, RTTMax: 1024 * time.Millisecond, RTTCost: 1024}

	if c := p.Cost(0, false); c != 32 {
		t.Errorf("no RTT sample: got %d, want 32", c)
	}
	if c := p.Cost(0, true); c != 32 {
		t.Errorf("rtt=0: got %d, want 32", c)
	}
	if c := p.Cost(2*time.Second, true); c != 32+1024 {
		t.Errorf("rtt above max: got %d, want %d", c, 32+1024)
	}
	if c := p.Cost(512*time.Millisecond, true); c != 32+512 {
		t.Errorf("rtt at midpoint: got %d, want %d", c, 32+512)
	}
}

// RFC 9616 section 4.2 maps the smoothed round trip to a link cost "suitable
// for input to the metric computation procedure (Section 3.5.2 of [RFC8966])",
// and that procedure is the one a node runs on its own routes. Feeding the
// penalty to the advertised rxcost instead leaves selection blind, because the
// other end advertises its nominal cost: measured against the fleet, all
// sixteen ysun nodes reported 96 whether the real round trip was 10 ms or
// 307 ms, and a node 10 ms from Paris took a 202 ms exit.
func TestRoundTripPenaltyLandsOnTheCostThisNodeComputes(t *testing.T) {
	params := DefaultCostParams()
	now := time.Now()
	neighbor := func(rtt time.Duration) *neighborState {
		n := &neighborState{
			alive: true, haveReportedCost: true, reportedCost: 96,
			ihuExpiry: now.Add(time.Minute), measuredRTT: rtt, haveRTT: true,
		}
		n.helloInterval = time.Minute
		n.lastHelloTime = now
		return n
	}
	near, far := neighbor(10*time.Millisecond), neighbor(307*time.Millisecond)
	nearCost, farCost := near.linkCost(now, params), far.linkCost(now, params)
	if nearCost != 96 {
		t.Errorf("a 10ms link costs %d, want the reported 96 with no penalty", nearCost)
	}
	if farCost <= nearCost {
		t.Fatalf("a 307ms link costs %d and a 10ms one %d, so selection cannot tell them apart", farCost, nearCost)
	}
	// The two ends measure the same round trip, so a node that also inflated
	// what it advertises would have the penalty counted twice.
	if got := params.Cost(307*time.Millisecond, true); got != farCost {
		t.Errorf("the advertised cost %d and the computed cost %d disagree", got, farCost)
	}
}

// A neighbor with no round-trip sample yet must cost exactly what it reports,
// or every link starts penalised before a single timestamp has been exchanged.
func TestNoRoundTripSampleAddsNoPenalty(t *testing.T) {
	now := time.Now()
	n := &neighborState{alive: true, haveReportedCost: true, reportedCost: 96, ihuExpiry: now.Add(time.Minute)}
	n.helloInterval, n.lastHelloTime = time.Minute, now
	if got := n.linkCost(now, DefaultCostParams()); got != 96 {
		t.Errorf("an unmeasured link costs %d, want 96", got)
	}
}
