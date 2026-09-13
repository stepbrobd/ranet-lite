package babel

import (
	"net/netip"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

// Each authenticated ESP tunnel is a point-to-point Babel link. Speaker.mu
// protects this state, its registration, and all routes learned through it.
type neighborState struct {
	peer                 *netstack.Peer
	addr                 netip.Addr
	alive                bool
	lastHelloTime        time.Time
	helloInterval        time.Duration
	unicastHelloTime     time.Time
	unicastHelloInterval time.Duration

	// RFC 9616 timestamps: echo their latest Hello in our IHU. Their reply
	// may refer to an older local Hello, so local transmit history is unneeded.
	theirHelloTxTS uint32
	theirHelloRxTS uint32
	haveTheirHello bool
	sentHello      bool

	reportedCost     uint16
	haveReportedCost bool
	ihuExpiry        time.Time
	measuredRTT      time.Duration
	haveRTT          bool
	// rttExpiry is when a measurement that stopped arriving stops being used.
	// The RFC 9616 timestamps are read off a wall clock, so a step makes
	// validTimestampGap reject every sample from then on, and without this the
	// neighbor would keep the last cost it computed for the life of the
	// session, which nothing can correct.
	rttExpiry time.Time

	// lastFullDump is when this neighbor was last answered with the whole
	// table, which rate-limits the answer to a wildcard route request.
	lastFullDump time.Time

	// advertised holds the prefixes this neighbor was last told were reachable
	// through us. A prefix that leaves the set is retracted explicitly rather
	// than left to expire, which matters most for split horizon: the neighbor
	// we now route through must stop routing back.
	advertised map[routeKey]struct{}
}

// destination is the neighbor's link-local address once it has spoken, and the
// Babel multicast group before that. Each ESP tunnel carries exactly one peer,
// so both reach the same node.
func (n *neighborState) destination() netip.Addr {
	if n.addr.IsValid() {
		return n.addr
	}
	return multicastGroup
}

func deadTimeout(interval time.Duration) time.Duration { return interval * 7 / 2 }

func (n *neighborState) helloExpiry() time.Time {
	var deadline time.Time
	if n.helloInterval > 0 {
		deadline = n.lastHelloTime.Add(deadTimeout(n.helloInterval))
	}
	if n.unicastHelloInterval > 0 {
		unicast := n.unicastHelloTime.Add(deadTimeout(n.unicastHelloInterval))
		if unicast.After(deadline) {
			deadline = unicast
		}
	}
	return deadline // either Hello class can keep the link alive
}

func (n *neighborState) isAlive(now time.Time) bool {
	return n.alive && now.Before(n.helloExpiry())
}

func (n *neighborState) linkCost(now time.Time) uint16 {
	if !n.isAlive(now) || !n.haveReportedCost || !now.Before(n.ihuExpiry) {
		return MetricInfinity
	}
	return n.reportedCost
}
