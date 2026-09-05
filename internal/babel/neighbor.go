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
