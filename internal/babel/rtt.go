package babel

import "time"

// nowMicros is a 32-bit microsecond clock for RFC 9616 Timestamp sub-TLVs
// (§6: "expressed in units of one microsecond ... wrap around every 4295
// seconds"). We only ever difference two nearby samples of our own clock
// (see microDelta), never compare across nodes' clocks directly, so that
// ~71-minute wraparound is harmless as long as no single measurement spans
// it.
func nowMicros() uint32 {
	return uint32(time.Now().UnixMicro())
}

// microDelta computes b-a as a wraparound-safe signed duration, the same
// trick TCP uses for sequence numbers: reinterpreting the unsigned
// difference as a signed 32-bit value is correct as long as the true gap
// is less than half the modulus (here, well under the ~71-minute wrap).
func microDelta(b, a uint32) time.Duration {
	return time.Duration(int32(b-a)) * time.Microsecond
}

// CostParams configures RTT-based costing, RFC 9616. Defaults mirror a
// typical tunnel-mesh deployment (see internal/babel doc comment): a fixed
// base rxcost plus up to RTTCost additional cost scaled linearly between
// RTTMin and RTTMax.
type CostParams struct {
	RxCost  uint16
	RTTMin  time.Duration
	RTTMax  time.Duration
	RTTCost uint16
}

func DefaultCostParams() CostParams {
	return CostParams{
		// 96 is what RFC 8966 Appendix B gives for a wired link, what BIRD
		// uses as BABEL_RXCOST_WIRED, and what the fleet sets explicitly. At
		// 32 a ranet-lite hop looks three times cheaper than a BIRD hop, so a
		// mixed fleet pulls transit onto whichever nodes run this.
		RxCost: 96,
		// RFC 9616 section 4.2: "The mapping should also be constant around 0,
		// so that small oscillations in the RTT of low-RTT links do not
		// contribute to routing instability", and it RECOMMENDS rtt-min = 10
		// ms for it. At zero the mapping was linear from the origin, so the
		// exponential average of a link with ordinary jitter moved the
		// advertised rxcost on most IHUs.
		RTTMin: 10 * time.Millisecond,
		// rtt-max and max-rtt-penalty deviate from the 120 ms and 150 the same
		// section RECOMMENDS, deliberately. This is a global mesh: 120 ms
		// saturates every intercontinental path, so the penalty stops ranking
		// exactly the links it exists to rank, and a penalty of 150 against a
		// wired rxcost of 96 makes a satellite hop cost less than two wired
		// ones.
		RTTMax:  1024 * time.Millisecond,
		RTTCost: 1024,
	}
}

// Cost implements the standard babeld/RFC 9616 RTT-cost formula: rxcost
// alone below RTTMin, rxcost+RTTCost at/above RTTMax, linear in between.
func (p CostParams) Cost(rtt time.Duration, haveRTT bool) uint16 {
	if !haveRTT || p.RTTCost == 0 || p.RTTMax <= p.RTTMin {
		return p.RxCost
	}
	if rtt <= p.RTTMin {
		return p.RxCost
	}
	if rtt >= p.RTTMax {
		return saturatingAdd(p.RxCost, p.RTTCost)
	}
	// int64 nanosecond products (e.g. 1024 * 1s) overflow uint32 well
	// before the division brings the result back into range.
	extra := uint64(p.RTTCost) * uint64(rtt-p.RTTMin) / uint64(p.RTTMax-p.RTTMin)
	return saturatingAdd(p.RxCost, uint16(extra))
}

func saturatingAdd(a, b uint16) uint16 {
	if a == MetricInfinity || b == MetricInfinity {
		return MetricInfinity
	}
	sum := uint32(a) + uint32(b)
	if sum >= uint32(MetricInfinity) {
		return MetricInfinity
	}
	return uint16(sum)
}
