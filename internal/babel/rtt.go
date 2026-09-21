package babel

import (
	"time"

	"github.com/NickCao/ranet-lite/internal/schema"
)

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

// CostParams is the cost block of the cap.babel capability, RFC 9616 costing
// as the file spells it: a fixed base rx cost plus up to RTT.Weight more,
// scaled linearly between RTT.Min and RTT.Max. Defaults mirror a typical
// tunnel-mesh deployment, see the internal/babel doc comment.
type CostParams struct {
	RxCost uint16  `yaml:"rx,omitempty" json:"rx,omitempty" toml:"rx,omitempty"`
	RTT    RTTCost `yaml:"rtt,omitempty" json:"rtt,omitempty" toml:"rtt,omitempty"`
	// Quality is carried in from cap.babel's own quality rather than written
	// inside the cost block, because the estimator is a property of the link
	// and the rest of this struct is a property of the mapping. Config.Validate
	// and the speaker resolve it; nothing reads it out of a file.
	Quality LinkQuality `yaml:"-" json:"-" toml:"-"`
}

// RTTCost is the round-trip half of the mapping.
type RTTCost struct {
	Weight uint16          `yaml:"weight,omitempty" json:"weight,omitempty" toml:"weight,omitempty"`
	Min    schema.Duration `yaml:"min,omitempty" json:"min,omitempty" toml:"min,omitempty"`
	Max    schema.Duration `yaml:"max,omitempty" json:"max,omitempty" toml:"max,omitempty"`
}

func DefaultCostParams() CostParams {
	return CostParams{
		// 96 is the value RFC 8966 Appendix B gives for a wired link, what BIRD
		// uses as BABEL_RXCOST_WIRED, and what the fleet sets explicitly. At
		// 32 a ranet-lite hop looks three times cheaper than a BIRD hop, so a
		// mixed fleet pulls transit onto whichever nodes run this.
		RxCost: 96,
		RTT: RTTCost{
			// RFC 9616 section 4.2: "The mapping should also be constant
			// around 0, so that small oscillations in the RTT of low-RTT links
			// do not contribute to routing instability", and it RECOMMENDS
			// rtt-min = 10 ms for it. At zero the mapping was linear from the
			// origin, so the exponential average of a link with ordinary
			// jitter moved the advertised rxcost on most IHUs.
			Min: schema.Duration(10 * time.Millisecond),
			// rtt-max and max-rtt-penalty deviate from the 120 ms and 150 the
			// same section RECOMMENDS, deliberately. This is a global mesh:
			// 120 ms saturates every intercontinental path, so the penalty
			// stops ranking exactly the links it exists to rank, and a penalty
			// of 150 against a wired rxcost of 96 makes a satellite hop cost
			// less than three wired ones.
			Max:    schema.Duration(1024 * time.Millisecond),
			Weight: 1024,
		},
	}
}

// Cost implements the standard babeld/RFC 9616 RTT-cost formula: rx cost alone
// below RTT.Min, rx cost plus RTT.Weight at or above RTT.Max, linear between.
func (p CostParams) Cost(rtt time.Duration, haveRTT bool) uint16 {
	return saturatingAdd(p.RxCost, p.RTTPenalty(rtt, haveRTT))
}

// RTTPenalty is the same mapping without the nominal hop cost. RFC 9616
// section 4.2 asks for it as input to "the metric computation procedure
// (Section 3.5.2 of [RFC8966])". That procedure is the one a node runs on its
// own routes, so the penalty belongs on the cost this node computes for the
// link, added to the rxcost the neighbor reports, rather than on the rxcost
// this node advertises.
//
// Measured against the fleet before this was so: every one of sixteen
// nodes reported cost 96 whether its real round trip was 10 ms or 307 ms,
// because BIRD applies the penalty locally and advertises the nominal cost.
// Selection could not tell Paris from Sydney and took a 202 ms exit from a
// node 10 ms from Paris.
func (p CostParams) RTTPenalty(rtt time.Duration, haveRTT bool) uint16 {
	low, high := p.RTT.Min.Duration(), p.RTT.Max.Duration()
	if !haveRTT || p.RTT.Weight == 0 || high <= low || rtt <= low {
		return 0
	}
	if rtt >= high {
		return p.RTT.Weight
	}
	// int64 nanosecond products (e.g. 1024 * 1s) overflow uint32 well
	// before the division brings the result back into range.
	return uint16(uint64(p.RTT.Weight) * uint64(rtt-low) / uint64(high-low))
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
