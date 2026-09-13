package babel

// Hello history and the link-quality estimators of RFC 8966 Appendix A.
//
// A node keeps, per neighbor and per kind of Hello, a 16-bit vector in which a
// one is a Hello that arrived and a zero one that did not, plus the sequence
// number it expects next. Appendix A.2 then reads a cost off that vector.
//
// The fleet's BIRD runs "link quality etx" on its tunnel interfaces, so a link
// dropping packets costs more there and cost nothing here until this existed.
//
// One part of Appendix A.1 is deliberately absent. It flushes a neighbor whose
// histories hold only zeros; this tree reaches the same end through liveness,
// where a neighbor that misses deadTimeout worth of Hellos goes down and its
// link cost goes infinite, so a second rule keyed on the same silence would
// only decide the same thing at a slightly different moment.

// helloHistory is the 16-bit vector of Appendix A.1, most recent in the low
// bit, together with the sequence number expected next.
type helloHistory struct {
	bits     uint16
	expected uint16
	started  bool
	// samples is how many entries the vector actually holds, capped at its
	// width. Without it a neighbor's first Hello reads as one arrival out of a
	// full window and the link starts out looking six times worse than it is,
	// which is the moment a new peer is least able to afford it.
	samples int
}

// historyDepth is the width of the vector, and rebootDrift the gap past which
// Appendix A.1 treats the sender as having rebooted and lost its counter.
const (
	historyDepth = 16
	rebootDrift  = 16
)

// record applies the receive half of Appendix A.1 for one Hello carrying
// sequence number seqno. It reports false when the two differ by more than the
// window, which the caller answers by flushing the neighbor rather than
// pretending the vector still describes the link.
func (h *helloHistory) record(seqno uint16) bool {
	if !h.started {
		h.bits, h.expected, h.started, h.samples = 1, seqno+1, true, 1
		return true
	}
	// Modular, so a counter wrapping 65535 to 0 is a gap of one rather than of
	// 65535. Both directions are measured the short way round.
	ahead := seqno - h.expected
	behind := h.expected - seqno
	switch {
	case ahead <= rebootDrift:
		// Some Hellos were lost, or the sender shortened its interval.
		h.shiftIn(0, int(ahead))
	case behind <= rebootDrift:
		// The sender lengthened its interval without our noticing, so the
		// zeros this node already wrote were never missed Hellos. Undo them,
		// and give back the samples they claimed: leaving those behind reads
		// two arrivals out of four and doubles the cost of a link that lost
		// nothing, for as long as the vector is shorter than the window.
		h.bits >>= behind
		h.samples = max(0, h.samples-int(behind))
	default:
		return false
	}
	h.shiftIn(1, 1)
	h.expected = seqno + 1
	return true
}

// missed applies the timer half of Appendix A.1: a Hello that never came is a
// zero, and the next one expected moves on.
func (h *helloHistory) missed() {
	if !h.started {
		return
	}
	h.shiftIn(0, 1)
	h.expected++
}

func (h *helloHistory) shiftIn(bit uint16, count int) {
	if count >= historyDepth {
		// Everything the vector held has been shifted out. Filling it with the
		// bit being shifted in is the answer for either value, where zeroing
		// and then shifting one in would read sixteen arrivals as fifteen
		// losses. Unreachable while the only ones shifted in come one at a
		// time, and written correctly so it stays a helper rather than a trap.
		h.bits, h.samples = 0, historyDepth
		if bit != 0 {
			h.bits = ^uint16(0)
		}
		return
	}
	h.bits = h.bits<<uint(count) | bit
	h.samples = min(h.samples+count, historyDepth)
}

// betaWindow is how many recent entries the reception probability is computed
// over. Appendix A.2.2 suggests "a small number (say, 6)", and the whole
// vector is chosen instead because the node at the other end of every link on
// this mesh uses the whole of its own: BIRD popcounts hello_map over
// hello_cnt. At six the two ends disagree by up to a factor of two on the same
// loss, and a steady one-in-sixteen loss makes this end's advertised cost a
// square wave while the other end reads it as flat.
const betaWindow = historyDepth

// beta is that probability as a fraction, left undivided so the cost formula
// rounds once rather than twice. The denominator is how much history there
// actually is, so a link is judged on what it has been asked to carry. ok is
// false before the first Hello, where there is nothing to judge.
func (h *helloHistory) beta() (received, window int, ok bool) {
	if !h.started {
		return 0, 0, false
	}
	window = min(betaWindow, h.samples)
	for i := range window {
		if h.bits&(1<<uint(i)) != 0 {
			received++
		}
	}
	return received, window, true
}

// LinkQuality selects the estimator of Appendix A.2 that turns Hello history
// into a cost. The fleet's BIRD runs "link quality etx" on the same tunnels.
type LinkQuality uint8

const (
	// LinkQualityETX is Appendix A.2.2, and the default because this mesh
	// already runs it at the other end of every link.
	LinkQualityETX LinkQuality = iota
	// LinkQualityNone keeps the configured rxcost however the history reads,
	// the behavior this tree had before it kept any.
	LinkQualityNone
)

// rxCost is the figure this node advertises in its IHU, C/beta of A.2.2 with
// the nominal hop cost C in place of the RFC's 256. Using the configured
// rxcost keeps a lossless link at exactly that figure, so the fleet's tuning
// carries over, and the BIRD this mesh runs makes the same substitution with
// its own cf->rxcost.
//
// It holds only against a peer that shares C. One computing alpha against a
// literal 256 clamps to one for every cost this node advertises below that,
// which at C of 96 discards the transmit-direction loss of any link receiving
// better than three Hellos in eight.
func (p CostParams) rxCost(history *helloHistory) uint16 {
	received, window, ok := history.beta()
	if p.LinkQuality != LinkQualityETX || !ok {
		return p.RxCost
	}
	if received == 0 {
		return MetricInfinity
	}
	return scaleCost(p.RxCost, window, received)
}

// linkQualityCost is the cost this node puts on the link: the rxcost the
// neighbor reports, scaled by this node's own reception. A link is therefore
// judged in both directions, the neighbor's through what it advertises and
// this node's through beta.
//
// Appendix A.2.2 writes it as 256/(alpha*beta) with alpha = MIN(1, 256/txcost),
// which clamps any txcost below the nominal hop cost up to it. This does not,
// because BIRD does not: proto/babel/babel.c computes
// "txcost = nbr->txcost * max / rcv" with no floor, and BIRD is at the other
// end of every link on this mesh. Clamping here would raise the cost of every
// neighbor advertising under the nominal, which on the live mesh is the
// majority of them, and leave the two ends disagreeing about every such link.
// The floor's purpose, refusing a neighbor that claims an implausibly cheap
// hop, is not served by a Babel node in any case: the same neighbor could
// claim a low metric instead.
func (p CostParams) linkQualityCost(history *helloHistory, txcost uint16) uint16 {
	if txcost == MetricInfinity {
		// RFC 8966 section 3.4.3: "if the txcost is infinite, then the cost is
		// infinite". Said outright rather than left to the arithmetic below,
		// where it holds only because the product happens to saturate.
		return MetricInfinity
	}
	if p.LinkQuality != LinkQualityETX {
		return txcost
	}
	received, window, ok := history.beta()
	if !ok {
		// No Hello has arrived yet, so there is no beta and nothing to scale
		// the neighbor's own figure by.
		return txcost
	}
	if received == 0 {
		return MetricInfinity
	}
	return scaleCost(txcost, window, received)
}

// scaleCost is base*window/received, saturating rather than wrapping: a link
// bad enough to overflow is one no route should use.
func scaleCost(base uint16, window, received int) uint16 {
	scaled := uint64(base) * uint64(window) / uint64(received)
	if scaled >= uint64(MetricInfinity) {
		return MetricInfinity
	}
	return uint16(scaled)
}
