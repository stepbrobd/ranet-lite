package babel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

// The receive half of RFC 8966 Appendix A.1, which decides what the vector
// says about a link before any cost is read off it.
func TestHelloHistoryFollowsAppendixA1(t *testing.T) {
	t.Run("consecutive hellos are all arrivals", func(t *testing.T) {
		var h helloHistory
		for seqno := uint16(7); seqno < 7+8; seqno++ {
			if !h.record(seqno) {
				t.Fatalf("seqno %d was refused", seqno)
			}
		}
		if got, window, ok := h.beta(); !ok || got != 8 || window != 8 {
			t.Errorf("eight arrivals read as %d of %d (ok %v), want 8 of 8", got, window, ok)
		}
	})

	t.Run("a gap fast-forwards zeros", func(t *testing.T) {
		var h helloHistory
		h.record(1)
		h.record(2)
		// Three lost, so the vector gains three zeros before the arrival.
		h.record(6)
		received, window, _ := h.beta()
		if received != 3 || window != 6 {
			t.Errorf("read %d of %d, want 3 of 6: two early arrivals, three lost, one late", received, window)
		}
		// The window is the history held, not the vector width, or a link
		// three Hellos old would be judged as though thirteen had been lost.
		if window > historyDepth {
			t.Errorf("the window ran past the vector at %d", window)
		}
	})

	t.Run("a lengthened interval undoes history", func(t *testing.T) {
		var h helloHistory
		h.record(1)
		h.missed()
		h.missed()
		// The sender was not missing Hellos, it had slowed down: seqno 2 is
		// the one this node wrote two zeros waiting for.
		h.record(2)
		received, window, _ := h.beta()
		if received != 2 {
			t.Errorf("read %d arrivals, want 2: the zeros were undone rather than kept", received)
		}
		// The window matters as much as the count. Undoing the bits while
		// keeping the samples they claimed reads two arrivals out of four and
		// doubles the cost of a link that lost nothing, which is invisible to
		// an assertion on the numerator alone.
		if window != 2 {
			t.Errorf("read %d of %d, want 2 of 2: the undone entries were not given back", received, window)
		}
		if got := DefaultCostParams().linkQualityCost(&h, 96); got != 96 {
			t.Errorf("a link that lost nothing costs %d, want 96", got)
		}
	})

	// "if the two differ by more than 16", so the drift is measured from the
	// expected number rather than from the last one seen, and exactly 16 is
	// still a gap rather than a reboot.
	// The timer writes a zero and moves the expectation on. Without the second
	// half, the Hello that was merely late arrives with a number the vector
	// has already passed, and the gap is counted a second time: one real loss
	// reads as two.
	t.Run("a late hello is not counted twice", func(t *testing.T) {
		var h helloHistory
		for seqno := uint16(1); seqno <= 4; seqno++ {
			h.record(seqno)
		}
		h.missed() // seqno 5 is overdue
		h.record(6)
		received, window, _ := h.beta()
		if received != 5 || window != 6 {
			t.Errorf("read %d of %d, want 5 of 6: one Hello was lost, not two", received, window)
		}
	})

	t.Run("a reboot past the window is refused", func(t *testing.T) {
		var h helloHistory
		h.record(1000) // expects 1001 next
		if !h.record(1001 + rebootDrift) {
			t.Error("a gap of exactly the window was read as a reboot")
		}
		var far helloHistory
		far.record(1000)
		if far.record(1002 + rebootDrift) {
			t.Error("a gap past the window was accepted, so the vector no longer describes the link")
		}
	})

	t.Run("the counter wrapping is a gap of one", func(t *testing.T) {
		var h helloHistory
		h.record(65535)
		if !h.record(0) {
			t.Fatal("a wrapped counter was read as a reboot")
		}
		received, window, _ := h.beta()
		if received != 2 || window != 2 {
			t.Errorf("read %d of %d, want 2 of 2", received, window)
		}
	})
}

// Appendix A.2.2 with the nominal hop cost C in place of the RFC's 256, so a
// lossless link costs exactly the configured rxcost and the fleet's tuning
// carries over unchanged.
func TestETXCostFollowsAppendixA22(t *testing.T) {
	params := DefaultCostParams()
	full := func(received int) *helloHistory {
		h := &helloHistory{}
		for i := range betaWindow {
			h.record(uint16(i + 1))
			if i >= received {
				// Overwrite the newest arrival with a loss.
				h.bits &^= 1
			}
		}
		return h
	}
	for _, c := range []struct {
		name           string
		received       int
		txcost         uint16
		wantAdvertised uint16
		wantComputed   uint16
	}{
		{"lossless costs the configured rxcost", 16, 96, 96, 96},
		{"one lost in sixteen costs a fifteenth more", 15, 96, 102, 102},
		{"half lost doubles", 8, 96, 192, 192},
		{"the neighbor's own cost gets scaled", 16, 192, 96, 192},
		// Not clamped up to the nominal, which is where this departs from
		// A.2.2's alpha and follows the BIRD at the other end instead.
		{"a cheap neighbor stays cheap", 16, 32, 96, 32},
		{"a cheap neighbor still pays for loss", 8, 32, 192, 64},
		{"nothing received is unreachable", 0, 96, MetricInfinity, MetricInfinity},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := full(c.received)
			if got := params.rxCost(h); got != c.wantAdvertised {
				t.Errorf("advertised %d, want %d", got, c.wantAdvertised)
			}
			if got := params.linkQualityCost(h, c.txcost); got != c.wantComputed {
				t.Errorf("computed %d, want %d", got, c.wantComputed)
			}
		})
	}
}

// A new neighbor has one entry, not a window with one arrival in it. Judging
// it on a full window would start every link six times worse than it is, at
// the moment a peer is least able to afford being deselected.
func TestShortHistoryIsJudgedOnWhatItHolds(t *testing.T) {
	params := DefaultCostParams()
	var h helloHistory
	h.record(1)
	if got := params.linkQualityCost(&h, 96); got != 96 {
		t.Errorf("a neighbor's first Hello costs %d, want the nominal 96", got)
	}
	if got := params.rxCost(&h); got != 96 {
		t.Errorf("a neighbor's first Hello advertises %d, want 96", got)
	}
}

// Before any Hello there is nothing to judge, and with the estimator off the
// history is kept but never read.
func TestNoHistoryAndNoEstimatorKeepTheReportedCost(t *testing.T) {
	params := DefaultCostParams()
	var empty helloHistory
	if got := params.linkQualityCost(&empty, 42); got != 42 {
		t.Errorf("an unmeasured link costs %d, want the reported 42", got)
	}
	off := DefaultCostParams()
	off.Quality = LinkQualityNone
	lossy := &helloHistory{}
	for i := range betaWindow {
		lossy.record(uint16(i*2 + 1)) // every other Hello lost
	}
	if got := off.linkQualityCost(lossy, 96); got != 96 {
		t.Errorf("with the estimator off a lossy link costs %d, want the reported 96", got)
	}
}

// The timer half of Appendix A.1 makes a quiet link cost more. Without
// it a neighbor that stops sending keeps the quality of its last Hello until
// liveness gives up on it entirely, so the cost goes from nominal to infinite
// with nothing in between and selection never sees the link degrading.
func TestSilenceDegradesTheLinkBeforeItDies(t *testing.T) {
	params := DefaultCostParams()
	var h helloHistory
	for i := range betaWindow {
		h.record(uint16(i + 1))
	}
	if got := params.linkQualityCost(&h, 96); got != 96 {
		t.Fatalf("a healthy link costs %d, want 96", got)
	}
	costs := []uint16{}
	for range 3 {
		h.missed()
		costs = append(costs, params.linkQualityCost(&h, 96))
	}
	for i := 1; i < len(costs); i++ {
		if costs[i] <= costs[i-1] {
			t.Errorf("costs %v do not rise as Hellos go missing", costs)
			break
		}
	}
	if costs[0] <= 96 {
		t.Errorf("one missed Hello left the cost at %d", costs[0])
	}
}

// The estimator has to be reached from the packet path and from the sweep, not
// only exist. Removing either wiring left every unit test above green, so this
// one drives Hellos through Receive and the clock through sweepExpiredLocked
// and reads back the cost selection would use.
func TestHelloLossReachesTheCostSelectionUses(t *testing.T) {
	s, _, _ := captureSpeaker(t, Config{Hello: dur(time.Second)})
	a := addReachablePeer(s, "a", 100)
	hello := func(seqno uint16) {
		s.Receive(a, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup,
			EncodePacket([]RawTLV{
				EncodeHello(Hello{Seqno: seqno, Interval: 100}),
				EncodeIHU(IHU{RxCost: 96, Interval: 1000}),
			})))
	}
	cost := func() uint16 {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.neighbors[a.ID].linkCost(time.Now(), s.cost)
	}

	for seqno := uint16(1); seqno <= betaWindow; seqno++ {
		hello(seqno)
	}
	healthy := cost()
	if healthy != 96 {
		t.Fatalf("a link that lost nothing costs %d, want the configured 96", healthy)
	}

	// Three Hellos in a row never arrive, which the sender's own numbering
	// reports the moment the next one does.
	hello(betaWindow + 4)
	if lossy := cost(); lossy <= healthy {
		t.Errorf("three lost Hellos left the cost at %d, so loss never reaches selection", lossy)
	}

	// And the same through the clock rather than through a packet: a neighbor
	// that simply goes quiet must degrade before liveness gives up on it.
	// Three Hello intervals, well inside the ten second IHU, so the rise has
	// to come from missed Hellos: letting the IHU expire instead takes the
	// cost to infinity and the assertion would pass either way.
	s.mu.Lock()
	quiet := s.neighbors[a.ID]
	before := quiet.linkCost(time.Now(), s.cost)
	later := time.Now().Add(3 * time.Second)
	s.sweepExpiredLocked(later)
	after := quiet.linkCost(later, s.cost)
	s.mu.Unlock()
	if after == MetricInfinity {
		t.Fatal("the neighbor expired instead of degrading, so this proves nothing")
	}
	if after <= before {
		t.Errorf("silence left the cost at %d from %d, so the sweep never writes a missed Hello", after, before)
	}
}

// A link that comes back is judged on the Hellos it has sent since, not on the
// ones it missed while it was down. See forgetLink for why the receive path
// cannot notice on its own; without it the link returns costing sixteen times
// nominal.
func TestLinkThatComesBackIsNotCostedByItsOutage(t *testing.T) {
	const interval = time.Second
	s, _, _ := captureSpeaker(t, Config{Hello: dur(interval)})
	a := addReachablePeer(s, "a", 96)
	start := time.Now()
	// The peer numbers its Hellos whether or not they arrive, one per
	// interval, so the first one after an outage of any length is in sequence.
	sent := uint16(1)
	deliver := func() {
		s.Receive(a, buildPacket(netip.MustParseAddr("fe80::2"), multicastGroup,
			EncodePacket([]RawTLV{
				EncodeHello(Hello{Seqno: sent, Interval: 100}),
				EncodeIHU(IHU{RxCost: 96, Interval: 1000}),
			})))
	}
	for range betaWindow {
		sent++
		deliver()
	}
	s.mu.Lock()
	n := s.neighbors[a.ID]
	healthy := n.linkCost(start, s.cost)
	s.mu.Unlock()
	if healthy != 96 {
		t.Fatalf("a link that lost nothing costs %d, want the configured 96", healthy)
	}

	// A minute of silence, swept the way Run sweeps it, one pass per interval.
	s.mu.Lock()
	for elapsed := interval; elapsed <= time.Minute; elapsed += interval {
		sent++
		s.sweepExpiredLocked(start.Add(elapsed))
	}
	up := n.alive
	s.mu.Unlock()
	if up {
		t.Fatal("a minute of silence left the neighbor up, so this proves nothing")
	}

	sent++
	deliver()
	s.mu.Lock()
	back := n.linkCost(time.Now(), s.cost)
	s.mu.Unlock()
	if back != healthy {
		t.Errorf("the link came back costing %d against %d before the outage", back, healthy)
	}
}

// The IHU says what this node knows about receiving from the neighbor, and
// there are three states rather than two. Never heard from keeps the nominal
// cost, so a new adjacency forms in one exchange. Heard and still heard reads
// beta. Heard and gone quiet is infinite, which forgetLink erases the evidence
// for and which on a one-way link is all that stops the far end selecting a
// direction that is dead.
func TestIHUSaysWhatThisNodeHearsFromTheNeighbor(t *testing.T) {
	const interval = time.Second
	s, _, _ := captureSpeaker(t, Config{Hello: dur(interval)})
	a := addReachablePeer(s, "a", 96)
	start := time.Now()
	rxcost := func(at time.Time) uint16 {
		s.mu.Lock()
		defer s.mu.Unlock()
		n := s.neighbors[a.ID]
		for _, tlv := range s.helloAction(n, at).tlvs {
			if tlv.Type != TLVIHU {
				continue
			}
			ihu, _, err := DecodeIHU(tlv.Body)
			if err != nil {
				t.Fatal(err)
			}
			return ihu.RxCost
		}
		t.Fatal("the hello action carried no IHU")
		return 0
	}
	if got := rxcost(start); got != 96 {
		t.Errorf("a neighbor this node hears is advertised %d, want the configured 96", got)
	}

	s.mu.Lock()
	for elapsed := interval; elapsed <= time.Minute; elapsed += interval {
		s.sweepExpiredLocked(start.Add(elapsed))
	}
	s.mu.Unlock()
	if got := rxcost(start.Add(time.Minute)); got != MetricInfinity {
		t.Errorf("a neighbor gone quiet is advertised %d, so the far end keeps selecting a dead direction", got)
	}

	fresh, _, _ := captureSpeaker(t, Config{Hello: dur(interval)})
	b := netstack.NewPeer("b", func(raw []byte, _ byte) ([]byte, error) { return raw, nil }, func([]byte) error { return nil })
	handle := fresh.AddPeer(b)
	defer func() { handle.Close(); b.Close() }()
	freshCost := func() uint16 {
		fresh.mu.Lock()
		defer fresh.mu.Unlock()
		for _, tlv := range fresh.helloAction(fresh.neighbors[b.ID], time.Now()).tlvs {
			if tlv.Type == TLVIHU {
				ihu, _, err := DecodeIHU(tlv.Body)
				if err != nil {
					t.Fatal(err)
				}
				return ihu.RxCost
			}
		}
		t.Fatal("the hello action carried no IHU")
		return 0
	}
	if got := freshCost(); got != 96 {
		t.Errorf("a neighbor never heard from is advertised %d, which costs the adjacency an exchange", got)
	}
}

// RFC 8966 section 4.6.5 counts Hellos that were sent. A reservation the peer
// refuses is a Hello that never reached the wire, so keeping the increment
// tells the neighbor it lost one nobody transmitted, and with Hello loss now
// priced that is a cost the link never earned. The speaker retries every
// quarter interval, so a few seconds of a stalled tunnel burned several
// numbers and the neighbor's window read every one of them as loss.
//
// emitLocked runs the rollbacks of any action it could not place whole, which
// TestACongestedPeerDoesNotReopenTheWakePerPacket already covers. This pins
// the Hello's own rollback.
func TestRefusedHelloDoesNotSpendASequenceNumber(t *testing.T) {
	s, _, _ := captureSpeaker(t, Config{Hello: dur(time.Second)})
	addReachablePeer(s, "a", 96)

	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.neighbors["a"]
	before := n.helloSeqno
	for range 4 {
		action := s.helloAction(n, time.Now())
		for _, restore := range action.whenRefused {
			restore()
		}
	}
	if n.helloSeqno != before {
		t.Errorf("four refused Hellos spent %d sequence numbers, want none: the neighbor is told it lost them",
			n.helloSeqno-before)
	}
	// And a Hello that was placed does spend one, or the counter never moves
	// and every Hello this node sends repeats a number.
	s.helloAction(n, time.Now())
	if n.helloSeqno != before+1 {
		t.Errorf("a sent Hello moved the counter by %d, want 1", n.helloSeqno-before)
	}
}
