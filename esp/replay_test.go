package esp

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// referenceWindow is the plain RFC 4303 section 3.4.3 window: a bitmap indexed
// from the highest sequence seen, rebuilt from scratch on every step. It is
// obviously correct and obviously slow, so it serves as a reference.
type referenceWindow struct {
	window uint32
	last   uint32
	seen   map[uint32]bool
}

func (r *referenceWindow) check(seq uint32) bool {
	if seq == 0 {
		return false
	}
	if r.last != 0 && seq <= r.last {
		if r.last-seq >= r.window {
			return false
		}
		if r.seen[seq] {
			return false
		}
	}
	return true
}

func (r *referenceWindow) commit(seq uint32) {
	r.seen[seq] = true
	if seq > r.last {
		r.last = seq
	}
	for old := range r.seen {
		if r.last-old >= r.window {
			delete(r.seen, old)
		}
	}
}

// The word-wise clear has to agree with the reference at every window size and
// every jump distance, including the wrap the circular index makes possible.
func TestReplayWindowMatchesReference(t *testing.T) {
	for _, window := range []uint32{1, 2, 3, 32, 63, 64, 65, 100, 128, 4096} {
		t.Run(fmt.Sprint(window), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(uint64(window), 7))
			for seed := 0; seed < 50; seed++ {
				w := newReplayWindow(window)
				ref := &referenceWindow{window: window, seen: map[uint32]bool{}}
				var highest uint32
				for step := 0; step < 400; step++ {
					var seq uint32
					switch rng.IntN(5) {
					case 0: // in order
						seq = highest + 1
					case 1: // just under a window forward, the worst case
						seq = highest + window - 1
					case 2: // a replay at the window edge
						seq = highest - min(highest, window-1) + 1
					case 3: // far past
						seq = highest - min(highest, window*2)
					default:
						seq = uint32(rng.IntN(int(highest) + int(window) + 2))
					}
					want := ref.check(seq)
					got := w.check(seq) == nil
					if got != want {
						t.Fatalf("window %d seed %d step %d: check(%d) = %v, reference says %v",
							window, seed, step, seq, got, want)
					}
					if !want {
						continue
					}
					w.commit(seq)
					ref.commit(seq)
					highest = max(highest, seq)
				}
			}
		})
	}
}

// The cost of one commit must not depend on how far the peer chose to jump.
func BenchmarkReplayCommitJumpDistances(b *testing.B) {
	// The largest window Config.Validate accepts is measured too: a peer
	// jumping just under it skips the whole window on every packet, which is
	// the case clearSpan's memclr exists for.
	for _, window := range []uint32{DefaultReplayWindow, 1 << 20} {
		for _, jump := range []uint32{1, window / 2, window - 1, window} {
			b.Run(fmt.Sprintf("window=%d/jump=%d", window, jump), func(b *testing.B) {
				w := newReplayWindow(window)
				seq := uint32(1)
				w.commit(seq)
				b.ResetTimer()
				for b.Loop() {
					seq += jump
					if seq < jump { // wrapped, start over rather than measure the reset
						seq = 1
						w = newReplayWindow(window)
					}
					w.commit(seq)
				}
			})
		}
	}
}

// clearRange has to clear exactly the bits the per-bit loop did, wrap
// included. Exhaustive at a small window, which is where the wrap is easy to
// get wrong.
func TestClearRangeClearsExactlyItsBits(t *testing.T) {
	for _, window := range []uint32{1, 2, 7, 64, 65, 130} {
		for start := uint32(0); start < window; start++ {
			for n := uint32(0); n <= window; n++ {
				got := newReplayWindow(window)
				want := newReplayWindow(window)
				for i := range got.mask {
					got.mask[i], want.mask[i] = ^uint64(0), ^uint64(0)
				}
				got.clearRange(start, n)
				for i := uint32(0); i < n; i++ {
					bit := (start + i) % window
					want.mask[bit/64] &^= uint64(1) << (bit % 64)
				}
				for i := range got.mask {
					if got.mask[i] != want.mask[i] {
						t.Fatalf("window %d start %d n %d: word %d is %#016x, want %#016x",
							window, start, n, i, got.mask[i], want.mask[i])
					}
				}
			}
		}
	}
}

// A peer chooses its own sequence numbers, so the cost of one commit must not
// be proportional to how far it jumped. Both figures are measured in the same
// run on the same machine.
//
// The threshold has to sit below what the word-at-a-time loop costs, not only
// below the per-bit loop it replaced: the per-bit form was about three
// thousand times the in-order case and the word form is thirty to forty-five,
// so a threshold sized for the first passes with the second still in place.
// Twenty is under the word loop and well over the memclr's fifteen.
func TestReplayCommitCostDoesNotFollowJumpDistance(t *testing.T) {
	const window = DefaultReplayWindow
	measure := func(jump uint32) time.Duration {
		const runs = 20000
		best := time.Duration(1<<62 - 1)
		for range 5 {
			w := newReplayWindow(window)
			seq := uint32(1)
			w.commit(seq)
			start := time.Now()
			for range runs {
				seq += jump
				if seq < jump {
					seq, w = 1, newReplayWindow(window)
				}
				w.commit(seq)
			}
			best = min(best, time.Since(start)/runs)
		}
		return best
	}
	inOrder, worst := measure(1), measure(window-1)
	if inOrder <= 0 {
		t.Skip("the clock is too coarse to measure this")
	}
	if ratio := worst / inOrder; ratio > 20 {
		t.Errorf("a commit that jumps %d costs %s against %s in order, %dx, "+
			"so the cost still follows the distance the peer chose", window-1, worst, inOrder, ratio)
	}
}

// The margin between asking for a rekey and refusing to send is a time budget:
// two round trips have to complete inside it, possibly behind an exchange that
// is already outstanding. Expressed as a packet count it shrinks with the link
// rate, and this implementation's own measured rate left it at milliseconds.
func TestProactiveRekeyLeavesTimeAndNotJustPackets(t *testing.T) {
	margin := uint64(0xffffffff) - ProactiveRekeySequence
	// A million packets per second is what 12.7 Gbit/s at path MTU comes to,
	// and small packets go several times faster.
	const perSecond = 1_000_000
	if seconds := margin / perSecond; seconds < 60 {
		t.Errorf("the rekey margin is %d packets, %d seconds at %d packets per second, "+
			"which is not enough for two round trips behind a pending exchange",
			margin, seconds, perSecond)
	}
	// It still has to be a small fraction of the space, or the SA spends its
	// life rekeying.
	if margin > 0xffffffff/8 {
		t.Errorf("the rekey margin is %d packets, over an eighth of the sequence space", margin)
	}
}

// The circular index arithmetic adds a window to a position, so a window above
// half the sequence space overflows the 32-bit counter it is computed in, and
// a caller of the exported option can ask for any uint32. Clamping is also
// what keeps the mask allocation bounded: one bit per sequence number means
// 2^32 of them is half a gigabyte per SA.
func TestReplayWindowIsClamped(t *testing.T) {
	var sa InboundSA
	WithReplayWindow(1 << 31)(&sa)
	if sa.window.window != MaxReplayWindow {
		t.Errorf("a window of 2^31 was built as %d, want it clamped to %d", sa.window.window, MaxReplayWindow)
	}
	if got, want := uint64(len(sa.window.mask))*64, uint64(MaxReplayWindow); got < want || got > want+64 {
		t.Errorf("the mask holds %d bits for a %d wide window", got, MaxReplayWindow)
	}

	// Anything at or below the cap is taken as asked, including the zero that
	// turns replay checking off.
	for _, window := range []uint32{0, 1, 64, MaxReplayWindow} {
		var sa InboundSA
		WithReplayWindow(window)(&sa)
		if sa.window.window != window {
			t.Errorf("a window of %d was built as %d", window, sa.window.window)
		}
	}
}
