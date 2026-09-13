package esp

import "fmt"

// DefaultReplayWindow is deliberately wider than the minimum interoperable
// window. RFC 4303 section 3.4.3 says receivers should increase the window in
// high-speed environments; multicore IPsec senders routinely reorder bursts
// by more than the 32-packet minimum before they reach userspace.
const DefaultReplayWindow uint32 = 4096

// replayWindow is an XFRM-style circular anti-replay bitmap. A zero window
// disables replay checking, matching strongSwan's replay_window = 0 behavior.
type replayWindow struct {
	window uint32
	last   uint32
	mask   []uint64
}

func newReplayWindow(window uint32) replayWindow {
	return replayWindow{window: window, mask: make([]uint64, (uint64(window)+63)/64)}
}

func (w *replayWindow) check(seq uint32) error {
	if w.window == 0 {
		return nil
	}
	if seq == 0 {
		return fmt.Errorf("esp: sequence number 0 is invalid")
	}
	if w.last == 0 || seq > w.last {
		return nil
	}
	diff := w.last - seq
	if diff >= w.window {
		return fmt.Errorf("esp: sequence %d too old (window is %d packets behind %d)", seq, w.window, w.last)
	}
	if w.set(w.bit(w.last, diff)) {
		return fmt.Errorf("esp: sequence %d replayed", seq)
	}
	return nil
}

func (w *replayWindow) commit(seq uint32) {
	if w.window == 0 {
		return
	}
	var bit uint32
	if w.last == 0 {
		w.last, bit = seq, (seq-1)%w.window
	} else if seq > w.last {
		diff := seq - w.last
		if diff >= w.window {
			clear(w.mask)
		} else {
			w.clearRange((w.last-1)%w.window+1, diff-1)
		}
		w.last, bit = seq, (seq-1)%w.window
	} else {
		bit = w.bit(w.last, w.last-seq)
	}
	w.mark(bit)
}

// clearRange clears n bits from start, wrapping at the window. The positions a
// forward jump skips are one or two contiguous runs, so they come out as two
// partial words and one memclr rather than one division and one mask per bit.
//
// A peer chooses how far to jump, so it chooses how much of this it pays for,
// on the per-session commit emitter, which is single-threaded and holds the
// inbound SA's lock. Sequence numbers just under a window apart are the worst
// case: they skip the whole window on every packet and miss the full-clear
// path by one. Measured per packet against 3.3 ns for a peer that counts by
// one, before and after the memclr: 94 ns and 17 ns at the 4096 default, 24.8
// us and 1.07 us at the 1048576 the configuration allows. The second figure is
// now what the full clear beside it costs, which is the floor for a window
// that size. See BenchmarkReplayCommitJumpDistances.
func (w *replayWindow) clearRange(start, n uint32) {
	if n == 0 {
		return
	}
	start %= w.window
	if start+n > w.window {
		head := w.window - start
		w.clearSpan(start, head)
		w.clearSpan(0, n-head)
		return
	}
	w.clearSpan(start, n)
}

// clearSpan clears n bits from start without wrapping.
func (w *replayWindow) clearSpan(start, n uint32) {
	if n == 0 {
		return
	}
	end := start + n
	first, last := start/64, (end-1)/64
	if first == last {
		w.mask[first] &^= (^uint64(0) >> (64 - n)) << (start % 64)
		return
	}
	if offset := start % 64; offset != 0 {
		w.mask[first] &^= ^uint64(0) << offset
		first++
	}
	if tail := end % 64; tail != 0 {
		w.mask[last] &^= ^uint64(0) >> (64 - tail)
		last--
	}
	if first <= last {
		clear(w.mask[first : last+1])
	}
}

func (w *replayWindow) bit(last, diff uint32) uint32 {
	pos := (last - 1) % w.window
	return (pos + w.window - diff) % w.window
}
func (w *replayWindow) set(bit uint32) bool { return w.mask[bit/64]&(uint64(1)<<(bit%64)) != 0 }
func (w *replayWindow) mark(bit uint32)     { w.mask[bit/64] |= uint64(1) << (bit % 64) }
