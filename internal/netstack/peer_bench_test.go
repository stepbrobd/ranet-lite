package netstack

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

var oneByte = []byte{0}

func benchSealer(raw [][]byte, _ []byte, storage [][]byte) ([][]byte, error) {
	storage = storage[:0]
	for range raw {
		// One byte stands in for the ciphertext. The point is the pipeline,
		// and a real seal would dominate the measurement.
		storage = append(storage, oneByte)
	}
	return storage, nil
}

func benchPeer(b *testing.B) (*Peer, *atomic.Uint64) {
	b.Helper()
	var sent atomic.Uint64
	peer := NewPeerReserved("bench",
		func(int) (BatchSealer, error) { return benchSealer, nil },
		func(sealed [][]byte) error {
			sent.Add(uint64(len(sealed)))
			return nil
		})
	b.Cleanup(peer.Close)
	return peer, &sent
}

// The send pipeline's own cost on the path routed traffic takes, with the
// crypto and the syscall replaced by nothing. What remains is exactly what
// ordered transmission buys and charges for: the slot semaphore, the ticket
// and sequence-range allocation under one lock, four allocations, the handoff
// to the ordered sender, and its reorder map.
//
// enqueue is the data path and does not wait for the send; transmit is the
// control path, measured separately below, and does.
func benchmarkPeerEnqueue(b *testing.B, workers, batch int) {
	peer, _ := benchPeer(b)
	payload := make([]byte, 1400)
	// Deliberately no SetBytes. append stores the slice header and the stand-in
	// sealer never reads it, so no payload byte is touched; reporting MB/s over
	// them prints a figure four orders of magnitude above what the pipeline
	// really moves. ns/packet below is the honest axis.
	b.ReportAllocs()
	b.ResetTimer()

	var group sync.WaitGroup
	each := max(b.N/workers, 1)
	for range workers {
		group.Go(func() {
			for range each {
				pb := peer.reserveBatch(batch)
				for range batch {
					pb.append(payload, 4)
				}
				if err := pb.enqueue(); err != nil {
					b.Error(err)
					return
				}
			}
		})
	}
	group.Wait()
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(each*workers*batch), "ns/packet")
}

// One worker is the floor: no contention, just the pipeline's fixed cost.
func BenchmarkPeerEnqueueSerialSinglePacket(b *testing.B) { benchmarkPeerEnqueue(b, 1, 1) }
func BenchmarkPeerEnqueueSerialBatched(b *testing.B)      { benchmarkPeerEnqueue(b, 1, 128) }

// One packet per batch is the worst case for a per-batch cost, and it is what
// a TCP ACK stream produces: each arrives as its own TUN read.
func BenchmarkPeerEnqueueParallelSinglePacket(b *testing.B) {
	benchmarkPeerEnqueue(b, runtime.GOMAXPROCS(0), 1)
}

// A full TUN read batch, where the fixed cost is amortized over 128 packets.
func BenchmarkPeerEnqueueParallelBatched(b *testing.B) {
	benchmarkPeerEnqueue(b, runtime.GOMAXPROCS(0), 128)
}

// The control path, which Babel uses through SendRaw: one packet, and the
// caller waits for the ordered sender to report the result.
func BenchmarkPeerTransmitSerial(b *testing.B) {
	peer, _ := benchPeer(b)
	payload := make([]byte, 1400)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		pb := peer.reserveBatch(1)
		pb.append(payload, 4)
		if err := pb.transmit(); err != nil {
			b.Fatal(err)
		}
	}
}

// The copy-and-release step every inbound packet takes. A sync.Pool holds an
// any, which a slice header does not fit in, so pooling slices allocates once
// per packet released; pooling the array pointer does not.
func BenchmarkInboundCopyAndRelease(b *testing.B) {
	for _, size := range []int{64, 1400} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			raw := make([][]byte, 128)
			backing := make([]byte, len(raw)*size)
			for i := range raw {
				raw[i] = backing[i*size : (i+1)*size]
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				releaseInboundPackets(copyInboundPackets(raw))
			}
		})
	}
}
