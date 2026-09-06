package esp

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
)

const espBenchmarkBatchSize = 128

func benchmarkESPSuites(b *testing.B, run func(*testing.B, ChildSA, int)) {
	for _, suite := range []struct {
		name string
		id   uint16
		bits uint16
	}{
		{"AES_GCM_128", ENCRAESGCM16, 128},
		{"AES_GCM_256", ENCRAESGCM16, 256},
		{"ChaCha20_Poly1305", ENCRChaCha20Poly1305, 256},
	} {
		for _, size := range []int{64, 1400} {
			b.Run(fmt.Sprintf("%s/bytes=%d", suite.name, size), func(b *testing.B) {
				// Fixed synthetic keys; these packets never leave the benchmark.
				key := make([]byte, int(suite.bits)/8+4)
				for i := range key {
					key[i] = byte(i)
				}
				run(b, ChildSA{
					EncrID: suite.id, EncrKeyBits: suite.bits,
					LocalSPI: 1, RemoteSPI: 1,
					InboundKey: key, OutboundKey: key,
				}, size)
			})
		}
	}
}

func benchmarkESPPlaintext(size int) ([][]byte, []byte) {
	packets := make([][]byte, espBenchmarkBatchSize)
	headers := make([]byte, len(packets))
	for i := range packets {
		packets[i] = make([]byte, size)
		for j := range packets[i] {
			packets[i][j] = byte(i + j)
		}
		headers[i] = NextHeaderIPv4
	}
	return packets, headers
}

// BenchmarkESPEncrypt includes shared-SA sequence reservation, ESP framing,
// AEAD, and worker-owned reusable output buffers, as in the production path.
// GOMAXPROCS controls the number of workers encrypting on the same SA.
func BenchmarkESPEncrypt(b *testing.B) {
	benchmarkESPSuites(b, func(b *testing.B, child ChildSA, size int) {
		out, err := NewOutbound(child)
		if err != nil {
			b.Fatal(err)
		}
		packets, headers := benchmarkESPPlaintext(size)
		b.SetBytes(int64(len(packets) * size))
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var sealed [][]byte
			for pb.Next() {
				r, err := out.ReserveSequenceRange(len(packets))
				if err != nil {
					b.Error(err)
					return
				}
				sealed, err = r.SealBatchInto(packets, headers, sealed)
				if err != nil {
					b.Error(err)
					return
				}
			}
		})
		b.StopTimer()
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(packets)), "ns/packet")
	})
}

type espBenchmarkDecryptBatch struct {
	first   int
	raw     [][]byte
	results []AuthenticatedPacket
	done    chan struct{}
}

// BenchmarkESPDecrypt measures in-place authentication and ordered replay
// commits on one shared SA with the default replay window enabled. One core
// runs inline; multiple cores authenticate bounded batches in parallel.
//
// A round contains 8192 distinct, pre-encrypted packets. Only after all workers
// and commits finish is the replay window reset to reuse this synthetic stream.
// Copying ciphertext into reusable receive buffers is timed; fixture encryption,
// key setup, UDP/TUN I/O, routing, and the client's queues are not measured.
func BenchmarkESPDecrypt(b *testing.B) {
	benchmarkESPSuites(b, func(b *testing.B, child ChildSA, size int) {
		const batchCount = 64
		const packetCount = batchCount * espBenchmarkBatchSize
		out, err := NewOutbound(child)
		if err != nil {
			b.Fatal(err)
		}
		in, err := NewInbound(child)
		if err != nil {
			b.Fatal(err)
		}
		plain, headers := benchmarkESPPlaintext(size)
		wire := make([][]byte, 0, packetCount)
		for range batchCount {
			r, err := out.ReserveSequenceRange(len(plain))
			if err != nil {
				b.Fatal(err)
			}
			sealed, err := r.SealBatch(plain, headers)
			if err != nil {
				b.Fatal(err)
			}
			wire = append(wire, sealed...)
		}
		workers := runtime.GOMAXPROCS(0)
		slots := make([]*espBenchmarkDecryptBatch, min(2*workers, batchCount))
		for i := range slots {
			batch := &espBenchmarkDecryptBatch{
				raw:     make([][]byte, espBenchmarkBatchSize),
				results: make([]AuthenticatedPacket, espBenchmarkBatchSize),
				done:    make(chan struct{}, 1),
			}
			storage := make([]byte, len(wire[0])*len(batch.raw))
			for j := range batch.raw {
				start := j * len(wire[0])
				batch.raw[j] = storage[start : start+len(wire[0])]
			}
			slots[i] = batch
		}
		authenticate := func(batch *espBenchmarkDecryptBatch) {
			for i, raw := range batch.raw {
				copy(raw, wire[batch.first+i])
			}
			batch.results = in.AuthenticateBatchInPlace(batch.raw, batch.results[:0])
		}
		commit := func(batch *espBenchmarkDecryptBatch) {
			CommitBatch(batch.results)
			for i, result := range batch.results {
				packet, nextHeader, err := result.Plaintext()
				if err != nil {
					b.Fatal(err)
				}
				if len(packet) != size || nextHeader != NextHeaderIPv4 || packet[0] != byte(i) {
					b.Fatal("incorrect decrypted packet")
				}
			}
			clear(batch.results)
		}
		jobs := make(chan *espBenchmarkDecryptBatch, len(slots))
		var wg sync.WaitGroup
		if workers > 1 {
			for range workers {
				wg.Go(func() {
					for batch := range jobs {
						authenticate(batch)
						batch.done <- struct{}{}
					}
				})
			}
		}
		defer func() {
			close(jobs)
			wg.Wait()
		}()
		b.SetBytes(int64(packetCount * size))
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			// There are no outstanding workers or commits between rounds.
			in.window.last = 0
			clear(in.window.mask)
			if workers == 1 {
				batch := slots[0]
				for j := range batchCount {
					batch.first = j * espBenchmarkBatchSize
					authenticate(batch)
					commit(batch)
				}
				continue
			}
			for i, batch := range slots {
				batch.first = i * espBenchmarkBatchSize
				jobs <- batch
			}
			next := len(slots)
			for j := range batchCount {
				batch := slots[j%len(slots)]
				<-batch.done
				commit(batch)
				if next < batchCount {
					batch.first = next * espBenchmarkBatchSize
					jobs <- batch
					next++
				}
			}
		}
		b.StopTimer()
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*packetCount), "ns/packet")
	})
}
