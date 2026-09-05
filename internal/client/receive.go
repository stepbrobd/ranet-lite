package client

import (
	"sync"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/transport"
)

type inboundDecrypted struct {
	authenticated *esp.AuthenticatedPacket
	err           error
}

type inboundBatch struct {
	ticket  uint64
	results []inboundDecrypted
}

// emitInboundBatches absorbs out-of-order worker completions and emits only
// receive-order results. Consecutive batches that are already complete are
// merged into one call so flow bucketing and TUN GRO see a larger vector
// without delaying a lone packet.
func emitInboundBatches(completed <-chan *inboundBatch, recycle chan<- *inboundBatch, emit func([]inboundDecrypted)) {
	pending := make(map[uint64]*inboundBatch, cap(completed))
	merged := make([]inboundDecrypted, 0, 128)
	next := uint64(0)
	for batch := range completed {
		pending[batch.ticket] = batch
		merged = merged[:0]
		for {
			ready := pending[next]
			if ready == nil {
				break
			}
			delete(pending, next)
			merged = append(merged, ready.results...)
			clear(ready.results)
			ready.results = ready.results[:0]
			recycle <- ready
			next++
		}
		if len(merged) != 0 {
			emit(merged)
			clear(merged)
		}
	}
}

// receiveESP keeps crypto parallel and replay commits in intake order. On one
// core those stages run inline, avoiding queues that cannot provide parallelism.
func receiveESP(mux *transport.Mux, workers int, decrypt func([][]byte, []inboundDecrypted) []inboundDecrypted, emit func([]inboundDecrypted)) error {
	if workers <= 1 {
		results := make([]inboundDecrypted, 0, 128)
		for {
			_, packets, err := mux.RecvESPBatchConcurrent()
			if err != nil {
				return err
			}
			results = decrypt(packets, results[:0])
			emit(results)
			clear(results)
		}
	}
	queueSize := 2 * workers
	free := make(chan *inboundBatch, queueSize)
	completed := make(chan *inboundBatch, queueSize)
	for range queueSize {
		free <- &inboundBatch{results: make([]inboundDecrypted, 0, 128)}
	}
	emitterDone := make(chan struct{})
	go func() {
		defer close(emitterDone)
		emitInboundBatches(completed, free, emit)
	}()
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for {
				batch := <-free
				ticket, packets, err := mux.RecvESPBatchConcurrent()
				if err != nil {
					free <- batch
					errs <- err
					return
				}
				batch.ticket = ticket
				batch.results = decrypt(packets, batch.results)
				completed <- batch
			}
		})
	}
	err := <-errs
	_ = mux.Close()
	wg.Wait()
	close(completed)
	<-emitterDone
	return err
}
