package netstack

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReservedPeerKeepsCiphertextUntilSendCompletes(t *testing.T) {
	for _, sendErr := range []error{nil, errors.New("transport failed")} {
		t.Run(fmt.Sprint(sendErr), func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			var sent []byte
			p := NewPeerReserved("peer", func(int) (BatchSealer, error) {
				return func(raw [][]byte, _ []byte, reuse [][]byte) ([][]byte, error) {
					if len(reuse) == 0 {
						reuse = [][]byte{{0}}
					}
					reuse[0][0] = raw[0][0]
					return reuse, nil
				}, nil
			}, func(packets [][]byte) error {
				if len(sent) == 0 {
					close(started)
					<-release
				}
				for _, packet := range packets {
					sent = append(sent, packet[0])
				}
				return sendErr
			})
			t.Cleanup(func() { once.Do(func() { close(release) }); p.Close() })
			first := p.reserveBatch(1)
			first.append([]byte{1}, 0)
			first.done = make(chan error, 1)
			if err := first.enqueue(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("sender did not start")
			}
			if first.storage == nil {
				t.Fatal("ciphertext recycled while transport still owns it")
			}
			second := p.reserveBatch(1)
			second.append([]byte{2}, 0)
			second.done = make(chan error, 1)
			if err := second.enqueue(); err != nil {
				t.Fatal(err)
			}
			once.Do(func() { close(release) })
			for _, b := range []*peerBatch{first, second} {
				select {
				case err := <-b.done:
					if !errors.Is(err, sendErr) {
						t.Fatalf("send result = %v, want %v", err, sendErr)
					}
				case <-time.After(time.Second):
					t.Fatal("sender did not complete")
				}
				if b.storage != nil || b.sealed != nil {
					t.Fatal("completed batch retained pooled ciphertext")
				}
			}
			if !bytes.Equal(sent, []byte{1, 2}) {
				t.Fatalf("in-flight ciphertext was overwritten: got %v", sent)
			}
		})
	}
}

// The speaker walks every neighbor from one goroutine, and Receive runs on the
// sending peer's decrypt path, so a control send that waits on a backed-up
// peer stops every other neighbor with it and lets two such peers hold each
// other's emitter. Dropping keeps the stall local.
func TestSendRawOrDropDoesNotWaitForBackedUpPeer(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var sent atomic.Int64
	peer := NewPeerReserved("stalled", func(int) (BatchSealer, error) {
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			return append(out[:0], raw...), nil
		}, nil
	}, func(sealed [][]byte) error {
		<-release
		sent.Add(int64(len(sealed))) // the sender merges batches into one call
		return nil
	})
	defer func() { unblock(); peer.Close() }()

	// Fill the queue, then keep going against a transport that never returns.
	// Each attempt gives up rather than waiting for a place that is never
	// coming, so the whole run is bounded. The sends are on their own
	// goroutine so a blocking one is reported rather than hanging.
	const beyond = 20
	attempts := cap(peer.controlSlots) + beyond
	dropped := make(chan int, 1)
	go func() {
		n := 0
		for range attempts {
			if err := sendOrDrop(peer, []byte("control packet"), 41); errors.Is(err, ErrSendQueueFull) {
				n++
			}
		}
		dropped <- n
	}()
	var lost int
	budget := 10 * time.Second
	select {
	case lost = <-dropped:
	case <-time.After(budget):
		t.Fatalf("%d control sends against a stalled peer took longer than %s", attempts, budget)
	}
	if lost == 0 {
		t.Fatal("nothing was dropped, so the queue never filled and this proves nothing")
	}

	// A dropped packet must not have consumed a ticket or a sequence range,
	// or the ordered sender would never reach the batches behind it.
	unblock()
	drained := time.Now().Add(10 * time.Second)
	for int(sent.Load()) < attempts-lost {
		if time.Now().After(drained) {
			t.Fatalf("the sender stalled at %d of %d queued packets", sent.Load(), attempts-lost)
		}
		time.Sleep(time.Millisecond)
	}
}

// A queue full of bulk data drops control packets, and the caller has to be
// told so it can give back whatever the packet consumed. What must not happen
// is a drop reported as a send.
func TestControlPacketDropsAreReported(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	peer := NewPeerReserved("busy", func(int) (BatchSealer, error) {
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			return append(out[:0], raw...), nil
		}, nil
	}, func([][]byte) error {
		<-release
		return nil
	})
	defer func() { unblock(); peer.Close() }()

	var dropped int
	for range cap(peer.controlSlots) + 50 {
		if err := sendOrDrop(peer, []byte("control packet"), 41); errors.Is(err, ErrSendQueueFull) {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("a stalled peer accepted every control packet, so nothing tells the caller to redo it")
	}

	// Once the transport drains, the peer takes them again.
	unblock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := sendOrDrop(peer, []byte("control packet"), 41); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the peer never took a control packet again after its transport drained")
		}
		time.Sleep(time.Millisecond)
	}
}

// A peer whose outbound SA cannot give out a sequence range transmits nothing,
// which is how a peer that has just deleted its Child SA looks from this
// side. Counting only the slot refusals would leave the drop counter reading
// zero through exactly that window.
func TestReservationFailureCountsAsADrop(t *testing.T) {
	refused := errors.New("no child sa")
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) { return nil, refused },
		func([][]byte) error { return nil })
	defer peer.Close()

	// The caller is told, so it can give back whatever the packet consumed,
	// and the place is sent anyway so the sender is not left waiting for it.
	if _, err := peer.ReserveRawOrDrop([]byte("packet"), 41); !errors.Is(err, refused) {
		t.Errorf("reserving reported %v, want the reservation's own error", err)
	}
	if got := peer.Dropped(); got != 1 {
		t.Errorf("the peer counted %d drops, want the one packet it could not send", got)
	}
}

// Babel and the dataplane must not share one budget. The data budget is sized
// by the core count, a bulk transfer consumes all of it, and sharing dropped
// 98 of every 100 control packets under load. Three lost hellos withdraw every
// route through the peer, so the transfer then has nowhere to go: the loss
// feeds itself.
func TestControlTrafficHasItsOwnBudget(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { <-release; return nil })
	defer func() { unblock(); peer.Close() }()

	// The dataplane takes everything it is allowed, which is how a bulk
	// transfer through a backpressured socket looks from here.
	for i := range cap(peer.slots) {
		if peer.reserveBatchNow(1) == nil {
			t.Fatalf("the dataplane was refused place %d below its own budget", i)
		}
	}
	if peer.reserveBatchNow(1) != nil {
		t.Fatal("the dataplane took more than its budget, so this proves nothing")
	}

	// Babel still gets through, for as many packets as a periodic dump needs.
	for i := range cap(peer.controlSlots) {
		if _, err := peer.ReserveRawOrDrop([]byte("hello"), 41); err != nil {
			t.Fatalf("control packet %d was dropped because the dataplane had filled its own budget: %v", i, err)
		}
	}
	if _, err := peer.ReserveRawOrDrop([]byte("hello"), 41); err == nil {
		t.Error("control traffic is bounded by nothing of its own")
	}
}

// A closed peer must refuse everything it is offered. A select with both the
// budget and the stop channel ready picks uniformly, so half of what a closed
// peer was offered was accepted, reported as sent, never transmitted, and
// never counted as dropped, which is the one counter that would have shown it.
func TestClosedPeerRefusesAndCountsEverything(t *testing.T) {
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { return nil })
	peer.Close()

	const offered = 64
	for range offered {
		if place, err := peer.ReserveRawOrDrop([]byte("packet"), 41); err == nil {
			place.Send()
			t.Fatal("a closed peer took a control packet")
		}
		if peer.reserveBatchNow(1) != nil {
			t.Fatal("a closed peer took a data batch")
		}
	}
	if got := peer.Dropped(); got != 2*offered {
		t.Errorf("the peer counted %d of %d packets it refused", got, 2*offered)
	}
}

// p.completed is sized to hold every batch the two budgets can hand a ticket
// to, so on a closing peer both arms of the enqueue select are ready and Go
// picks uniformly. Half of what was reserved before Close and encrypted after
// it was reported as sent, never transmitted, and counted by nothing, which is
// the one signal that would have shown it. Every session teardown and
// replacement creates that overlap.
func TestBatchReservedBeforeCloseIsRefusedAndCounted(t *testing.T) {
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { t.Error("a closed peer transmitted"); return nil })

	// Reserved while the peer is open, so each holds a ticket and a slot. The
	// dataplane budget is sized by the core count, so this takes all of it.
	reserved := cap(peer.slots)
	var batches []*peerBatch
	for i := range reserved {
		b := peer.reserveBatchNow(1)
		if b == nil {
			t.Fatalf("the peer refused reservation %d while it was open", i)
		}
		b.append([]byte{1}, 0)
		batches = append(batches, b)
	}
	peer.Close()

	for i, b := range batches {
		if err := b.enqueue(); err == nil {
			t.Fatalf("batch %d was accepted by a closed peer and will never be transmitted", i)
		}
	}
	if got := peer.Dropped(); got != uint64(reserved) {
		t.Errorf("the peer counted %d of the %d packets it will never send", got, reserved)
	}
}

// A batch whose sealer could not give out a sequence range is counted where
// that happens, which is the case a peer that deleted its Child SA presents,
// and Close follows on the same path. Counting it again when the closed peer
// refuses it makes the drop counter report more packets than the peer was
// ever given.
func TestReservationFailureIsCountedOnce(t *testing.T) {
	refused := errors.New("no child sa")
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) { return nil, refused },
		func([][]byte) error { return nil })

	b := peer.reserveBatchNow(1)
	if b == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	b.append([]byte{1}, 0)
	if peer.Dropped() != 1 {
		t.Fatalf("the sealer failure counted %d, want one", peer.Dropped())
	}
	peer.Close()
	if err := b.enqueue(); err == nil {
		t.Fatal("a closed peer accepted the batch")
	}
	if got := peer.Dropped(); got != 1 {
		t.Errorf("the peer counted %d drops for one packet it was given once", got)
	}
}

// The reservation is the only place a batch is counted early, so that is the
// only thing abandon may treat as already counted. A batch that reserved a
// sequence range and then failed to seal has its packets counted by nothing
// else, and reading the error field instead of a flag that says "counted"
// silently puts every such packet outside the one counter that would show it.
func TestSealFailureOnAClosedPeerIsStillCounted(t *testing.T) {
	sealing := errors.New("seal")
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) {
			return func([][]byte, []byte, [][]byte) ([][]byte, error) { return nil, sealing }, nil
		},
		func([][]byte) error { t.Error("a closed peer transmitted"); return nil })

	b := peer.reserveBatchNow(2)
	if b == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	b.append([]byte{1}, 0)
	b.append([]byte{2}, 0)
	if got := peer.Dropped(); got != 0 {
		t.Fatalf("a reservation that succeeded counted %d drops", got)
	}
	peer.Close()
	if err := b.enqueue(); err == nil {
		t.Fatal("a closed peer accepted the batch")
	}
	if got := peer.Dropped(); got != 2 {
		t.Errorf("the peer counted %d of the 2 packets it will never send", got)
	}
}

// Every packet a peer will not send has to reach the counter exactly once, and
// the sender's own stop path was the hole: a batch already queued behind the
// one the sender is waiting for is holding a transmission slot and a place in
// the transmission order, and returning from the loop left both, with its
// packets counted by nothing.
func TestBatchesStrandedInTheSenderAreCounted(t *testing.T) {
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { return nil })

	var discarded []uint64
	peer.noteDiscarded = func(ticket uint64) { discarded = append(discarded, ticket) }
	first, second, third := peer.reserveBatchNow(3), peer.reserveBatchNow(5), peer.reserveBatchNow(7)
	if first == nil || second == nil || third == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	for _, reserved := range []struct {
		batch *peerBatch
		count int
	}{{first, 3}, {second, 5}, {third, 7}} {
		for range reserved.count {
			reserved.batch.append([]byte{1}, 0)
		}
	}
	// The first never goes in, so the sender holds the other two waiting for
	// it, which is where Close finds them. They are queued out of order so the
	// order they come back in is the sender's doing rather than the caller's.
	for _, batch := range []*peerBatch{third, second} {
		if err := batch.enqueue(); err != nil {
			t.Fatalf("an open peer refused the batch: %v", err)
		}
	}
	peer.Close()
	if err := first.enqueue(); err == nil {
		t.Fatal("a closed peer accepted the batch")
	}
	if got := peer.Dropped(); got != 15 {
		t.Errorf("the peer counted %d of the 15 packets it will never send", got)
	}
	if len(discarded) != 2 {
		t.Fatalf("the sender gave back %d batches, want the two it was holding", len(discarded))
	}
	// Given back in ticket order, which is the order everything else in this
	// peer observes: a caller watching the counter while its own batch is
	// discarded would otherwise see them arrive in map order.
	if !slices.IsSorted(discarded) {
		t.Errorf("the sender gave batches back in ticket order %v", discarded)
	}
}

// A batch that could not seal produced nothing for the transport, so its
// packets are gone whether or not the peer is closing. The sender logged that
// and counted nothing, which put every packet lost this way outside the one
// counter that would show it.
func TestSealFailureOnAnOpenPeerIsCounted(t *testing.T) {
	sealing := errors.New("seal")
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) {
			return func([][]byte, []byte, [][]byte) ([][]byte, error) { return nil, sealing }, nil
		},
		func([][]byte) error { t.Error("a batch that sealed nothing reached the transport"); return nil })
	defer peer.Close()

	b := peer.reserveBatchNow(4)
	if b == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	for range 4 {
		b.append([]byte{1}, 0)
	}
	if err := b.transmit(); !errors.Is(err, sealing) {
		t.Fatalf("transmit reported %v, want the sealer's own error", err)
	}
	if got := peer.Dropped(); got != 4 {
		t.Errorf("the peer counted %d of the 4 packets that never reached the transport", got)
	}
}

// A batch that sealed and then lost the syscall was attempted, which is not
// the same as one this peer refused: the first says the link or the socket is
// failing and the second says this node is out of room. Neither reached a
// counter at all before, so a link losing everything read as a quiet node.
func TestATransportFailureIsCountedApartFromARefusal(t *testing.T) {
	sending := errors.New("no route to host")
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { return sending })
	defer peer.Close()

	b := peer.reserveBatchNow(3)
	if b == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	for range 3 {
		b.append([]byte{1}, 0)
	}
	if err := b.transmit(); !errors.Is(err, sending) {
		t.Fatalf("transmit reported %v, want the transport's own error", err)
	}
	if got := peer.SendFailed(); got != 3 {
		t.Errorf("the peer counted %d of the 3 packets the transport lost", got)
	}
	if got := peer.Dropped(); got != 0 {
		t.Errorf("it also counted %d as refused, which means this node ran out of room", got)
	}
}

// A peer whose Child SA the other end deleted fails every reservation from
// then on, so a line per failed batch is a line per TUN batch for as long as
// that lasts. The count is exact; only the saying of it is bounded.
func TestATransportFailureIsSaidRarely(t *testing.T) {
	var lines atomic.Int64
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(countingWriter{&lines}, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	sending := errors.New("no route to host")
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				return append(out[:0], raw...), nil
			}, nil
		},
		func([][]byte) error { return sending })
	defer peer.Close()

	// The transmission budget is the core count, and the sender gives a slot
	// back only after the transport returns, so a batch that finds none free
	// is waited for rather than counted as a failure to send.
	const batches = 200
	for sent := 0; sent < batches; {
		b := peer.reserveBatchNow(1)
		if b == nil {
			time.Sleep(time.Millisecond)
			continue
		}
		b.append([]byte{1}, 0)
		if err := b.enqueue(); err != nil {
			t.Fatalf("an open peer refused the batch: %v", err)
		}
		sent++
	}
	deadline := time.Now().Add(10 * time.Second)
	for lines.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no failure was said at all, so an operator sees nothing")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := lines.Load(); got != 1 {
		t.Errorf("%d failed batches wrote %d lines, want the one the interval allows", batches, got)
	}
}

// countingWriter counts writes rather than keeping them, the unit a report
// that must not be one line per batch is measured in.
type countingWriter struct{ n *atomic.Int64 }

func (w countingWriter) Write(b []byte) (int, error) { w.n.Add(1); return len(b), nil }

// A batch that lands in the queue after the sender's last drain is read by
// nobody: never transmitted, never counted, its slot never given back, and its
// caller told it went. Testing the stop channel before the send cannot close
// that, because the drain happens between the test and the send, and the queue
// is sized so its send arm is always ready. Every teardown and every session
// replacement creates the window.
//
// The window is narrow without help: reverting the fix loses about one batch
// in ninety thousand here and none at all in some runs. Under -race, which is
// how this suite and the flake check run it, the scheduler widens it enough to
// lose one every time.
func TestNoBatchIsLostBetweenTheStopCheckAndTheQueue(t *testing.T) {
	const teardowns, producers, packets = 2000, 4, 6
	for range teardowns {
		var transmitted atomic.Int64
		peer := NewPeerReserved("peer",
			func(int) (BatchSealer, error) {
				return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
					return append(out[:0], raw...), nil
				}, nil
			},
			func(sealed [][]byte) error { transmitted.Add(int64(len(sealed))); return nil })

		var sent atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range producers {
			wg.Go(func() {
				<-start
				for range packets {
					b := peer.reserveBatchNow(1)
					if b == nil {
						continue // the budget was full, which is counted where it happens
					}
					b.append([]byte{1}, 0)
					if err := b.enqueue(); err == nil {
						sent.Add(1)
					}
				}
			})
		}
		close(start)
		peer.Close()
		wg.Wait()

		// Counted against what reached the transport, not against what the
		// caller was told: a lost batch was told it went, so a test that
		// believes the caller cannot see the loss at all.
		offered := int64(producers * packets)
		if got := transmitted.Load() + int64(peer.Dropped()); got != offered {
			t.Fatalf("%d packets were reserved, %d reached the transport and %d were counted as dropped",
				offered, transmitted.Load(), peer.Dropped())
		}
		// enqueue returning nil promises the queue took the batch, not that it
		// left: the sender may still give it back, and that is counted above.
		_ = sent.Load()
		// And every transmission slot came back, or the next session on this
		// peer has fewer of them for good.
		if got := len(peer.slots) + len(peer.controlSlots); got != 0 {
			t.Fatalf("%d transmission slots were not given back", got)
		}
	}
}

// A compatibility peer has no sender goroutine, so nothing between the
// encryptor and the transport counted anything: NewPeer and NewPeerBatched are
// exported with a Dropped that was structurally zero. A partial failure is the
// case that shows it, because the batch reports an error for the whole of
// itself while some of its packets did leave.
func TestACompatibilityPeerCountsWhatItLoses(t *testing.T) {
	refused := errors.New("no key")
	var seen int
	peer := NewPeerBatched("peer",
		func(raw []byte, _ byte) ([]byte, error) {
			seen++
			if seen == 2 {
				return nil, refused
			}
			return raw, nil
		},
		func(sealed [][]byte) error { return nil })

	b := peer.reserveBatchNow(3)
	if b == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	for range 3 {
		b.append([]byte{1}, 0)
	}
	if err := b.transmit(); !errors.Is(err, refused) {
		t.Fatalf("transmit reported %v, want the encryptor's own error", err)
	}
	if got := peer.Dropped(); got != 1 {
		t.Errorf("the peer counted %d of the one packet that never sealed", got)
	}
	if got := peer.SendFailed(); got != 0 {
		t.Errorf("it counted %d as lost by the transport, which took everything it was given", got)
	}
}

// Once the peer is closing, both arms of transmit's select are ready and Go
// picks uniformly, so a batch the sender had already transmitted was reported
// as closed about half the time. The sender always answers a batch that
// carries done, so a finished answer is the one to take.
func TestTransmitPrefersTheAnswerOverTheStopSignal(t *testing.T) {
	for range 200 {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		peer := NewPeerReserved("peer",
			func(int) (BatchSealer, error) {
				return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
					return append(out[:0], raw...), nil
				}, nil
			},
			func([][]byte) error {
				once.Do(func() { close(entered) })
				<-release
				return nil
			})

		b := peer.reserveBatchNow(1)
		if b == nil {
			t.Fatal("the peer refused a reservation while it was open")
		}
		b.append([]byte{1}, 0)
		done := make(chan error, 1)
		go func() { done <- b.transmit() }()

		// The transport has the batch, so the answer is about to arrive.
		<-entered
		// Closed directly rather than through Close, which would wait on the
		// sender this test has parked inside the transport.
		close(peer.stop)
		close(release)

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("transmit reported %v for a batch the transport took", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("transmit never returned")
		}
		<-peer.senderDone
	}
}
