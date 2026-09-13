package netstack

import (
	"bytes"
	"errors"
	"fmt"
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
	// Each attempt gives up after controlSendWait rather than waiting for a
	// slot that is never coming, so the whole run is bounded. The sends are on
	// their own goroutine so a blocking one is reported rather than hanging.
	// Enough to fill the queue and then keep pushing at a transport that has
	// stopped, which is the case the drop exists for.
	const beyond = 20
	attempts := cap(peer.slots) + beyond
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
	for range cap(peer.slots) + 50 {
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
// which is what a peer that has just deleted its Child SA looks like from this
// side. Counting only the slot refusals would leave the drop counter reading
// zero through exactly that window.
func TestReservationFailureCountsAsADrop(t *testing.T) {
	refused := errors.New("no child sa")
	peer := NewPeerReserved("peer",
		func(int) (BatchSealer, error) { return nil, refused },
		func([][]byte) error { return nil })
	defer peer.Close()

	place, err := peer.ReserveRawOrDrop([]byte("packet"), 41)
	if err != nil {
		t.Fatalf("the reservation was refused outright: %v", err)
	}
	// The sender reports the failure where it discards the batch, not here, so
	// the counter is the only thing a scrape can see.
	place.Send()
	if got := peer.Dropped(); got != 1 {
		t.Errorf("the peer counted %d drops, want the one packet it could not send", got)
	}
}
