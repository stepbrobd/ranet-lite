package netstack

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"
)

// Peer separates parallel packet encryption from ordered, batched transport.
type Peer struct {
	ID              string
	encryptFn       func(raw []byte, nextHeader byte) ([]byte, error)
	reserveFn       func(count int) (BatchSealer, error)
	transmitBatchFn func(sealed [][]byte) error

	reserveMu sync.Mutex
	reserved  uint64

	// Reserved peers hand completed crypto batches to one sender. slots bounds
	// the total number of batches that may be encrypting, queued out of order,
	// or in the transport syscall at once.
	completed  chan *peerBatch
	slots      chan struct{}
	stop       chan struct{}
	senderDone chan struct{}
	closeOnce  sync.Once
	sealedPool sync.Pool // *[][]byte, returned only after the transport finishes

	// Compatibility peers allocate their sequence number during encryption,
	// so their complete encrypt/send operation remains synchronously ordered.
	sendMu   sync.Mutex
	sendCond *sync.Cond
	nextSend uint64
}

// BatchSealer consumes a sequence range previously reserved from one outbound
// SA. It returns packet slices backed by one packed allocation so the transport
// can hand them to UDP GSO without another copy. reuse is a previous result
// whose transport has finished; the sealer may overwrite it or replace it.
// Output must not alias raw, whose TUN buffers are recycled after encryption.
type BatchSealer func(raw [][]byte, nextHeaders []byte, reuse [][]byte) ([][]byte, error)

func NewPeer(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), transmitFn func(sealed []byte) error) *Peer {
	return NewPeerBatched(id, encryptFn, func(sealed [][]byte) error {
		for _, packet := range sealed {
			if err := transmitFn(packet); err != nil {
				return err
			}
		}
		return nil
	})
}

// NewPeerBatched constructs a compatibility peer for an encryptor that cannot
// reserve sequence ranges. Its complete encrypt-and-send operation is ordered,
// so it is safe but intentionally cannot encrypt multiple batches in parallel.
func NewPeerBatched(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), transmitBatchFn func(sealed [][]byte) error) *Peer {
	return newPeer(id, encryptFn, nil, transmitBatchFn)
}

// NewPeerReserved constructs a peer whose expensive encryption can run in
// parallel. reserveFn is called in packet-intake order and must return a sealer
// owning count consecutive sequence numbers from the current outbound SA.
// transmitBatchFn must finish using every packet before returning.
func NewPeerReserved(id string, reserveFn func(count int) (BatchSealer, error), transmitBatchFn func(sealed [][]byte) error) *Peer {
	return newPeer(id, nil, reserveFn, transmitBatchFn)
}

func newPeer(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), reserveFn func(count int) (BatchSealer, error), transmitBatchFn func(sealed [][]byte) error) *Peer {
	p := &Peer{ID: id, encryptFn: encryptFn, reserveFn: reserveFn, transmitBatchFn: transmitBatchFn}
	if reserveFn == nil {
		p.sendCond = sync.NewCond(&p.sendMu)
	} else {
		queueSize := max(2, 2*runtime.GOMAXPROCS(0))
		p.completed = make(chan *peerBatch, queueSize)
		p.slots = make(chan struct{}, queueSize)
		p.stop = make(chan struct{})
		p.senderDone = make(chan struct{})
		go p.senderLoop()
	}
	return p
}

// Close stops the reserved peer's ordered sender. Compatibility peers do not
// own a goroutine, so closing them is a no-op.
func (p *Peer) Close() {
	if p == nil || p.stop == nil {
		return
	}
	p.closeOnce.Do(func() { close(p.stop) })
	<-p.senderDone
}

// ErrSendQueueFull reports a packet dropped rather than queued, so the caller
// can count it without treating the peer as broken.
var ErrSendQueueFull = errors.New("netstack: peer send queue is full")

// SendRawOrDrop hands one packet to the peer's ordered sender without waiting
// for the transport to finish with it, and gives up if no transmission slot
// comes free within controlSendWait. Babel sends this way because waiting
// there does not stay local: the speaker walks every neighbor from one
// goroutine, and Receive runs on the sending peer's own decrypt path, so one
// peer whose queue is backed up would stop hellos, updates and retractions to
// every other neighbor until it drained, and two such peers would each hold
// the other's emitter. Bounding the wait rather than refusing outright is what
// keeps a queue full of bulk data from starving the control traffic that keeps
// the adjacency up.
func (p *Peer) SendRawOrDrop(raw []byte, nextHeader byte) error {
	b := p.reserveBatchWithin(1, controlSendWait)
	if b == nil {
		return ErrSendQueueFull
	}
	b.append(raw, nextHeader)
	return b.enqueue()
}

type peerBatch struct {
	peer      *Peer
	ticket    uint64
	reserved  bool
	sealer    BatchSealer
	sealed    [][]byte
	storage   *[][]byte
	raw       [][]byte
	headers   []byte
	encrypted bool
	err       error
	done      chan error
	hasSlot   bool
}

// reserveBatch assigns both the peer's transmission ticket and, when
// supported, its ESP sequence range under one lock. Consequently ticket order,
// sequence-range order, and the TUN intake order established by Mesh agree.
func (p *Peer) reserveBatch(count int) *peerBatch {
	return p.reserveBatchUntil(count, nil)
}

func (p *Peer) reserveBatchUntil(count int, canceled <-chan struct{}) *peerBatch {
	hasSlot := false
	if p.slots != nil {
		select {
		case p.slots <- struct{}{}:
			hasSlot = true
		case <-p.stop:
			return &peerBatch{peer: p, reserved: true, err: fmt.Errorf("netstack: peer %s closed", p.ID)}
		case <-canceled:
			return &peerBatch{peer: p, reserved: true, err: fmt.Errorf("netstack: packet intake closed")}
		}
	}
	return p.reserveBatchWithSlot(count, hasSlot)
}

// controlSendWait bounds how long a control packet waits for a transmission
// slot. Long enough that an ordinary burst drains, which takes microseconds
// even when the queue is full of bulk data, and short enough that a peer whose
// transport has stopped cannot hold the babel speaker, which walks every
// neighbor from one goroutine and runs on the sending peer's own decrypt path
// when a packet arrives.
const controlSendWait = 50 * time.Millisecond

// reserveBatchWithin takes a transmission slot, waiting at most wait for one.
// A caller that would rather drop its packet than wait indefinitely gets nil,
// having consumed neither a ticket nor a sequence range, which is why the slot
// is taken before either: a reserved ticket that never reaches the sender
// stalls it forever.
func (p *Peer) reserveBatchWithin(count int, wait time.Duration) *peerBatch {
	if p.slots == nil {
		return p.reserveBatchWithSlot(count, false)
	}
	select {
	case p.slots <- struct{}{}:
		return p.reserveBatchWithSlot(count, true)
	case <-p.stop:
		return nil
	default:
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case p.slots <- struct{}{}:
		return p.reserveBatchWithSlot(count, true)
	case <-p.stop:
		return nil
	case <-timer.C:
		return nil
	}
}

func (p *Peer) reserveBatchWithSlot(count int, hasSlot bool) *peerBatch {
	p.reserveMu.Lock()
	ticket := p.reserved
	p.reserved++
	b := &peerBatch{peer: p, ticket: ticket, reserved: p.reserveFn != nil, hasSlot: hasSlot}
	if p.reserveFn != nil {
		b.sealer, b.err = p.reserveFn(count)
	}
	p.reserveMu.Unlock()
	b.raw = make([][]byte, 0, count)
	b.headers = make([]byte, 0, count)
	return b
}

// append retains a view of plaintext owned by the surrounding TUN batch.
// enqueue performs reserved batch encryption in that same worker before the
// TUN buffers are recycled.
func (b *peerBatch) append(raw []byte, nextHeader byte) {
	b.raw = append(b.raw, raw)
	b.headers = append(b.headers, nextHeader)
}

func (b *peerBatch) encrypt() {
	if b.encrypted || b.err != nil {
		return
	}
	b.encrypted = true
	if b.reserved {
		b.storage, _ = b.peer.sealedPool.Get().(*[][]byte)
		if b.storage == nil {
			b.storage = new([][]byte)
		}
		b.sealed, b.err = b.sealer(b.raw, b.headers, *b.storage)
		return
	}
	for i, raw := range b.raw {
		sealed, err := b.peer.encryptFn(raw, b.headers[i])
		if err != nil {
			b.err = err
			continue
		}
		b.sealed = append(b.sealed, sealed)
	}
}

// enqueue hands a completed reserved batch to the dedicated ordered sender and
// returns as soon as the bounded queue accepts it. That keeps crypto workers
// available while an earlier batch is in sendmmsg. Compatibility peers retain
// their synchronous ordered path.
func (b *peerBatch) enqueue() error {
	p := b.peer
	if p.completed == nil {
		return b.transmit()
	}
	if !b.hasSlot {
		return b.err // canceled before receiving a transmission ticket
	}
	b.encrypt()
	select {
	case p.completed <- b:
		return nil
	case <-p.stop:
		b.releaseStorage()
		b.releaseSlot()
		return fmt.Errorf("netstack: peer %s closed", p.ID)
	}
}

// transmit is the synchronous form used by control traffic and tests. Routed
// data uses enqueue so workers never wait for the transport syscall.
func (b *peerBatch) transmit() error {
	p := b.peer
	if p.completed != nil {
		b.done = make(chan error, 1)
		if err := b.enqueue(); err != nil {
			return err
		}
		select {
		case err := <-b.done:
			return err
		case <-p.stop:
			return fmt.Errorf("netstack: peer %s closed", p.ID)
		}
	}

	p.sendMu.Lock()
	for b.ticket != p.nextSend {
		p.sendCond.Wait()
	}
	defer func() {
		p.nextSend++
		p.sendCond.Broadcast()
		p.sendMu.Unlock()
	}()

	return b.send()
}

func (b *peerBatch) send() error {
	p := b.peer
	if !b.reserved {
		b.encrypt()
	}
	if len(b.sealed) != 0 {
		if err := p.transmitBatchFn(b.sealed); err != nil && b.err == nil {
			b.err = err
		}
	}
	return b.err
}

func (b *peerBatch) releaseSlot() {
	if b.hasSlot {
		<-b.peer.slots
		b.hasSlot = false
	}
}

func (b *peerBatch) releaseStorage() {
	if b.storage != nil {
		*b.storage = b.sealed
		b.peer.sealedPool.Put(b.storage)
		b.storage, b.sealed = nil, nil
	}
}

func (p *Peer) senderLoop() {
	defer close(p.senderDone)
	pending := make(map[uint64]*peerBatch, cap(p.completed))
	ready := make([]*peerBatch, 0, cap(p.completed))
	packets := make([][]byte, 0, 128)
	next := uint64(0)
	for {
		if pending[next] == nil {
			select {
			case b := <-p.completed:
				pending[b.ticket] = b
			case <-p.stop:
				return
			}
		}
		// Small packets such as TCP ACKs arrive as individual TUN reads. Merge
		// completed work without waiting for another packet or changing order.
	drain:
		for range cap(p.completed) {
			select {
			case b := <-p.completed:
				pending[b.ticket] = b
			default:
				break drain
			}
		}
		for len(packets) < 128 {
			b := pending[next]
			if b == nil {
				break
			}
			delete(pending, next)
			ready = append(ready, b)
			packets = append(packets, b.sealed...)
			next++
		}
		var sendErr error
		if len(packets) != 0 {
			sendErr = p.transmitBatchFn(packets)
		}
		for _, b := range ready {
			if b.err == nil {
				b.err = sendErr
			}
			b.releaseStorage()
			b.releaseSlot()
			if b.done != nil {
				b.done <- b.err
			} else if b.err != nil {
				log.Printf("netstack: send batch through peer %s: %v", p.ID, b.err)
			}
		}
		clear(packets)
		clear(ready)
		packets, ready = packets[:0], ready[:0]
	}
}
