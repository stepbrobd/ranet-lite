package netstack

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
)

// Peer separates parallel packet encryption from ordered, batched transport.
type Peer struct {
	ID              string
	encryptFn       func(raw []byte, nextHeader byte) ([]byte, error)
	reserveFn       func(count int) (BatchSealer, error)
	transmitBatchFn func(sealed [][]byte) error

	reserveMu sync.Mutex
	reserved  uint64
	dropped   atomic.Uint64

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
// for the transport to finish with it, and drops it when no transmission slot
// is free. Babel sends this way because waiting does not stay local: the
// speaker walks every neighbor from one goroutine, and Receive runs on the
// sending peer's own decrypt path, so one peer whose queue is backed up would
// stop hellos, updates and retractions to every other neighbor until it
// drained, and two such peers would each hold the other's emitter. The caller
// is told, and gives back whatever the dropped packet had consumed.
func (p *Peer) SendRawOrDrop(raw []byte, nextHeader byte) error {
	reserved, err := p.ReserveRawOrDrop(raw, nextHeader)
	if err != nil {
		return err
	}
	return reserved.Send()
}

// Reserved is one packet holding its place in a peer's transmission order. A
// peer sends in the order places were taken, not in the order Send is called.
type Reserved struct{ batch *peerBatch }

// ReserveRawOrDrop takes the peer's next place for one packet and drops it
// rather than waiting when no transmission slot is free, exactly as
// SendRawOrDrop does. It exists for a caller that decides several packets
// under a lock it cannot hold while sending: taking the places under that lock
// and sending after releasing it is what keeps two such callers from inverting
// what they decided. Every reservation has to be sent -- a place taken and
// never used stalls everything behind it.
func (p *Peer) ReserveRawOrDrop(raw []byte, nextHeader byte) (*Reserved, error) {
	b := p.reserveBatchNow(1)
	if b == nil {
		return nil, ErrSendQueueFull
	}
	b.append(raw, nextHeader)
	return &Reserved{batch: b}, nil
}

// Send hands a reservation to the peer's sender, which emits it once
// everything reserved ahead of it has gone.
func (r *Reserved) Send() error { return r.batch.enqueue() }

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
//
// It waits for a transmission slot, which nothing in the dataplane does: Mesh
// reserves through reserveBatchNow so that one backpressured peer cannot stall
// the readers feeding every other peer. What is left here is the unthrottled
// producer the ordering tests and the benchmarks need.
func (p *Peer) reserveBatch(count int) *peerBatch {
	hasSlot := false
	if p.slots != nil {
		select {
		case p.slots <- struct{}{}:
			hasSlot = true
		case <-p.stop:
			return &peerBatch{peer: p, reserved: true, err: fmt.Errorf("netstack: peer %s closed", p.ID)}
		}
	}
	return p.reserveBatchWithSlot(count, hasSlot)
}

// reserveBatchNow takes a transmission slot only if one is free. A caller that
// would rather drop its packets than wait gets nil, having consumed neither a
// ticket nor a sequence range, which is why the slot is taken before either: a
// reserved ticket that never reaches the sender stalls it forever. The count
// is what the caller was about to send, and is what the refusal is counted in.
//
// It does not wait at all, even briefly. A slot frees when the peer's sender
// returns from the transport, so a queue that is full is one whose socket is
// backpressured, and that lasts far longer than any wait worth having; a wait
// would only add latency before dropping anyway. Both callers also run on a
// goroutine that serves other peers: the speaker walks every neighbor from
// one, Receive runs on the sending peer's own decrypt path, and Mesh dispatches
// under a lock every TUN reader takes.
func (p *Peer) reserveBatchNow(count int) *peerBatch {
	if p.slots == nil {
		return p.reserveBatchWithSlot(count, false)
	}
	select {
	case p.slots <- struct{}{}:
		return p.reserveBatchWithSlot(count, true)
	case <-p.stop:
		p.dropped.Add(uint64(count))
		return nil
	default:
		p.dropped.Add(uint64(count))
		return nil
	}
}

// Dropped counts the packets this peer refused rather than queued, because no
// transmission slot was free or because it was already closing. It is the only
// loss this package causes on purpose, so a peer whose path is congested shows
// up as a rising counter here rather than as latency somewhere else.
func (p *Peer) Dropped() uint64 { return p.dropped.Load() }

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
