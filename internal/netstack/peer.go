package netstack

import (
	"fmt"
	"log"
	"runtime"
	"sync"
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

	// Compatibility peers allocate their sequence number during encryption,
	// so their complete encrypt/send operation remains synchronously ordered.
	sendMu   sync.Mutex
	sendCond *sync.Cond
	nextSend uint64
}

// BatchSealer consumes a sequence range previously reserved from one outbound
// SA. It returns packet slices backed by one packed allocation so the transport
// can hand them to UDP GSO without another copy.
type BatchSealer func(raw [][]byte, nextHeaders []byte) ([][]byte, error)

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

// SendRaw transmits a hand-built tunnel-mode IP packet directly through this
// peer. Babel uses this path; reserving and transmitting through the same Peer
// as routed traffic keeps its ESP packet ordered with concurrently encrypted
// TUN batches.
func (p *Peer) SendRaw(raw []byte, nextHeader byte) error {
	b := p.reserveBatch(1)
	b.append(raw, nextHeader)
	return b.transmit()
}

type peerBatch struct {
	peer      *Peer
	ticket    uint64
	reserved  bool
	sealer    BatchSealer
	sealed    [][]byte
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
		b.sealed, b.err = b.sealer(b.raw, b.headers)
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

func (p *Peer) senderLoop() {
	defer close(p.senderDone)
	pending := make(map[uint64]*peerBatch, cap(p.completed))
	next := uint64(0)
	for {
		if b := pending[next]; b != nil {
			delete(pending, next)
			err := b.send()
			b.releaseSlot()
			if b.done != nil {
				b.done <- err
			} else if err != nil {
				log.Printf("netstack: send batch through peer %s: %v", p.ID, err)
			}
			next++
			continue
		}
		select {
		case b := <-p.completed:
			pending[b.ticket] = b
		case <-p.stop:
			return
		}
	}
}
