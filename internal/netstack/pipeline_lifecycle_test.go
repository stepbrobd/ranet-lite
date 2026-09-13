package netstack

import (
	"bytes"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

func TestOutboundDispatchKeepsMixedPeerReservationsTogether(t *testing.T) {
	firstReserved := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce, firstOnce sync.Once
	secondReserved := make(chan struct{}, 2)
	transmitted := make(chan struct{}, 4)
	sealer := func(raw [][]byte, _ []byte, _ [][]byte) ([][]byte, error) {
		sealed := make([][]byte, len(raw))
		for i := range raw {
			sealed[i] = bytes.Clone(raw[i])
		}
		return sealed, nil
	}
	send := func(packets [][]byte) error {
		for range packets {
			transmitted <- struct{}{}
		}
		return nil
	}
	a := NewPeerReserved("a", func(int) (BatchSealer, error) {
		firstOnce.Do(func() { close(firstReserved); <-releaseFirst })
		return sealer, nil
	}, send)
	b := NewPeerReserved("b", func(int) (BatchSealer, error) {
		secondReserved <- struct{}{}
		return sealer, nil
	}, send)
	m := &Mesh{closed: make(chan struct{}), outboundJobs: make(chan *outboundBatch, 4), outboundFree: make(chan *outboundBatch, 4)}
	m.outboundWorkerWG.Add(2)
	go m.outboundWorker()
	go m.outboundWorker()
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseFirst) })
		m.Close()
		a.Close()
		b.Close()
	})
	dispatch := func(peers []*Peer) {
		batch := &outboundBatch{
			n: 2, bufs: [][]byte{framed(1), framed(2)}, sizes: []int{1, 1}, headers: []byte{0, 0}, peers: peers,
			peerOrder: append([]*Peer(nil), peers...), counts: map[*Peer]int{a: 1, b: 1}, batches: make(map[*Peer]*peerBatch),
		}
		m.outboundReaderWG.Add(1)
		go func() { defer m.outboundReaderWG.Done(); m.dispatchOutbound(batch) }()
	}
	dispatch([]*Peer{a, b})
	<-firstReserved
	dispatch([]*Peer{b, a})
	select {
	case <-secondReserved:
		t.Fatal("another reader reserved B before the first mixed batch could be submitted")
	case <-time.After(20 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseFirst) })
	for range 4 {
		select {
		case <-transmitted:
		case <-time.After(time.Second):
			t.Fatal("mixed-peer batches stopped making progress")
		}
	}
}

// A reader that has handed its batch to the workers has also handed them every
// ticket it reserved, and a ticket the sender never sees stalls that peer for
// good. Close therefore has to drain the queue rather than abandon it, and has
// to return while a peer is still open and still behind.
func TestMeshCloseDrainsQueuedTickets(t *testing.T) {
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) {
		return func(raw [][]byte, _ []byte, _ [][]byte) ([][]byte, error) { return [][]byte{bytes.Clone(raw[0])}, nil }, nil
	}, func([][]byte) error { return nil })
	defer peer.Close()
	// Keep the sender waiting on its first ticket, with every slot spoken for,
	// so the dispatch below reserves nothing and Close still has a peer that
	// will never finish.
	for range cap(peer.slots) {
		peer.reserveBatch(1)
	}
	m := &Mesh{closed: make(chan struct{}), outboundJobs: make(chan *outboundBatch, 4), outboundFree: make(chan *outboundBatch, 4)}
	m.outboundWorkerWG.Add(1)
	go m.outboundWorker()
	m.outboundReaderWG.Add(1)
	go func() {
		defer m.outboundReaderWG.Done()
		m.dispatchOutbound(&outboundBatch{
			n: 1, bufs: [][]byte{framed(1)}, sizes: []int{1}, headers: []byte{0}, peers: []*Peer{peer},
			peerOrder: []*Peer{peer}, counts: map[*Peer]int{peer: 1}, batches: make(map[*Peer]*peerBatch),
		})
	}()
	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		peer.Close()
		<-done
		t.Fatal("Mesh.Close did not return while a peer was still behind")
	}
	if len(m.outboundJobs) != 0 {
		t.Fatal("Mesh.Close abandoned queued transmission tickets")
	}
}

func TestSingleQueueInboundSplitsLargeBatches(t *testing.T) {
	dev := &recordingDevice{writes: make(chan recordedWrite, 2)}
	m := &Mesh{devs: []tun.Device{dev}, closed: make(chan struct{})}
	packets := make([][]byte, inboundWriteBatchSize+1)
	for i := range packets {
		packets[i] = []byte{byte(i)}
	}
	m.DeliverInboundBatch(packets)
	if len(dev.writes) != 2 {
		t.Fatalf("got %d TUN writes, want two bounded batches", len(dev.writes))
	}
	first, second := <-dev.writes, <-dev.writes
	if len(first.packets) != inboundWriteBatchSize || len(second.packets) != 1 {
		t.Fatal("single-queue delivery exceeded the TUN GRO table capacity")
	}
	if second.packets[0][0] != byte(inboundWriteBatchSize) {
		t.Fatal("split delivery changed packet order")
	}
}

// One peer whose transport is behind must not stop the mesh forwarding to any
// other. Every TUN reader dispatches under one lock, and a batch read off one
// queue carries whichever destinations the kernel hashed onto it, so a
// reservation that waits there puts the whole dataplane behind the slowest
// peer on the mesh.
func TestCongestedPeerDoesNotStallOthers(t *testing.T) {
	sealer := func(raw [][]byte, _ []byte, _ [][]byte) ([][]byte, error) {
		sealed := make([][]byte, len(raw))
		for i := range raw {
			sealed[i] = bytes.Clone(raw[i])
		}
		return sealed, nil
	}
	reserve := func(int) (BatchSealer, error) { return sealer, nil }
	transmitted := make(chan struct{}, 4)
	stuck := NewPeerReserved("stuck", reserve, func([][]byte) error { return nil })
	defer stuck.Close()
	healthy := NewPeerReserved("healthy", reserve, func(packets [][]byte) error {
		for range packets {
			transmitted <- struct{}{}
		}
		return nil
	})
	defer healthy.Close()
	// Every slot spoken for and never returned, which is what a socket that
	// cannot keep up looks like from this side.
	for range cap(stuck.slots) {
		stuck.reserveBatch(1)
	}

	m := &Mesh{closed: make(chan struct{}), outboundJobs: make(chan *outboundBatch, 4), outboundFree: make(chan *outboundBatch, 4)}
	m.outboundWorkerWG.Add(1)
	go m.outboundWorker()
	defer m.Close()

	dispatched := make(chan struct{})
	go func() {
		defer close(dispatched)
		m.dispatchOutbound(&outboundBatch{
			n: 2, bufs: [][]byte{framed(1), framed(2)}, sizes: []int{1, 1}, headers: []byte{0, 0},
			peers: []*Peer{stuck, healthy}, peerOrder: []*Peer{stuck, healthy},
			counts: map[*Peer]int{stuck: 1, healthy: 1}, batches: make(map[*Peer]*peerBatch),
		})
	}()
	select {
	case <-dispatched:
	case <-time.After(2 * time.Second):
		t.Fatal("the congested peer held the dispatch lock every reader shares")
	}
	select {
	case <-transmitted:
	case <-time.After(2 * time.Second):
		t.Fatal("the packet for the peer that was not congested never reached its transport")
	}
	if got := stuck.Dropped(); got != 1 {
		t.Errorf("the congested peer counted %d dropped packets, want 1", got)
	}
	if got := healthy.Dropped(); got != 0 {
		t.Errorf("the peer that was not congested counted %d dropped packets, want 0", got)
	}
}

// failingReadDevice returns one transient read error and would go on reading
// afterwards, which is what a netlink failure on linux or a route-socket
// overflow on darwin looks like from here. Neither is device closure.
type failingReadDevice struct {
	recordingDevice
	reads atomic.Int64
	fail  int64
}

func (d *failingReadDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if d.reads.Add(1) == d.fail {
		return 0, errors.New("read failed")
	}
	if len(bufs) == 0 {
		return 0, nil
	}
	sizes[0] = 1
	bufs[0][offset] = 0x60
	return 1, nil
}

// A read error that is not closure used to end the queue's reader with no log,
// no metric and no restart. On linux the kernel keeps steering its share of
// flows to that queue, so a share of the mesh black-holes for the life of the
// process with nothing saying so; on darwin there is one queue, so all
// outbound forwarding stops. The reader still stops, because nothing here can
// repair the device, but it says so and gives its batch back.
func TestTunReadFailureIsReportedAndGivesTheBatchBack(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	dev := &failingReadDevice{fail: 3}
	m := &Mesh{Name: "test0", devs: []tun.Device{dev}, closed: make(chan struct{}),
		Routes: NewRouteTable(), outboundFree: make(chan *outboundBatch, 2),
		outboundBufferSize: DefaultMTU + tunOffset}
	for range 2 {
		m.outboundFree <- m.newOutboundBatch(4)
	}
	m.outboundReaderWG.Add(1)
	done := make(chan struct{})
	go func() { m.outboundReader(dev); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the reader never returned after its device failed")
	}
	if got := dev.reads.Load(); got != 3 {
		t.Errorf("the device was read %d times, want the three up to the failure", got)
	}
	if len(m.outboundFree) != 2 {
		t.Errorf("the reader kept %d of its batches, so the pool shrinks on every failure", 2-len(m.outboundFree))
	}
	if !bytes.Contains(logs.Bytes(), []byte("tun reader stopped")) {
		t.Errorf("a failed read said nothing: %s", logs.Bytes())
	}
}
