// Package netstack wires a real Linux TUN device to the ranet mesh: outbound
// packets the kernel routes to it are forwarded to whichever peer's Child SA
// can reach the destination (see RouteTable), and inbound packets decrypted
// from any peer are written back to the device as if they'd arrived over any
// other interface. It knows nothing about ESP or IKE directly — peers are
// just a send function plus routes, so this package is testable without real
// crypto.
//
// This package never touches the device's address or route configuration —
// creating it and bringing it up is all it does. Assigning an address,
// and adding kernel routes to the TUN are the operator's responsibility.
// The embedded Babel speaker exchanges control traffic only inside ESP.
package netstack

import (
	"encoding/binary"
	"fmt"
	"log"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/packet"
	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1400 // leaves room for outer IP/UDP/ESP overhead under a 1500-byte link MTU

const (
	outboundPacketBufferSize = 2048
	inboundWriteBatchSize    = 128
	inboundWriteQueueSize    = 64
	// inboundPacketBufferSize leaves enough tail capacity for the TUN
	// backend to merge adjacent TCP packets into a single GSO frame before
	// writing it. Exact-capacity packet buffers silently disable that GRO.
	inboundPacketBufferSize = tunOffset + 65535
)

var (
	// Pooled as a pointer to the array rather than as a slice. A sync.Pool
	// takes an any, and a slice header does not fit in one, so putting a slice
	// back boxes it: one heap allocation for every inbound packet released, on
	// the path every inbound packet takes. The array pointer fits, so the same
	// release allocates nothing. Measured over 128 packets per release by
	// BenchmarkInboundCopyAndRelease: 4226 ns and 129 allocations against 3472
	// ns and 1 at 64 bytes, 8358 against 6561 at 1400.
	inboundPacketPool = sync.Pool{New: func() any { return new([inboundPacketBufferSize]byte) }}
)

// tunOffset is how much leading space every Device.Read and Device.Write
// needs in each buffer, the same offset wireguard-go's own device code uses
// (device.MessageTransportOffsetContent), and for the same reasons. A backend
// slices backwards from it to reach its own framing: linux prepends a
// virtio-net header (the tun package always requests IFF_VNET_HDR), darwin
// prepends the four-byte address family header a utun frame carries. Offset 0
// doesn't just lose performance, it fails outright, and on darwin it fails
// before the first packet arrives: tun_darwin.go's Read evaluates
// bufs[0][offset-4:] on entry, so offset 0 panics the reader goroutine and
// takes the process down with it.
//
// The contract on the way back is that a read leaves packet i at
// bufs[i][tunOffset : tunOffset+sizes[i]], which is where linux puts each
// packet it splits out of one GRO'd read as well.
const tunOffset = 16

type Mesh struct {
	Routes *RouteTable
	// Name is the TUN device's real interface name (e.g. "ranet0"), as
	// reported by the kernel — needed by whoever configures its address
	// and routes, since the kernel doesn't always honor the requested
	// name exactly.
	Name string

	devs               []tun.Device
	outboundBufferSize int
	outboundJobs       chan *outboundBatch
	outboundFree       chan *outboundBatch
	outboundDispatchMu sync.Mutex
	inboundWriters     []chan inboundWriteBatch
	closed             chan struct{}
	closeOnce          sync.Once
	deliveryMu         sync.Mutex
	deliveryWG         sync.WaitGroup
	closing            bool
	outboundReaderWG   sync.WaitGroup
	outboundWorkerWG   sync.WaitGroup
	writerWG           sync.WaitGroup

	// segmentCounters is the segment routing state, in its own struct so that
	// everything this file does not touch stays in segments.go with the code
	// that does.
	segmentCounters
}

// outboundBatch owns the TUN buffers from one read until a crypto worker has
// encrypted every routed packet. Readers can therefore immediately continue
// with another buffer set instead of tying one encryption worker to each TUN
// queue (and to whatever flows the kernel happened to hash onto that queue).
type outboundBatch struct {
	n         int
	bufs      [][]byte
	sizes     []int
	peers     []*Peer
	headers   []byte
	counts    map[*Peer]int
	batches   map[*Peer]*peerBatch
	peerOrder []*Peer
}

type inboundWriteBatch struct {
	packets [][]byte
}

// New creates an automatically named TUN device.
func New(mtu int) (*Mesh, error) { return NewNamed(mtu, "") }

// NewRoutesOnly is a mesh with a forwarding table and no device, for a test
// that exercises routing and sessions rather than the dataplane. Creating a
// TUN needs root on every platform, and babel intercepts its own traffic
// before delivery, so a mesh that never carries a data packet does not need
// one. Delivering one to it is a no-op.
func NewRoutesOnly() *Mesh {
	return &Mesh{Routes: NewRouteTable(), closed: make(chan struct{})}
}

// NewNamed attaches to or creates name through wireguard-go's TUN backend.
// An empty name retains the project's automatically assigned ranet%d name.
func NewNamed(mtu int, name string) (*Mesh, error) {
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if name == "" {
		name = defaultTUNName
	}
	queueCount := max(1, runtime.GOMAXPROCS(0))
	devs, actualName, err := createTUNQueues(name, mtu, queueCount)
	if err != nil && queueCount == 1 {
		// A pre-existing single-queue TUN rejects an IFF_MULTI_QUEUE attach.
		// Preserve the single-core compatibility path while new interfaces and
		// multicore processes use the scalable multiqueue setup.
		var dev tun.Device
		dev, err = tun.CreateTUN(name, mtu)
		if err == nil {
			actualName, err = dev.Name()
			if err == nil {
				devs = []tun.Device{dev}
			} else {
				_ = dev.Close()
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("netstack: create tun device: %w", err)
	}
	if err := bringTUNUp(actualName); err != nil {
		for _, dev := range devs {
			_ = dev.Close()
		}
		return nil, fmt.Errorf("netstack: bring tun device up: %w", err)
	}
	m := &Mesh{
		Routes:             NewRouteTable(),
		Name:               actualName,
		devs:               devs,
		outboundBufferSize: tunOffset + max(mtu, outboundPacketBufferSize),
		closed:             make(chan struct{}),
	}
	m.startSegmentReports()
	m.startInboundWriters()
	m.startOutboundPipeline()
	return m, nil
}

// QueueCount reports the number of independent TUN I/O lanes.
func (m *Mesh) QueueCount() int { return len(m.devs) }

// MTU is the device's own, asked of the kernel rather than reported from the
// value New was given: attaching to a device somebody else created takes
// whatever MTU that device already has. Zero means the device could not
// answer, which is a device on its way out.
func (m *Mesh) MTU() int {
	if len(m.devs) == 0 {
		return 0
	}
	mtu, err := m.devs[0].MTU()
	if err != nil {
		return 0
	}
	return mtu
}

func (m *Mesh) startOutboundPipeline() {
	workers := max(1, runtime.GOMAXPROCS(0))
	m.outboundJobs = make(chan *outboundBatch, 2*workers)
	batchSize := 1
	for _, dev := range m.devs {
		batchSize = max(batchSize, dev.BatchSize())
	}
	m.outboundFree = make(chan *outboundBatch, cap(m.outboundJobs)+len(m.devs))
	for range cap(m.outboundFree) {
		m.outboundFree <- m.newOutboundBatch(batchSize)
	}
	for range workers {
		m.outboundWorkerWG.Add(1)
		go m.outboundWorker()
	}
	for _, dev := range m.devs {
		m.outboundReaderWG.Add(1)
		go m.outboundReader(dev)
	}
}

func (m *Mesh) newOutboundBatch(size int) *outboundBatch {
	b := &outboundBatch{
		bufs:      make([][]byte, size),
		sizes:     make([]int, size),
		peers:     make([]*Peer, size),
		headers:   make([]byte, size),
		counts:    make(map[*Peer]int),
		batches:   make(map[*Peer]*peerBatch),
		peerOrder: make([]*Peer, 0, size),
	}
	for i := range b.bufs {
		b.bufs[i] = make([]byte, m.outboundBufferSize)
	}
	return b
}

// outboundReader only reads and classifies packets. Reserving each peer's ESP
// sequence range here fixes the order before independently scheduled workers
// encrypt later batches, so the ordered sender can restore per-flow FIFO.
func (m *Mesh) outboundReader(dev tun.Device) {
	defer m.outboundReaderWG.Done()
	for {
		var b *outboundBatch
		select {
		case b = <-m.outboundFree:
		case <-m.closed:
			return
		}
		n, err := dev.Read(b.bufs, b.sizes, tunOffset)
		if err != nil {
			// Closure is the ordinary reason and says nothing. Anything else
			// ends this queue's reader for the life of the process, and on
			// linux the kernel keeps steering its share of flows to the queue
			// it belongs to, so a share of the mesh black-holes with nothing
			// in the log. The device's own error channel carries a netlink
			// failure on linux and a route-socket overflow on darwin, neither
			// of which is closure.
			select {
			case <-m.closed:
			default:
				slog.Error("netstack tun reader stopped", "interface", m.Name, "err", err)
			}
			m.outboundFree <- b
			return
		}
		b.n = n
		for i := 0; i < n; i++ {
			raw := b.bufs[i][tunOffset : tunOffset+b.sizes[i]]
			src, dst, nh, ok := addrsOf(raw)
			if !ok {
				continue
			}
			// Steering happens before the route lookup, because a steered
			// packet is routed by the segment it is going to rather than by
			// the address it was addressed to.
			steered := false
			if size, ok := m.steer(b.bufs[i], b.sizes[i], src, dst); ok {
				b.sizes[i], steered = size, true
				if src, dst, nh, ok = addrsOf(b.bufs[i][tunOffset : tunOffset+size]); !ok {
					continue
				}
			}
			peer, ok := m.Routes.Lookup(src, dst)
			if !ok {
				// A steered packet whose first segment the mesh cannot reach
				// is gone at this point, so it is counted here: without this
				// the steered counter climbs while the traffic disappears.
				if steered {
					m.segmentsDropped.Add(1)
					m.reportSegmentDrop("no route to the first segment of a steered packet", "segment", dst)
				}
				continue
			}
			b.peers[i], b.headers[i] = peer, nh
			if b.counts[peer] == 0 {
				b.peerOrder = append(b.peerOrder, peer)
			}
			b.counts[peer]++
		}
		if len(b.peerOrder) == 0 {
			b.reset()
			m.outboundFree <- b
			continue
		}
		m.dispatchOutbound(b)
	}
}

// Reserve and submit each batch as one operation. Otherwise two readers can
// retain the first tickets for different peers while later completed batches
// fill both peers' slots, preventing either reader from reserving its second
// peer. Submission order also keeps compatibility workers from all waiting on
// an earlier ticket that is still queued behind them.
//
// Nothing here waits. Every TUN reader passes through this lock, and a batch
// read off one queue carries whichever destinations the kernel hashed onto it,
// so waiting for one peer's transmission slot would stop forwarding to every
// other peer as well: a single backpressured socket would take the whole
// dataplane down with it, and a queue that is full stays full for as long as
// the transport is behind. That peer's share of the batch is dropped instead,
// the way a full egress queue drops, and every other peer's packets go out on
// time. The drop is counted per peer.
func (m *Mesh) dispatchOutbound(b *outboundBatch) {
	m.outboundDispatchMu.Lock()
	defer m.outboundDispatchMu.Unlock()
	for _, peer := range b.peerOrder {
		if batch := peer.reserveBatchNow(b.counts[peer]); batch != nil {
			b.batches[peer] = batch
		}
	}
	// Submission never blocks: outboundFree is sized so that every batch in
	// flight fits here. Workers drain the queue during Close, including every
	// reserved ticket.
	m.outboundJobs <- b
}

func (m *Mesh) outboundWorker() {
	defer m.outboundWorkerWG.Done()
	for b := range m.outboundJobs {
		for i := 0; i < b.n; i++ {
			// A peer with no batch had no transmission slot, so its share of
			// this read was dropped before the tickets were handed out.
			if peer := b.peers[i]; peer != nil && b.batches[peer] != nil {
				b.batches[peer].append(b.bufs[i][tunOffset:tunOffset+b.sizes[i]], b.headers[i])
			}
		}
		for _, peer := range b.peerOrder {
			batch := b.batches[peer]
			if batch == nil {
				continue
			}
			if err := batch.enqueue(); err != nil {
				log.Printf("netstack: send batch through peer %s: %v", peer.ID, err)
			}
		}
		b.reset()
		select {
		case m.outboundFree <- b:
		case <-m.closed:
		}
	}
}

func (b *outboundBatch) reset() {
	for i := 0; i < b.n; i++ {
		b.peers[i] = nil
		b.sizes[i] = 0
	}
	b.n = 0
	clear(b.counts)
	clear(b.batches)
	clear(b.peerOrder)
	b.peerOrder = b.peerOrder[:0]
}

// addrsOf extracts both the source and destination address from a raw IP
// packet — the route table needs both to support source-specific (SADR)
// routes, not just the destination.
func addrsOf(raw []byte) (src, dst netip.Addr, nextHeader byte, ok bool) {
	src, dst, version := packet.Addrs(raw)
	switch version {
	case 4:
		return src, dst, esp.NextHeaderIPv4, true
	case 6:
		return src, dst, esp.NextHeaderIPv6, true
	default:
		return src, dst, 0, false
	}
}

// DeliverInbound injects an already-decapsulated tunnel-mode IP packet into
// the TUN device, as if it had arrived on the wire.
func (m *Mesh) DeliverInbound(raw []byte) {
	m.DeliverInboundBatch([][]byte{raw})
}

// DeliverInboundBatch injects a group of already-decapsulated tunnel-mode IP
// packets. On a multiqueue TUN, packets are assigned by their inner flow to a
// persistent writer lane. That preserves each flow's packet order and lets the
// kernel process unrelated streams in parallel. Buffers are copied to leave
// the headroom and tail capacity required by the TUN backend's virtio/GRO
// implementation.
func (m *Mesh) DeliverInboundBatch(raw [][]byte) {
	// A mesh with no device only exists in a test, where nothing should reach
	// here: babel's own traffic is intercepted before delivery.
	if len(raw) == 0 || len(m.devs) == 0 {
		return
	}
	m.deliveryMu.Lock()
	if m.closing {
		m.deliveryMu.Unlock()
		return
	}
	m.deliveryWG.Add(1)
	m.deliveryMu.Unlock()
	defer m.deliveryWG.Done()
	// A packet addressed to one of this node's own segments is acted on here
	// rather than written to the tun, where it would arrive as an
	// undeliverable packet addressed to an address of ours.
	raw = m.applySegments(raw)
	if len(raw) == 0 {
		return
	}
	if len(m.devs) == 1 {
		for len(raw) != 0 {
			n := min(len(raw), inboundWriteBatchSize)
			m.writeInbound(0, copyInboundPackets(raw[:n]))
			raw = raw[n:]
		}
		return
	}

	groups := make([][][]byte, len(m.devs))
	for _, packet := range raw {
		lane := int(innerFlowHash(packet) % uint64(len(m.devs)))
		groups[lane] = append(groups[lane], packet)
	}
	for lane, packets := range groups {
		if len(packets) == 0 {
			continue
		}
		// The authenticated plaintext remains owned by this queue entry.
		// Deferring the required headroom copy to the writer keeps it off the
		// ordered ESP commit path and lets the writer merge adjacent entries
		// into a larger GRO batch.
		batch := inboundWriteBatch{packets: packets}
		select {
		case m.inboundWriters[lane] <- batch:
		case <-m.closed:
		}
	}
}

func (m *Mesh) startInboundWriters() {
	if len(m.devs) <= 1 {
		return
	}
	m.inboundWriters = make([]chan inboundWriteBatch, len(m.devs))
	for lane := range m.devs {
		queue := make(chan inboundWriteBatch, inboundWriteQueueSize)
		m.inboundWriters[lane] = queue
		m.writerWG.Add(1)
		go func() {
			defer m.writerWG.Done()
			pending := make([][]byte, 0, 2*inboundWriteBatchSize)
			for {
				var first inboundWriteBatch
				select {
				case first = <-queue:
				case <-m.closed:
					// Deliveries that began before Close may still choose the
					// buffered send arm after closed becomes readable. Wait for
					// those sends before abandoning their plaintext references.
					m.deliveryWG.Wait()
					return
				}

				pending = collectReadyInbound(first, queue, pending)
				for offset := 0; offset < len(pending); offset += inboundWriteBatchSize {
					end := min(offset+inboundWriteBatchSize, len(pending))
					m.writeInbound(lane, copyInboundPackets(pending[offset:end]))
				}
				clear(pending)
				pending = pending[:0]
			}
		}()
	}
}

// collectReadyInbound drains only work that is already available. This keeps
// the idle-path latency unchanged while giving a busy writer a full batch for
// NativeTun.Write's GRO pass, reducing the number of TUN write syscalls.
func collectReadyInbound(first inboundWriteBatch, queue <-chan inboundWriteBatch, pending [][]byte) [][]byte {
	pending = append(pending, first.packets...)
	for len(pending) < inboundWriteBatchSize {
		select {
		case batch := <-queue:
			pending = append(pending, batch.packets...)
		default:
			return pending
		}
	}
	return pending
}

func copyInboundPackets(raw [][]byte) [][]byte {
	bufs := make([][]byte, len(raw))
	for i := range raw {
		buf := inboundPacketPool.Get().(*[inboundPacketBufferSize]byte)[:]
		if cap(buf) < tunOffset+len(raw[i]) {
			buf = make([]byte, tunOffset+len(raw[i]))
		} else {
			buf = buf[:tunOffset+len(raw[i])]
		}
		bufs[i] = buf
		copy(bufs[i][tunOffset:], raw[i])
	}
	return bufs
}

func releaseInboundPackets(bufs [][]byte) {
	for _, buf := range bufs {
		if cap(buf) == inboundPacketBufferSize {
			// The capacity check keeps out a buffer this package did not
			// hand out, and one grown past the pool's size. A buffer is
			// re-sliced on every use for the header offset, and recovering
			// the array from the full-capacity slice is exact.
			inboundPacketPool.Put((*[inboundPacketBufferSize]byte)(buf[:inboundPacketBufferSize]))
		}
	}
}

func (m *Mesh) writeInbound(lane int, bufs [][]byte) {
	if _, err := m.devs[lane].Write(bufs, tunOffset); err != nil {
		select {
		case <-m.closed:
		default:
			log.Printf("netstack: write to tun device queue %d: %v", lane, err)
		}
	}
	releaseInboundPackets(bufs)
}

// innerFlowHash assigns both directions of an inner TCP/UDP flow to the same
// lane. The commutative endpoint mix is useful for request/response workloads,
// while the final avalanche avoids the sequential-port clustering produced by
// taking low hash bits.
func innerFlowHash(packet []byte) uint64 {
	var src, dst []byte
	var protocol byte
	var payload []byte
	fragmented := false
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || headerLength > len(packet) {
			return hashBytes(packet)
		}
		protocol, src, dst = packet[9], packet[12:16], packet[16:20]
		payload = packet[headerLength:]
		fragmented = binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0
	} else if len(packet) >= 40 && packet[0]>>4 == 6 {
		protocol, src, dst = packet[6], packet[8:24], packet[24:40]
		payload = packet[40:]
	} else {
		return hashBytes(packet)
	}

	srcHash, dstHash := hashBytes(src), hashBytes(dst)
	if !fragmented && len(payload) >= 4 && (protocol == 6 || protocol == 17) {
		srcPort := binary.BigEndian.Uint16(payload[:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		srcHash ^= uint64(srcPort) * 0x9e3779b185ebca87
		dstHash ^= uint64(dstPort) * 0x9e3779b185ebca87
	}
	h := srcHash ^ dstHash ^ uint64(protocol)*0x517cc1b727220a95
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	return h ^ h>>31
}

func hashBytes(raw []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, b := range raw {
		h ^= uint64(b)
		h *= 1099511628211
	}
	return h
}

func (m *Mesh) Close() {
	m.closeOnce.Do(func() {
		m.deliveryMu.Lock()
		m.closing = true
		close(m.closed)
		m.deliveryMu.Unlock()
		for _, dev := range m.devs {
			_ = dev.Close()
		}
		m.outboundReaderWG.Wait()
		if m.outboundJobs != nil {
			close(m.outboundJobs)
		}
		m.outboundWorkerWG.Wait()
		m.deliveryWG.Wait()
		m.writerWG.Wait()
	})
}
