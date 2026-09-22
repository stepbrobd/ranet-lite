// Package transport shares one UDP socket between IKE control messages and
// UDP-encapsulated ESP packets. IKE packets carry a four-byte non-ESP marker,
// ESP packets are bare and begin with their nonzero inbound SPI. That rule is
// RFC 3948 section 2.2, and it carries IKE and its own ESP traffic across a
// NAT on one port.
//
// # What a caller uses
//
// [NewHub] binds the port and owns the socket. Each peer then gets a [Mux]
// from [Hub.NewMux] or [Hub.NewMuxTo], which is that peer's logical channel:
// the caller registers the inbound SPIs it has negotiated with
// [Mux.RegisterIKE] and [Mux.RegisterESP], and from then on [Mux.SendIKE] and
// [Mux.RecvIKE] carry control messages while [Mux.SendESP], [Mux.RecvESP] and
// their batch forms carry the data. An IKE datagram whose SPI no Mux has
// registered arrives on [Hub.Listen] as an [Unclaimed], which is how a peer
// that has never dialed this node opens an IKE_SA_INIT. [Dial] is the one-peer
// shorthand: a hub and a single mux, closed together.
//
// A peer that moves keeps working because a received datagram carries the
// [Endpoint] it came from. [Mux.AdoptEndpoint] repoints the channel at it once
// IKE has authenticated the move, so this package never decides on its own
// that a peer's address changed.
//
// # Keeping the socket out of its own tunnel
//
// [Underlay] and [Runtime] are the one setting that keeps this socket off the
// routes a mesh running over it installs, a mark on linux and an interface
// binding on darwin. [Underlay] is a plain value a config file or a control
// plane can produce whole, and [Runtime] carries what the caller has to
// resolve at startup, so a caller that wants neither passes both zero.
//
// # What it does not do
//
// Nothing here encrypts, authenticates or parses a payload: an IKE message
// leaves and arrives as bytes, and an ESP packet is opaque. Nothing here
// writes a policy rule either, including the one that has to match
// [Underlay.Mark].
package transport

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// nonESPMarkerLen is the four zero octets of RFC 3948 section 2.2 that
	// tell an IKE message from an ESP packet on one port.
	//
	// A NAT keepalive is one octet of 0xff, section 2.3, which says "The
	// receiver SHOULD ignore a received NAT-keepalive packet": recognized by
	// name below rather than swept up by the length test, so a peer that sends
	// one every twenty seconds does not spend the counter an operator reads
	// for hostile traffic. It raises keepalives instead, because ignoring a
	// datagram is a rule about processing it and not about counting it.
	//
	// This end sends none, which section 4 asks for: "A peer SHOULD send a
	// NAT-keepalive packet if a need for it is detected according to [RFC3947]
	// and if no other packet to the peer has been sent in M seconds. M is a
	// locally configurable parameter with a default value of 20 seconds." What
	// keeps the mapping open here is the babel hellos, and nothing else does:
	// the liveness probe fires only once inbound traffic has stopped for its
	// interval, so a peer that keeps sending draws no outbound IKE at all.
	// babel.hello_interval is configurable and Validate accepts up to 655
	// seconds, which is past the two minute mapping timer RFC 4787 REQ-5
	// permits, so a NATed node at a long interval can lose the mapping while
	// traffic is still arriving.
	nonESPMarkerLen = 4
	// natKeepaliveByte is the payload of that one octet datagram.
	natKeepaliveByte = 0xff
	readBufferSize   = 65536
	espSendBatch     = 128
	// espChanSize absorbs receive bursts before a peer's workers can drain
	// them. It counts socket batches, which is the datagram count only where
	// the backend returns one datagram per batch, as darwin's does. The
	// channel is allocated with the mux, so a half-open SA carries this cost
	// while its handshake runs: 40 KiB a piece here, against 160 KiB at the
	// 4096 this used to be, and a flood can pin halfOpenLimit of them at
	// once.
	espChanSize = 1024
	// espQueueBytes is the bound that actually holds that queue. A batch holds up to
	// espSendBatch datagrams of up to readBufferSize each, so the batch count
	// alone bounds nothing: even at 1024 that is 8.6 GB per peer at the UDP
	// maximum.
	// An ESP SPI is cleartext on the wire and the queue is filled before
	// anything is authenticated, so whoever has seen one packet from a peer
	// can aim that at us. Steady-state occupancy is a handful of batches
	// either way, since the workers drain continuously; this only has to
	// absorb a burst.
	espQueueBytes = 8 << 20
)

// Hub owns one local UDP port and routes incoming packets to registered Muxes.
type Hub struct {
	bind packetBind
	port uint16

	// underlay is the configuration the socket was opened under, and boundTo
	// the interface index it currently carries, zero for none. Both are read
	// under mu, which the follower goroutine and a status reader share.
	underlay Underlay
	boundTo  int

	mu        sync.Mutex
	ike       map[uint64]*Mux
	esp       map[uint32]*Mux
	muxes     map[*Mux]struct{}
	listen    chan Unclaimed
	done      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once

	// dropped counts every datagram a full receive queue refused, and reported
	// bounds how often that is said out loud. One receive loop serves every
	// session on this hub, and anyone who can reach the port can fill a
	// queue: at line rate a line per datagram is a synchronous write to
	// stderr per packet, on the goroutine that receives for all of them.
	// An operator reads the counter; the log line only has to point at it.
	dropped atomic.Uint64
	// refused counts datagrams this node read and did not deliver because
	// nothing here wanted them: too short to carry an SPI, zero length, naming
	// an SPI no Mux holds, arriving for an unclaimed queue that is already
	// full, or carrying a control message or source address the receiver could
	// not read. Anyone who can reach the port can raise it, which is why it is
	// a counter and not a log line, and why it is separate from dropped: a
	// rising dropped means this node is behind on receive, and mixing the two
	// would make the one number an operator watches unreadable.
	refused atomic.Uint64
	// keepalives counts the one-octet NAT keepalives of RFC 3948 section 2.3.
	// They are ignored rather than delivered, but they are expected traffic
	// from a NATed peer rather than traffic nothing wanted, so they stay off
	// refused: an operator watching that number for a flood should not see it
	// move because a peer is holding its mapping open.
	keepalives atomic.Uint64
	// reported is nanoseconds since started, which is read through time.Since
	// so it comes from the monotonic clock: on the wall clock a step backwards
	// silences the report for the length of the step. It starts one interval
	// in the past, so the first drop is said out loud rather than swallowed by
	// a hub that has only just opened.
	reported atomic.Int64
	started  time.Time
}

// dropReportInterval bounds how often a full receive queue is logged. The
// counter behind it is exact.
const dropReportInterval = 10 * time.Second

// Dropped is how many inbound datagrams a full receive queue has refused. It
// is the inbound counterpart of Peer.Dropped, and the only signal that this
// node is behind on receive rather than losing packets on the wire.
func (h *Hub) Dropped() uint64 { return h.dropped.Load() }

// Refused is how many inbound datagrams this node read and had nowhere to put:
// see Hub.refused.
func (h *Hub) Refused() uint64 { return h.refused.Load() }

// Keepalives reports the RFC 3948 section 2.3 NAT keepalives this hub read and
// ignored. They are separate from Refused because a NATed peer holding its
// mapping open is expected traffic, not traffic nothing wanted.
func (h *Hub) Keepalives() uint64 { return h.keepalives.Load() }

// noteDrop counts refused datagrams and reports them at most once an interval.
func (h *Hub) noteDrop(count int, reason string) {
	total := h.dropped.Add(uint64(count))
	now := int64(time.Since(h.started))
	last := h.reported.Load()
	if now-last < int64(dropReportInterval) || !h.reported.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("transport receive queue full", "detail", reason, "dropped_total", total)
}

// Unclaimed is one IKE datagram whose SPI belongs to no registered Mux, which
// is how an IKE_SA_INIT from a peer that has never dialed us arrives. Raw is
// the message with the non-ESP marker already stripped, and Endpoint is the
// source to answer, which is also the endpoint a new Mux is created for.
type Unclaimed struct {
	Raw      []byte
	Endpoint Endpoint
}

// Endpoint is the authenticated datagram source retained by IKE so replies
// can follow a peer whose NAT mapping changed. It prints as an address, which
// a responder needs both to log an unauthenticated peer and to bind a cookie
// to the address it was issued to.
type Endpoint interface {
	transportEndpoint()
	String() string
	// AddrPort is the peer's address as this socket observed it, which NAT
	// detection has to hash (RFC 7296 section 2.23).
	AddrPort() netip.AddrPort
}

type packetBind interface {
	ParseEndpoint(string) (Endpoint, error)
	Send([][]byte, Endpoint) error
	Close() error
}

// A receiver owns its buffers; their views remain valid until its next call.
// receiveFunc fills the vectors and reports how many datagrams it produced
// and how many it read and could not use, which the hub counts so an operator
// can tell a receive path that is discarding from one that is idle.
type receiveFunc func([][]byte, []int, []Endpoint) (n, refused int, err error)

// Datagram is one received IKE message and the endpoint it arrived from.
type Datagram struct {
	Raw      []byte
	Endpoint Endpoint
}

type espDatagramBatch struct {
	ticket  uint64
	packets [][]byte
	// bytes is this batch's charge against the queue's byte budget, kept with
	// it so every receive path releases exactly what was reserved.
	bytes int
}

// NewHub binds the one UDP socket every session shares, on localAddr's port
// and on all local IPv4 and IPv6 interfaces. underlay says how that socket is
// kept out of the reach of the routes the mesh installs, and rt carries what
// the caller had to resolve to answer it; see Underlay for why both platforms
// need one and why they need different things.
func NewHub(localAddr string, underlay Underlay, rt Runtime) (*Hub, error) {
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve local addr: %w", err)
	}
	if laddr.IP != nil && !laddr.IP.IsUnspecified() {
		log.Printf("transport: binding to a specific local address (%s) is not supported, binding all interfaces on port %d instead", laddr.IP, laddr.Port)
	}
	index, err := bindUnderlay(underlay, rt)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	// Before the socket exists, for the same reason a move prepares before it
	// rebinds: the first datagram this node sends goes out of a socket that is
	// already bound, and nothing else will make that interface usable first.
	if index != 0 && rt.Routes != nil {
		if err := rt.Routes.Prepare(index); err != nil {
			return nil, fmt.Errorf("transport: prepare interface %d: %w", index, err)
		}
	}
	bind, fns, port, err := openPacketBind(uint16(laddr.Port), underlay, index, rt.Routes != nil)
	if err != nil {
		return nil, fmt.Errorf("transport: open bind: %w", err)
	}
	if index != 0 && rt.Routes != nil {
		if err := rt.Routes.Settle(index); err != nil {
			// The sockets are already open at this point, so returning
			// without closing them leaves both bound to the port for the life
			// of the process and the next attempt on it fails with EADDRINUSE.
			_ = bind.Close()
			return nil, fmt.Errorf("transport: settle on interface %d: %w", index, err)
		}
	}
	h := &Hub{bind: bind, port: port, underlay: underlay, boundTo: index,
		ike: make(map[uint64]*Mux), esp: make(map[uint32]*Mux),
		muxes: make(map[*Mux]struct{}), done: make(chan struct{}), started: time.Now()}
	h.reported.Store(-int64(dropReportInterval))
	for _, fn := range fns {
		go h.receiveLoop(fn)
	}
	// Started only where the binding has to follow something, so a hub that
	// binds nothing carries no goroutine and no link source.
	if underlay.Bind && rt.Links != nil {
		go h.follow(rt.Links, rt.Routes)
	}
	return h, nil
}

// NewMux creates a logical peer channel on this hub.
func (h *Hub) NewMux(remoteIP net.IP, remotePort int) (*Mux, error) {
	endpoint, err := h.bind.ParseEndpoint(net.JoinHostPort(remoteIP.String(), strconv.Itoa(remotePort)))
	if err != nil {
		return nil, fmt.Errorf("transport: parse remote endpoint: %w", err)
	}
	m := &Mux{hub: h, endpoint: endpoint, ikeCh: make(chan Datagram, 16), espCh: make(chan espDatagramBatch, espChanSize), done: make(chan struct{})}
	h.mu.Lock()
	if h.closed.Load() {
		h.mu.Unlock()
		return nil, fmt.Errorf("transport: hub closed")
	}
	h.muxes[m] = struct{}{}
	h.mu.Unlock()
	return m, nil
}

// NewMuxTo creates a logical peer channel for an endpoint a datagram arrived
// from, rather than for a configured address. A responder learns where its
// peer is only from that datagram, and the endpoint carries the reply source
// address and interface the datagram was received on.
func (h *Hub) NewMuxTo(endpoint Endpoint) (*Mux, error) {
	if endpoint == nil {
		return nil, fmt.Errorf("transport: nil remote endpoint")
	}
	m := &Mux{hub: h, endpoint: endpoint, ikeCh: make(chan Datagram, 16), espCh: make(chan espDatagramBatch, espChanSize), done: make(chan struct{})}
	h.mu.Lock()
	if h.closed.Load() {
		h.mu.Unlock()
		return nil, fmt.Errorf("transport: hub closed")
	}
	h.muxes[m] = struct{}{}
	h.mu.Unlock()
	return m, nil
}

// Listen turns on delivery of unclaimed IKE datagrams and returns the channel
// they arrive on. Until it is called nothing accumulates: an initiator-only
// node keeps dropping them exactly as before. Calling it again returns the
// same channel, and the channel is never closed; use Done to stop.
//
// The queue is bounded and a full queue drops the datagram rather than
// blocking the receive loop, because an unauthenticated peer must not be able
// to stall the dataplane. IKE retransmits, so a dropped IKE_SA_INIT costs a
// retransmission interval and nothing else.
func (h *Hub) Listen() <-chan Unclaimed {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.listen == nil {
		h.listen = make(chan Unclaimed, 64)
	}
	return h.listen
}

// SendIKETo writes one IKE message to an endpoint without a Mux. A responder
// under load answers an unauthenticated IKE_SA_INIT with a COOKIE or an
// INVALID_KE_PAYLOAD notify and keeps no state for it, which is the whole
// point of those exchanges, so there is nothing for a Mux to own.
func (h *Hub) SendIKETo(b []byte, endpoint Endpoint) error {
	out := make([]byte, nonESPMarkerLen+len(b))
	copy(out[nonESPMarkerLen:], b)
	return h.bind.Send([][]byte{out}, endpoint)
}

// Done is closed when the hub's socket is gone, so an accept loop can stop.
func (h *Hub) Done() <-chan struct{} { return h.done }

// LocalAddr returns the hub's wildcard local address; only its port is useful.
func (h *Hub) LocalAddr() net.Addr { return &net.UDPAddr{Port: int(h.port)} }

// Close closes the socket and every mux using it.
func (h *Hub) Close() error {
	return h.fail(fmt.Errorf("transport: closed"))
}

func (h *Hub) fail(cause error) (bindErr error) {
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		bindErr = h.bind.Close()
		close(h.done)
		h.mu.Lock()
		muxes := make([]*Mux, 0, len(h.muxes))
		for m := range h.muxes {
			muxes = append(muxes, m)
		}
		h.ike = make(map[uint64]*Mux)
		h.esp = make(map[uint32]*Mux)
		h.muxes = make(map[*Mux]struct{})
		h.mu.Unlock()
		for _, m := range muxes {
			m.closed.Store(true)
			m.closeDone(cause)
		}
	})
	return bindErr
}

func (h *Hub) receiveLoop(fn receiveFunc) {
	batch := espSendBatch
	bufs, sizes, eps := make([][]byte, batch), make([]int, batch), make([]Endpoint, batch)
	// Only the index is recorded while h.mu is held. The copy onto the heap
	// happens after unlocking: h.mu also serializes ESP demultiplexing and
	// every RegisterESP, and on linux one acquisition can otherwise cover up
	// to espSendBatch datagrams of copying.
	type pendingIKE struct {
		mux   *Mux
		index int
	}
	espBatches := make(map[*Mux][][]byte)
	ikeDatagrams := make([]pendingIKE, 0, batch)
	unclaimed := make([]int, 0, batch)
	for {
		n, refused, err := fn(bufs, sizes, eps)
		if refused > 0 {
			h.refused.Add(uint64(refused))
		}
		if err != nil {
			if h.closed.Load() {
				h.fail(fmt.Errorf("transport: closed"))
			} else {
				h.fail(fmt.Errorf("transport: read: %w", err))
			}
			return
		}
		clear(espBatches)
		ikeDatagrams = ikeDatagrams[:0]
		unclaimed = unclaimed[:0]
		unwanted := 0
		h.mu.Lock()
		for i := 0; i < n; i++ {
			raw := bufs[i][:sizes[i]]
			// Every arm that reaches no Mux is counted. The SPI is cleartext,
			// so anyone who can reach the port can send these, which is the
			// case an operator needs a number for rather than a log line.
			if len(raw) == 1 && raw[0] == natKeepaliveByte {
				// RFC 3948 section 2.3 has the receiver ignore these. Counted
				// all the same, on its own counter: a flood of them costs a
				// read, a demultiplex under this lock and, coalesced by GRO,
				// up to forty iterations per read, and an arm that reaches no
				// Mux and raises nothing is the one gap in the accounting.
				h.keepalives.Add(1)
				continue
			}
			if len(raw) < nonESPMarkerLen {
				unwanted++
				continue
			}
			if raw[0]|raw[1]|raw[2]|raw[3] == 0 {
				if len(raw) < nonESPMarkerLen+8 {
					unwanted++
					continue
				}
				spi := uint64(raw[4])<<56 | uint64(raw[5])<<48 | uint64(raw[6])<<40 | uint64(raw[7])<<32 | uint64(raw[8])<<24 | uint64(raw[9])<<16 | uint64(raw[10])<<8 | uint64(raw[11])
				if m := h.ike[spi]; m != nil {
					ikeDatagrams = append(ikeDatagrams, pendingIKE{mux: m, index: i})
				} else if h.listen != nil && eps[i] != nil {
					// An SA no Mux owns yet. Only a listening hub keeps
					// these; otherwise they stay dropped as before.
					unclaimed = append(unclaimed, i)
				} else {
					unwanted++
				}
			} else {
				spi := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
				if m := h.esp[spi]; m != nil {
					// Keep views into the receive buffers only until this socket
					// batch has been demultiplexed. packReceivedBatch below moves
					// all packets for a peer into one allocation before fn is
					// allowed to reuse the buffers.
					espBatches[m] = append(espBatches[m], raw)
				} else {
					unwanted++
				}
			}
		}
		h.mu.Unlock()
		if unwanted > 0 {
			h.refused.Add(uint64(unwanted))
		}
		// The queue is tested before the datagram is copied, not after, so a
		// flood from an unauthenticated peer is refused without allocating for
		// it. The send still cannot block: a hub runs one receive loop per
		// bound socket, IPv4 and IPv6 separately on linux, so room seen here
		// may be gone by the time this one gets there.
		for _, pending := range ikeDatagrams {
			if len(pending.mux.ikeCh) == cap(pending.mux.ikeCh) {
				h.noteDrop(1, "an IKE SA's receive queue")
				continue
			}
			raw := bufs[pending.index][:sizes[pending.index]]
			datagram := Datagram{
				Raw:      append([]byte(nil), raw[nonESPMarkerLen:]...),
				Endpoint: eps[pending.index],
			}
			select {
			case pending.mux.ikeCh <- datagram:
			default:
				h.noteDrop(1, "an IKE SA's receive queue")
			}
		}
		// Counted as refused rather than dropped, on a responder as much as
		// anywhere: this queue holds messages from peers that have not dialed
		// us, so anyone who can reach the port fills it, and dropped is the
		// one signal that says this node is behind on receive.
		for _, i := range unclaimed {
			if len(h.listen) == cap(h.listen) {
				h.refused.Add(1)
				continue
			}
			raw := bufs[i][:sizes[i]]
			datagram := Unclaimed{
				Raw:      append([]byte(nil), raw[nonESPMarkerLen:]...),
				Endpoint: eps[i],
			}
			select {
			case h.listen <- datagram:
			default:
				h.refused.Add(1)
			}
		}
		for m, packets := range espBatches {
			total := 0
			for _, packet := range packets {
				total += len(packet)
			}
			// Tested before packReceivedBatch copies, so a flood is refused
			// without allocating for it.
			if !m.hasRoomForESP(total) || !m.dispatchESP(packReceivedBatch(packets), total) {
				h.noteDrop(len(packets), "a peer's ESP receive queue")
			}
		}
	}
}

// packReceivedBatch detaches packets from receiveLoop's reusable recvmmsg
// buffers with one allocation per peer and socket read, rather than one heap
// allocation per datagram. Packet slice boundaries are retained so parallel
// ESP workers can authenticate the batch without any further framing work.
func packReceivedBatch(packets [][]byte) [][]byte {
	total := 0
	for _, packet := range packets {
		total += len(packet)
	}
	storage := make([]byte, total)
	offset := 0
	for i, packet := range packets {
		n := copy(storage[offset:], packet)
		packets[i] = storage[offset : offset+n]
		offset += n
	}
	return packets
}

// Mux is one peer's logical IKE and ESP channel on a Hub.
type Mux struct {
	hub           *Hub
	endpointMu    sync.RWMutex
	endpoint      Endpoint
	ikeCh         chan Datagram
	espRecvMu     sync.Mutex
	espDispatchMu sync.Mutex
	espTicket     uint64
	espCh         chan espDatagramBatch
	espQueued     atomic.Int64
	espPending    [][]byte
	done          chan struct{}
	doneOnce      sync.Once
	doneErr       atomic.Value
	closed        atomic.Bool
	ownHub        bool
}

// hasRoomForESP is consulted before packReceivedBatch copies a batch onto the
// heap. dispatchESP still decides; this only keeps the copy from happening for
// a batch that is about to be dropped anyway.
func (m *Mux) hasRoomForESP(bytes int) bool {
	return len(m.espCh) < cap(m.espCh) && m.espQueued.Load()+int64(bytes) <= espQueueBytes
}

// dispatchESP hands one demultiplexed batch to this peer's receive queue under
// the ticket that fixes its order, and reports whether the queue took it. A
// dropped batch consumes no ticket, because a hub may have separate IPv4 and
// IPv6 receive loops and the gap would stall whichever emitter waits for it.
func (m *Mux) dispatchESP(packets [][]byte, bytes int) bool {
	m.espDispatchMu.Lock()
	defer m.espDispatchMu.Unlock()
	if m.espQueued.Load()+int64(bytes) > espQueueBytes {
		return false
	}
	batch := espDatagramBatch{ticket: m.espTicket, packets: packets, bytes: bytes}
	select {
	case m.espCh <- batch:
		m.espQueued.Add(int64(bytes))
		m.espTicket++
		return true
	default:
		return false
	}
}

// takeESP releases a batch's share of the queue's byte budget. Every path that
// reads from espCh goes through it, or the budget only ever shrinks.
func (m *Mux) takeESP(batch espDatagramBatch) [][]byte {
	m.espQueued.Add(-int64(batch.bytes))
	return batch.packets
}

// Dial preserves the one-peer convenience path. The returned mux owns its
// newly-created hub and closes it when closed.
func Dial(localAddr string, remoteIP net.IP, remotePort int) (*Mux, error) {
	h, err := NewHub(localAddr, Underlay{}, Runtime{})
	if err != nil {
		return nil, err
	}
	m, err := h.NewMux(remoteIP, remotePort)
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	m.ownHub = true
	return m, nil
}

func (m *Mux) LocalAddr() net.Addr { return m.hub.LocalAddr() }
func (m *Mux) IsClosed() bool      { return m.closed.Load() || m.hub.closed.Load() }

// Done is closed when this peer's transport becomes unavailable.
func (m *Mux) Done() <-chan struct{} { return m.done }

// RegisterIKE routes packets whose marked IKE header has spi as SPIi to m.
func (m *Mux) RegisterIKE(spi uint64) error { return m.registerIKE(spi) }
func (m *Mux) registerIKE(spi uint64) error {
	if spi == 0 {
		// RFC 7296 section 3.1 on the initiator's SPI: "This value MUST NOT be
		// zero." Claiming it here would route every datagram carrying one to
		// this mux, which is the same reason RegisterESP refuses it.
		return fmt.Errorf("transport: IKE SPI must be nonzero")
	}
	m.hub.mu.Lock()
	defer m.hub.mu.Unlock()
	if m.closed.Load() || m.hub.closed.Load() {
		return fmt.Errorf("transport: closed")
	}
	if owner := m.hub.ike[spi]; owner != nil && owner != m {
		return fmt.Errorf("transport: IKE SPI %016x already registered", spi)
	}
	m.hub.ike[spi] = m
	return nil
}

// UnregisterIKE stops routing IKE packets for spi to m.
func (m *Mux) UnregisterIKE(spi uint64) {
	m.hub.mu.Lock()
	if m.hub.ike[spi] == m {
		delete(m.hub.ike, spi)
	}
	m.hub.mu.Unlock()
}

// RegisterESP routes bare ESP packets whose inbound SPI is spi to m.
func (m *Mux) RegisterESP(spi uint32) error {
	if spi == 0 {
		return fmt.Errorf("transport: ESP SPI must be nonzero")
	}
	m.hub.mu.Lock()
	defer m.hub.mu.Unlock()
	if m.closed.Load() || m.hub.closed.Load() {
		return fmt.Errorf("transport: closed")
	}
	if owner := m.hub.esp[spi]; owner != nil && owner != m {
		return fmt.Errorf("transport: ESP SPI %08x already registered", spi)
	}
	m.hub.esp[spi] = m
	return nil
}

// UnregisterESP stops routing ESP packets for spi to m.
func (m *Mux) UnregisterESP(spi uint32) {
	m.hub.mu.Lock()
	if m.hub.esp[spi] == m {
		delete(m.hub.esp, spi)
	}
	m.hub.mu.Unlock()
}

func (m *Mux) SendIKE(b []byte) error {
	return m.SendIKETo(b, m.currentEndpoint())
}

func (m *Mux) currentEndpoint() Endpoint {
	m.endpointMu.RLock()
	defer m.endpointMu.RUnlock()
	return m.endpoint
}

// AdoptEndpoint changes the destination used for subsequent IKE and ESP
// traffic. IKE calls this only after authenticating a request from endpoint.
func (m *Mux) AdoptEndpoint(endpoint Endpoint) {
	m.endpointMu.Lock()
	m.endpoint = endpoint
	m.endpointMu.Unlock()
}

// Endpoint is the destination this mux currently sends to, which a NAT may
// have moved since the session opened. It takes the same lock AdoptEndpoint
// writes under, so a diagnostic reads one endpoint rather than a torn one.
func (m *Mux) Endpoint() Endpoint {
	m.endpointMu.Lock()
	defer m.endpointMu.Unlock()
	return m.endpoint
}

func (m *Mux) SendIKETo(b []byte, endpoint Endpoint) error {
	out := make([]byte, nonESPMarkerLen+len(b))
	copy(out[nonESPMarkerLen:], b)
	return m.hub.bind.Send([][]byte{out}, endpoint)
}
func (m *Mux) SendESP(b []byte) error { return m.SendESPBatch([][]byte{b}) }

// SendESPBatch writes directly to the shared UDP bind. Production batches are
// already adjacent slices of one encryption allocation, which lets Bind use
// UDP GSO without another packing copy. Bind may append into spare capacity
// while coalescing, so callers transfer exclusive ownership of that capacity
// for the duration of the send, just as for the packet contents themselves.
func (m *Mux) SendESPBatch(bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	select {
	case <-m.done:
		return m.doneError()
	default:
	}

	endpoint := m.currentEndpoint()
	for len(bufs) != 0 {
		n := min(len(bufs), espSendBatch)
		if err := m.hub.bind.Send(bufs[:n], endpoint); err != nil {
			return fmt.Errorf("transport: send ESP batch: %w", err)
		}
		bufs = bufs[n:]
	}
	return nil
}

func (m *Mux) RecvIKE() ([]byte, error) {
	b, _, err := m.RecvIKEFrom()
	return b, err
}
func (m *Mux) RecvIKEFrom() ([]byte, Endpoint, error) {
	select {
	case d := <-m.ikeCh:
		return d.Raw, d.Endpoint, nil
	case <-m.done:
		return nil, nil, m.doneError()
	}
}

// IKE is the channel this peer's IKE messages arrive on, so a control loop can
// select over it together with its own work instead of waking on a timer to
// check both. It is the same queue the Recv methods drain, so only one reader
// may use either at a time: the handshake uses Recv and hands over to the
// control loop once the SA is established.
func (m *Mux) IKE() <-chan Datagram { return m.ikeCh }

// Err is why this mux is done, for a caller that selected on Done itself.
func (m *Mux) Err() error { return m.doneError() }
func (m *Mux) RecvIKEUntil(deadline time.Time) ([]byte, error) {
	b, _, err := m.RecvIKEFromUntil(deadline)
	return b, err
}
func (m *Mux) RecvIKEFromUntil(deadline time.Time) ([]byte, Endpoint, error) {
	select {
	case d := <-m.ikeCh:
		return d.Raw, d.Endpoint, nil
	case <-m.done:
		return nil, nil, m.doneError()
	case <-time.After(time.Until(deadline)):
		return nil, nil, errTimeout
	}
}
func (m *Mux) RecvESP() ([]byte, error) {
	m.espRecvMu.Lock()
	defer m.espRecvMu.Unlock()
	if len(m.espPending) == 0 {
		select {
		case batch := <-m.espCh:
			m.espPending = m.takeESP(batch)
		case <-m.done:
			return nil, m.doneError()
		}
	}
	b := m.espPending[0]
	m.espPending = m.espPending[1:]
	return b, nil
}

// RecvESPBatchConcurrent returns one complete socket-demultiplexed batch and
// its receive-order ticket. It is safe for multiple data-plane workers to call
// concurrently: the transport channel distributes batches, while the ticket
// lets their independently decrypted results be emitted in original order.
// It must not be mixed with RecvESP, RecvESPBatch, or RecvESPUntil on one Mux.
func (m *Mux) RecvESPBatchConcurrent() (uint64, [][]byte, error) {
	select {
	case batch := <-m.espCh:
		return batch.ticket, m.takeESP(batch), nil
	case <-m.done:
		return 0, nil, m.doneError()
	}
}

// RecvESPBatch blocks for one ESP packet, then drains immediately available
// packets into dst up to its capacity. A nil dst gets the transport's normal
// batch capacity. Keeping the receive batch intact lets callers amortize
// decrypt-pipeline and TUN write overhead without delaying a lone packet.
func (m *Mux) RecvESPBatch(dst [][]byte) ([][]byte, error) {
	m.espRecvMu.Lock()
	defer m.espRecvMu.Unlock()
	if cap(dst) == 0 {
		dst = make([][]byte, 0, espSendBatch)
	} else {
		dst = dst[:0]
	}
	for len(dst) < cap(dst) {
		if len(m.espPending) == 0 {
			if len(dst) == 0 {
				select {
				case batch := <-m.espCh:
					m.espPending = m.takeESP(batch)
				case <-m.done:
					return nil, m.doneError()
				}
			} else {
				select {
				case batch := <-m.espCh:
					m.espPending = m.takeESP(batch)
				case <-m.done:
					return dst, nil
				default:
					return dst, nil
				}
			}
		}
		n := min(cap(dst)-len(dst), len(m.espPending))
		dst = append(dst, m.espPending[:n]...)
		m.espPending = m.espPending[n:]
	}
	return dst, nil
}

func (m *Mux) RecvESPUntil(deadline time.Time) ([]byte, error) {
	m.espRecvMu.Lock()
	defer m.espRecvMu.Unlock()
	if len(m.espPending) == 0 {
		select {
		case batch := <-m.espCh:
			m.espPending = m.takeESP(batch)
		case <-m.done:
			return nil, m.doneError()
		case <-time.After(time.Until(deadline)):
			return nil, errTimeout
		}
	}
	b := m.espPending[0]
	m.espPending = m.espPending[1:]
	return b, nil
}

var errTimeout = fmt.Errorf("transport: receive timeout")

func (m *Mux) closeDone(err error) { m.doneOnce.Do(func() { m.doneErr.Store(err); close(m.done) }) }
func (m *Mux) doneError() error {
	if err, _ := m.doneErr.Load().(error); err != nil {
		return err
	}
	return fmt.Errorf("transport: closed")
}

// Close unregisters this peer. It does not close the shared hub.
func (m *Mux) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	m.hub.mu.Lock()
	for spi, owner := range m.hub.ike {
		if owner == m {
			delete(m.hub.ike, spi)
		}
	}
	for spi, owner := range m.hub.esp {
		if owner == m {
			delete(m.hub.esp, spi)
		}
	}
	delete(m.hub.muxes, m)
	m.hub.mu.Unlock()
	m.closeDone(fmt.Errorf("transport: closed"))
	if m.ownHub {
		return m.hub.Close()
	}
	return nil
}
