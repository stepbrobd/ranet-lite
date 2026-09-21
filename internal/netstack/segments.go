package netstack

import (
	"errors"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/srv6"
)

// This file is where segment routing meets the dataplane. The decision itself
// is in internal/srv6, which takes bytes and returns bytes; here is the part
// that knows about peers, about the tun and about backpressure.
//
// It sits on the inbound path rather than on the kernel's forwarding table
// because a decrypted packet passes through this process before anything else
// sees it, and because three of the four platforms this tree builds for have
// no forwarding table to put a local SID in.

// errNotIP is a waypoint's result that is no longer an IP packet, which
// cannot happen while End only rewrites two fields, and is reported rather
// than silently dropped so that a change which made it possible is visible.
var errNotIP = errors.New("netstack: a forwarded segment is not an IP packet")

// segmentDropInterval bounds how often a refused segment is reported. A peer
// choosing to send malformed headers should cost this node a counter, not a
// log line per packet.
const segmentDropInterval = 30 * time.Second

// icmpBurst and icmpRefill bound the ICMP errors this node answers refused
// packets with. A traceroute sends three probes per hop, so the burst carries
// two hops' worth without waiting, and the refill bounds what a peer sending
// refused headers in a loop gets out of this node.
const (
	icmpBurst  = 8
	icmpRefill = 250 * time.Millisecond
)

// SetSteering installs the table deciding which of this node's own packets go
// through a segment list, or nil for none. Like SetSegments it is called
// before the device carries anything and read on the hot path, so the pointer
// is swapped rather than the table mutated.
func (m *Mesh) SetSteering(table *srv6.SteerTable) { m.steerTable.Store(table) }

// Steering is the table currently installed, for a diagnostic to report.
func (m *Mesh) Steering() *srv6.SteerTable { return m.steerTable.Load() }

// steerAction tells the caller how to treat a packet steer has looked at.
type steerAction uint8

const (
	// steerPass is a packet no policy claims, which is almost all of them on a
	// node that steers at all, and every packet on one that does not.
	steerPass steerAction = iota
	// steerSent is a packet encapsulated in place, to be routed by the segment
	// it now carries rather than by the address it was written to.
	steerSent
	// steerDrop is a packet a policy claimed and this node could not
	// encapsulate.
	steerDrop
)

// steer encapsulates one outbound packet when a policy claims it, in the
// buffer the tun reader already owns.
//
// A packet no policy claims costs one trie lookup, which is the same lookup
// the forwarding table is about to do anyway. One a policy claims and this
// node cannot encapsulate is dropped rather than sent as it was: a steering
// policy here selects an exit, so sending the packet by the metric instead
// puts it out of a different node under a source address that node does not
// announce, which is a wrong path rather than a degraded one. Every reason
// the encapsulation can fail is refused when the configuration is read, so
// what is left needs a packet larger than the device MTU this node set, and
// that is a deployment to fix rather than to carry.
func (m *Mesh) steer(buf []byte, size int, source, destination netip.Addr) (int, steerAction) {
	table := m.steerTable.Load()
	if table == nil {
		return size, steerPass
	}
	policy := table.Lookup(source, destination)
	if policy == nil {
		return size, steerPass
	}
	encapsulated, err := srv6.EncapsulateInPlace(buf, tunOffset, size, policy.Source, policy.Path)
	if err != nil {
		m.segmentsUnsteered.Add(1)
		m.reportSegmentDrop("a packet a policy claimed could not be encapsulated", "policy", policy, "err", err)
		return size, steerDrop
	}
	m.segmentsSteered.Add(1)
	return encapsulated, steerSent
}

// SetSegments installs the segments this node answers for, or nil for none.
// It is called before any session exists and read on the inbound path, so the
// pointer is swapped rather than the table mutated.
func (m *Mesh) SetSegments(table *srv6.LocalTable) { m.segmentTable.Store(table) }

// Segments is the table currently installed, for a diagnostic to report.
func (m *Mesh) Segments() *srv6.LocalTable { return m.segmentTable.Load() }

// SegmentCounters records how this node has acted as a waypoint and as an
// exit.
type SegmentCounters struct {
	Forwarded uint64
	Delivered uint64
	Dropped   uint64
	// Steered counts this node's own packets that a policy encapsulated, and
	// Unsteered the ones a policy claimed and this node could not, which are
	// dropped rather than sent by a route the policy exists to override.
	Steered   uint64
	Unsteered uint64
	// Answered counts the ICMP errors sent for refused packets, which is the
	// half of Dropped a sender was told about.
	Answered uint64
}

func (m *Mesh) SegmentCounters() SegmentCounters {
	return SegmentCounters{
		Forwarded: m.segmentsForwarded.Load(),
		Delivered: m.segmentsDelivered.Load(),
		Dropped:   m.segmentsDropped.Load(),
		Steered:   m.segmentsSteered.Load(),
		Unsteered: m.segmentsUnsteered.Load(),
		Answered:  m.segmentsAnswered.Load(),
	}
}

// applySegments takes the packets addressed to this node's own segments out of
// an inbound batch, acts on each, and returns what is left to be written to
// the tun.
//
// A node with no segments configured returns immediately, and one that has
// them pays a map lookup per IPv6 packet and nothing else until a segment of
// its own actually arrives: the replacement slice is built only from the first
// packet that is ours, and a batch with none is returned untouched.
func (m *Mesh) applySegments(raw [][]byte) [][]byte {
	table := m.segmentTable.Load()
	if table == nil {
		return raw
	}
	var deliver [][]byte
	// take copies the packets already passed over, the first time one of this
	// node's own segments turns up in the batch.
	take := func(i int) {
		if deliver == nil {
			deliver = append(make([][]byte, 0, len(raw)), raw[:i]...)
		}
	}
	var forward []forwardedSegment
	for i, packet := range raw {
		result := actLocally(table, packet)
		switch result.Action {
		case srv6.ActionPass:
			if deliver != nil {
				deliver = append(deliver, packet)
			}
		case srv6.ActionDeliver:
			take(i)
			m.segmentsDelivered.Add(1)
			deliver = append(deliver, result.Inner)
		case srv6.ActionForward:
			take(i)
			forward = append(forward, forwardedSegment{raw: packet, next: result.Next})
		case srv6.ActionDrop:
			take(i)
			m.noteSegmentDrop(result.Err)
			m.answerRefused(packet, result.Err)
		}
	}
	m.forwardSegments(forward)
	if deliver == nil {
		return raw
	}
	return deliver
}

// actLocally runs this node's own segments until the packet is going somewhere
// else. A kernel repeats its FIB lookup after a waypoint rewrites the
// destination, so a list naming two segments of one node is acted on twice
// there, and consulting the table again does the same here. Without it the
// second segment has no mesh route, because a node does not route to itself,
// and the packet is dropped one hop short.
//
// The number of times is bounded by the longest list this node acts on rather
// than by the hop limit, which the peer chooses.
func actLocally(table *srv6.LocalTable, packet []byte) srv6.Result {
	result := table.Handle(packet)
	for range srv6.MaxSegments {
		if result.Action != srv6.ActionForward {
			return result
		}
		again := table.Handle(packet)
		if again.Action == srv6.ActionPass {
			return result
		}
		result = again
	}
	return result
}

// forwardedSegment is one waypointed packet between the decision and the send,
// held so that a whole batch can be reserved for at once.
type forwardedSegment struct {
	raw        []byte
	next       netip.Addr
	peer       *Peer
	nextHeader byte
}

// forwardSegments sends the packets a waypoint has rewritten on to the peers
// their new destinations select.
//
// It takes one place on each peer's budget for that peer's whole share of the
// batch, as dispatchOutbound does for a tun read. Taking one per packet
// instead would be the same accounting at a 128th of the batch size, since an
// ESP receive batch is 128 packets against a budget of twice the core count:
// most of a forwarded burst would be dropped on an idle machine, and a peer
// could spend this node's whole allowance to a third peer.
//
// The budget is the peer's ordinary one rather than the control budget babel
// runs on, because this is somebody else's traffic: a segment list pointed at
// this node must not be able to spend the allowance this node's own routing
// protocol needs. A peer with no place free drops its share and counts it, the
// way a full egress queue drops.
func (m *Mesh) forwardSegments(segments []forwardedSegment) {
	if len(segments) == 0 {
		return
	}
	counts := make(map[*Peer]int, len(segments))
	order := make([]*Peer, 0, len(segments))
	for i := range segments {
		segment := &segments[i]
		src, dst, nextHeader, ok := addrsOf(segment.raw)
		if !ok {
			m.noteSegmentDrop(errNotIP)
			continue
		}
		peer, ok := m.Routes.Lookup(src, dst)
		if !ok || peer == nil {
			m.segmentsDropped.Add(1)
			m.reportSegmentDrop("no route to the next segment", "segment", segment.next)
			continue
		}
		if counts[peer] == 0 {
			order = append(order, peer)
		}
		counts[peer]++
		segment.peer, segment.nextHeader = peer, nextHeader
	}
	batches := make(map[*Peer]*peerBatch, len(order))
	for _, peer := range order {
		batch := peer.reserveBatchNow(counts[peer])
		if batch == nil {
			// The peer counts its own share of this; the segment counter says
			// how much of it was somebody else's traffic.
			m.segmentsDropped.Add(uint64(counts[peer]))
			continue
		}
		batches[peer] = batch
	}
	for _, segment := range segments {
		if batch := batches[segment.peer]; batch != nil {
			batch.append(segment.raw, segment.nextHeader)
		}
	}
	for _, peer := range order {
		batch := batches[peer]
		if batch == nil {
			continue
		}
		if err := batch.enqueue(); err != nil {
			m.segmentsDropped.Add(uint64(counts[peer]))
			m.reportSegmentDrop("the transport lost a forwarded segment", "err", err)
			continue
		}
		m.segmentsForwarded.Add(uint64(counts[peer]))
	}
}

func (m *Mesh) noteSegmentDrop(err error) {
	m.segmentsDropped.Add(1)
	m.reportSegmentDrop("a packet addressed to one of this node's segments was refused", "err", err)
}

// answerRefused sends the ICMP error RFC 8986 section 4.1 answers a refused
// packet with, S06 for a hop limit that ran out here and S10 for a header this
// node will not act on. Everything else is dropped in silence, because an
// error is only worth sending where it names something the sender can fix.
//
// The budget is the whole of the bound. An error is a packet a peer's packet
// caused this node to send, which is the shape every amplification this tree
// has had took, and RFC 4443 section 2.4 (f) requires a limit for that reason.
// A burst covers a traceroute's three probes per hop, and the refill bounds a
// node sending refused headers in a loop.
func (m *Mesh) answerRefused(offending []byte, reason error) {
	var answer []byte
	var ok bool
	source := netip.AddrFrom16([16]byte(offending[24:40]))
	switch {
	case errors.Is(reason, srv6.ErrHopLimit):
		answer, ok = srv6.TimeExceeded(offending, source)
	case errors.Is(reason, srv6.ErrHeaderInvalid):
		answer, ok = srv6.ParameterProblem(offending, source)
	}
	if !ok || !m.takeICMPToken() {
		return
	}
	peer, ok := m.Routes.Lookup(source, netip.AddrFrom16([16]byte(offending[8:24])))
	if !ok || peer == nil {
		return
	}
	batch := peer.reserveBatchNow(1)
	if batch == nil {
		return
	}
	batch.append(answer, esp.NextHeaderIPv6)
	if err := batch.enqueue(); err != nil {
		m.reportSegmentDrop("the transport lost an icmp error", "err", err)
		return
	}
	m.segmentsAnswered.Add(1)
}

// takeICMPToken reports whether this node may answer one more refused packet.
// The bucket holds icmpBurst and refills at icmpRefill, so a traceroute gets
// its probes answered and a flood gets the refill rate.
func (m *Mesh) takeICMPToken() bool {
	now := int64(time.Since(m.segmentsStarted))
	for {
		last := m.icmpFilled.Load()
		tokens := min(icmpBurst, m.icmpTokens.Load()+(now-last)/int64(icmpRefill))
		if tokens < 1 {
			return false
		}
		if m.icmpFilled.CompareAndSwap(last, now) {
			m.icmpTokens.Store(tokens - 1)
			return true
		}
	}
}

// reportSegmentDrop writes at most one line per interval, whatever the reason,
// so a peer sending a stream of refused headers costs a counter rather than a
// log. The counter is the record; the line is there to say what kind.
func (m *Mesh) reportSegmentDrop(message string, args ...any) {
	now := int64(time.Since(m.segmentsStarted))
	previous := m.segmentReported.Load()
	if now-previous < int64(segmentDropInterval) || !m.segmentReported.CompareAndSwap(previous, now) {
		return
	}
	slog.Warn(message, append([]any{"interface", m.Name}, args...)...)
}

// segmentCounters is the atomic half of SegmentCounters, embedded in Mesh.
type segmentCounters struct {
	segmentTable      atomic.Pointer[srv6.LocalTable]
	segmentsForwarded atomic.Uint64
	segmentsDelivered atomic.Uint64
	segmentsDropped   atomic.Uint64
	steerTable        atomic.Pointer[srv6.SteerTable]
	segmentsSteered   atomic.Uint64
	segmentsUnsteered atomic.Uint64
	segmentsAnswered  atomic.Uint64
	// icmpTokens and icmpFilled are the bucket answerRefused draws from, in
	// tokens and in nanoseconds since segmentsStarted.
	icmpTokens atomic.Int64
	icmpFilled atomic.Int64
	// segmentsStarted and segmentReported space the drop reports on the
	// monotonic clock, as Peer.sendErrReported does, so a backward step of the
	// wall clock cannot suppress every report until it catches up.
	segmentsStarted time.Time
	segmentReported atomic.Int64
}

// startSegmentReports lets the first refused packet report immediately and
// spaces the rest.
func (c *segmentCounters) startSegmentReports() {
	c.segmentsStarted = time.Now()
	c.segmentReported.Store(-int64(segmentDropInterval))
	c.icmpTokens.Store(icmpBurst)
}
