package netstack

import (
	"errors"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

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

// SetSteering installs the table deciding which of this node's own packets go
// through a segment list, or nil for none. Like SetSegments it is called
// before the device carries anything and read on the hot path, so the pointer
// is swapped rather than the table mutated.
func (m *Mesh) SetSteering(table *srv6.SteerTable) { m.steerTable.Store(table) }

// Steering is the table currently installed, for a diagnostic to report.
func (m *Mesh) Steering() *srv6.SteerTable { return m.steerTable.Load() }

// steer encapsulates one outbound packet when a policy claims it, in the
// buffer the tun reader already owns, and reports whether it did.
//
// A packet no policy claims costs one trie lookup, which is the same lookup
// the forwarding table is about to do anyway. One that cannot be encapsulated
// is left alone rather than dropped: it then takes the route it would have
// taken unsteered, which is the more conservative of the two failures, and the
// counter says it happened.
func (m *Mesh) steer(buf []byte, size int, source, destination netip.Addr) (int, bool) {
	table := m.steerTable.Load()
	if table == nil {
		return size, false
	}
	policy := table.Lookup(source, destination)
	if policy == nil {
		return size, false
	}
	encapsulated, err := srv6.EncapsulateInPlace(buf, tunOffset, size, policy.Source, policy.Path, 0)
	if err != nil {
		m.segmentsUnsteered.Add(1)
		m.reportSegmentDrop("a packet could not be steered and went unencapsulated", "policy", policy, "err", err)
		return size, false
	}
	m.segmentsSteered.Add(1)
	return encapsulated, true
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
	// Unsteered the ones a policy claimed and could not, which went out as
	// they were.
	Steered   uint64
	Unsteered uint64
}

func (m *Mesh) SegmentCounters() SegmentCounters {
	return SegmentCounters{
		Forwarded: m.segmentsForwarded.Load(),
		Delivered: m.segmentsDelivered.Load(),
		Dropped:   m.segmentsDropped.Load(),
		Steered:   m.segmentsSteered.Load(),
		Unsteered: m.segmentsUnsteered.Load(),
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
	for i, packet := range raw {
		result := table.Handle(packet)
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
			m.forwardSegment(packet, result.Next)
		case srv6.ActionDrop:
			take(i)
			m.noteSegmentDrop(result.Err)
		}
	}
	if deliver == nil {
		return raw
	}
	return deliver
}

// forwardSegment sends one packet a waypoint has already rewritten on to the
// peer its new destination selects.
//
// It takes a single place on the peer's ordinary budget rather than the
// control budget babel uses, because this is somebody else's traffic: a
// segment list pointed at this node must not be able to spend the allowance
// this node's own routing protocol runs on. A peer with no place free drops
// the packet and counts it, the way a full egress queue drops.
func (m *Mesh) forwardSegment(raw []byte, next netip.Addr) {
	src, dst, nextHeader, ok := addrsOf(raw)
	if !ok {
		m.noteSegmentDrop(errNotIP)
		return
	}
	peer, ok := m.Routes.Lookup(src, dst)
	if !ok || peer == nil {
		m.segmentsDropped.Add(1)
		m.reportSegmentDrop("no route to the next segment", "segment", next)
		return
	}
	batch := peer.reserveBatchNow(1)
	if batch == nil {
		// The peer counts this one: it is the same drop an ordinary packet
		// takes when the peer has no transmission slot free.
		m.segmentsDropped.Add(1)
		return
	}
	batch.append(raw, nextHeader)
	if err := batch.enqueue(); err != nil {
		m.segmentsDropped.Add(1)
		m.reportSegmentDrop("the transport lost a forwarded segment", "err", err)
		return
	}
	m.segmentsForwarded.Add(1)
}

func (m *Mesh) noteSegmentDrop(err error) {
	m.segmentsDropped.Add(1)
	m.reportSegmentDrop("a packet addressed to one of this node's segments was refused", "err", err)
}

// reportSegmentDrop writes at most one line per interval, whatever the reason,
// so a peer sending a stream of refused headers costs a counter rather than a
// log. The counter is the record; the line is there to say what kind.
func (m *Mesh) reportSegmentDrop(message string, args ...any) {
	now := time.Now()
	last := m.segmentReported.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < segmentDropInterval {
		return
	}
	if !m.segmentReported.CompareAndSwap(last, now.UnixNano()) {
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
	// segmentReported is the last report in unix nanoseconds, zero for never.
	segmentReported atomic.Int64
}
