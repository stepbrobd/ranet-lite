package babel

import (
	"bytes"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/netstack"
)

// sendPriority orders what a pass gives up first when the peer's transmission
// budget runs out. emitLocked takes a place for every packet before any is
// sent, so a pass that fills the budget drops whatever it reached last.
type sendPriority int

const (
	// A Hello and its IHU hold the adjacency up: three lost in a row withdraw
	// every route through the neighbor, and the only retry is the next hello
	// interval.
	priorityHello sendPriority = iota
	// A request is recorded as asked before it leaves, and that record is
	// what stops it being asked again, so a dropped one is a prefix that
	// stops being asked about at all.
	priorityRequest
	// A dump is the largest action of a pass and the one that can wait for
	// the next interval.
	priorityDump
)

// tlvUndo gives back what one group of an action's TLVs consumed: the prefix
// the group advertised, and whether that advertisement spent the record of the
// neighbor having been told about it, which only a retraction does. firstTLV
// must be the group's first index and the list must stay in ascending order of
// it: reserveBatchesTo never splits a group across packets, so an undo then
// belongs to exactly one packet, and takeUndos walks the list once.
//
// It carries the prefix rather than a closure over it because a dump builds
// one per prefix, sixteen thousand at maxRouteKeys, and a closure each is an
// allocation each under the lock the whole protocol runs on.
type tlvUndo struct {
	firstTLV int
	key      routeKey
	spent    bool
}

type sendAction struct {
	neighbor *neighborState
	dest     netip.Addr
	priority sendPriority
	tlvs     []RawTLV
	// rollback undoes what the TLVs consumed, per packet: a record spent by a
	// packet that never left is one nothing will redo, and a whole action
	// rolled back for one refused packet re-owes a table the neighbor is
	// already receiving. See oweAgain and takeUndos.
	rollback []tlvUndo
	// whenRefused runs for the whole action when no packet reached the
	// transport and the retry will send the same bytes again. A Hello's
	// sequence number belongs here rather than in rollback: one lost in the
	// syscall was spent, and giving it back repeats a number to the peer.
	whenRefused []func()
}

// lostUndo is one undo waiting for the next pass, with the neighbor it belongs
// to: the sender reports on its own goroutine, where the speaker's state is
// not this goroutine's to touch.
type lostUndo struct {
	neighbor *neighborState
	undo     tlvUndo
}

// reservedPacket is one packet holding a place in its peer's transmission
// order, with the neighbor it is for and the undos of the TLVs it carries.
// They outlive the reservation because the transport answers later, see
// netstack.Place.OnFailure.
type reservedPacket struct {
	place    *netstack.Place
	neighbor *neighborState
	undo     []tlvUndo
}

// takeUndos splits off the undos of the TLVs in [from, to) and returns the
// rest. Rescanning from the front for each packet is quadratic in the dump,
// 4.2 ms of it at maxRouteKeys prefixes, under the lock the whole protocol
// runs on.
func takeUndos(rollback []tlvUndo, from, to int) ([]tlvUndo, []tlvUndo) {
	for len(rollback) > 0 && rollback[0].firstTLV < from {
		rollback = rollback[1:]
	}
	end := 0
	for end < len(rollback) && rollback[end].firstTLV < to {
		end++
	}
	return rollback[:end], rollback[end:]
}

// emitLocked fixes the transmission order of everything the caller decided
// under s.mu and returns the function that sends it, which runs after the lock
// is released. It must be called with s.mu held.
//
// Two goroutines emit: Run, and Receive on the sending peer's own decrypt
// path. Both decide under this lock and both have to send after releasing it,
// because an in-memory transport delivers inline and would re-enter Receive.
// Taking each packet's place in its peer's transmission order here, rather
// than at send time, stops the second one overtaking the first: a retraction
// decided before the update that replaces it would otherwise reach the
// neighbor after it, and the neighbor would hold the wrong answer until the
// next periodic dump.
//
// A packet with no transmission slot free is dropped here, and the bookkeeping
// it consumed is rolled back while the lock is still held. One that takes a
// slot and is then lost in the transport is given back on a later pass
// instead, because that answer arrives on the sender's own goroutine. See
// noteLost.
func (s *Speaker) emitLocked(actions []sendAction) func() {
	var packets []reservedPacket
	// Ordered by what a pass can afford to lose, least first. Sorting on the
	// destination instead put the Hello behind every request of the pass,
	// because a Hello is multicast too and coalesce had merged it into the
	// dump; a Hello is the one packet here that nothing else can stand in
	// for. See sendPriority.
	merged := coalesce(actions)
	slices.SortStableFunc(merged, func(a, b sendAction) int {
		return int(a.priority) - int(b.priority)
	})
	refused := false
	for _, action := range merged {
		reserved, lost, whole := s.reserveBatchesTo(action)
		packets = append(packets, reserved...)
		for _, undo := range lost {
			s.oweAgain(action.neighbor, undo)
		}
		if whole {
			continue
		}
		refused = true
		for _, restore := range action.whenRefused {
			restore()
		}
	}
	if refused {
		// The rollbacks have put the work back where the next pass will find
		// it, and nothing else will wake for it. See noteSendRetryLocked.
		s.noteSendRetryLocked(time.Now())
	}
	if len(packets) == 0 {
		return func() {}
	}
	return func() {
		for _, packet := range packets {
			// Registered before the send, because the sender may finish with
			// the packet inside Send on a peer that transmits synchronously.
			packet.place.OnFailure(s.noteLost(packet.neighbor, packet.undo))
			if err := packet.place.Send(); err != nil {
				slog.Warn("babel send failed", "err", err)
			}
		}
	}
}

// noteLost is the completion signal for one packet, or nil when the packet
// carries no bookkeeping to give back. It runs on the peer's sender goroutine,
// so it takes no speaker lock.
//
// The wake is spaced like the retry a refused reservation schedules, and for
// the same reason. A peer whose transport keeps failing after the reservation
// succeeded closes a loop with nothing in it to wait on: give the work back,
// rebuild it, reserve it, lose it, wake, as fast as the syscall returns.
// Measured at 40,000 passes a second, each a reselection of the whole table
// under the lock every neighbor's receive path needs.
func (s *Speaker) noteLost(n *neighborState, undo []tlvUndo) func(error) {
	if len(undo) == 0 {
		return nil
	}
	return func(err error) {
		now := time.Now()
		s.lostMu.Lock()
		for _, entry := range undo {
			s.lost = append(s.lost, lostUndo{neighbor: n, undo: entry})
		}
		soon := now.Sub(s.lostWoke) < s.sendRetryInterval()
		if !soon {
			s.lostWoke = now
		}
		s.lostMu.Unlock()
		slog.Debug("babel packet lost after it was queued", "err", err)
		if !soon {
			s.wake()
		}
	}
}

// applyLostLocked gives back the bookkeeping of every packet a peer's sender
// lost since the last pass. Without it a retraction that reached the transport
// and no further leaves the prefix out of n.advertised, so every later dump
// skips it and the neighbor keeps routing through a next hop that has
// withdrawn it. It must be called with s.mu held.
func (s *Speaker) applyLostLocked() {
	s.lostMu.Lock()
	lost := s.lost
	s.lost = nil
	s.lostMu.Unlock()
	for _, entry := range lost {
		s.oweAgain(entry.neighbor, entry.undo)
	}
}

// coalesce merges the actions aimed at the same neighbor and destination and
// carrying the same priority into one, preserving order. The priority is part
// of the key so a Hello, which is multicast like the dump, keeps its own place
// in the transmission order and its own rollback. Requests are produced one per TLV, so one arriving
// packet carrying forty seqno requests for forty prefixes would otherwise
// leave as forty packets aimed at whichever third peer can answer them, and a
// neighbor loss that starves a thousand prefixes as a thousand. reserveBatchesTo
// still splits whatever this produces at the configured packet size.
func coalesce(actions []sendAction) []sendAction {
	if len(actions) < 2 {
		return actions
	}
	type target struct {
		neighbor *neighborState
		dest     netip.Addr
		priority sendPriority
	}
	merged := make([]sendAction, 0, len(actions))
	at := make(map[target]int, len(actions))
	owned := make(map[int]bool, len(actions))
	for _, action := range actions {
		if len(action.tlvs) == 0 {
			continue
		}
		key := target{action.neighbor, action.dest, action.priority}
		i, seen := at[key]
		if !seen {
			at[key] = len(merged)
			merged = append(merged, action)
			continue
		}
		if !owned[i] {
			// Copied once, on the first merge into this entry: the slice came
			// from the caller and its spare capacity is not ours to append
			// into. Copying on every merge instead would make a neighbor loss
			// that starves a thousand prefixes quadratic in the number of
			// prefixes, which is the case this function exists for.
			merged[i].rollback = slices.Clone(merged[i].rollback)
			merged[i].tlvs = slices.Clone(merged[i].tlvs)
			merged[i].whenRefused = slices.Clone(merged[i].whenRefused)
			owned[i] = true
		}
		// Renumbered onto the end of what is already there, in place: a
		// neighbor loss that starves a thousand prefixes merges a thousand
		// actions, and a fresh slice for each one is a thousand allocations.
		offset := len(merged[i].tlvs)
		for _, entry := range action.rollback {
			entry.firstTLV += offset
			merged[i].rollback = append(merged[i].rollback, entry)
		}
		merged[i].tlvs = append(merged[i].tlvs, action.tlvs...)
		merged[i].whenRefused = append(merged[i].whenRefused, action.whenRefused...)
	}
	return merged
}

// reserveTo builds one packet and takes its place in the peer's transmission
// order, or reports nil when the peer has no slot free.
func (s *Speaker) reserveTo(n *neighborState, destination netip.Addr, tlvs []RawTLV) *netstack.Place {
	// Timestamp as the packet takes its place in the queue, rather than when
	// the timer collected actions for potentially many peers.
	for i, tlv := range tlvs {
		if tlv.Type == TLVHello {
			h, err := DecodeHello(tlv.Body)
			if err == nil {
				h.TxTS, h.HasTS = nowMicros(), true
				tlvs[i] = EncodeHello(h)
			}
		}
	}
	pkt := buildPacket(s.linkLocal, destination, EncodePacket(tlvs))
	reserved, err := n.peer.ReserveRawOrDrop(pkt, esp.NextHeaderIPv6)
	switch {
	case errors.Is(err, netstack.ErrSendQueueFull):
		slog.Warn("babel packet dropped, peer send queue full", "peer", n.peer.ID, "tlvs", len(tlvs))
		return nil
	case err != nil:
		slog.Warn("babel send failed", "peer", n.peer.ID, "err", err)
		return nil
	default:
		slog.Debug("babel queued packet", "peer", n.peer.ID, "tlvs", len(tlvs), "bytes", len(pkt))
		return reserved
	}
}

// reserveBatchesTo splits an action at the configured packet size and takes a
// place for each piece. It reports the pieces that took one, the undos of the
// pieces that did not, and whether every piece did.
func (s *Speaker) reserveBatchesTo(action sendAction) ([]reservedPacket, []tlvUndo, bool) {
	tlvs := action.tlvs
	var reserved []reservedPacket
	var lost []tlvUndo
	whole := true
	pending := action.rollback
	take := func(batch []RawTLV, from, to int) {
		var undo []tlvUndo
		undo, pending = takeUndos(pending, from, to)
		if place := s.reserveTo(action.neighbor, action.dest, batch); place != nil {
			reserved = append(reserved, reservedPacket{place: place, neighbor: action.neighbor, undo: undo})
			return
		}
		lost = append(lost, undo...)
		whole = false
	}
	var batch []RawTLV
	size := headerLen
	// inEffect is the router-id the packet being built has already set, RFC
	// 8966 section 4.6.7: the TLV "establishes a router-id that is implied by
	// subsequent Update TLVs", within one packet. Every Update here is built
	// with an id of its own, and repeating one that is already in effect costs
	// twelve bytes against the twenty an IPv6 /64 Update takes. It repeats
	// most in the answer a neighbor can ask for: a Route Request for a prefix
	// this node has no route to draws a retraction carrying this node's own
	// id, and three hundred and thirty seven four byte requests fit in one
	// packet at the default size, the figure routeReply uses for the same TLV.
	// Cleared with the batch, because the state does not cross the boundary.
	var inEffect []byte
	batchFrom := 0
	encoded := func(group []RawTLV) int {
		n := 0
		for _, tlv := range group {
			n += 2 + len(tlv.Body)
		}
		return n
	}
	for i := 0; i < len(tlvs); {
		end := i + 1
		// Router-Id parser state is packet-local; keep each ID with its Update.
		if tlvs[i].Type == TLVRouterID && end < len(tlvs) && tlvs[end].Type == TLVUpdate {
			end++
		}
		group := tlvs[i:end]
		// Decided against what this packet has already set, and decided again
		// after a split, because a split starts a packet that has set nothing.
		trimmed := group
		if group[0].Type == TLVRouterID && bytes.Equal(group[0].Body, inEffect) {
			trimmed = group[1:]
		}
		groupSize := encoded(trimmed)
		if len(batch) > 0 && size+groupSize > s.packetSize {
			take(batch, batchFrom, i)
			batch, size, inEffect, batchFrom = nil, headerLen, nil, i
			trimmed, groupSize = group, encoded(group)
		}
		if group[0].Type == TLVRouterID {
			inEffect = group[0].Body
		}
		batch = append(batch, trimmed...)
		size += groupSize
		i = end
	}
	if len(batch) > 0 {
		take(batch, batchFrom, len(tlvs))
	}
	return reserved, lost, whole
}

// The action builders below require s.mu. They never perform I/O.
func (s *Speaker) helloAction(n *neighborState, now time.Time) sendAction {
	centis := uint16(s.hello / (10 * time.Millisecond))
	n.sentHello = true
	n.helloSeqno++
	// The rxcost is the only thing that tells the far end about the direction
	// this node receives on, so a neighbor this node once heard and no longer
	// does is told so. forgetLink discards the history that would have said it
	// through beta, and on a link that works one way the far end otherwise
	// keeps selecting routes through a direction that is dead. A neighbor never
	// heard from is a different thing and keeps the nominal cost, so a new
	// adjacency forms in one exchange rather than two.
	rxcost := s.cost.rxCost(&n.multicastHistory)
	if n.heard && !n.isAlive(now) {
		rxcost = MetricInfinity
	}
	ihu := IHU{RxCost: rxcost, Interval: centis}
	if n.haveTheirHello {
		ihu.OriginTS, ihu.ReceiveTS, ihu.HasTS = n.theirHelloTxTS, n.theirHelloRxTS, true
	}
	return sendAction{neighbor: n, dest: multicastGroup, priority: priorityHello, tlvs: []RawTLV{
		EncodeHello(Hello{Seqno: n.helloSeqno, Interval: centis, HasTS: true}),
		EncodeIHU(ihu),
	}, whenRefused: []func(){func() {
		// The seqno is given back. RFC 8966 section 4.6.5 counts Hellos that
		// were sent, and a refused reservation is one that never reached the
		// wire, so keeping the increment tells the neighbor it lost a Hello
		// nobody transmitted. That was cosmetic until Hello loss became a
		// cost: the speaker retries every quarter interval, so a few seconds
		// of a stalled tunnel burned several sequence numbers and the peer's
		// six-entry window read them all as loss, costing the link up to six
		// times nominal at each end over a local queue that dropped nothing.
		n.helloSeqno--
		n.sentHello = false
	}}}
}

// advertisementFor states what this node has to say about one prefix: a local
// origination, the selected route, or a retraction of a prefix that has been
// advertised and then lost. The second result is the selected route's next
// hop, which split horizon needs.
func (s *Speaker) advertisementFor(key routeKey) (advertisement, *neighborState, bool) {
	if _, local := s.originate[key]; local {
		// RFC 8966 section 3.7: a locally injected route carries this node's
		// router-id and sequence number with an arbitrary finite metric.
		return advertisement{routerID: s.routerID, seqno: s.originSeqno}, nil, true
	}
	if s.noTransit {
		// Reported as unknown rather than as a retraction of this node's own
		// making. advertiseTo synthesizes the identical infinite
		// advertisement for a prefix nothing here knows, so the two are the
		// same on the wire, and saying "not mine" is the honest shape: a node
		// that never relays has no route of its own to withdraw. What matters
		// for RFC 8966 section 3.8.1.1 is that a Route Request still draws a
		// retraction rather than silence, which the shared path provides.
		//
		// Refusing to advertise cannot close a loop, and Appendix C allows it
		// outright: "Babel can use any metric that is strictly monotonic,
		// including one that assigns an infinite metric to a selected subset
		// of routes."
		return advertisement{}, nil, false
	}
	entry := s.routes.entries[key]
	if entry == nil {
		return advertisement{}, nil, false
	}
	if sel := entry.selected; sel.neighbor != nil {
		return advertisement{routerID: sel.routerID, seqno: sel.seqno, metric: sel.cost}, sel.neighbor, true
	}
	return advertisement{routerID: entry.retractID, seqno: entry.retractSeqno, metric: MetricInfinity}, nil, true
}

// advertiseTo builds the Update TLVs for one prefix toward one neighbor. Every
// advertisement this node sends goes through here, keeping the
// feasibility distance of RFC 8966 section 3.7.3 an upper bound on what the
// mesh has been told. force answers a route request, which must produce a
// retraction even for a prefix we know nothing about (section 3.8.1.1).
// advertiseTo returns the TLVs for one prefix and whether building them spent
// the record of this neighbor having been told the prefix is reachable, which
// a packet that never leaves has to give back. See sendAction.rollback.
func (s *Speaker) advertiseTo(n *neighborState, key routeKey, force bool, now time.Time) ([]RawTLV, bool) {
	adv, nextHop, known := s.advertisementFor(key)
	if !known {
		adv = advertisement{routerID: s.routerID, seqno: s.originSeqno, metric: MetricInfinity}
	}
	if nextHop == n {
		// Section 3.7.4: split horizon, which these point-to-point ESP tunnels
		// satisfy the symmetry and transitivity conditions for. The route is
		// retracted rather than merely omitted so that a neighbor that had
		// selected us for this prefix stops immediately instead of waiting out
		// its expiry timer.
		adv.metric = MetricInfinity
	}
	spent := false
	if adv.metric == MetricInfinity {
		_, sent := n.advertised[key]
		if !sent && !force {
			return nil, false
		}
		// Only what was actually spent is given back. A forced retraction for
		// a prefix this node never advertised consumes nothing, and rolling
		// one back recorded a prefix the neighbor chose as advertised: the
		// key comes out of its Route Request, advertisableKeys unions the set,
		// and every later dump then carried an Update for a prefix that does
		// not exist. Nothing bounds that set, and each dropped dump rolls the
		// phantoms back in, so it never drains.
		if sent {
			delete(n.advertised, key)
			spent = true
		}
	} else {
		// observe records the feasibility distance this advertisement commits
		// to, and is not rolled back: having promised a distance and then not
		// sent it is safe, while sending one we did not record is not. The
		// neighbor it is charged to is the one whose route this node selected,
		// or nobody for a prefix this node originates.
		s.routes.observe(key, adv, s.selectedPeer(key), now)
		n.advertised[key] = struct{}{}
	}
	return updateTLVs(key, adv, s.update), spent
}

// selectedPeer names the neighbor whose route this node has chosen for a
// prefix, or nothing for one it originates itself.
func (s *Speaker) selectedPeer(key routeKey) string {
	entry := s.routes.entries[key]
	if entry == nil || entry.selected.neighbor == nil {
		return ""
	}
	return entry.selected.neighbor.peer.ID
}

// updateAE is the address encoding an Update carries, which is not the one a
// request carries. The ESP control link has an IPv6 link-local address only,
// so an IPv4 prefix has no next hop of its own family in the packet and RFC
// 8966 section 4.6.9 would have the receiver ignore a plain AE 1 Update. RFC
// 9229's AE 4 says to take the packet's IPv6 source as the next hop, which is
// what this link offers. Requests stay on AE 1, per RFC 9229 section 2.3.
func updateAE(p netip.Prefix) uint8 {
	if p.Addr().Is4() {
		return AEIPv4ViaIPv6
	}
	return AEIPv6
}

func updateTLVs(key routeKey, adv advertisement, interval time.Duration) []RawTLV {
	return []RawTLV{EncodeRouterID(adv.routerID), EncodeUpdate(Update{
		AE: updateAE(key.dest), Plen: key.dest.Bits(), Prefix: key.dest.Addr().AsSlice(),
		Interval:     uint16(interval / (10 * time.Millisecond)),
		Seqno:        adv.seqno,
		Metric:       adv.metric,
		SourcePrefix: key.source,
	})}
}

// advertisableKeys is every prefix a full dump covers: the locally originated
// ones plus the selected and recently retracted routes.
func (s *Speaker) advertisableKeys() []routeKey {
	keys := make([]routeKey, 0, len(s.originate)+len(s.routes.entries))
	seen := make(map[routeKey]struct{}, len(s.originate)+len(s.routes.entries))
	add := func(key routeKey) {
		if _, done := seen[key]; done {
			return
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range s.originate {
		add(key)
	}
	for key := range s.routes.entries {
		add(key)
	}
	// Anything a neighbor was told is reachable stays advertisable until it
	// has been told otherwise. A prefix dropped from the originated set is in
	// neither map above, so without this it is never mentioned again and the
	// neighbor holds it until it expires, which is three and a half update
	// intervals of black hole if the address moved.
	for _, n := range s.neighbors {
		for key := range n.advertised {
			add(key)
		}
	}
	return keys
}

func (s *Speaker) updateActionsFor(keys []routeKey, now time.Time) []sendAction {
	if len(keys) == 0 {
		return nil
	}
	actions := make([]sendAction, 0, len(s.neighbors))
	for _, n := range s.neighbors {
		tlvs, rollback := s.dumpFor(n, keys, now)
		if len(tlvs) > 0 {
			actions = append(actions, sendAction{neighbor: n, dest: multicastGroup, priority: priorityDump, tlvs: tlvs, rollback: rollback})
		}
	}
	return actions
}

// dumpFor builds the advertisements for one neighbor and the undo of each,
// keyed to the TLVs it produced. updateActions clears every owed set before
// building, on the grounds that the dump supersedes them, so a packet that
// cannot be sent has to leave the neighbor owing what it was carrying.
func (s *Speaker) dumpFor(n *neighborState, keys []routeKey, now time.Time) ([]RawTLV, []tlvUndo) {
	tlvs := make([]RawTLV, 0, 2*len(keys))
	rollback := make([]tlvUndo, 0, len(keys))
	for _, key := range keys {
		advertised, spent := s.advertiseTo(n, key, false, now)
		if len(advertised) == 0 {
			continue
		}
		rollback = append(rollback, tlvUndo{firstTLV: len(tlvs), key: key, spent: spent})
		tlvs = append(tlvs, advertised...)
	}
	return tlvs, rollback
}

// oweAgain gives back what one prefix's advertisement consumed and leaves this
// neighbor, and no other, owing it. Recording a speaker-wide pending dump
// instead would make pendingWorkLocked true for as long as the one peer stays
// stuck, which reopens the per-packet wake that function exists to close.
// triggeredActions picks the key up on the retry noteSendRetryLocked
// schedules and sends it to this neighbor alone.
//
// A key nothing would rebuild is not owed. A Route Request may name any
// prefix, and the retry builds nothing for one this node has no route to, does
// not originate and has never told this neighbor about, so owing it grows a
// set neighborState.owed says is bounded by the route table. The last of the
// three is the retraction case, where the prefix has left both tables and the
// only reason to speak is that the neighbor was told it was reachable.
func (s *Speaker) oweAgain(n *neighborState, undo tlvUndo) {
	if undo.spent {
		n.advertised[undo.key] = struct{}{}
	}
	_, known := s.routes.entries[undo.key]
	_, local := s.originate[undo.key]
	_, told := n.advertised[undo.key]
	if known || local || told {
		n.owed[undo.key] = struct{}{}
	}
}

// updateActions is the periodic full dump of RFC 8966 section 3.7.1. It
// supersedes any triggered update still queued, so the queue is cleared here
// rather than left to fire again behind the dump. A prefix flushed from the
// route table is still covered: advertisableKeys carries everything any
// neighbor was told is reachable, which is exactly the set that still needs
// retracting.
func (s *Speaker) updateActions(now time.Time) []sendAction {
	keys := s.advertisableKeys()
	s.routes.takeDirty()
	for _, n := range s.neighbors {
		clear(n.owed)
	}
	return s.updateActionsFor(keys, now)
}

// triggeredActions covers RFC 8966 section 3.7.2. Selection changes are
// collected by the route table and flushed by Run rather than sent from the
// receive path, so a burst of updates in one packet produces one advertisement.
func (s *Speaker) triggeredActions(now time.Time) []sendAction {
	for _, key := range s.routes.takeDirty() {
		for _, n := range s.neighbors {
			n.owed[key] = struct{}{}
		}
	}
	var actions []sendAction
	for _, n := range s.neighbors {
		if len(n.owed) == 0 {
			continue
		}
		keys := slices.Collect(maps.Keys(n.owed))
		clear(n.owed)
		// "Whenever it changes the selected router-id for a given destination,
		// a node MUST send an update as an urgent TLV", section 3.7.2, and
		// takeDirty has already consumed the record that one is owed. A
		// dropped packet without dumpFor's re-owe leaves the change to the
		// next periodic dump, which is sixteen seconds at the defaults and
		// four expiries at a neighbor that has lost the prefix.
		tlvs, rollback := s.dumpFor(n, keys, now)
		if len(tlvs) == 0 {
			continue
		}
		actions = append(actions, sendAction{neighbor: n, dest: multicastGroup, priority: priorityDump, tlvs: tlvs, rollback: rollback})
	}
	return actions
}

// starvedActions turns the route table's pending seqno requests into unicast
// packets, RFC 8966 sections 3.8.2.1 and 3.8.2.2.
//
// Every neighbor holding an unfeasible route for the prefix is asked, which is
// what section 3.8.2.1 means by "SHOULD send it to all of them". The
// suppression table is not consulted here: it exists to stop a forwarded
// request being relayed twice (section 3.8.1.2), and it is indexed without the
// neighbor, so honoring it would let the first neighbor in map order consume
// the allowance and silently drop the rest.
func (s *Speaker) starvedActions(now time.Time) []sendAction {
	var actions []sendAction
	for _, request := range s.routes.takeStarved() {
		if s.neighbors[request.neighbor.peer.ID] != request.neighbor {
			continue // the peer was replaced or removed while we held the lock
		}
		if !s.allowAsk(request.neighbor, request.key, request.routerID, now) {
			continue
		}
		actions = append(actions, s.seqnoRequestTo(request.neighbor, request.key,
			request.routerID, request.seqno, now))
		// Recorded whether or not this particular packet went out, so a prefix
		// starved inside the window of a request we forwarded moments earlier
		// still gets a retry rather than never being asked about again.
		s.rememberStarved(request.key, request.routerID, request.seqno, request.neighbor.peer.ID, now)
	}
	return actions
}

// seqnoRequestTo builds one unicast seqno request, bypassing the forwarding
// suppression table.
func (s *Speaker) seqnoRequestTo(n *neighborState, key routeKey, routerID [8]byte, seqno uint16, now time.Time) sendAction {
	// Charged to this node's own bucket under the same cap as a forwarded
	// request. The router-id half of the index still comes from a neighbor's
	// packet, so "this node's own requests come from its own route table" was
	// only half true; refusing to record one costs the suppression that stops
	// it being relayed twice, not the request itself, which still goes out.
	s.allowSeqnoRequest(sourceKey{route: key, routerID: routerID}, seqno, "", now)
	return sendAction{neighbor: n, dest: n.destination(), priority: priorityRequest, tlvs: []RawTLV{EncodeSeqnoRequest(SeqnoRequest{
		AE: aeFor(key.dest), Prefix: key.dest, SourcePrefix: key.source,
		Seqno: seqno, HopCount: seqnoRequestHopCount, RouterID: routerID,
	})}}
}

func (s *Speaker) seqnoRequestAction(n *neighborState, asker string, key routeKey, routerID [8]byte, seqno uint16, hops uint8, now time.Time) (sendAction, bool) {
	if !s.allowSeqnoRequest(sourceKey{route: key, routerID: routerID}, seqno, asker, now) {
		return sendAction{}, false
	}
	return sendAction{neighbor: n, dest: n.destination(), priority: priorityRequest, tlvs: []RawTLV{EncodeSeqnoRequest(SeqnoRequest{
		AE: aeFor(key.dest), Prefix: key.dest, SourcePrefix: key.source,
		Seqno: seqno, HopCount: hops, RouterID: routerID,
	})}}, true
}

// flushUpdates sends the periodic dump out of band, the way a pass of the run
// loop would. Nothing in production calls it: Run builds the same actions
// itself. It is here for the tests that drive a dump without running the loop,
// and it does what the loop does, wake included, so that what those tests
// measure is the behavior the loop has rather than a simpler one.
func (s *Speaker) flushUpdates() {
	now := time.Now()
	s.mu.Lock()
	send := s.emitLocked(s.updateActions(now))
	// updateActions drains the triggered queue and clears every owed set, and
	// emitLocked puts them back for a neighbor it could not send to. Nothing
	// here is a pass of the run loop, so the retry that rollback schedules has
	// to be woken for the way an arriving packet is.
	s.wakeForPacketLocked()
	s.mu.Unlock()
	send()
}

func aeFor(p netip.Prefix) uint8 {
	if p.Addr().Is4() {
		return AEIPv4
	}
	return AEIPv6
}

// rememberStarved records a prefix whose seqno request has just gone out, so
// it can be repeated if no feasible route appears. RFC 8966 section 3.8.2.1.
//
// It is bounded by maxStarveRetries and by maxStarveRetriesPerNeighbor. The
// index carries a router id a neighbor writes into a packet, so a neighbor
// that alternates a feasible update with an unfeasible one on an origin this
// node has not recorded starves a new entry every packet; each lives through
// four retries, and retryStarvedLocked
// walks the whole map on every wake of the run loop, under the lock that also
// carries hellos and retractions.
func (s *Speaker) rememberStarved(key routeKey, routerID [8]byte, seqno uint16, asker string, now time.Time) {
	id := sourceKey{route: key, routerID: routerID}
	if retry, ok := s.starveRetries[id]; ok {
		retry.seqno, retry.nextAt = seqno, now.Add(seqnoRetryInitial)
		s.nextStarveRetry = earlier(s.nextStarveRetry, retry.nextAt)
		return
	}
	if len(s.starveRetries) >= maxStarveRetries || s.starveBy[asker] >= maxStarveRetriesPerNeighbor {
		return
	}
	s.starveRetries[id] = &starveRetry{
		key: key, routerID: routerID, seqno: seqno, asker: asker, nextAt: now.Add(seqnoRetryInitial),
	}
	s.nextStarveRetry = earlier(s.nextStarveRetry, now.Add(seqnoRetryInitial))
	s.starveBy[asker]++
}

// forgetStarved drops one repeat and gives its neighbor the slot back.
func (s *Speaker) forgetStarved(id sourceKey, retry *starveRetry) {
	delete(s.starveRetries, id)
	if s.starveBy[retry.asker] <= 1 {
		delete(s.starveBy, retry.asker)
		return
	}
	s.starveBy[retry.asker]--
}

// retryStarvedLocked repeats the seqno requests for prefixes that are still
// starved. A prefix that has a feasible route again, or that has run out of
// attempts, is forgotten rather than asked about forever.
func (s *Speaker) retryStarvedLocked(now time.Time) []sendAction {
	var actions []sendAction
	// Rebuilt as the walk goes: this is the pass that reads every deadline, so
	// it is where the kept minimum can be made exact again after the removals
	// and the writes that only ever moved it earlier.
	s.nextStarveRetry = time.Time{}
	for id, retry := range s.starveRetries {
		if entry := s.routes.entries[retry.key]; entry != nil && entry.selected.neighbor != nil {
			s.forgetStarved(id, retry)
			continue
		}
		if now.Before(retry.nextAt) {
			s.nextStarveRetry = earlier(s.nextStarveRetry, retry.nextAt)
			continue
		}
		if retry.attempts >= seqnoRequestRetries {
			s.forgetStarved(id, retry)
			continue
		}
		retry.attempts++
		retry.nextAt = now.Add(seqnoRetryInitial << (retry.attempts - 1))
		s.nextStarveRetry = earlier(s.nextStarveRetry, retry.nextAt)
		// Ask everyone holding a route for this prefix, not only whoever the
		// starved one came from: the neighbor that can reach the origin may be
		// a different one, and BIRD rebroadcasts for the same reason.
		for _, n := range s.neighbors {
			if !n.alive {
				continue
			}
			if s.routes.route(n, retry.key) == nil {
				continue
			}
			if !s.allowAsk(n, retry.key, retry.routerID, now) {
				continue
			}
			actions = append(actions, s.seqnoRequestTo(n, retry.key, retry.routerID, retry.seqno, now))
		}
	}
	return actions
}

// allowAsk rate-limits the seqno requests this node originates, per neighbor
// and per prefix. The route table can queue the same starve twice, once from
// the update that made the route unfeasible and once from the selection that
// followed it, and two neighbors worsening in quick succession re-starve each
// other's prefixes.
func (s *Speaker) allowAsk(n *neighborState, key routeKey, routerID [8]byte, now time.Time) bool {
	index := askedKey{sourceKey{route: key, routerID: routerID}, n}
	if at, ok := s.askedSeqno[index]; ok && now.Before(at.Add(seqnoRequestSuppress)) {
		return false
	}
	s.askedSeqno[index] = now
	s.noteRequestSweep(now)
	return true
}
