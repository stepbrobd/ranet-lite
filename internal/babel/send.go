package babel

import (
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/netstack"
)

type sendAction struct {
	neighbor *neighborState
	dest     netip.Addr
	tlvs     []RawTLV
	// rollback undoes the bookkeeping this packet consumed, and runs only if
	// the packet was dropped. Recording has to happen while the actions are
	// built, so that two requests in one packet do not each draw a full dump,
	// but a record consumed by a packet that never left is a record nothing
	// will redo: a dropped retraction takes the prefix out of every later
	// dump as well, and the neighbor black-holes it until its own expiry.
	rollback []func()
}

func (s *Speaker) sendActions(actions []sendAction) {
	var undo []func()
	for _, action := range coalesce(actions) {
		if !s.sendBatchesTo(action.neighbor, action.dest, action.tlvs) {
			undo = append(undo, action.rollback...)
		}
	}
	if len(undo) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, restore := range undo {
		restore()
	}
}

// coalesce merges the actions aimed at the same neighbor and destination into
// one, preserving order. Requests are produced one per TLV, so one arriving
// packet carrying forty seqno requests for forty prefixes would otherwise
// leave as forty packets aimed at whichever third peer can answer them, and a
// neighbor loss that starves a thousand prefixes as a thousand. sendBatchesTo
// still splits whatever this produces at the configured packet size.
func coalesce(actions []sendAction) []sendAction {
	if len(actions) < 2 {
		return actions
	}
	type target struct {
		neighbor *neighborState
		dest     netip.Addr
	}
	merged := make([]sendAction, 0, len(actions))
	at := make(map[target]int, len(actions))
	owned := make(map[int]bool, len(actions))
	for _, action := range actions {
		if len(action.tlvs) == 0 {
			continue
		}
		key := target{action.neighbor, action.dest}
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
			merged[i].tlvs = append(slices.Clone(merged[i].tlvs), action.tlvs...)
			merged[i].rollback = append(slices.Clone(merged[i].rollback), action.rollback...)
			owned[i] = true
			continue
		}
		merged[i].tlvs = append(merged[i].tlvs, action.tlvs...)
		merged[i].rollback = append(merged[i].rollback, action.rollback...)
	}
	return merged
}

// sendTo reports whether the packet reached the peer's ordered sender.
func (s *Speaker) sendTo(n *neighborState, destination netip.Addr, tlvs []RawTLV) bool {
	// Timestamp just before entering the packet/ESP queues, rather than when
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
	pkt := buildPacket(s.cfg.LinkLocalAddr, destination, EncodePacket(tlvs))
	switch err := n.peer.SendRawOrDrop(pkt, esp.NextHeaderIPv6); {
	case errors.Is(err, netstack.ErrSendQueueFull):
		slog.Warn("babel packet dropped, peer send queue full", "peer", n.peer.ID, "tlvs", len(tlvs))
		return false
	case err != nil:
		slog.Warn("babel send failed", "peer", n.peer.ID, "err", err)
		return false
	default:
		slog.Debug("babel sent packet", "peer", n.peer.ID, "tlvs", len(tlvs), "bytes", len(pkt))
		return true
	}
}

// sendBatchesTo splits tlvs at the configured packet size and reports whether
// every piece reached the peer's sender.
func (s *Speaker) sendBatchesTo(n *neighborState, destination netip.Addr, tlvs []RawTLV) bool {
	delivered := true
	var batch []RawTLV
	size := headerLen
	for i := 0; i < len(tlvs); {
		end := i + 1
		// Router-Id parser state is packet-local; keep each ID with its Update.
		if tlvs[i].Type == TLVRouterID && end < len(tlvs) && tlvs[end].Type == TLVUpdate {
			end++
		}
		groupSize := 0
		for _, tlv := range tlvs[i:end] {
			groupSize += 2 + len(tlv.Body)
		}
		if len(batch) > 0 && size+groupSize > s.cfg.PacketSize {
			delivered = s.sendTo(n, destination, batch) && delivered
			batch, size = nil, headerLen
		}
		batch = append(batch, tlvs[i:end]...)
		size += groupSize
		i = end
	}
	if len(batch) > 0 {
		delivered = s.sendTo(n, destination, batch) && delivered
	}
	return delivered
}

// The action builders below require s.mu. They never perform I/O.
func (s *Speaker) helloAction(n *neighborState, seqno uint16, now time.Time) sendAction {
	centis := uint16(s.cfg.HelloInterval / (10 * time.Millisecond))
	n.sentHello = true
	rxCost := s.cfg.Cost.RxCost
	if n.isAlive(now) {
		rxCost = s.cfg.Cost.Cost(n.measuredRTT, n.haveRTT)
	}
	ihu := IHU{RxCost: rxCost, Interval: centis}
	if n.haveTheirHello {
		ihu.OriginTS, ihu.ReceiveTS, ihu.HasTS = n.theirHelloTxTS, n.theirHelloRxTS, true
	}
	return sendAction{neighbor: n, dest: multicastGroup, tlvs: []RawTLV{
		EncodeHello(Hello{Seqno: seqno, Interval: centis, HasTS: true}),
		EncodeIHU(ihu),
	}}
}

// advertisementFor states what this node has to say about one prefix: a local
// origination, the selected route, or a retraction of a prefix that has been
// advertised and then lost. The second result is the selected route's next
// hop, which split horizon needs.
func (s *Speaker) advertisementFor(key routeKey) (advertisement, *neighborState, bool) {
	if _, local := s.originate[key]; local {
		// RFC 8966 section 3.7: a locally injected route carries this node's
		// router-id and sequence number with an arbitrary finite metric.
		return advertisement{routerID: s.cfg.RouterID, seqno: s.originSeqno}, nil, true
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
// advertiseTo returns the TLVs for one prefix and, separately, how to undo the
// bookkeeping it just consumed if the packet is dropped. See
// sendAction.rollback.
func (s *Speaker) advertiseTo(n *neighborState, key routeKey, force bool, now time.Time) ([]RawTLV, func()) {
	adv, nextHop, known := s.advertisementFor(key)
	if !known {
		adv = advertisement{routerID: s.cfg.RouterID, seqno: s.originSeqno, metric: MetricInfinity}
	}
	if nextHop == n {
		// Section 3.7.4: split horizon, which these point-to-point ESP tunnels
		// satisfy the symmetry and transitivity conditions for. The route is
		// retracted rather than merely omitted so that a neighbor that had
		// selected us for this prefix stops immediately instead of waiting out
		// its expiry timer.
		adv.metric = MetricInfinity
	}
	var rollback func()
	if adv.metric == MetricInfinity {
		if _, sent := n.advertised[key]; !sent && !force {
			return nil, nil
		}
		delete(n.advertised, key)
		rollback = func() { n.advertised[key] = struct{}{} }
	} else {
		// observe records the feasibility distance this advertisement commits
		// to, and is not rolled back: having promised a distance and then not
		// sent it is safe, while sending one we did not record is not.
		s.routes.observe(key, adv, now)
		n.advertised[key] = struct{}{}
	}
	return updateTLVs(key, adv, s.cfg.UpdateInterval), rollback
}

func updateTLVs(key routeKey, adv advertisement, interval time.Duration) []RawTLV {
	ae := aeFor(key.dest)
	if ae == AEIPv4 {
		// The ESP control link has an IPv6 link-local address only. AE 4
		// tells BIRD/Linux to use that address as the IPv4 route's next hop.
		ae = AEIPv4ViaIPv6
	}
	return []RawTLV{EncodeRouterID(adv.routerID), EncodeUpdate(Update{
		AE: ae, Plen: key.dest.Bits(), Prefix: key.dest.Addr().AsSlice(),
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
		var tlvs []RawTLV
		var rollback []func()
		for _, key := range keys {
			advertised, undo := s.advertiseTo(n, key, false, now)
			tlvs = append(tlvs, advertised...)
			if undo != nil {
				rollback = append(rollback, undo)
			}
		}
		if len(tlvs) > 0 {
			actions = append(actions, sendAction{neighbor: n, dest: multicastGroup, tlvs: tlvs, rollback: rollback})
		}
	}
	return actions
}

// updateActions is the periodic full dump of RFC 8966 section 3.7.1. It
// supersedes any triggered update still queued, except for prefixes that have
// been flushed from the route table: those are gone from the dump and would
// otherwise never be retracted.
func (s *Speaker) updateActions(now time.Time) []sendAction {
	keys := s.advertisableKeys()
	for _, key := range s.routes.takeDirty() {
		if _, known := s.routes.entries[key]; known {
			continue
		}
		if _, local := s.originate[key]; !local {
			keys = append(keys, key)
		}
	}
	return s.updateActionsFor(keys, now)
}

// triggeredActions covers RFC 8966 section 3.7.2. Selection changes are
// collected by the route table and flushed by Run rather than sent from the
// receive path, so a burst of updates in one packet produces one advertisement.
func (s *Speaker) triggeredActions(now time.Time) []sendAction {
	return s.updateActionsFor(s.routes.takeDirty(), now)
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
		s.rememberStarved(request.key, request.routerID, request.seqno, now)
	}
	return actions
}

// seqnoRequestTo builds one unicast seqno request, bypassing the forwarding
// suppression table.
func (s *Speaker) seqnoRequestTo(n *neighborState, key routeKey, routerID [8]byte, seqno uint16, now time.Time) sendAction {
	s.pendingSeqno[sourceKey{route: key, routerID: routerID}] = pendingSeqno{seqno: seqno, sentAt: now}
	return sendAction{neighbor: n, dest: n.destination(), tlvs: []RawTLV{EncodeSeqnoRequest(SeqnoRequest{
		AE: aeFor(key.dest), Prefix: key.dest, SourcePrefix: key.source,
		Seqno: seqno, HopCount: seqnoRequestHopCount, RouterID: routerID,
	})}}
}

func (s *Speaker) seqnoRequestAction(n *neighborState, key routeKey, routerID [8]byte, seqno uint16, hops uint8, now time.Time) (sendAction, bool) {
	if !s.allowSeqnoRequest(sourceKey{route: key, routerID: routerID}, seqno, now) {
		return sendAction{}, false
	}
	return sendAction{neighbor: n, dest: n.destination(), tlvs: []RawTLV{EncodeSeqnoRequest(SeqnoRequest{
		AE: aeFor(key.dest), Prefix: key.dest, SourcePrefix: key.source,
		Seqno: seqno, HopCount: hops, RouterID: routerID,
	})}}, true
}

func (s *Speaker) flushUpdates() {
	now := time.Now()
	s.mu.Lock()
	actions := s.updateActions(now)
	s.mu.Unlock()
	s.sendActions(actions)
}

func aeFor(p netip.Prefix) uint8 {
	if p.Addr().Is4() {
		return AEIPv4
	}
	return AEIPv6
}

// rememberStarved records a prefix whose seqno request has just gone out, so
// it can be repeated if no feasible route appears. RFC 8966 section 3.8.2.1.
func (s *Speaker) rememberStarved(key routeKey, routerID [8]byte, seqno uint16, now time.Time) {
	id := sourceKey{route: key, routerID: routerID}
	if retry, ok := s.starveRetries[id]; ok {
		retry.seqno, retry.nextAt = seqno, now.Add(seqnoRetryInitial)
		return
	}
	s.starveRetries[id] = &starveRetry{
		key: key, routerID: routerID, seqno: seqno, nextAt: now.Add(seqnoRetryInitial),
	}
}

// retryStarvedLocked repeats the seqno requests for prefixes that are still
// starved. A prefix that has a feasible route again, or that has run out of
// attempts, is forgotten rather than asked about forever.
func (s *Speaker) retryStarvedLocked(now time.Time) []sendAction {
	var actions []sendAction
	for id, retry := range s.starveRetries {
		if entry := s.routes.entries[retry.key]; entry != nil && entry.selected.neighbor != nil {
			delete(s.starveRetries, id)
			continue
		}
		if now.Before(retry.nextAt) {
			continue
		}
		if retry.attempts >= seqnoRequestRetries {
			delete(s.starveRetries, id)
			continue
		}
		retry.attempts++
		retry.nextAt = now.Add(seqnoRetryInitial << (retry.attempts - 1))
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
	return true
}
