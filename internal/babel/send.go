package babel

import (
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/NickCao/ranet-lite/esp"
)

type sendAction struct {
	neighbor *neighborState
	dest     netip.Addr
	tlvs     []RawTLV
}

func (s *Speaker) sendActions(actions []sendAction) {
	for _, action := range coalesce(actions) {
		s.sendBatchesTo(action.neighbor, action.dest, action.tlvs)
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
			owned[i] = true
			continue
		}
		merged[i].tlvs = append(merged[i].tlvs, action.tlvs...)
	}
	return merged
}

func (s *Speaker) sendTo(n *neighborState, destination netip.Addr, tlvs []RawTLV) {
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
	if err := n.peer.SendRaw(pkt, esp.NextHeaderIPv6); err != nil {
		slog.Warn("babel send failed", "peer", n.peer.ID, "err", err)
	} else {
		slog.Debug("babel sent packet", "peer", n.peer.ID, "tlvs", len(tlvs), "bytes", len(pkt))
	}
}

func (s *Speaker) sendBatchesTo(n *neighborState, destination netip.Addr, tlvs []RawTLV) {
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
			s.sendTo(n, destination, batch)
			batch, size = nil, headerLen
		}
		batch = append(batch, tlvs[i:end]...)
		size += groupSize
		i = end
	}
	if len(batch) > 0 {
		s.sendTo(n, destination, batch)
	}
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
	return sendAction{n, multicastGroup, []RawTLV{
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
// advertisement this node sends goes through here, which is what keeps the
// feasibility distance of RFC 8966 section 3.7.3 an upper bound on what the
// mesh has been told. force answers a route request, which must produce a
// retraction even for a prefix we know nothing about (section 3.8.1.1).
func (s *Speaker) advertiseTo(n *neighborState, key routeKey, force bool, now time.Time) []RawTLV {
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
	if adv.metric == MetricInfinity {
		if _, sent := n.advertised[key]; !sent && !force {
			return nil
		}
		delete(n.advertised, key)
	} else {
		s.routes.observe(key, adv, now)
		n.advertised[key] = struct{}{}
	}
	return updateTLVs(key, adv, s.cfg.UpdateInterval)
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
		for _, key := range keys {
			tlvs = append(tlvs, s.advertiseTo(n, key, false, now)...)
		}
		if len(tlvs) > 0 {
			actions = append(actions, sendAction{n, multicastGroup, tlvs})
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
func (s *Speaker) starvedActions(now time.Time) []sendAction {
	var actions []sendAction
	for _, request := range s.routes.takeStarved() {
		if s.neighbors[request.neighbor.peer.ID] != request.neighbor {
			continue // the peer was replaced or removed while we held the lock
		}
		action, ok := s.seqnoRequestAction(request.neighbor, request.key,
			request.routerID, request.seqno, seqnoRequestHopCount, now)
		if ok {
			actions = append(actions, action)
		}
	}
	return actions
}

func (s *Speaker) seqnoRequestAction(n *neighborState, key routeKey, routerID [8]byte, seqno uint16, hops uint8, now time.Time) (sendAction, bool) {
	if !s.allowSeqnoRequest(sourceKey{route: key, routerID: routerID}, seqno, now) {
		return sendAction{}, false
	}
	return sendAction{n, n.destination(), []RawTLV{EncodeSeqnoRequest(SeqnoRequest{
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
