package babel

import (
	"log/slog"
	"net/netip"
	"time"
)

// handlePacket is also used by protocol tests that supply a bare Babel payload.
func (s *Speaker) handlePacket(n *neighborState, raw []byte) {
	s.mu.Lock()
	if s.neighbors[n.peer.ID] != n {
		s.mu.Unlock()
		return
	}
	send := s.emitLocked(s.handlePacketLocked(n, raw, time.Now()))
	s.wakeForPacketLocked()
	s.mu.Unlock()
	send()
}

func (s *Speaker) handlePacketLocked(n *neighborState, raw []byte, now time.Time) []sendAction {
	tlvs, err := DecodePacket(raw)
	if err != nil {
		slog.Warn("babel bad packet", "err", err)
		return nil
	}
	// Reset per packet: the sequence number this node originates rises at most
	// once for the whole of it, however many requests it carries.
	s.raisedSeqno = false
	recvTS := uint32(now.UnixMicro())
	var helloTxTS uint32
	var haveHelloTS bool
	// RFC 9616 associates Hello and IHU within a packet regardless of order.
	for _, t := range tlvs {
		if t.Type == TLVHello {
			if h, err := DecodeHello(t.Body); err == nil && h.HasTS {
				helloTxTS, haveHelloTS = h.TxTS, true
				break
			}
		}
	}

	var actions []sendAction
	var prefixDec PrefixDecoder
	var routerID [8]byte
	var haveRouterID bool
	// haveIPv4NextHop is the packet's next-hop parser state for the IPv4
	// family, RFC 8966 section 4.5. There is no IPv6 counterpart because every
	// babel packet here is sent from an IPv6 link-local address, which is the
	// next hop an IPv6 prefix falls back to.
	var haveIPv4NextHop bool
	// One MTU-sized packet holds about ninety Update TLVs, so a peer that
	// sends a packet of malformed ones costs one log line rather than ninety.
	// RFC 8966 section 4.6.9 asks for them to be "silently ignored".
	badUpdates := 0
	linkChanged := false
	for _, t := range tlvs {
		switch t.Type {
		case TLVHello:
			h, err := DecodeHello(t.Body)
			if err != nil {
				continue
			}
			// An unscheduled Hello, which RFC 8966 section 3.4.1 permits a node
			// to send "for any reason", carries no interval and so promises
			// nothing about the next one. Marking the neighbor up on one with
			// no promise outstanding makes it up and immediately down again,
			// which costs a pair of log lines and a full reselection per Hello.
			if h.Interval == 0 && n.helloExpiry().IsZero() {
				continue
			}
			if !n.alive {
				slog.Info("babel neighbor up", "peer", n.peer.ID)
			}
			n.alive = true
			// An unscheduled Hello cannot extend the last scheduled promise.
			if h.Interval != 0 {
				if h.Unicast {
					n.unicastHelloTime = now
					n.unicastHelloInterval = time.Duration(h.Interval) * 10 * time.Millisecond
				} else {
					n.lastHelloTime = now
					n.helloInterval = time.Duration(h.Interval) * 10 * time.Millisecond
				}
			}
			if h.HasTS {
				n.theirHelloTxTS, n.theirHelloRxTS, n.haveTheirHello = h.TxTS, recvTS, true
			}
			linkChanged = true

		case TLVIHU:
			ihu, addr, err := DecodeIHU(t.Body)
			if err != nil {
				continue
			}
			if addr != nil {
				address, ok := netip.AddrFromSlice(addr)
				if !ok || address != s.cfg.LinkLocalAddr {
					continue
				}
			}
			if ihu.Interval == 0 {
				// RFC 8966 section 4.6.6 on the same field the hold is
				// computed from: "An upper bound, expressed in centiseconds,
				// on the time after which the sending node will send a new
				// IHU; this MUST NOT be 0." Honoring a zero puts ihuExpiry at
				// now, which takes the link cost to infinity and unselects
				// every route through this neighbor in this same call, so one
				// eight-byte TLV retracts everything it carries. PrefixDecoder
				// refuses the identical rule on the Update TLV.
				continue
			}
			n.reportedCost, n.haveReportedCost = ihu.RxCost, true
			n.ihuExpiry = now.Add(deadTimeout(time.Duration(ihu.Interval) * 10 * time.Millisecond))
			// A new Hello can overtake the reply to an older one. RFC 9616
			// bounds timestamp ages; it does not require the latest local Hello.
			if ihu.HasTS && haveHelloTS &&
				validTimestampGap(microDelta(recvTS, ihu.OriginTS)) && validTimestampGap(microDelta(helloTxTS, ihu.ReceiveTS)) {
				rtt := microDelta(recvTS, ihu.OriginTS) - microDelta(helloTxTS, ihu.ReceiveTS)
				if rtt > 0 {
					if n.haveRTT {
						n.measuredRTT = (836*n.measuredRTT + 164*rtt) / 1000
					} else {
						n.measuredRTT, n.haveRTT = rtt, true
					}
					n.rttExpiry = n.ihuExpiry
				}
			}
			linkChanged = true

		case TLVNextHop:
			// Kept as parser state and not as a destination: these are
			// point-to-point ESP tunnels, so the next hop toward a prefix a
			// neighbor announces is that neighbor. What the TLV decides here
			// is whether an IPv4 prefix has a next hop at all.
			// Section 4.6.8: "This TLV sets up the next hop for subsequent
			// Update TLVs even if it is otherwise ignored due to an unknown
			// mandatory sub-TLV", so the state follows the address rather than
			// the decision to ignore.
			//
			// Matched on the encoding, which is the address family section
			// 4.6.9 pairs an Update with. See DecodeNextHop.
			if _, ae, _, err := DecodeNextHop(t.Body); err == nil && ae == AEIPv4 {
				haveIPv4NextHop = true
			}

		case TLVRouterID:
			// The parser state is set even when the TLV is ignored, which the
			// second result reports. Only a malformed TLV leaves it alone.
			if id, _, err := DecodeRouterID(t.Body); err == nil {
				routerID, haveRouterID = id, true
			}

		case TLVUpdate:
			u, err := prefixDec.Decode(t.Body)
			if err != nil {
				if badUpdates == 0 {
					slog.Warn("babel bad update", "peer", n.peer.ID, "err", err)
				}
				badUpdates++
				continue
			}
			if u.HasRouterID {
				routerID, haveRouterID = u.RouterID, true
			}
			if u.Ignore {
				continue // compression state still follows the ignored Update
			}
			if u.AE == AEWildcard {
				s.routes.retractNeighbor(n, now)
				continue
			}
			// RFC 8966 section 4.6.9: the next hop "is taken from the last
			// preceding Next Hop TLV with a matching address family ... if no
			// such TLV exists, it is taken from the network-layer source
			// address of this packet if it belongs to the same address family
			// as the prefix being announced; otherwise, this Update MUST be
			// ignored." Every packet here is IPv6, so a plain AE 1 prefix has
			// neither. RFC 9229's AE 4 is the spelling that does, and is what
			// this node sends.
			//
			// A retraction is exempt, by the same section: "If the metric
			// field is FFFF hexadecimal, this TLV specifies a retraction. In
			// that case, the router-id, next hop, and seqno are not used."
			// RFC 9229 section 2.1 says so for this link in as many words, and
			// dropping one holds the withdrawn prefix until it expires while
			// this node keeps advertising it onward.
			if u.AE == AEIPv4 && !haveIPv4NextHop && u.Metric != MetricInfinity {
				continue
			}
			addr, ok := netip.AddrFromSlice(u.Prefix)
			if !ok {
				continue
			}
			dest := netip.PrefixFrom(addr.Unmap(), u.Plen).Masked()
			// A v4-mapped address under AE 2 unmaps to IPv4 while its prefix
			// length still counts IPv6 bits, so the pair names no route. Such
			// an entry would be re-advertised as a malformed Update.
			if !dest.IsValid() || (u.SourcePrefix.IsValid() && u.SourcePrefix.Addr().Is4() != dest.Addr().Is4()) {
				continue
			}
			key := routeKey{source: u.SourcePrefix, dest: dest}
			if _, local := s.originate[key]; local {
				continue // a directly attached prefix always wins, Appendix E
			}
			adv := advertisement{routerID: routerID, seqno: u.Seqno, metric: u.Metric}
			if !haveRouterID {
				if u.Metric != MetricInfinity {
					continue
				}
				// A retraction can arrive with no router-id in the packet's
				// parser state (RFC 8966 section 4.5). It retracts whatever
				// this neighbor last advertised, so the entry keeps its origin.
				if route := s.routes.route(n, key); route != nil {
					adv.routerID, adv.seqno = route.routerID, route.seqno
				}
			} else if routerID == s.cfg.RouterID {
				// Our own router-id only ever reaches us back through the mesh,
				// and we never re-advertise it, so this is a reflection.
				continue
			}
			s.routes.update(n, key, adv, deadTimeout(time.Duration(u.Interval)*10*time.Millisecond), now)

		case TLVAckReq:
			if nonce, err := DecodeAckReq(t.Body); err == nil && n.addr.IsValid() {
				actions = append(actions, sendAction{neighbor: n, dest: n.addr, priority: priorityRequest, tlvs: []RawTLV{EncodeAck(nonce)}})
			}

		case TLVRouteRequest:
			if request, err := DecodeRouteRequest(t.Body); err == nil {
				actions = append(actions, s.routeReply(n, request, now)...)
			}

		case TLVSeqnoRequest:
			if request, err := DecodeSeqnoRequest(t.Body); err == nil {
				actions = append(actions, s.seqnoReply(n, request, now)...)
			}
		}
	}
	if badUpdates > 1 {
		slog.Warn("babel ignored more malformed updates in the same packet",
			"peer", n.peer.ID, "count", badUpdates-1)
	}
	if linkChanged {
		s.routes.recomputeNeighbor(n, now)
	}
	// Requests are a direct consequence of what this packet said, so they leave
	// with its replies; triggered updates are aggregated by Run instead.
	return append(actions, s.starvedActions(now)...)
}

// routeReply implements RFC 8966 section 3.8.1.1: a wildcard request gets a
// full dump, and any other request gets an update or an explicit retraction.
//
// The same section says a full dump SHOULD be rate-limited, and on a transit
// node it has to be. The dump is the whole learned table, so one 1400 byte
// packet holds 337 four byte wildcard requests and, unlimited, each would draw
// its own copy: measured at 5000 routes that is 42,125 packets and 59 MB out
// for one packet in, with the table walked under the lock the whole protocol
// runs under. One dump per update interval is all a neighbor can use anyway,
// since the periodic update carries the same thing.
func (s *Speaker) routeReply(n *neighborState, request RouteRequest, now time.Time) []sendAction {
	var tlvs []RawTLV
	var rollback []func()
	if request.AE == AEWildcard {
		if !n.lastFullDump.IsZero() && now.Sub(n.lastFullDump) < s.cfg.UpdateInterval {
			return nil
		}
		// Taken now, so forty requests in one packet draw one dump, and not
		// given back if the packets are dropped. The cost this limits is the
		// table walk under the lock, which has already happened by then, so
		// refunding it would turn off the limit exactly while this node is too
		// congested to deliver: every later request would walk the table
		// again, under the lock that also carries hellos and retractions.
		n.lastFullDump = now
		for _, key := range s.advertisableKeys() {
			advertised, undo := s.advertiseTo(n, key, false, now)
			tlvs = append(tlvs, advertised...)
			if undo != nil {
				rollback = append(rollback, undo)
			}
		}
	} else {
		advertised, undo := s.advertiseTo(n, routeKey{source: request.SourcePrefix, dest: request.Prefix}, true, now)
		tlvs = advertised
		if undo != nil {
			rollback = append(rollback, undo)
		}
	}
	if len(tlvs) == 0 {
		return nil
	}
	return []sendAction{{neighbor: n, dest: n.destination(), priority: priorityRequest, tlvs: tlvs, rollback: rollback}}
}

// seqnoReply implements RFC 8966 section 3.8.1.2: satisfy the request from a
// locally originated prefix or from the selected route, and otherwise forward
// it one hop along a route toward the origin.
func (s *Speaker) seqnoReply(n *neighborState, request SeqnoRequest, now time.Time) []sendAction {
	key := routeKey{source: request.SourcePrefix, dest: request.Prefix}
	if _, local := s.originate[key]; local {
		// At most one increment per request, and at most one per packet: a
		// peer chooses how many requests to put in one, and eighty fit. RFC
		// 8966 section 3.2.2 asks a node not to raise its own sequence number
		// spontaneously, and every raise re-dirties everything this node
		// originates.
		if request.RouterID == s.cfg.RouterID && seqnoGT(request.Seqno, s.originSeqno) && !s.raisedSeqno {
			s.raisedSeqno = true
			s.originSeqno++
			// Everything we originate carries the new sequence number, so the
			// whole set is due a triggered update, not just this prefix.
			for origin := range s.originate {
				s.routes.dirty[origin] = struct{}{}
			}
		}
		advertised, undo := s.advertiseTo(n, key, true, now)
		return sendTLVs(n, advertised, undo)
	}
	if entry := s.routes.entries[key]; entry != nil {
		// Split horizon keeps us from answering the neighbor we learned the
		// route from; forwarding the request onwards is the useful reply.
		if sel := entry.selected; sel.neighbor != nil && sel.neighbor != n &&
			(sel.routerID != request.RouterID || !seqnoGT(request.Seqno, sel.seqno)) {
			advertised, undo := s.advertiseTo(n, key, true, now)
			return sendTLVs(n, advertised, undo)
		}
	}
	if request.RouterID == s.cfg.RouterID || request.HopCount < 2 {
		return nil // no other node can raise this node's sequence number
	}
	target := s.forwardTarget(key, n)
	if target == nil {
		return nil
	}
	action, ok := s.seqnoRequestAction(target, n.peer.ID, key, request.RouterID, request.Seqno, request.HopCount-1, now)
	if !ok {
		return nil // a recent request for the same source is still outstanding
	}
	return []sendAction{action}
}

// forwardTarget picks the single neighbor a seqno request is forwarded to,
// RFC 8966 section 3.8.1.2: the next hop of a feasible route if there is one,
// otherwise of an unfeasible one, and never the requester.
func (s *Speaker) forwardTarget(key routeKey, from *neighborState) *neighborState {
	entry := s.routes.entries[key]
	if entry == nil {
		return nil
	}
	if sel := entry.selected.neighbor; sel != nil && sel != from {
		return sel
	}
	var feasible, unfeasible *neighborState
	for n, route := range entry.routes {
		if n == from || route.rxMetric == MetricInfinity {
			continue
		}
		// Break ties by peer ID: a request must not follow map iteration order.
		if s.routes.feasible(key, route.advertised(), n.peer.ID) {
			if feasible == nil || n.peer.ID < feasible.peer.ID {
				feasible = n
			}
		} else if unfeasible == nil || n.peer.ID < unfeasible.peer.ID {
			unfeasible = n
		}
	}
	if feasible != nil {
		return feasible
	}
	return unfeasible
}

func sendTLVs(n *neighborState, tlvs []RawTLV, rollback func()) []sendAction {
	if len(tlvs) == 0 {
		return nil
	}
	action := sendAction{neighbor: n, dest: n.destination(), priority: priorityRequest, tlvs: tlvs}
	if rollback != nil {
		action.rollback = []func(){rollback}
	}
	return []sendAction{action}
}

const rttTimestampHorizon = 3 * time.Minute

func validTimestampGap(gap time.Duration) bool {
	return gap >= 0 && gap <= rttTimestampHorizon
}
