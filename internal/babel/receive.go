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
	actions := s.handlePacketLocked(n, raw, time.Now())
	s.wake()
	s.mu.Unlock()
	s.sendActions(actions)
}

func (s *Speaker) handlePacketLocked(n *neighborState, raw []byte, now time.Time) []sendAction {
	tlvs, err := DecodePacket(raw)
	if err != nil {
		slog.Warn("babel bad packet", "err", err)
		return nil
	}
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
	linkChanged := false
	for _, t := range tlvs {
		switch t.Type {
		case TLVHello:
			h, err := DecodeHello(t.Body)
			if err != nil {
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
				}
			}
			linkChanged = true

		case TLVRouterID:
			if id, err := DecodeRouterID(t.Body); err == nil {
				routerID, haveRouterID = id, true
			}

		case TLVUpdate:
			u, err := prefixDec.Decode(t.Body)
			if err != nil {
				slog.Warn("babel bad update", "err", err)
				continue
			}
			if u.HasRouterID {
				routerID, haveRouterID = u.RouterID, true
			}
			if u.Ignore {
				continue // compression state still follows the ignored Update
			}
			if u.AE == AEWildcard {
				s.routes.expireNeighbor(n, now)
				continue
			}
			if !haveRouterID && u.Metric != MetricInfinity {
				continue
			}
			addr, ok := netip.AddrFromSlice(u.Prefix)
			if !ok {
				continue
			}
			prefix := netip.PrefixFrom(addr.Unmap(), u.Plen).Masked()
			_, local := s.originate[prefix]
			if local || (haveRouterID && routerID == s.cfg.RouterID) {
				continue
			}
			key := routeKey{source: u.SourcePrefix, dest: prefix}
			s.routes.update(n, key, u.Metric, deadTimeout(time.Duration(u.Interval)*10*time.Millisecond), now)

		case TLVAckReq:
			if nonce, err := DecodeAckReq(t.Body); err == nil && n.addr.IsValid() {
				actions = append(actions, sendAction{n, n.addr, []RawTLV{EncodeAck(nonce)}})
			}

		case TLVRouteRequest:
			if request, err := DecodeRouteRequest(t.Body); err == nil && n.addr.IsValid() {
				actions = append(actions, s.routeReply(n, request))
			}

		case TLVSeqnoRequest:
			request, err := DecodeSeqnoRequest(t.Body)
			if err != nil || request.RouterID != s.cfg.RouterID || !n.addr.IsValid() {
				continue // no transit request forwarding
			}
			if _, local := s.originate[request.Prefix]; local {
				if seqnoGT(request.Seqno, s.originSeqno) {
					s.originSeqno++ // at most one increment per request
				}
				actions = append(actions, sendAction{n, n.addr, s.originatedUpdate(request.Prefix, 0)})
			}
		}
	}
	if linkChanged {
		s.routes.recomputeNeighbor(n, now)
	}
	return actions
}

func (s *Speaker) routeReply(n *neighborState, request RouteRequest) sendAction {
	var tlvs []RawTLV
	if request.AE == AEWildcard {
		for prefix := range s.originate {
			tlvs = append(tlvs, s.originatedUpdate(prefix, 0)...)
		}
	} else {
		metric := MetricInfinity
		if _, local := s.originate[request.Prefix]; local {
			metric = 0
		}
		tlvs = s.originatedUpdate(request.Prefix, metric)
	}
	return sendAction{n, n.addr, tlvs}
}

const rttTimestampHorizon = 3 * time.Minute

func validTimestampGap(gap time.Duration) bool {
	return gap >= 0 && gap <= rttTimestampHorizon
}
