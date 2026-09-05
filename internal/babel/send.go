package babel

import (
	"log/slog"
	"net/netip"
	"time"

	"github.com/NickCao/ranet-lite/esp"
)

type sendAction struct {
	neighbor *neighborState
	dest     netip.Addr
	tlvs     []RawTLV
}

func (s *Speaker) sendActions(actions []sendAction) {
	for _, action := range actions {
		s.sendBatchesTo(action.neighbor, action.dest, action.tlvs)
	}
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

func (s *Speaker) originatedUpdate(prefix netip.Prefix, metric uint16) []RawTLV {
	ae := aeFor(prefix)
	if ae == AEIPv4 {
		// The ESP control link has an IPv6 link-local address only. AE 4
		// tells BIRD/Linux to use that address as the IPv4 route's next hop.
		ae = AEIPv4ViaIPv6
	}
	return []RawTLV{EncodeRouterID(s.cfg.RouterID), EncodeUpdate(Update{
		AE: ae, Plen: prefix.Bits(), Prefix: prefix.Addr().AsSlice(),
		Interval: uint16(s.cfg.UpdateInterval / (10 * time.Millisecond)),
		Seqno:    s.originSeqno, Metric: metric,
	})}
}

func (s *Speaker) updateActions() []sendAction {
	var tlvs []RawTLV
	for prefix := range s.originate {
		tlvs = append(tlvs, s.originatedUpdate(prefix, 0)...)
	}
	if len(tlvs) == 0 {
		return nil
	}
	actions := make([]sendAction, 0, len(s.neighbors))
	for _, n := range s.neighbors {
		actions = append(actions, sendAction{n, multicastGroup, tlvs})
	}
	return actions
}

func (s *Speaker) flushUpdates() {
	s.mu.Lock()
	actions := s.updateActions()
	s.mu.Unlock()
	s.sendActions(actions)
}

func aeFor(p netip.Prefix) uint8 {
	if p.Addr().Is4() {
		return AEIPv4
	}
	return AEIPv6
}
