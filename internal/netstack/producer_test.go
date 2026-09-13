package netstack

import "fmt"

// reserveBatch assigns the peer's transmission ticket and, when supported, its
// ESP sequence range under one lock, waiting for a slot rather than dropping.
// Nothing in the dataplane does that: Mesh reserves through reserveBatchNow so
// one backpressured peer cannot stall the readers feeding every other peer.
// This is the unthrottled producer the ordering tests and the benchmarks need,
// which is why it lives here rather than beside them.
func (p *Peer) reserveBatch(count int) *peerBatch {
	hasSlot := false
	if p.slots != nil {
		select {
		case p.slots <- struct{}{}:
			hasSlot = true
		case <-p.stop:
			return &peerBatch{peer: p, reserved: true, err: fmt.Errorf("netstack: peer %s closed", p.ID)}
		}
	}
	return p.reserveBatchWithSlot(count, hasSlot, false)
}

// sendOrDrop takes a place and sends it in one step, as a caller with
// nothing to decide under a lock does.
func sendOrDrop(p *Peer, raw []byte, nextHeader byte) error {
	place, err := p.ReserveRawOrDrop(raw, nextHeader)
	if err != nil {
		return err
	}
	return place.Send()
}
