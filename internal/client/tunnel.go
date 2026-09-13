package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/packet"
)

// Each socket batch captures one immutable SA set. Rekeys publish replacements
// without holding a lock through crypto. In-flight batches retain the old keys;
// new batches see only the SAs that are still installed.
type tunnelSAs struct {
	outbound    *esp.OutboundSA
	outboundSPI uint32
	inbound     map[uint32]*esp.InboundSA
}

type tunnel struct {
	mu           sync.Mutex // writers only
	sas          atomic.Pointer[tunnelSAs]
	replayWindow uint32
	rekeying     atomic.Bool
	rekey        func()
	// askedAt is nanoseconds since started, read through time.Since so it
	// comes off the monotonic clock, and primed one interval in the past so
	// the first ask goes straight through. See requestRekey.
	askedAt atomic.Int64
	started time.Time
}

// rekeyAskInterval is the floor between two attempts to replace the Child SA.
// The one-at-a-time guard alone does not bound the rate: a rekey that fails
// without an exchange -- no Child SA to rekey, or one already running -- comes
// back at once, and both callers ask per batch, which on a routed tun is per
// packet. It is well under the two round trips ProactiveRekeySequence leaves
// room for, so a genuine retry still lands inside the margin.
const rekeyAskInterval = 250 * time.Millisecond

// errNoChildSA means the peer deleted the Child SA and kept the IKE SA, which
// RFC 7296 section 1.4.1 allows. Sending resumes once a replacement is
// negotiated, so it is not a reason to close anything.
var errNoChildSA = errors.New("peer has no active Child SA")

// fatalReserveError reports whether a refusal from reserve is a reason to
// close the session's mux, which ends Run, drops the babel peer and withdraws
// every route through it.
//
// Two refusals are not. A peer may delete the Child SA and keep the IKE SA
// (RFC 7296 section 1.4.1), and a non-ESN SA may run out of sequence numbers,
// which RFC 4303 section 3.3.3 makes a refusal to send rather than a failure
// of anything else. Both leave the IKE SA intact with a replacement already
// asked for, and section 1.3.1 is explicit about the answer: "A failed attempt
// to create a Child SA SHOULD NOT tear down the IKE SA: there is no reason to
// lose the work done to set up the IKE SA."
func fatalReserveError(err error) bool {
	return err != nil && !errors.Is(err, errNoChildSA) && !errors.Is(err, esp.ErrSequenceExhausted)
}

// dialerWasDropped reports whether a session is ending because the dialer that
// opened it was canceled while the node keeps running, which a reload that
// drops a peer does. Shutdown is not this case: closeAll has already told every
// peer by the time the node's own context is canceled, and the sweep exists so
// that no peer is told twice.
func dialerWasDropped(dial, node context.Context) bool {
	return dial.Err() != nil && node.Err() == nil
}

// requestRekey asks for a replacement Child SA, at most one attempt at a time.
// Every batch that finds no outbound SA calls this, which on a routed tun is
// once per packet.
func (t *tunnel) requestRekey() {
	if t.rekey == nil || !t.rekeying.CompareAndSwap(false, true) {
		return
	}
	now := int64(time.Since(t.started))
	if previous := t.askedAt.Load(); now-previous < int64(rekeyAskInterval) ||
		!t.askedAt.CompareAndSwap(previous, now) {
		t.rekeying.Store(false)
		return
	}
	go func() {
		defer t.rekeying.Store(false)
		t.rekey()
	}()
}

func (t *tunnel) install(child esp.ChildSA) error {
	out, err := esp.NewOutbound(child)
	if err != nil {
		return err
	}
	in, err := esp.NewInbound(child, esp.WithReplayWindow(t.replayWindow))
	if err != nil {
		return err
	}
	out.SetRekeyCallback(t.requestRekey)
	t.mu.Lock()
	defer t.mu.Unlock()
	inbound := make(map[uint32]*esp.InboundSA)
	if current := t.sas.Load(); current != nil {
		maps.Copy(inbound, current.inbound)
	}
	if _, exists := inbound[child.LocalSPI]; exists {
		return fmt.Errorf("inbound ESP SPI %08x already installed", child.LocalSPI)
	}
	inbound[child.LocalSPI] = in
	t.sas.Store(&tunnelSAs{outbound: out, outboundSPI: child.LocalSPI, inbound: inbound})
	return nil
}

func (t *tunnel) retire(spi uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.sas.Load()
	if current == nil || current.inbound[spi] == nil {
		return fmt.Errorf("retiring inbound ESP SPI %08x was not installed", spi)
	}
	next := *current
	next.inbound = maps.Clone(current.inbound)
	delete(next.inbound, spi)
	if next.outboundSPI == spi {
		next.outbound, next.outboundSPI = nil, 0
	}
	t.sas.Store(&next)
	return nil
}

func (t *tunnel) reserve(count int) (netstack.BatchSealer, error) {
	current := t.sas.Load()
	if current == nil || current.outbound == nil {
		t.requestRekey()
		return nil, errNoChildSA
	}
	r, err := current.outbound.ReserveSequenceRange(count)
	if err != nil {
		// The SA that ran out is still installed, so nothing else will ask.
		if errors.Is(err, esp.ErrSequenceExhausted) {
			t.requestRekey()
		}
		return nil, err
	}
	return r.SealBatchInto, nil
}

var errUnknownSPI = errors.New("no matching inbound ESP SA")

func (t *tunnel) decryptBatch(packets [][]byte, results []inboundDecrypted) []inboundDecrypted {
	current := t.sas.Load()
	for len(packets) > 0 {
		raw := packets[0]
		if current != nil && len(raw) >= 4 {
			spi := binary.BigEndian.Uint32(raw[:4])
			if sa := current.inbound[spi]; sa != nil {
				end := 1
				for end < len(packets) && len(packets[end]) >= 4 && binary.BigEndian.Uint32(packets[end][:4]) == spi {
					end++
				}
				results = sa.AuthenticateBatchInPlace(packets[:end], results)
				packets = packets[end:]
				continue
			}
		}
		results = append(results, inboundDecrypted{Err: errUnknownSPI})
		packets = packets[1:]
	}
	return results
}

// validateESPTunnelPayload returns the inner packet a decrypted ESP payload
// carries, trimmed to the length its own header declares. RFC 4303 section 2.7
// lets a sender append Traffic Flow Confidentiality padding after it in tunnel
// mode, which ESP cannot tell from the payload, so requiring the payload to be
// exactly one packet dropped every padded packet from such a peer and left the
// loss visible only as a drop count. The second result is false for a Next
// Header of 59, which carries no packet at all.
func validateESPTunnelPayload(plain []byte, nextHeader byte) ([]byte, bool, error) {
	if nextHeader == esp.NextHeaderNone {
		return nil, false, nil
	}
	inner, version := packet.Payload(plain)
	if (nextHeader == esp.NextHeaderIPv4 && version == 4) || (nextHeader == esp.NextHeaderIPv6 && version == 6) {
		return inner, true, nil
	}
	return nil, false, fmt.Errorf("invalid IP tunnel payload for ESP Next Header %d", nextHeader)
}
