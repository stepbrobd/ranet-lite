package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"

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
	rekey        func()
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
	out.SetRekeyCallback(t.rekey)
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
		return nil, errors.New("peer has no active Child SA")
	}
	r, err := current.outbound.ReserveSequenceRange(count)
	if err != nil {
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

func validateESPTunnelPayload(plain []byte, nextHeader byte) (bool, error) {
	if nextHeader == esp.NextHeaderNone {
		return false, nil
	}
	version := packet.Version(plain)
	if (nextHeader == esp.NextHeaderIPv4 && version == 4) || (nextHeader == esp.NextHeaderIPv6 && version == 6) {
		return true, nil
	}
	return false, fmt.Errorf("invalid IP tunnel payload for ESP Next Header %d", nextHeader)
}
