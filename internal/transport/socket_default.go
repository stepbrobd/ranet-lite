//go:build !linux

package transport

import (
	"errors"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
)

type portableBind struct{ conn.Bind }
type portableEndpoint struct{ conn.Endpoint }

func (*portableEndpoint) transportEndpoint() {}
func (e *portableEndpoint) String() string   { return e.DstToString() }

func (e *portableEndpoint) AddrPort() netip.AddrPort {
	addr, err := netip.ParseAddrPort(e.DstToString())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

func (b *portableBind) ParseEndpoint(s string) (Endpoint, error) {
	ep, err := b.Bind.ParseEndpoint(s)
	return &portableEndpoint{ep}, err
}

func (b *portableBind) Send(packets [][]byte, endpoint Endpoint) error {
	return b.Bind.Send(packets, endpoint.(*portableEndpoint).Endpoint)
}

func openPacketBind(port uint16, fwmark uint32) (packetBind, []receiveFunc, uint16, error) {
	if fwmark != 0 {
		// Refused rather than ignored: a mark this platform cannot set is a
		// rule somewhere that will never match, and the configuration that
		// asked for it was written to keep the underlay out of the overlay.
		// darwin reaches the same end through interface scope on the routes
		// the reconciler installs, which scopeRoute in internal/kernel
		// decides.
		return nil, nil, 0, errors.New("fwmark is a linux facility and is set on no other platform")
	}
	b := &portableBind{conn.NewStdNetBind()}
	fns, port, err := b.Open(port)
	if err != nil {
		return nil, nil, 0, err
	}
	var receivers []receiveFunc
	for _, fn := range fns {
		size := b.BatchSize()
		eps := make([]conn.Endpoint, size)
		receivers = append(receivers, func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, int, error) {
			for i := range size {
				if bufs[i] == nil {
					bufs[i] = make([]byte, readBufferSize)
				}
			}
			n, err := fn(bufs[:size], sizes[:size], eps)
			for i := range n {
				endpoints[i] = &portableEndpoint{eps[i]}
			}
			// This bind hands every datagram it reads straight through, so
			// there is nothing it refuses of its own.
			return n, 0, err
		})
	}
	return b, receivers, port, nil
}
