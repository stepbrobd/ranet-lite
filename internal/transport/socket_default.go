//go:build !linux && !darwin

package transport

import (
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

// This platform has neither facility, so Underlay.refuse turns down every
// configuration that asks for one by name rather than opening a socket that
// quietly does nothing about the underlay.
const (
	marksSockets = false
	bindsSockets = false
)

func openPacketBind(port uint16, underlay Underlay, index int) (packetBind, []receiveFunc, uint16, error) {
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
