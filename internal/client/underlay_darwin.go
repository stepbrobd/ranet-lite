//go:build darwin && !ios

package client

import (
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/internal/transport"
)

// underlayRuntime opens what the transport needs to keep the one UDP socket
// out of the mesh's own routing. On darwin that means binding the socket to
// the interface the host's default route leaves by, which only the routing
// table knows and only the route socket can say, so internal/kernel answers
// it: this package wires the two together and speaks neither.
//
// The returned close is always safe to call.
func underlayRuntime(underlay transport.Underlay) (transport.Runtime, func(), error) {
	if !underlay.Bind {
		return transport.Runtime{}, func() {}, nil
	}
	links, err := kernel.WatchLinks()
	if err != nil {
		return transport.Runtime{}, func() {}, err
	}
	return transport.Runtime{Links: links}, func() { _ = links.Close() }, nil
}
