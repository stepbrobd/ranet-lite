//go:build darwin && !ios

package client

import (
	"path/filepath"

	"github.com/NickCao/ranet-lite/internal/control"
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/internal/transport"
)

// underlayRuntime opens what the transport needs to keep the one UDP socket
// out of the mesh's own routing. On darwin that means binding the socket to
// the interface the host's default route leaves by, and writing that
// interface a default of its own scoped to it, because a bound socket still
// reads the shared forwarding table. Only the route socket can answer either
// question, so internal/kernel does both; this package wires the two together
// and speaks neither.
//
// mesh is this node's own tun, which the lookup must never answer with: once
// the mesh holds a route covering the address space, an ordinary lookup for
// the unspecified address names the tun, and binding to that would put every
// datagram this node sends inside its own tunnel.
//
// The returned close is always safe to call.
func underlayRuntime(underlay transport.Underlay, mesh string) (transport.Runtime, kernel.CaptureRoutes, func(), error) {
	if !underlay.Bind {
		return transport.Runtime{}, nil, func() {}, nil
	}
	links, err := kernel.WatchLinksOn(mesh)
	if err != nil {
		return transport.Runtime{}, nil, func() {}, err
	}
	// Beside the control socket's lock, which is the other file in that
	// directory saying what this process owns, and which a RuntimeDirectory=
	// unit clears on a clean boot.
	state := filepath.Join(filepath.Dir(control.DefaultSocket), "underlay.json")
	routes, err := kernel.NewUnderlayDefaults(links, state)
	if err != nil {
		_ = links.Close()
		return transport.Runtime{}, nil, func() {}, err
	}
	close := func() {
		// The routes first: they are withdrawn through the route socket this
		// owns, and the link watcher is only a notification channel.
		_ = routes.Close()
		_ = links.Close()
	}
	return transport.Runtime{Links: links, Routes: routes}, routes, close, nil
}
