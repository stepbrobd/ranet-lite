//go:build !darwin || ios

package client

import (
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/transport"
)

// underlayRuntime has nothing to open here. linux keeps its underlay out of
// the mesh's routing with a socket mark and a policy rule, which needs neither
// a lookup nor a route of its own, and every other platform refuses both
// spellings by name in transport rather than opening a socket that
// does neither. The host is taken and ignored for the same reason: this
// platform reads no routing table of its own here.
func underlayRuntime(transport.Underlay, string, kernel.Host) (transport.Runtime, kernel.CaptureRoutes, func(), error) {
	return transport.Runtime{}, nil, func() {}, nil
}
