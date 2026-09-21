//go:build !darwin || ios

package client

import "github.com/NickCao/ranet-lite/internal/transport"

// underlayRuntime has nothing to open here. linux keeps its underlay out of
// the mesh's routing with a socket mark and a policy rule, which needs no
// runtime lookup, and every other platform refuses both spellings by name in
// internal/transport rather than opening a socket that does neither.
func underlayRuntime(transport.Underlay) (transport.Runtime, func(), error) {
	return transport.Runtime{}, func() {}, nil
}
