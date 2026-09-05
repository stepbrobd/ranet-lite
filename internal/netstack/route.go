package netstack

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/NickCao/ranet-lite/sadr"
)

// RouteTable adds peer diagnostics to the shared SADR implementation. The
// forwarding trie is the sole source of truth for lookup, removal and dumps.
type RouteTable struct{ table sadr.Table[*Peer] }

func NewRouteTable() *RouteTable { return &RouteTable{} }

func (rt *RouteTable) Set(src, dst netip.Prefix, peer *Peer) {
	rt.table.Set(src, dst, peer)
}

func (rt *RouteTable) Remove(src, dst netip.Prefix) { rt.table.Remove(src, dst) }

func (rt *RouteTable) RemovePeer(peer *Peer) { rt.table.RemoveValue(peer) }

func (rt *RouteTable) Lookup(src, dst netip.Addr) (*Peer, bool) { return rt.table.Lookup(src, dst) }

func (rt *RouteTable) Debug() []string {
	var out []string
	for route := range rt.table.All() {
		if route.Source.IsValid() {
			out = append(out, fmt.Sprintf("%s from %s via %s", route.Destination, route.Source, route.Value.ID))
		} else {
			out = append(out, fmt.Sprintf("%s via %s", route.Destination, route.Value.ID))
		}
	}
	sort.Strings(out)
	return out
}
