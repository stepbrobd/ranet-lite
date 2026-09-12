package netstack

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/NickCao/ranet-lite/sadr"
)

// RouteTable adds peer diagnostics to the shared SADR implementation. The
// forwarding trie is the sole source of truth for lookup, removal and dumps.
type RouteTable struct {
	table   sadr.Table[*Peer]
	changed chan struct{}
}

func NewRouteTable() *RouteTable { return &RouteTable{changed: make(chan struct{}, 1)} }

// Changed carries one coalesced notification per batch of forwarding table
// changes, so a mirror outside this process reconciles from Snapshot rather
// than from an event stream it could fall behind on. A writer never blocks on
// it, so a reader that misses a wake still sees the change on the next one.
func (rt *RouteTable) Changed() <-chan struct{} { return rt.changed }

// Snapshot is one consistent view of the forwarding table. The underlying
// trie publishes immutable roots, so this is safe to call from any goroutine.
func (rt *RouteTable) Snapshot() []sadr.Route[*Peer] {
	var out []sadr.Route[*Peer]
	for route := range rt.table.All() {
		out = append(out, route)
	}
	return out
}

func (rt *RouteTable) notify() {
	if rt.changed == nil {
		return
	}
	select {
	case rt.changed <- struct{}{}:
	default:
	}
}

func (rt *RouteTable) Set(src, dst netip.Prefix, peer *Peer) {
	rt.table.Set(src, dst, peer)
	rt.notify()
}

func (rt *RouteTable) Remove(src, dst netip.Prefix) {
	rt.table.Remove(src, dst)
	rt.notify()
}

func (rt *RouteTable) RemovePeer(peer *Peer) {
	rt.table.RemoveValue(peer)
	rt.notify()
}

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
