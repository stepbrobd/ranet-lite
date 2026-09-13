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

// Unreachable is installed for a prefix that is known and has no usable route.
// A lookup that lands on it is answered rather than falling through to a
// covering entry, as RFC 8966 section 3.5.4 requires while a
// retracted prefix is still held: "packets destined to an address within P
// MUST NOT be forwarded by following a route for a shorter prefix". Without it
// a more specific prefix that has just been retracted immediately starts
// following the default a transit node also carries, and the two ends pass the
// packet back and forth until its hop limit runs out.
// It is a sentinel rather than a usable Peer: nothing in it is initialized, so
// anything that sends through it instead of comparing against it dereferences
// a nil. Lookup answers it as "no route", and Snapshot hands it out as a value
// a caller has to recognize, which is what the doc there says.
var Unreachable = &Peer{ID: "unreachable"}

// IsUnreachable reports whether a peer from Snapshot or Lookup is the hold a
// retracted prefix leaves behind rather than somewhere to send. Comparing
// against the sentinel directly works too; this names the question.
func IsUnreachable(p *Peer) bool { return p == Unreachable }

// Changed carries one coalesced notification per batch of forwarding table
// changes, so a mirror outside this process reconciles from Snapshot rather
// than from an event stream it could fall behind on. A writer never blocks on
// it, so a reader that misses a wake still sees the change on the next one.
func (rt *RouteTable) Changed() <-chan struct{} { return rt.changed }

// Snapshot is one consistent view of the forwarding table. The underlying
// trie publishes immutable roots, so this is safe to call from any goroutine.
//
// The unreachable holds are included, carrying the Unreachable sentinel as
// their value. They exist to stop a packet for a retracted prefix following a
// shorter one instead, and a mirror of this table has to hold them for the
// same reason rather than letting its own longest-prefix match fall through.
// The sentinel is not a Peer that can be sent through, so a caller walking
// these has to ask IsUnreachable before treating one as a destination.
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

// Lookup answers with the most specific entry that matches. An entry holding
// Unreachable answers "no route" rather than letting the lookup continue to a
// covering prefix, which is the whole point of holding it: the caller sees the
// same "drop this packet" it would see for an unknown destination, and the
// shorter prefix is not consulted.
func (rt *RouteTable) Lookup(src, dst netip.Addr) (*Peer, bool) {
	peer, ok := rt.table.Lookup(src, dst)
	if !ok || peer == Unreachable {
		return nil, false
	}
	return peer, true
}

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
