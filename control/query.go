package control

import (
	"net/netip"
	"slices"
)

// This file is the questions a caller asks of what the reads returned rather
// than of the daemon: which prefix covers an address, which routes carry a
// default, and which addresses this node holds on the mesh. They live beside
// the types they read so that a monitor asks them the way the subcommands do,
// and so that a test asks them of the wire form rather than of a table.

// Covering is every route whose destination contains an address, longest
// prefix first, so the first entry is the one the forwarding table would use.
// Entries of equal length are ordered by their source prefix, since a
// source-specific route is keyed by the pair and several can share one
// destination.
//
// A retracted prefix is in the answer like any other, with no next hop. It is
// held rather than removed exactly so a packet does not follow a shorter
// prefix instead, and a reader asking where an address goes needs to see that.
func Covering(routes []Route, address netip.Addr) []Route {
	out := make([]Route, 0, 4)
	for _, route := range routes {
		if route.Destination.Contains(address) {
			out = append(out, route)
		}
	}
	slices.SortStableFunc(out, func(a, b Route) int {
		if order := b.Destination.Bits() - a.Destination.Bits(); order != 0 {
			return order
		}
		return b.From.Bits() - a.From.Bits()
	})
	return out
}

// Defaults is every route carrying a default, the advertisement that makes a
// node an exit. Both families are included and the order the daemon gave is
// kept, so two entries for one family read next to each other.
//
// The test is the prefix length against a zero address rather than the length
// alone: a /0 is the only prefix that covers everything, and spelling it this
// way refuses a prefix whose length happens to be zero for another reason.
func Defaults(routes []Route) []Route {
	out := make([]Route, 0, 2)
	for _, route := range routes {
		if route.Destination.Bits() == 0 && route.Destination.Addr().IsUnspecified() {
			out = append(out, route)
		}
	}
	return out
}

// MeshAddresses is the addresses this node carries on the mesh, taken from
// what it announces. Only a host prefix counts: a shorter one is a range this
// node carries traffic for rather than an address it answers at, and a
// default announced by an exit is neither. The daemon applies the same rule
// when it decides which addresses its egress translates into the mesh.
func MeshAddresses(status Status) []netip.Addr {
	out := make([]netip.Addr, 0, len(status.Originate))
	for _, announced := range status.Originate {
		prefix := announced.Prefix
		if prefix.Bits() != prefix.Addr().BitLen() || slices.Contains(out, prefix.Addr()) {
			continue
		}
		out = append(out, prefix.Addr())
	}
	return out
}
