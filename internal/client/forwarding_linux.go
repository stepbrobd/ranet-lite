//go:build linux

package client

import (
	"os"
	"strings"
)

// forwardingEnabled reports whether this host forwards, per family. Babel has
// no way to say "I carry my own prefixes but nothing else": a node that
// advertises a route is promising to forward it, so the only signal a peer
// ever gets is the advertisement itself. A node that redistributes with
// forwarding off therefore attracts traffic it drops, and nothing tells the
// sender.
//
// It is read here rather than in each package that needs it, so that transit
// and the egress capability answer the question the same way. Forwarding
// exports it; internal/egress withholds an advertisement over the same fact
// this warns about.
func forwardingEnabled() (v4, v6 bool) {
	return sysctlIsOne("/proc/sys/net/ipv4/ip_forward"),
		sysctlIsOne("/proc/sys/net/ipv6/conf/all/forwarding")
}

func sysctlIsOne(path string) bool {
	body, err := os.ReadFile(path)
	if err != nil {
		// Unreadable is not "off": reporting a warning this node cannot
		// substantiate is worse than staying quiet.
		return true
	}
	return strings.TrimSpace(string(body)) != "0"
}

// l3mdevAccept reports whether a socket outside a VRF is matched by traffic
// that arrived through one. It is off by default, and with a VRF holding the
// mesh addresses that decides whether anything on this node can use them: a
// reply arriving through the master is looked up only against sockets bound to
// that master, so every TCP and UDP flow to and from a mesh address fails
// while ICMP, which is matched differently, answers. Measured on a fleet node
// on 2026-09-21, where it read as a routing problem for an afternoon.
//
// Both halves have to be on to say yes, since a node with one of them is half
// broken in a way that is harder to find than a node with neither.
func l3mdevAccept() bool {
	return sysctlIsOne("/proc/sys/net/ipv4/tcp_l3mdev_accept") &&
		sysctlIsOne("/proc/sys/net/ipv4/udp_l3mdev_accept")
}
