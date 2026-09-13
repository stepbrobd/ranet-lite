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
