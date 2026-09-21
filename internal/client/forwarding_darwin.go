//go:build darwin

package client

import "golang.org/x/sys/unix"

// forwardingEnabled reports whether this host forwards, per family. See the
// linux file for what it decides. A Mac is not necessarily a leaf: anything
// that turns on subnet routing, tailscale among them, sets these.
func forwardingEnabled() (v4, v6 bool) {
	return sysctlIsOne("net.inet.ip.forwarding"), sysctlIsOne("net.inet6.ip6.forwarding")
}

func sysctlIsOne(name string) bool {
	value, err := unix.SysctlUint32(name)
	if err != nil {
		// Unreadable is not "off", as on linux.
		return true
	}
	return value != 0
}

// l3mdevAccept is a linux question. darwin has no VRFs, and the reconciler
// refuses a configuration that asks for one, so nothing here consults this.
func l3mdevAccept() bool { return true }
