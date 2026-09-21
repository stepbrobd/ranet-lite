//go:build !linux && !darwin

package client

// forwardingEnabled cannot be answered on a platform with no implementation,
// and a warning this node cannot substantiate is worse than silence.
func forwardingEnabled() (v4, v6 bool) { return true, true }

// l3mdevAccept cannot be answered here either. See forwardingEnabled.
func l3mdevAccept() bool { return true }
