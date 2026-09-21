//go:build !linux

package egress

import "fmt"

// newBackend refuses the capability by name where there is nothing to install
// it with. It is a refusal rather than a stub that does nothing, for the same
// reason internal/kernel refuses a policy rule on darwin: a node that accepted
// the configuration and translated nothing would come up with a working mesh,
// advertise itself as an exit, and drop every flow that took it.
//
// darwin gets a pf anchor of its own, which is not written yet. iOS and
// android have no packet filter a process may write at all, and a phone has to
// use an exit node rather than be one.
func newBackend(cfg Config, _ Runtime) (backend, error) {
	return nil, refuseWhatThisPlatformLacks(cfg)
}

// refuseWhatThisPlatformLacks is the refusal on its own, so that a capability
// nobody switched on is not refused for a facility it never asked for. New
// returns before this on a disabled capability, so the backend it hands back
// there reaches no caller.
func refuseWhatThisPlatformLacks(cfg Config) error {
	if !cfg.Enable {
		return nil
	}
	return fmt.Errorf("%w: egress.enable asks this node to translate a source address, and nftables is a linux facility", ErrUnsupported)
}
