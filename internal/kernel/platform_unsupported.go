//go:build !linux || android

package kernel

// android is excluded with darwin and ios: the kernel there is Linux, but an
// application has neither CAP_NET_ADMIN nor a routing table of its own, so the
// netlink backend would only ever fail at runtime. Each platform gets its own
// backend when it gets one; until then New reports it rather than starting a
// reconciler that quietly installs nothing.
func newPlatform(Config) (platform, error) { return nil, ErrUnsupported }
