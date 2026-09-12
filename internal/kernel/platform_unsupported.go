//go:build (!linux && !darwin) || android || ios

package kernel

// android is excluded with the linux backend and ios with the darwin one: the
// kernel under each is the supported one, but an application there has neither
// the privilege nor a routing table of its own, so the backend would only ever
// fail at runtime. On ios the tunnel's routes come from the network extension's
// settings rather than from PF_ROUTE at all. Each platform gets its own backend
// when it gets one; until then New reports it rather than starting a reconciler
// that installs nothing and reports no error.
func newPlatform(Config) (platform, error) { return nil, ErrUnsupported }
