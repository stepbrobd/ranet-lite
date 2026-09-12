//go:build darwin

package netstack

// darwin's utun control accepts "utun" for the next free unit, or "utunN" for
// a specific one. Any other name fails at creation, so the Linux default
// cannot be shared.
const defaultTUNName = "utun"
