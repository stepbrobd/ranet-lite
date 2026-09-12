//go:build !linux && !darwin

package netstack

// defaultTUNName is empty so the platform backend picks its own name.
const defaultTUNName = ""
