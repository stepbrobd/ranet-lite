// Package version carries the build's own version string. The control surface
// reports it so a fleet can be asked what it is running without reading a nix
// store path off every node.
package version

// Value is set at link time from version.txt by the nix build. A plain
// `go build` leaves it at "dev", which is the honest answer for one.
var Value = "dev"
