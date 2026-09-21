// Package version carries the build's own version string. The control surface
// reports it so a fleet can be asked what it is running without reading a nix
// store path off every node.
package version

import "runtime/debug"

// Value is set at link time from version.txt by the nix build, and Revision
// from the commit that build came from. A plain `go build` leaves Value at
// "dev", which is the honest answer for one, and reads the revision out of the
// build info the toolchain embeds instead.
var (
	Value    = "dev"
	Revision = ""
)

// String is Value with the revision the build came from, which tells two nodes
// apart during a migration: version.txt moves once per release and the fleet
// converts one node at a time in between.
//
// The revision comes from the build info the go toolchain embeds rather than
// from a second link flag, so it is right for a plain `go build` as well.
func String() string {
	revision, modified := vcs()
	switch {
	case revision == "":
		return Value
	case modified:
		return Value + "+" + revision + "-dirty"
	default:
		return Value + "+" + revision
	}
}

func vcs() (revision string, modified bool) {
	if Revision != "" {
		// A nix build has no .git in its source, so the toolchain embeds
		// nothing and the flake passes the revision in instead.
		return Revision, false
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
			if len(revision) > 12 {
				revision = revision[:12]
			}
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	return revision, modified
}
