// Package notices carries the third party notice into the binary, so the
// obligation to reproduce a license travels with what is distributed rather
// than with the repository somebody did not clone.
package notices

import _ "embed"

// ThirdParty is every module linked into this binary and the license it is
// under. internal/cmd/notices writes it and the formatter keeps it current.
//
//go:embed third_party.md
var ThirdParty string
