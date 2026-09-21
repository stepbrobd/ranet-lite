// Command notices writes internal/notices/third_party.md, the notice that has
// to travel with a binary built from this tree.
//
// Apache 2.0 and the BSD and MIT licenses all require their text and their
// copyright line to be reproduced in a distribution, and a Go binary is a
// distribution of every module linked into it. The file this writes is
// embedded in the daemon and printed by `ranet-lite licenses`, so the
// obligation travels with the binary rather than with the repository.
//
// Only modules actually linked are listed. The module graph is far larger than
// the link set, because one dependency's own test and tooling requirements
// reach it, and nothing in that tail is distributed.
//
// The formatter runs this, and a check compares what it writes against what is
// committed, so the file cannot drift from go.mod.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

func run() error {
	cache, err := output("go", "env", "GOMODCACHE")
	if err != nil {
		return err
	}
	modules, err := linkedModules()
	if err != nil {
		return err
	}
	var out strings.Builder
	out.WriteString(header)
	for _, m := range modules {
		text, name, err := license(cache, m)
		if err != nil {
			return err
		}
		fmt.Fprintf(&out, "\n## %s\n\n%s %s, from `%s`.\n\n```\n%s\n```\n",
			m.path, m.path, m.version, name, strings.TrimRight(text, "\n"))
	}
	// A check writes somewhere else and compares, since the source a nix build
	// sees is read only and the point is to prove the committed file matches.
	path := filepath.Join("internal", "notices", "third_party.md")
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	return os.WriteFile(path, []byte(out.String()), 0o644)
}

const header = `# Third party notices

Every module linked into a ranet-lite binary, with the license it is under.
` + "`ranet-lite licenses`" + ` prints this same text out of the binary.

This file is generated. Run the formatter rather than editing it.
`

// module is one linked dependency.
type module struct{ path, version string }

// linkedModules is the modules the built binary actually contains, read back
// out of the binary rather than asked of the source tree. `go list -deps`
// reports no module for a package when the build is vendored, which a nix
// build's is, so asking the source gives an empty answer there and a correct
// one here; the binary answers the same way everywhere. It is also the more
// honest question, since the obligation attaches to what is distributed.
func linkedModules() ([]module, error) {
	binary := filepath.Join(os.TempDir(), "ranet-lite-notices-subject")
	defer os.Remove(binary)
	if _, err := output("go", "build", "-o", binary, "./cmd/ranet-lite"); err != nil {
		return nil, err
	}
	listed, err := output("go", "version", "-m", binary)
	if err != nil {
		return nil, err
	}
	seen := map[module]bool{}
	for line := range strings.SplitSeq(listed, "\n") {
		// "\tdep\t<path>\t<version>\t<hash>", and a replaced module adds a
		// "=>" line naming the replacement, and the replacement ships.
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) < 3 || (fields[0] != "dep" && fields[0] != "=>") {
			continue
		}
		seen[module{fields[1], fields[2]}] = true
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no modules reported by go version -m, which cannot be right")
	}
	modules := slices.Collect(maps(seen))
	slices.SortFunc(modules, func(a, b module) int { return strings.Compare(a.path, b.path) })
	return modules, nil
}

func maps(set map[module]bool) func(func(module) bool) {
	return func(yield func(module) bool) {
		for m := range set {
			if !yield(m) {
				return
			}
		}
	}
}

// license reads one module's license out of the module cache. A module whose
// license this cannot find is an error rather than an omission, because the
// point of the file is that nothing is missing from it.
func license(cache string, m module) (text, name string, err error) {
	dir := filepath.Join(cache, escape(m.path)+"@"+m.version)
	for _, candidate := range []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt"} {
		body, err := os.ReadFile(filepath.Join(dir, candidate))
		if err == nil {
			return string(body), candidate, nil
		}
	}
	return "", "", fmt.Errorf("no license file in %s", dir)
}

// escape is the module cache's spelling of a path: an uppercase letter becomes
// an exclamation mark and its lowercase, so BurntSushi is !burnt!sushi.
func escape(path string) string {
	var out strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			out.WriteByte('!')
			out.WriteRune(r + ('a' - 'A'))
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

func output(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	body, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(body)), nil
}
