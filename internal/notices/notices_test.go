package notices

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The notice is generated, so the thing worth holding is not its text but that
// nobody added a dependency and shipped without regenerating it. A direct
// requirement gets added by hand, so every one of them has to be
// named here, and nothing may be named that go.mod no longer requires at all.
//
// The check reads go.mod rather than asking the toolchain because a nix build
// has neither a module cache nor an in-tree vendor directory, so `go list` and
// go version -m both come back empty there and a check that used them would
// pass by finding nothing.
func TestEveryDirectRequirementIsNoticed(t *testing.T) {
	body, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	direct, all := requirements(string(body))
	if len(direct) == 0 {
		t.Fatal("go.mod names no direct requirement, which cannot be right")
	}
	for _, module := range direct {
		if !strings.Contains(ThirdParty, "\n## "+module+"\n") {
			t.Errorf("%s is a direct requirement with no license section: run the formatter", module)
		}
	}
	for _, module := range sections(ThirdParty) {
		if !all[module] {
			t.Errorf("%s has a license section and go.mod does not require it: run the formatter", module)
		}
	}
}

// Every section carries its license text, so an entry reduced to a heading
// says a module was noticed when nothing about it was reproduced.
func TestEverySectionCarriesItsLicense(t *testing.T) {
	for _, module := range sections(ThirdParty) {
		heading := "\n## " + module + "\n"
		body, _, _ := strings.Cut(ThirdParty[strings.Index(ThirdParty, heading)+len(heading):], "\n## ")
		if !strings.Contains(body, "```") || len(body) < 200 {
			t.Errorf("%s carries %d bytes and no license block", module, len(body))
		}
	}
}

var (
	requireLine = regexp.MustCompile(`^\s*([^\s/][^\s]*\.[^\s]*/[^\s]+)\s+v\S+(\s*//\s*indirect)?\s*$`)
	sectionLine = regexp.MustCompile(`(?m)^## (\S+)$`)
)

// requirements splits go.mod's require blocks into the modules written by
// hand and every module named at all.
func requirements(body string) (direct []string, all map[string]bool) {
	all = map[string]bool{}
	for line := range strings.SplitSeq(body, "\n") {
		match := requireLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		all[match[1]] = true
		if match[2] == "" {
			direct = append(direct, match[1])
		}
	}
	return direct, all
}

func sections(text string) []string {
	var out []string
	for _, match := range sectionLine.FindAllStringSubmatch(text, -1) {
		out = append(out, match[1])
	}
	return out
}
