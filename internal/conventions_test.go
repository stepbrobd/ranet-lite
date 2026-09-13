// Package conventions holds the checks that keep this tree's own writing
// rules from drifting. They are here rather than in a script because the two
// below have each been swept once already and come back the moment nothing
// runs them: the audit ledger records the phrasing habit removed in one commit
// and reintroduced thirteen times, and twenty-five test names carrying back
// articles a rename had just stripped.
package conventions

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// goFiles walks the tree from its root, which is one directory up.
func goFiles(t *testing.T) []string { return treeFiles(t, map[string]int{".go": 50}) }

// prose covers the go files and the two documents an operator reads. The rules
// are about writing rather than about Go, and scanning only the source left
// the readme with three instances of the phrasing the sweep had removed
// everywhere else, because nothing looked there.
func proseFiles(t *testing.T) []string {
	return treeFiles(t, map[string]int{".go": 50, ".md": 1, ".yaml": 1})
}

// least is per suffix rather than a total. The tree holds well over a hundred
// go files against one markdown and a handful of yaml, so any total a go-only
// walk already meets would let the documents silently drop out of the checks
// that were widened to reach them.
func treeFiles(t *testing.T, least map[string]int) []string {
	t.Helper()
	var out []string
	seen := make(map[string]int, len(least))
	root := ".."
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "vendor" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		for suffix := range least {
			if strings.HasSuffix(path, suffix) {
				out = append(out, path)
				seen[suffix]++
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for suffix, want := range least {
		if seen[suffix] < want {
			t.Fatalf("found %d %s files, want at least %d, so the walk is not reaching them", seen[suffix], suffix, want)
		}
	}
	return out
}

// The framing the prose rules ban, which says a thing matters instead of
// saying what it does. Upstream carries one instance of the substring, inside
// "doesn't care what order", so the pattern requires the whole phrase.
func TestNoFramingPhrase(t *testing.T) {
	banned := regexp.MustCompile(`\b(is|are|was|were) what\b|\bis the point\b`)
	for _, path := range proseFiles(t) {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			if banned.MatchString(line) {
				t.Errorf("%s:%d says a thing matters instead of what it does: %s",
					path, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// Test names read as statements, not as sentences opening with an article.
// Upstream has none of these in 203 test functions.
func TestNoArticleLeadingTestName(t *testing.T) {
	article := regexp.MustCompile(`^func ((?:Test|Benchmark|Fuzz))(A|An|The)([A-Z]\w*)`)
	for _, path := range goFiles(t) {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			if m := article.FindStringSubmatch(line); m != nil {
				t.Errorf("%s:%d opens with an article, want %s%s", path, i+1, m[1], m[3])
			}
		}
	}
}

// Counting files cannot tell a narrowed walk from a tree that grew, because
// the go files alone satisfy any total the documents were added to. The walk
// that was widened past them is guarded by naming them.
func TestProseChecksReachTheDocuments(t *testing.T) {
	want := map[string]bool{"../readme.md": false, "../examples/config.yaml": false}
	for _, path := range proseFiles(t) {
		if _, named := want[path]; named {
			want[path] = true
		}
	}
	for path, reached := range want {
		if !reached {
			t.Errorf("the prose checks do not read %s, so its wording is unchecked", path)
		}
	}
}
