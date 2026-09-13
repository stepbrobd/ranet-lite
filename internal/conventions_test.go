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
func goFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	root := ".."
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "vendor" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 50 {
		t.Fatalf("found %d go files, so the walk is not reaching the tree", len(out))
	}
	return out
}

// The framing the prose rules ban, which says a thing matters instead of
// saying what it does. Upstream carries one instance of the substring, inside
// "doesn't care what order", so the pattern requires the whole phrase.
func TestNoFramingPhrase(t *testing.T) {
	banned := regexp.MustCompile(`\b(is|are|was|were) what\b|\bis the point\b`)
	for _, path := range goFiles(t) {
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
