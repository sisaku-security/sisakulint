package lint

import (
	"strings"
	"testing"
)

func TestParseSourceFile(t *testing.T) {
	const sha = "a408f5dd083a9a4be259bb44478598002f9387a6"
	for _, c := range []struct {
		name, s   string
		key, path string
		err       string
	}{
		{"a file", "https://github.com/NVIDIA/OpenShell/blob/" + sha + "/.github/workflows/release-canary.yml", "nvidia/openshell:.github/workflows/release-canary.yml", ".github/workflows/release-canary.yml", ""},
		{"a line", "https://github.com/o/r/blob/" + sha + "/a.yml#L3", "o/r:a.yml", "a.yml", ""},
		{"lines", "https://github.com/o/r/blob/" + sha + "/d/a.yml#L3-L9", "o/r:d/a.yml", "d/a.yml", ""},
		{"lines backwards", "https://github.com/o/r/blob/" + sha + "/a.yml#L9-L3", "", "", "fragment"},
		{"line zero", "https://github.com/o/r/blob/" + sha + "/a.yml#L0", "", "", "fragment"},
		{"another fragment", "https://github.com/o/r/blob/" + sha + "/a.yml#x", "", "", "fragment"},
		{"a branch", "https://github.com/o/r/blob/main/a.yml", "", "", "commit"},
		{"a short commit", "https://github.com/o/r/blob/a408f5d/a.yml", "", "", "commit"},
		{"a tree", "https://github.com/o/r/tree/" + sha + "/d", "", "", "blob"},
		{"no path", "https://github.com/o/r/blob/" + sha, "", "", "blob"},
		{"a directory", "https://github.com/o/r/blob/" + sha + "/d/", "", "", "blob"},
		{"a query", "https://github.com/o/r/blob/" + sha + "/a.yml?plain=1", "", "", "query"},
		{"another host", "https://raw.githubusercontent.com/o/r/" + sha + "/a.yml", "", "", "github.com"},
		{"http", "http://github.com/o/r/blob/" + sha + "/a.yml", "", "", "https"},
	} {
		f, err := ParseSourceFile(c.s)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error %v, want %q", c.name, err, c.err)
		case c.err == "" && (f.Key() != c.key || f.Path() != c.path || f.URL().String() != c.s || f.SHA().String() != sha):
			t.Errorf("%s: key %q path %q url %q sha %q", c.name, f.Key(), f.Path(), f.URL(), f.SHA())
		}
	}
}
