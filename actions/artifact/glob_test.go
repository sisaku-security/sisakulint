package artifact

import (
	"strings"
	"testing"
)

// TestTakes is @actions/glob as upload-artifact runs it: minimatch with
// dot, a directory takes what is under it, and
// without hidden files an item whose name starts with a dot is left out,
// the root of the search included, what is above it not.
func TestTakes(t *testing.T) {
	const git = ".git/config"
	for _, c := range []struct {
		lines  string
		file   string
		hidden bool
		want   bool
	}{
		{".", git, true, true},
		{".", git, false, false},
		{"./", git, true, true},
		{"  ./  ", git, true, true},
		{".git/config", git, false, true},
		{".git", git, false, false},
		{".git", git, true, true},
		{"*", git, true, true},
		{"**", git, true, true},
		{"*", git, false, false},
		{"src", "src/.git/config", true, true},
		{"src", git, true, false},
		{"dist", git, true, false},
		{".", gcpCreds, false, true},
		{"gha-creds-*.json", gcpCreds, false, true},
		{".\n!gha-creds-*.json", gcpCreds, false, false},
		{"# a comment\n\n.", git, true, true},
		{".", "../nuget.config", false, false},
		{"..", "../nuget.config", false, false}, // @actions/glob refuses ..
		{"!.git/config\n.", git, true, true},    // a later line takes it back
		{".\n!.git\n.git/config", git, true, true},
		{".\n.git/config", git, false, false}, // the search from . leaves .git out
		{"sub\nsub/.hidden/f", "sub/.hidden/f", false, false},
		{".\nsub/../x", gcpCreds, false, false}, // a line with .. fails the whole upload
		{"./.git/config", git, false, true},
		{"../x", "../nuget.config", false, false},
		// a line that ends in / matches a directory only
		{".git/config/", git, true, false},
		{".git/config/", git, false, false},
		{".git/", git, true, true},
		{"**/config/", git, true, false},
		{".git/config/\n.git/", git, true, true},
		{".\n!.git/config/", git, true, true},
		{".git/config\n!.git/", git, true, false},
	} {
		lines := strings.Split(c.lines, "\n")
		if got := parseLines(lines).takes(strings.Split(c.file, "/"), c.hidden); got != c.want {
			t.Errorf("%q %s hidden %v: %v, want %v", c.lines, c.file, c.hidden, got, c.want)
		}
	}
}
