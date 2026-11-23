package prcode

import (
	"strings"
	"testing"
)

// TestPermissionRunsTree: an agent's permission of a command, read by the
// table of tools past the wrappers; with open, the agent chooses the words
// after it.
func TestPermissionRunsTree(t *testing.T) {
	for _, c := range []struct {
		words string
		open  bool
		runs  bool
	}{
		{"npm ci", false, true},
		{"pnpm build", false, true},
		{"composer install", false, true},
		{"yarn build", false, true},
		{"timeout 60 npm test", false, true},
		{"env CI=1 npm test", false, true},
		{"sudo npm test", false, true},
		{"npm view x", false, false},
		{"npm publish --ignore-scripts", false, false},
		{"./build.sh", false, false},
		{"bash build.sh", false, false},
		{"cat x", false, false},
		{"npm", true, true},
		{"npm run", true, true},
		{"npm audit", true, true},
		{"npm view", true, false},
		{"pip install", true, true},
		{"npm publish --ignore-scripts", true, true},
		{"composer --no-scripts --no-plugins install", true, false},
		{"composer --no-scripts --no-plugins", true, true},
	} {
		if runs := PermissionRunsTree(strings.Fields(c.words), c.open); runs != c.runs {
			t.Errorf("%q open %v: runs %v; want %v", c.words, c.open, runs, c.runs)
		}
	}
}
