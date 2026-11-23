package reportview

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: the report view reads a report; it does not run the
// rules or the command.
func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "github.com/gh-intel/sisakulint/actions/rules" || dep == "github.com/gh-intel/sisakulint/actions/cli" {
			t.Errorf("actions/reportview depends on %s", dep)
		}
	}
}
