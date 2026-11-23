package repofile

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: the resolver reads files and YAML, not the model, the
// engine, the rules or the CLI.
func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, bad := range []string{"github.com/gh-intel/sisakulint/actions/workflow", "github.com/gh-intel/sisakulint/actions/lint", "github.com/gh-intel/sisakulint/actions/rules", "github.com/gh-intel/sisakulint/actions/cli"} {
			if dep == bad {
				t.Errorf("actions/repofile depends on %s", dep)
			}
		}
	}
}
