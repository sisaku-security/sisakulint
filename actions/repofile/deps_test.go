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
		for _, bad := range []string{"github.com/sisaku-security/sisakulint/actions/workflow", "github.com/sisaku-security/sisakulint/actions/lint", "github.com/sisaku-security/sisakulint/actions/rules", "github.com/sisaku-security/sisakulint/actions/cli"} {
			if dep == bad {
				t.Errorf("actions/repofile depends on %s", dep)
			}
		}
	}
}
