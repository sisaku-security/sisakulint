package prcode

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: the job's context reads the model, taint and the shell,
// and the types of facts; not the engine nor the rules. taint does not read
// it back.
func TestDependencies(t *testing.T) {
	for pkg, bad := range map[string][]string{
		".":        {"github.com/sisaku-security/sisakulint/actions/lint", "github.com/sisaku-security/sisakulint/actions/rules"},
		"../taint": {"github.com/sisaku-security/sisakulint/actions/prcode"},
	} {
		out, err := exec.Command("go", "list", "-deps", pkg).Output()
		if err != nil {
			t.Skipf("go list: %v", err)
		}
		for _, dep := range strings.Fields(string(out)) {
			for _, b := range bad {
				if dep == b {
					t.Errorf("%s depends on %s", pkg, dep)
				}
			}
		}
	}
}
