package ir

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: package ir imports neither the engine nor the rules.
func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "github.com/sisaku-security/sisakulint/actions/lint" || strings.HasPrefix(dep, "github.com/sisaku-security/sisakulint/actions/rules") {
			t.Errorf("actions/ir depends on %s", dep)
		}
	}
}
