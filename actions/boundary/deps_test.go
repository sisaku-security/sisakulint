package boundary

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: the tables are read by the report view and by the
// tests of the rules, so they import neither, nor the command.
func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch dep {
		case "github.com/sisaku-security/sisakulint/actions/rules", "github.com/sisaku-security/sisakulint/actions/cli", "github.com/sisaku-security/sisakulint/actions/reportview":
			t.Errorf("actions/boundary depends on %s", dep)
		}
	}
}
