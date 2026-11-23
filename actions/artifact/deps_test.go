package artifact

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: the analysis reads the model and the types of facts;
// not the engine, the rules nor the IR.
func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch {
		case dep == "github.com/sisaku-security/sisakulint/actions/lint", dep == "github.com/sisaku-security/sisakulint/actions/ir", strings.HasPrefix(dep, "github.com/sisaku-security/sisakulint/actions/rules"):
			t.Errorf("actions/artifact depends on %s", dep)
		}
	}
}
