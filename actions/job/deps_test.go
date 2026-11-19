package job

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: the analysis reads the model, the events of taint and
// the types of facts; not the engine, the rules, the IR, nor the analyses
// that use it (prcode, artifact).
func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch {
		case dep == "github.com/sisaku-security/sisakulint/actions/lint", dep == "github.com/sisaku-security/sisakulint/actions/ir",
			dep == "github.com/sisaku-security/sisakulint/actions/prcode", dep == "github.com/sisaku-security/sisakulint/actions/artifact",
			strings.HasPrefix(dep, "github.com/sisaku-security/sisakulint/actions/rules"):
			t.Errorf("actions/job depends on %s", dep)
		}
	}
}
