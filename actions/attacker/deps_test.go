package attacker

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: the shared analysis reads the model and expressions,
// not the contract layer, the rules, nor the analysis of taint, which reads
// it.
func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch dep {
		case "github.com/sisaku-security/sisakulint/actions/lint", "github.com/sisaku-security/sisakulint/actions/rules", "github.com/sisaku-security/sisakulint/actions/facts", "github.com/sisaku-security/sisakulint/actions/taint":
			t.Errorf("actions/attacker depends on %s", dep)
		}
	}
}
