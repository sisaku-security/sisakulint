package taint

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: the shared analysis reads the model, expressions and
// the shell's quotes, and the types of facts (the names of the inputs, as
// actions/calls has them); not the engine nor the rules. It asks no fact.
func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch dep {
		case "github.com/sisaku-security/sisakulint/actions/lint", "github.com/sisaku-security/sisakulint/actions/rules":
			t.Errorf("actions/taint depends on %s", dep)
		}
	}
}
