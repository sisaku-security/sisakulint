package rules

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: actions/lint and actions/facts do not import the rules.
func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../lint", "../facts/...").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "github.com/gh-intel/sisakulint/actions/rules" {
			t.Error("actions/lint or actions/facts depends on actions/rules")
		}
	}
}
