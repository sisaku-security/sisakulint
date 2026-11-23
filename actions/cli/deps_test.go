package cli

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: nothing below the CLI imports it.
func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../lint", "../facts/...", "../rules").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "github.com/sisaku-security/sisakulint/actions/cli" {
			t.Error("actions/lint, actions/facts or actions/rules depends on actions/cli")
		}
	}
}
