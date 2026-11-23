package analysis

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDependencies: of this module, package analysis imports only
// actions/workflow and what it imports, so that the analyses, the IR and
// the rules can all import it.
func TestDependencies(t *testing.T) {
	deps := func(pkg string) []string {
		out, err := exec.Command("go", "list", "-deps", pkg).Output()
		if err != nil {
			t.Skipf("go list: %v", err)
		}
		return strings.Fields(string(out))
	}
	allowed := map[string]bool{"github.com/sisaku-security/sisakulint/actions/analysis": true}
	for _, d := range deps("github.com/sisaku-security/sisakulint/actions/workflow") {
		allowed[d] = true
	}
	for _, d := range deps(".") {
		if strings.HasPrefix(d, "github.com/sisaku-security/sisakulint/") && !allowed[d] {
			t.Errorf("actions/analysis depends on %s", d)
		}
	}
}
