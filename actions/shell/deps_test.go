package shell

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasPrefix(dep, "github.com/sisaku-security/sisakulint/") && dep != "github.com/sisaku-security/sisakulint/actions/shell" {
			t.Errorf("actions/shell depends on %s", dep)
		}
	}
}
