package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// writeEcosystemFixture sets up a temp project with .github/workflows, an optional
// dependabot config, and optional root-level lockfiles. It returns the workflow file path.
func writeEcosystemFixture(t *testing.T, dependabotYAML string, lockfiles ...string) string {
	t.Helper()
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if dependabotYAML != "" {
		p := filepath.Join(tmp, ".github", "dependabot.yaml")
		if err := os.WriteFile(p, []byte(dependabotYAML), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	for _, lf := range lockfiles {
		p := filepath.Join(tmp, lf)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	return filepath.Join(wfDir, "test.yaml")
}

// runEcosystemRule drives the rule over a workflow that contains the given steps.
func runEcosystemRule(t *testing.T, rule *DependabotEcosystemRule, steps ...*ast.Step) []*LintingError {
	t.Helper()
	wf := &ast.Workflow{}
	if err := rule.VisitWorkflowPre(wf); err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if err := rule.VisitStep(s); err != nil {
			t.Fatal(err)
		}
	}
	if err := rule.VisitWorkflowPost(wf); err != nil {
		t.Fatal(err)
	}
	return rule.Errors()
}

func TestDependabotEcosystem_NpmLockfileMissingEcosystem(t *testing.T) {
	t.Parallel()

	dependabot := `version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
`
	wfPath := writeEcosystemFixture(t, dependabot, "package-lock.json")
	rule := NewDependabotEcosystemRule(wfPath, false)

	errs := runEcosystemRule(t, rule)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
	if errs[0].Type != "dependabot-ecosystem" {
		t.Errorf("expected type dependabot-ecosystem, got %s", errs[0].Type)
	}
}

func TestDependabotEcosystem_GomodLockfileSatisfied(t *testing.T) {
	t.Parallel()

	dependabot := `version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
`
	wfPath := writeEcosystemFixture(t, dependabot, "go.sum")
	rule := NewDependabotEcosystemRule(wfPath, false)

	errs := runEcosystemRule(t, rule)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors (gomod configured), got %d: %v", len(errs), errs)
	}
}

func TestDependabotEcosystem_RemoteScanSkipped(t *testing.T) {
	t.Parallel()

	dependabot := `version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
`
	wfPath := writeEcosystemFixture(t, dependabot, "package-lock.json")
	rule := NewDependabotEcosystemRule(wfPath, true) // isRemote = true

	errs := runEcosystemRule(t, rule)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors in remote scan mode, got %d: %v", len(errs), errs)
	}
}
