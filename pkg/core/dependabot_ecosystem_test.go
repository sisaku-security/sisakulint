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

func TestDependabotEcosystem_SetupPythonMissingPip(t *testing.T) {
	t.Parallel()

	dependabot := `version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
`
	wfPath := writeEcosystemFixture(t, dependabot)
	rule := NewDependabotEcosystemRule(wfPath, false)

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-python@v5", Pos: &ast.Position{Line: 7, Col: 9}},
		},
	}
	errs := runEcosystemRule(t, rule, step)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
	if errs[0].LineNumber != 7 {
		t.Errorf("expected warning anchored at step line 7, got line %d", errs[0].LineNumber)
	}
}

func TestDependabotEcosystem_LockfileAndSetupSameEcosystemDeduped(t *testing.T) {
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

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-node@v4", Pos: &ast.Position{Line: 7, Col: 9}},
		},
	}
	errs := runEcosystemRule(t, rule, step)
	if len(errs) != 1 {
		t.Fatalf("expected 1 deduped npm error, got %d: %v", len(errs), errs)
	}
	if errs[0].LineNumber != 7 {
		t.Errorf("expected the deduped warning to keep the setup-action anchor (line 7), got line %d", errs[0].LineNumber)
	}
}

func TestDependabotEcosystem_SetupNodeSatisfied(t *testing.T) {
	t.Parallel()

	dependabot := `version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
`
	wfPath := writeEcosystemFixture(t, dependabot)
	rule := NewDependabotEcosystemRule(wfPath, false)

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-node@v4", Pos: &ast.Position{Line: 7, Col: 9}},
		},
	}
	errs := runEcosystemRule(t, rule, step)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors (npm configured), got %d: %v", len(errs), errs)
	}
}

func TestDependabotEcosystem_SetupJavaNeitherMavenNorGradle(t *testing.T) {
	t.Parallel()

	dependabot := `version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
`
	wfPath := writeEcosystemFixture(t, dependabot)
	rule := NewDependabotEcosystemRule(wfPath, false)

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-java@v4", Pos: &ast.Position{Line: 7, Col: 9}},
		},
	}
	errs := runEcosystemRule(t, rule, step)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error (neither maven nor gradle), got %d: %v", len(errs), errs)
	}
}

func TestDependabotEcosystem_SetupJavaMavenSatisfies(t *testing.T) {
	t.Parallel()

	dependabot := `version: 2
updates:
  - package-ecosystem: "maven"
    directory: "/"
    schedule:
      interval: "weekly"
`
	wfPath := writeEcosystemFixture(t, dependabot)
	rule := NewDependabotEcosystemRule(wfPath, false)

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-java@v4", Pos: &ast.Position{Line: 7, Col: 9}},
		},
	}
	errs := runEcosystemRule(t, rule, step)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors (maven satisfies setup-java), got %d: %v", len(errs), errs)
	}
}

func TestDependabotEcosystem_SetupJavaGradleSatisfies(t *testing.T) {
	t.Parallel()

	dependabot := `version: 2
updates:
  - package-ecosystem: "gradle"
    directory: "/"
    schedule:
      interval: "weekly"
`
	wfPath := writeEcosystemFixture(t, dependabot)
	rule := NewDependabotEcosystemRule(wfPath, false)

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-java@v4", Pos: &ast.Position{Line: 7, Col: 9}},
		},
	}
	errs := runEcosystemRule(t, rule, step)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors (gradle satisfies setup-java), got %d: %v", len(errs), errs)
	}
}

func TestDependabotEcosystem_SetupJavaSbtSatisfies(t *testing.T) {
	t.Parallel()

	dependabot := `version: 2
updates:
  - package-ecosystem: "sbt"
    directory: "/"
    schedule:
      interval: "weekly"
`
	wfPath := writeEcosystemFixture(t, dependabot)
	rule := NewDependabotEcosystemRule(wfPath, false)

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-java@v4", Pos: &ast.Position{Line: 7, Col: 9}},
		},
	}
	errs := runEcosystemRule(t, rule, step)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors (sbt satisfies setup-java), got %d: %v", len(errs), errs)
	}
}

func TestDependabotEcosystem_NoConfigWarnsForLockfile(t *testing.T) {
	t.Parallel()

	// No dependabot config at all; a root lockfile is present.
	wfPath := writeEcosystemFixture(t, "", "package-lock.json")
	rule := NewDependabotEcosystemRule(wfPath, false)

	errs := runEcosystemRule(t, rule)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error (npm, no dependabot config), got %d: %v", len(errs), errs)
	}
}

func TestDependabotEcosystem_RenovateBroadPresetSkips(t *testing.T) {
	t.Parallel()

	wfPath := writeEcosystemFixture(t, "", "package-lock.json")
	// Place a Renovate config with a broad preset at the project root's .github dir.
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(wfPath))) // <tmp> from <tmp>/.github/workflows/test.yaml
	renovate := `{ "extends": ["config:recommended"] }`
	if err := os.WriteFile(filepath.Join(projectRoot, ".github", "renovate.json"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	rule := NewDependabotEcosystemRule(wfPath, false)

	errs := runEcosystemRule(t, rule)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors (renovate manages deps), got %d: %v", len(errs), errs)
	}
}

func TestDependabotEcosystem_RenovateScopedManagerDoesNotSuppressOthers(t *testing.T) {
	t.Parallel()

	// Cargo.lock present, no dependabot config, Renovate scoped to npm only.
	// The missing cargo coverage must still be reported.
	wfPath := writeEcosystemFixture(t, "", "Cargo.lock")
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(wfPath)))
	renovate := `{ "packageRules": [{ "matchManagers": ["npm"] }] }`
	if err := os.WriteFile(filepath.Join(projectRoot, ".github", "renovate.json"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	rule := NewDependabotEcosystemRule(wfPath, false)

	errs := runEcosystemRule(t, rule)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error (cargo not managed by npm-scoped renovate), got %d: %v", len(errs), errs)
	}
}

func TestDependabotEcosystem_RenovateEnabledManagersDoesNotSkipUnlistedEcosystems(t *testing.T) {
	t.Parallel()

	// Repo with a root package-lock.json but no dependabot config. Renovate extends a
	// broad preset and sets enabledManagers:["github-actions"], so Renovate will NOT
	// update npm — the rule must still surface the missing npm coverage.
	wfPath := writeEcosystemFixture(t, "", "package-lock.json")
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(wfPath)))
	renovate := `{ "extends": ["config:recommended"], "enabledManagers": ["github-actions"] }`
	if err := os.WriteFile(filepath.Join(projectRoot, ".github", "renovate.json"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	rule := NewDependabotEcosystemRule(wfPath, false)

	errs := runEcosystemRule(t, rule)
	if len(errs) != 1 {
		t.Fatalf("expected 1 npm warning (enabledManagers narrowed renovate to github-actions only), got %d: %v", len(errs), errs)
	}
}

func TestDependabotEcosystem_RootLockfileWarningDedupedAcrossWorkflows(t *testing.T) {
	// Repository with one root lockfile and several workflow files must produce a
	// single project-level warning, not one warning per workflow file. This test
	// shares dependabotEcosystemReported with parallel tests, so it cannot use
	// t.Parallel; it resets the dedupe state at start to keep ordering hermetic.
	resetDependabotEcosystemRunState()
	t.Cleanup(resetDependabotEcosystemRunState)

	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "package-lock.json"), []byte("x"), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	wfPaths := []string{
		filepath.Join(wfDir, "ci.yaml"),
		filepath.Join(wfDir, "release.yaml"),
		filepath.Join(wfDir, "nightly.yaml"),
	}

	totalErrs := 0
	for _, wfPath := range wfPaths {
		rule := NewDependabotEcosystemRule(wfPath, false)
		errs := runEcosystemRule(t, rule)
		totalErrs += len(errs)
	}

	if totalErrs != 1 {
		t.Fatalf("expected the root-lockfile npm warning to be reported once across %d workflows, got %d", len(wfPaths), totalErrs)
	}
}

func TestDependabotEcosystem_SetupActionWarningNotDedupedAcrossWorkflows(t *testing.T) {
	// Setup-action requirements are anchored to a step position and remain per-workflow
	// even when the repo-level dedupe map is shared. This guards against accidentally
	// suppressing them along with project-level findings.
	resetDependabotEcosystemRunState()
	t.Cleanup(resetDependabotEcosystemRunState)

	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	wfPaths := []string{
		filepath.Join(wfDir, "ci.yaml"),
		filepath.Join(wfDir, "release.yaml"),
	}

	totalErrs := 0
	for _, wfPath := range wfPaths {
		rule := NewDependabotEcosystemRule(wfPath, false)
		step := &ast.Step{
			Exec: &ast.ExecAction{
				Uses: &ast.String{Value: "actions/setup-node@v4", Pos: &ast.Position{Line: 7, Col: 9}},
			},
		}
		errs := runEcosystemRule(t, rule, step)
		totalErrs += len(errs)
	}

	if totalErrs != len(wfPaths) {
		t.Fatalf("expected %d setup-action warnings (one per workflow), got %d", len(wfPaths), totalErrs)
	}
}

func TestDependabotEcosystem_RenovateScopedManagerSuppressesMatch(t *testing.T) {
	t.Parallel()

	// Cargo.lock present, no dependabot config, Renovate scoped to cargo.
	// The cargo requirement is covered by Renovate, so no warning is expected.
	wfPath := writeEcosystemFixture(t, "", "Cargo.lock")
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(wfPath)))
	renovate := `{ "packageRules": [{ "matchManagers": ["cargo"] }] }`
	if err := os.WriteFile(filepath.Join(projectRoot, ".github", "renovate.json"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	rule := NewDependabotEcosystemRule(wfPath, false)

	errs := runEcosystemRule(t, rule)
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors (cargo managed by renovate), got %d: %v", len(errs), errs)
	}
}
