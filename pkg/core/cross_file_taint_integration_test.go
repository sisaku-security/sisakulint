package core

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCrossFileLinter runs the Linter on the given fixtures from script/actions/.
// The project is rooted at the repo root so caller `uses:` paths
// (e.g. `./script/actions/cross-file-taint-callee-run.yaml`) match the
// callee's pathToWorkflowSpecification output, enabling chain resolution.
// This mirrors how GitHub Actions resolves `./...` — repo-root-relative.
// Returns the aggregated results.
func runCrossFileLinter(t *testing.T, files ...string) []*ValidateResult {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	proj, err := NewProject(repoRoot)
	if err != nil {
		t.Fatalf("NewProject(%q): %v", repoRoot, err)
	}
	if proj == nil {
		t.Fatalf("NewProject returned nil; expected project at %s", repoRoot)
	}
	opts := &LinterOptions{
		CurrentWorkingDirectoryPath: repoRoot,
	}
	l, err := NewLinter(io.Discard, opts)
	if err != nil {
		t.Fatalf("NewLinter: %v", err)
	}
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = filepath.Join(repoRoot, "script/actions", f)
	}
	results, err := l.LintFiles(paths, proj)
	if err != nil {
		t.Fatalf("LintFiles: %v", err)
	}
	return results
}

func collectErrors(results []*ValidateResult, ruleType, severityNeedle string) []*LintingError {
	var out []*LintingError
	for _, r := range results {
		for _, e := range r.Errors {
			if e.Type != ruleType {
				continue
			}
			if severityNeedle != "" && !strings.Contains(e.Description, severityNeedle) {
				continue
			}
			out = append(out, e)
		}
	}
	return out
}

func collectChainErrors(results []*ValidateResult, severity string) []*LintingError {
	var out []*LintingError
	for _, r := range results {
		for _, e := range r.Errors {
			if e.Type != "reusable-workflow-taint" {
				continue
			}
			expectedPrefix := "reusable-workflow-taint-chain"
			if severity != "" {
				expectedPrefix += " (" + severity + ")"
			}
			if !strings.HasPrefix(e.Description, expectedPrefix) {
				continue
			}
			out = append(out, e)
		}
	}
	return out
}

func dumpErrors(t *testing.T, results []*ValidateResult) {
	t.Helper()
	for _, r := range results {
		for _, e := range r.Errors {
			t.Logf("  %s [%s] %s", r.FilePath, e.Type, e.Description)
		}
	}
}

func TestCrossFileTaint_Critical_RunSink(t *testing.T) {
	t.Parallel()
	res := runCrossFileLinter(t,
		"cross-file-taint-caller-critical.yaml",
		"cross-file-taint-callee-run.yaml",
	)
	got := collectChainErrors(res, "critical")
	if len(got) != 1 {
		t.Errorf("expected 1 critical chain warning, got %d", len(got))
		dumpErrors(t, res)
	}
}

func TestCrossFileTaint_Medium_ScriptSink(t *testing.T) {
	t.Parallel()
	res := runCrossFileLinter(t,
		"cross-file-taint-caller-medium.yaml",
		"cross-file-taint-callee-script.yaml",
	)
	got := collectChainErrors(res, "medium")
	if len(got) != 1 {
		t.Errorf("expected 1 medium chain warning, got %d", len(got))
		dumpErrors(t, res)
	}
}

func TestCrossFileTaint_Critical_EnvSink(t *testing.T) {
	t.Parallel()
	res := runCrossFileLinter(t,
		"cross-file-taint-caller-env.yaml",
		"cross-file-taint-callee-env.yaml",
	)
	got := collectChainErrors(res, "critical")
	if len(got) != 1 {
		t.Errorf("expected 1 critical env-sink chain warning, got %d", len(got))
		dumpErrors(t, res)
	}
}

func TestCrossFileTaint_NoWarning_WhenCallerSafe(t *testing.T) {
	t.Parallel()
	res := runCrossFileLinter(t,
		"cross-file-taint-caller-safe.yaml",
		"cross-file-taint-callee-run.yaml",
	)
	if got := collectChainErrors(res, ""); len(got) != 0 {
		t.Errorf("expected 0 chain warnings (caller safe), got %d", len(got))
		dumpErrors(t, res)
	}
}

func TestCrossFileTaint_CalleeSolo_WhenNoCaller(t *testing.T) {
	t.Parallel()
	res := runCrossFileLinter(t,
		"cross-file-taint-callee-solo.yaml",
	)
	got := collectErrors(res, "reusable-workflow-taint", "medium")
	if len(got) != 1 {
		t.Errorf("expected 1 callee-solo medium warning, got %d", len(got))
		dumpErrors(t, res)
	}
}

func TestCrossFileTaint_MultiCaller_OnlyUntrustedReports(t *testing.T) {
	t.Parallel()
	// caller A (untrusted) + caller B (safe) + same callee.
	res := runCrossFileLinter(t,
		"cross-file-taint-caller-critical.yaml",
		"cross-file-taint-caller-safe.yaml",
		"cross-file-taint-callee-run.yaml",
	)
	if got := collectChainErrors(res, "critical"); len(got) != 1 {
		t.Errorf("expected exactly 1 critical (only caller A), got %d", len(got))
		dumpErrors(t, res)
	}
}

func TestCrossFileTaint_IgnoreFiltersResolvedChains(t *testing.T) {
	t.Parallel()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	proj, err := NewProject(repoRoot)
	if err != nil {
		t.Fatalf("NewProject(%q): %v", repoRoot, err)
	}
	l, err := NewLinter(io.Discard, &LinterOptions{
		CurrentWorkingDirectoryPath: repoRoot,
		ErrorIgnorePatterns:         []string{"reusable-workflow-taint"},
	})
	if err != nil {
		t.Fatalf("NewLinter: %v", err)
	}
	results, err := l.LintFiles([]string{
		filepath.Join(repoRoot, "script/actions/cross-file-taint-caller-critical.yaml"),
		filepath.Join(repoRoot, "script/actions/cross-file-taint-callee-run.yaml"),
	}, proj)
	if err != nil {
		t.Fatalf("LintFiles: %v", err)
	}
	assertNoReusableWorkflowTaintResults(t, results)
}

func TestCrossFileTaint_LintFileIgnoreFiltersResolvedChains(t *testing.T) {
	t.Parallel()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	proj, err := NewProject(repoRoot)
	if err != nil {
		t.Fatalf("NewProject(%q): %v", repoRoot, err)
	}
	l, err := NewLinter(io.Discard, &LinterOptions{
		CurrentWorkingDirectoryPath: repoRoot,
		ErrorIgnorePatterns:         []string{"reusable-workflow-taint"},
	})
	if err != nil {
		t.Fatalf("NewLinter: %v", err)
	}
	result, err := l.LintFile(filepath.Join(repoRoot, "script/actions/cross-file-taint-callee-solo.yaml"), proj)
	if err != nil {
		t.Fatalf("LintFile: %v", err)
	}
	assertNoReusableWorkflowTaintResults(t, []*ValidateResult{result})
}

func TestCrossFileTaint_LintIgnoreFiltersResolvedChains(t *testing.T) {
	t.Parallel()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	proj, err := NewProject(repoRoot)
	if err != nil {
		t.Fatalf("NewProject(%q): %v", repoRoot, err)
	}
	l, err := NewLinter(io.Discard, &LinterOptions{
		CurrentWorkingDirectoryPath: repoRoot,
		ErrorIgnorePatterns:         []string{"reusable-workflow-taint"},
	})
	if err != nil {
		t.Fatalf("NewLinter: %v", err)
	}
	path := filepath.Join(repoRoot, "script/actions/cross-file-taint-callee-solo.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	result, err := l.Lint(path, content, proj)
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	assertNoReusableWorkflowTaintResults(t, []*ValidateResult{result})
}

func assertNoReusableWorkflowTaintResults(t *testing.T, results []*ValidateResult) {
	t.Helper()
	for _, r := range results {
		for _, e := range r.Errors {
			if e.Type != "reusable-workflow-taint" {
				continue
			}
			dumpErrors(t, results)
			t.Fatalf("ignored reusable-workflow-taint error should be filtered: %s", e.Description)
		}
		for _, fixer := range r.AutoFixers {
			if fixer.RuleName() != "reusable-workflow-taint" {
				continue
			}
			t.Fatalf("ignored reusable-workflow-taint autofixer should be filtered")
		}
	}
}
