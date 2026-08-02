package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLintFilesReportsTargetsButAnalyzesAllFiles(t *testing.T) {
	root := makeTestProject(t)
	reported := filepath.Join(root, ".github", "workflows", "reported.yml")
	contextFile := filepath.Join(root, ".github", "workflows", "context.yml")
	writeTestFile(t, reported, "jobs: [\n")
	writeTestFile(t, contextFile, "on: [\n")

	var output bytes.Buffer
	linter, err := NewLinter(&output, &LinterOptions{
		CurrentWorkingDirectoryPath: root,
		CustomErrorMessageFormat:    "{{json .}}",
		ReportFilePaths:             []string{".github/workflows/reported.yml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	results, err := linter.LintFiles([]string{reported, contextFile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("LintFiles returned %d results, want 2 analysis results", len(results))
	}
	if !strings.Contains(output.String(), ".github/workflows/reported.yml") {
		t.Fatalf("reported file missing from output: %s", output.String())
	}
	if strings.Contains(output.String(), ".github/workflows/context.yml") {
		t.Fatalf("context-only file leaked into output: %s", output.String())
	}
}

func TestLintFileUsesResolvedProjectRootOutsideProcessWorkingDirectory(t *testing.T) {
	root := makeTestProject(t)
	workflow := filepath.Join(root, ".github", "workflows", "ci.yml")
	writeTestFile(t, workflow, `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)

	linter, err := NewLinter(&bytes.Buffer{}, &LinterOptions{
		CurrentWorkingDirectoryPath: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := linter.LintFile(workflow, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, lintError := range result.Errors {
		if lintError.Type == "dependabot-github-actions" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("errors = %#v, want missing Dependabot finding", result.Errors)
	}
}

func TestRepositoryFileAutoFixersCanBeDisabled(t *testing.T) {
	root := makeTestProject(t)
	workflow := filepath.Join(root, ".github", "workflows", "ci.yml")
	writeTestFile(t, workflow, `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)

	for _, tt := range []struct {
		name      string
		disabled  bool
		wantFixer bool
	}{
		{name: "local scan keeps project fixer", wantFixer: true},
		{name: "repository response scope disables project fixer", disabled: true, wantFixer: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			linter, err := NewLinter(&bytes.Buffer{}, &LinterOptions{
				CurrentWorkingDirectoryPath:     root,
				DisableRepositoryFileAutoFixers: tt.disabled,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := linter.LintFile(workflow, nil)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, fixer := range result.AutoFixers {
				if fixer.RuleName() == "dependabot-github-actions" {
					found = true
					break
				}
			}
			if found != tt.wantFixer {
				t.Fatalf("dependabot project fixer present = %v, want %v", found, tt.wantFixer)
			}
		})
	}
}

func TestContextWorkflowDoesNotConsumeProjectFindingDedupe(t *testing.T) {
	root := makeTestProject(t)
	contextFile := filepath.Join(root, ".github", "workflows", "a-context.yml")
	targetFile := filepath.Join(root, ".github", "workflows", "z-target.yml")
	workflow := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`
	writeTestFile(t, contextFile, workflow)
	writeTestFile(t, targetFile, workflow)
	writeTestFile(t, filepath.Join(root, "go.sum"), "example.invalid/module v1.0.0 h1:test\n")

	var output bytes.Buffer
	linter, err := NewLinter(&output, &LinterOptions{
		CurrentWorkingDirectoryPath: root,
		CustomErrorMessageFormat:    "{{json .}}",
		ReportFilePaths:             []string{".github/workflows/z-target.yml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linter.LintFiles([]string{contextFile, targetFile}, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "dependabot-ecosystem") {
		t.Fatalf("project finding was lost to context-file dedupe: %s", output.String())
	}
	if strings.Contains(output.String(), ".github/workflows/a-context.yml") {
		t.Fatalf("context-only path leaked into project finding output: %s", output.String())
	}
}

func makeTestProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeTestFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
