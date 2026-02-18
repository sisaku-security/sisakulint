package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestDependabotGitHubActionsRule_NoDependabotFile(t *testing.T) {
	t.Parallel()

	// Create a temporary directory structure
	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github", "workflows")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a workflow file path (file doesn't need to exist for the rule)
	workflowPath := filepath.Join(githubDir, "test.yaml")

	rule := NewDependabotGitHubActionsRule(workflowPath)

	// Simulate visiting a workflow with unpinned action
	workflow := &ast.Workflow{}

	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatal(err)
	}

	// Simulate step with unpinned action
	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
		},
	}

	if err := rule.VisitStep(step); err != nil {
		t.Fatal(err)
	}

	if err := rule.VisitWorkflowPost(workflow); err != nil {
		t.Fatal(err)
	}

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(errors))
	}

	if len(errors) > 0 && errors[0].Type != "dependabot-github-actions" {
		t.Errorf("expected rule type 'dependabot-github-actions', got '%s'", errors[0].Type)
	}

	// Check that auto-fixer is added
	fixers := rule.AutoFixers()
	if len(fixers) != 1 {
		t.Errorf("expected 1 auto-fixer, got %d", len(fixers))
	}
}

func TestDependabotGitHubActionsRule_DependabotWithoutGitHubActions(t *testing.T) {
	t.Parallel()

	// Create a temporary directory structure
	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github")
	workflowsDir := filepath.Join(githubDir, "workflows")
	if err := os.MkdirAll(workflowsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create dependabot.yaml without github-actions
	dependabotContent := `version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
`
	dependabotPath := filepath.Join(githubDir, "dependabot.yaml")
	if err := os.WriteFile(dependabotPath, []byte(dependabotContent), 0o644); err != nil {
		t.Fatal(err)
	}

	workflowPath := filepath.Join(workflowsDir, "test.yaml")

	rule := NewDependabotGitHubActionsRule(workflowPath)

	workflow := &ast.Workflow{}

	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatal(err)
	}

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
		},
	}

	if err := rule.VisitStep(step); err != nil {
		t.Fatal(err)
	}

	if err := rule.VisitWorkflowPost(workflow); err != nil {
		t.Fatal(err)
	}

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(errors))
	}

	if len(errors) > 0 {
		expected := "dependabot.yaml exists but github-actions ecosystem is not configured"
		if !strings.Contains(errors[0].Description, expected) {
			t.Errorf("error message should contain '%s', got '%s'", expected, errors[0].Description)
		}
	}
}

func TestDependabotGitHubActionsRule_DependabotWithGitHubActions(t *testing.T) {
	t.Parallel()

	// Create a temporary directory structure
	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github")
	workflowsDir := filepath.Join(githubDir, "workflows")
	if err := os.MkdirAll(workflowsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create dependabot.yaml with github-actions
	dependabotContent := `version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
`
	dependabotPath := filepath.Join(githubDir, "dependabot.yaml")
	if err := os.WriteFile(dependabotPath, []byte(dependabotContent), 0o644); err != nil {
		t.Fatal(err)
	}

	workflowPath := filepath.Join(workflowsDir, "test.yaml")

	rule := NewDependabotGitHubActionsRule(workflowPath)

	workflow := &ast.Workflow{}

	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatal(err)
	}

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
		},
	}

	if err := rule.VisitStep(step); err != nil {
		t.Fatal(err)
	}

	if err := rule.VisitWorkflowPost(workflow); err != nil {
		t.Fatal(err)
	}

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("expected 0 errors when github-actions is configured, got %d", len(errors))
	}
}

func TestDependabotGitHubActionsRule_PinnedActions(t *testing.T) {
	t.Parallel()

	// Create a temporary directory structure
	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github", "workflows")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}

	workflowPath := filepath.Join(githubDir, "test.yaml")

	rule := NewDependabotGitHubActionsRule(workflowPath)

	workflow := &ast.Workflow{}

	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatal(err)
	}

	// Step with SHA-pinned action
	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"},
		},
	}

	if err := rule.VisitStep(step); err != nil {
		t.Fatal(err)
	}

	if err := rule.VisitWorkflowPost(workflow); err != nil {
		t.Fatal(err)
	}

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("expected 0 errors when action is SHA-pinned, got %d", len(errors))
	}
}

func TestDependabotGitHubActionsRule_LocalAction(t *testing.T) {
	t.Parallel()

	// Create a temporary directory structure
	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github", "workflows")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}

	workflowPath := filepath.Join(githubDir, "test.yaml")

	rule := NewDependabotGitHubActionsRule(workflowPath)

	workflow := &ast.Workflow{}

	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatal(err)
	}

	// Local action should be skipped
	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "./local-action"},
		},
	}

	if err := rule.VisitStep(step); err != nil {
		t.Fatal(err)
	}

	if err := rule.VisitWorkflowPost(workflow); err != nil {
		t.Fatal(err)
	}

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("expected 0 errors for local action, got %d", len(errors))
	}
}

func TestDependabotGitHubActionsRule_DockerAction(t *testing.T) {
	t.Parallel()

	// Create a temporary directory structure
	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github", "workflows")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}

	workflowPath := filepath.Join(githubDir, "test.yaml")

	rule := NewDependabotGitHubActionsRule(workflowPath)

	workflow := &ast.Workflow{}

	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatal(err)
	}

	// Docker action should be skipped
	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "docker://alpine:3.8"},
		},
	}

	if err := rule.VisitStep(step); err != nil {
		t.Fatal(err)
	}

	if err := rule.VisitWorkflowPost(workflow); err != nil {
		t.Fatal(err)
	}

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("expected 0 errors for docker action, got %d", len(errors))
	}
}

func TestCreateDependabotFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := createDependabotFile(tmpDir); err != nil {
		t.Fatal(err)
	}

	// Verify the file was created
	createdPath := filepath.Join(githubDir, "dependabot.yaml")
	data, err := os.ReadFile(createdPath)
	if err != nil {
		t.Fatalf("expected dependabot.yaml to be created: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "github-actions") {
		t.Error("created file should contain github-actions ecosystem")
	}
	if !strings.Contains(content, "weekly") {
		t.Error("created file should contain weekly schedule")
	}
}

func TestUpdateDependabotFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create existing dependabot.yaml without github-actions
	existingContent := `version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
`
	dependabotPath := filepath.Join(githubDir, "dependabot.yaml")
	if err := os.WriteFile(dependabotPath, []byte(existingContent), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := updateDependabotFile(dependabotPath); err != nil {
		t.Fatal(err)
	}

	// Verify the file was updated
	data, err := os.ReadFile(dependabotPath)
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Should still contain npm
	if !strings.Contains(content, "npm") {
		t.Error("updated file should still contain npm ecosystem")
	}
	// Should now contain github-actions
	if !strings.Contains(content, "github-actions") {
		t.Error("updated file should contain github-actions ecosystem")
	}
}

func TestDependabotGitHubActionsRule_DependabotYml(t *testing.T) {
	t.Parallel()

	// Create a temporary directory structure
	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github")
	workflowsDir := filepath.Join(githubDir, "workflows")
	if err := os.MkdirAll(workflowsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create dependabot.yml (not .yaml) with github-actions
	dependabotContent := `version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
`
	dependabotPath := filepath.Join(githubDir, "dependabot.yml")
	if err := os.WriteFile(dependabotPath, []byte(dependabotContent), 0o644); err != nil {
		t.Fatal(err)
	}

	workflowPath := filepath.Join(workflowsDir, "test.yaml")

	rule := NewDependabotGitHubActionsRule(workflowPath)

	workflow := &ast.Workflow{}

	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatal(err)
	}

	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
		},
	}

	if err := rule.VisitStep(step); err != nil {
		t.Fatal(err)
	}

	if err := rule.VisitWorkflowPost(workflow); err != nil {
		t.Fatal(err)
	}

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("expected 0 errors when github-actions is configured in .yml file, got %d", len(errors))
	}
}

func TestDependabotGitHubActionsRule_RemoteScanMode(t *testing.T) {
	t.Parallel()

	// Test remote scan mode with virtual path (owner/repo/.github/workflows/test.yml)
	workflowPath := "SynkraAI/aios-core/.github/workflows/ci.yml"

	rule := NewDependabotGitHubActionsRule(workflowPath)

	workflow := &ast.Workflow{}

	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatal(err)
	}

	// Simulate step with unpinned action
	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
		},
	}

	if err := rule.VisitStep(step); err != nil {
		t.Fatal(err)
	}

	if err := rule.VisitWorkflowPost(workflow); err != nil {
		t.Fatal(err)
	}

	// In remote scan mode, the rule should not report errors
	// because it cannot access the filesystem to check for dependabot.yaml
	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("expected 0 errors in remote scan mode, got %d", len(errors))
		for _, err := range errors {
			t.Logf("  error: %s", err.Description)
		}
	}
}

func TestDependabotGitHubActionsRule_isRemoteScanMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		workflowPath string
		want         bool
	}{
		{
			name:         "remote path",
			workflowPath: "owner/repo/.github/workflows/ci.yml",
			want:         true,
		},
		{
			name:         "remote path with org",
			workflowPath: "kubernetes/kubernetes/.github/workflows/test.yml",
			want:         true,
		},
		{
			name:         "absolute unix path",
			workflowPath: "/home/user/project/.github/workflows/ci.yml",
			want:         false,
		},
		{
			name:         "relative path with dot",
			workflowPath: "./.github/workflows/ci.yml",
			want:         false,
		},
		{
			name:         "relative path",
			workflowPath: "../.github/workflows/ci.yml",
			want:         false,
		},
		{
			name:         "windows path",
			workflowPath: "C:\\Users\\user\\.github\\workflows\\ci.yml",
			want:         false,
		},
		{
			name:         "short path without owner/repo",
			workflowPath: ".github/workflows/ci.yml",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDependabotGitHubActionsRule(tt.workflowPath)
			got := rule.isRemoteScanMode()
			if got != tt.want {
				t.Errorf("isRemoteScanMode() = %v, want %v (path: %s)", got, tt.want, tt.workflowPath)
			}
		})
	}
}
