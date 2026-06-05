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

	rule := NewDependabotGitHubActionsRule(workflowPath, false)

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
	if err := os.WriteFile(dependabotPath, []byte(dependabotContent), 0o644); err != nil { //nolint:gosec // test helper writes fixture files with standard permissions
		t.Fatal(err)
	}

	workflowPath := filepath.Join(workflowsDir, "test.yaml")

	rule := NewDependabotGitHubActionsRule(workflowPath, false)

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
	if err := os.WriteFile(dependabotPath, []byte(dependabotContent), 0o644); err != nil { //nolint:gosec // test helper writes fixture files with standard permissions
		t.Fatal(err)
	}

	workflowPath := filepath.Join(workflowsDir, "test.yaml")

	rule := NewDependabotGitHubActionsRule(workflowPath, false)

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

	rule := NewDependabotGitHubActionsRule(workflowPath, false)

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

	rule := NewDependabotGitHubActionsRule(workflowPath, false)

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

	rule := NewDependabotGitHubActionsRule(workflowPath, false)

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
	if err := os.WriteFile(dependabotPath, []byte(existingContent), 0o644); err != nil { //nolint:gosec // test helper writes fixture files with standard permissions
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
	if err := os.WriteFile(dependabotPath, []byte(dependabotContent), 0o644); err != nil { //nolint:gosec // test helper writes fixture files with standard permissions
		t.Fatal(err)
	}

	workflowPath := filepath.Join(workflowsDir, "test.yaml")

	rule := NewDependabotGitHubActionsRule(workflowPath, false)

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

func TestRenovateManagesGitHubActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "packageRule with matchManagers github-actions",
			content: `{
  "packageRules": [
    {
      "matchManagers": ["github-actions"],
      "groupName": "github-actions",
      "pinDigests": true
    }
  ]
}`,
			expected: true,
		},
		{
			name: "config:recommended preset",
			content: `{
  "extends": ["config:recommended"]
}`,
			expected: true,
		},
		{
			name: "config:base preset",
			content: `{
  "extends": ["config:base"]
}`,
			expected: true,
		},
		{
			name: "config:best-practices preset",
			content: `{
  "extends": ["config:best-practices"]
}`,
			expected: true,
		},
		{
			name: "no github-actions manager",
			content: `{
  "packageRules": [
    {
      "matchManagers": ["npm"],
      "groupName": "npm-packages"
    }
  ]
}`,
			expected: false,
		},
		{
			name:     "empty config",
			content:  `{}`,
			expected: false,
		},
		{
			name:     "invalid json",
			content:  `not-json`,
			expected: false,
		},
		{
			name: "multiple managers including github-actions",
			content: `{
  "packageRules": [
    {
      "matchManagers": ["npm", "github-actions", "pip"],
      "automerge": true
    }
  ]
}`,
			expected: true,
		},
		{
			// enabledManagers narrows Renovate to the listed managers; the broad
			// preset alone must NOT mark github-actions as managed when the manager
			// is globally disabled.
			name: "broad preset but enabledManagers excludes github-actions",
			content: `{
  "extends": ["config:recommended"],
  "enabledManagers": ["npm"]
}`,
			expected: false,
		},
		{
			name: "enabledManagers explicitly includes github-actions",
			content: `{
  "extends": ["config:recommended"],
  "enabledManagers": ["github-actions"]
}`,
			expected: true,
		},
		{
			// A packageRule targeting github-actions does not save a config that
			// globally disables the github-actions manager — Renovate would skip
			// the rule entirely.
			name: "packageRules target github-actions but enabledManagers excludes it",
			content: `{
  "enabledManagers": ["npm"],
  "packageRules": [{ "matchManagers": ["github-actions"] }]
}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := renovateManagesGitHubActions([]byte(tt.content))
			if got != tt.expected {
				t.Errorf("renovateManagesGitHubActions() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDependabotGitHubActionsRule_RenovateWithGitHubActions(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github")
	workflowsDir := filepath.Join(githubDir, "workflows")
	if err := os.MkdirAll(workflowsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create renovate.json with github-actions manager
	renovateContent := `{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "packageRules": [
    {
      "matchManagers": ["github-actions"],
      "groupName": "github-actions",
      "pinDigests": true
    }
  ]
}`
	renovatePath := filepath.Join(githubDir, "renovate.json")
	if err := os.WriteFile(renovatePath, []byte(renovateContent), 0o644); err != nil { //nolint:gosec // test helper writes fixture files with standard permissions
		t.Fatal(err)
	}

	workflowPath := filepath.Join(workflowsDir, "test.yaml")
	rule := NewDependabotGitHubActionsRule(workflowPath, false)

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
		t.Errorf("expected 0 errors when renovate.json with github-actions manager is configured, got %d", len(errors))
		for _, err := range errors {
			t.Logf("  error: %s", err.Description)
		}
	}
}

func TestDependabotGitHubActionsRule_RenovateAtRootLevel(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	workflowsDir := filepath.Join(tmpDir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create renovate.json at project root
	renovateContent := `{
  "packageRules": [
    {
      "matchManagers": ["github-actions"],
      "pinDigests": true
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "renovate.json"), []byte(renovateContent), 0o644); err != nil { //nolint:gosec // test helper writes fixture files with standard permissions
		t.Fatal(err)
	}

	workflowPath := filepath.Join(workflowsDir, "test.yaml")
	rule := NewDependabotGitHubActionsRule(workflowPath, false)

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
		t.Errorf("expected 0 errors when root-level renovate.json with github-actions manager is configured, got %d", len(errors))
	}
}

func TestDependabotGitHubActionsRule_RenovateWithoutGitHubActions(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github")
	workflowsDir := filepath.Join(githubDir, "workflows")
	if err := os.MkdirAll(workflowsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Renovate manages only npm, not github-actions
	renovateContent := `{
  "packageRules": [
    {
      "matchManagers": ["npm"],
      "groupName": "npm-packages"
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(githubDir, "renovate.json"), []byte(renovateContent), 0o644); err != nil { //nolint:gosec // test helper writes fixture files with standard permissions
		t.Fatal(err)
	}

	workflowPath := filepath.Join(workflowsDir, "test.yaml")
	rule := NewDependabotGitHubActionsRule(workflowPath, false)

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
		t.Errorf("expected 1 error when renovate.json does not manage github-actions, got %d", len(errors))
	}
}

func TestDependabotGitHubActionsRule_RemoteScanMode(t *testing.T) {
	t.Parallel()

	// isRemote=true を明示的に渡してリモートスキャンモードをシミュレートする
	workflowPath := "SynkraAI/aios-core/.github/workflows/ci.yml"

	rule := NewDependabotGitHubActionsRule(workflowPath, true)

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

// TestRenovateManagesGitHubActions_JSON5 confirms that a Renovate config written in
// JSON5 (// line comment + trailing comma) is parsed via the JSON5 sugar-strip path
// instead of being silently dropped, which would otherwise produce a false-positive
// dependabot-github-actions warning when Renovate actually manages the ecosystem.
func TestRenovateManagesGitHubActions_JSON5(t *testing.T) {
	t.Parallel()

	content := `{
  // JSON5-style line comment
  "extends": ["config:recommended",],
}
`
	if !renovateManagesGitHubActions([]byte(content)) {
		t.Errorf("expected JSON5 renovate config with config:recommended to manage github-actions")
	}
}

// TestDependabotGitHubActionsRule_RenovateFirstValidConfigWins guards against the
// previous all-candidates-union behavior. With a higher-priority config that does NOT
// manage github-actions and a lower-priority config that does, Renovate would only run
// the first; honoring the second would incorrectly suppress the dependabot-github-actions
// warning.
func TestDependabotGitHubActionsRule_RenovateFirstValidConfigWins(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	githubDir := filepath.Join(tmpDir, ".github")
	if err := os.MkdirAll(filepath.Join(githubDir, "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	// First candidate: scoped to npm only — does NOT manage github-actions.
	npmOnly := `{ "packageRules": [{ "matchManagers": ["npm"] }] }`
	if err := os.WriteFile(filepath.Join(githubDir, "renovate.json"), []byte(npmOnly), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	// Later candidate: extends a broad preset that WOULD manage github-actions. This
	// file must be ignored because Renovate already loaded the first one.
	broad := `{ "extends": ["config:recommended"] }`
	if err := os.WriteFile(filepath.Join(tmpDir, "renovate.json"), []byte(broad), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	workflowPath := filepath.Join(githubDir, "workflows", "ci.yml")
	if err := os.WriteFile(workflowPath, []byte("name: ci\non: push\njobs: {}\n"), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	rule := NewDependabotGitHubActionsRule(workflowPath, false)
	if got := rule.hasRenovateGitHubActionsManager(tmpDir); got {
		t.Errorf("expected first-valid-config-wins: the npm-only first candidate must NOT mark github-actions as managed (got %v)", got)
	}
}
