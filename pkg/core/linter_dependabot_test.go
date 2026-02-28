package core

import (
	"bytes"
	"testing"
)

func TestIsDependabotConfigFile(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "dependabot.yml in .github",
			filePath: ".github/dependabot.yml",
			want:     true,
		},
		{
			name:     "dependabot.yaml in .github",
			filePath: ".github/dependabot.yaml",
			want:     true,
		},
		{
			name:     "absolute path to dependabot.yml",
			filePath: "/home/user/project/.github/dependabot.yml",
			want:     true,
		},
		{
			name:     "absolute path to dependabot.yaml",
			filePath: "/home/user/project/.github/dependabot.yaml",
			want:     true,
		},
		{
			name:     "workflow file",
			filePath: ".github/workflows/ci.yml",
			want:     false,
		},
		{
			name:     "dependabot in wrong location",
			filePath: "dependabot.yml",
			want:     false,
		},
		{
			name:     "similar name but not dependabot",
			filePath: ".github/my-dependabot.yml",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDependabotConfigFile(tt.filePath); got != tt.want {
				t.Errorf("isDependabotConfigFile(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestValidateDependabotFile(t *testing.T) {
	// Create a valid dependabot configuration
	dependabotContent := []byte(`version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
`)

	opts := &LinterOptions{}
	linter, err := NewLinter(new(bytes.Buffer), opts)
	if err != nil {
		t.Fatalf("Failed to create linter: %v", err)
	}

	// Test that dependabot.yml does not produce workflow validation errors
	result, err := linter.Lint(".github/dependabot.yml", dependabotContent, nil)
	if err != nil {
		t.Fatalf("Lint failed: %v", err)
	}

	// Should not have any errors since we skip workflow validation for dependabot files
	if len(result.Errors) > 0 {
		t.Errorf("Expected no errors for dependabot file, got %d errors:", len(result.Errors))
		for _, e := range result.Errors {
			t.Logf("  - %s: %s", e.Type, e.Description)
		}
	}

	// ParsedWorkflow should be nil for dependabot files
	if result.ParsedWorkflow != nil {
		t.Errorf("Expected ParsedWorkflow to be nil for dependabot file, got %v", result.ParsedWorkflow)
	}
}

func TestValidateWorkflowFile(t *testing.T) {
	// Create a minimal valid workflow
	workflowContent := []byte(`name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)

	opts := &LinterOptions{}
	linter, err := NewLinter(new(bytes.Buffer), opts)
	if err != nil {
		t.Fatalf("Failed to create linter: %v", err)
	}

	// Test that workflow files are still validated normally
	result, err := linter.Lint(".github/workflows/test.yml", workflowContent, nil)
	if err != nil {
		t.Fatalf("Lint failed: %v", err)
	}

	// ParsedWorkflow should NOT be nil for workflow files
	if result.ParsedWorkflow == nil {
		t.Errorf("Expected ParsedWorkflow to be non-nil for workflow file")
	}
}
