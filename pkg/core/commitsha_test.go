package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

// TestCommitShaRule tests the CommitShaRule constructor function.
func TestCommitShaRule(t *testing.T) {
	rule := CommitShaRule()

	if rule.RuleName != "commit-sha" {
		t.Errorf("Expected RuleName to be 'commit-sha', got '%s'", rule.RuleName)
	}

	expectedDesc := "Warn if the action ref is not a full length commit SHA and not an official GitHub Action."
	if rule.RuleDesc != expectedDesc {
		t.Errorf("Expected RuleDesc to be '%s', got '%s'", expectedDesc, rule.RuleDesc)
	}
}

// TestIsFullLengthSha tests the isFullLengthSha function.
func TestIsFullLengthSha(t *testing.T) {
	tests := []struct {
		name     string
		ref      string
		expected bool
	}{
		{
			name:     "valid full length SHA",
			ref:      "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
			expected: true,
		},
		{
			name:     "valid full length SHA lowercase",
			ref:      "actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7",
			expected: true,
		},
		{
			name:     "short SHA (7 chars)",
			ref:      "actions/checkout@a81bbbf",
			expected: false,
		},
		{
			name:     "short SHA (8 chars)",
			ref:      "actions/checkout@a81bbbf8",
			expected: false,
		},
		{
			name:     "semantic version",
			ref:      "actions/checkout@v3",
			expected: false,
		},
		{
			name:     "semantic version with full version",
			ref:      "actions/checkout@v3.5.2",
			expected: false,
		},
		{
			name:     "tag reference",
			ref:      "actions/checkout@main",
			expected: false,
		},
		{
			name:     "short tag with number",
			ref:      "actions/checkout@v4",
			expected: false,
		},
		{
			name:     "SHA with uppercase letters (invalid)",
			ref:      "actions/checkout@A81BBBF8298C0FA03EA29CDC473D45769F953675",
			expected: false,
		},
		{
			name:     "SHA with mixed case (invalid)",
			ref:      "actions/checkout@A81bbbf8298c0fa03ea29cdc473d45769f953675",
			expected: false,
		},
		{
			name:     "SHA with 39 chars (too short)",
			ref:      "actions/checkout@81bbbf8298c0fa03ea29cdc473d45769f95367",
			expected: false,
		},
		{
			name:     "SHA with 41 chars (too long)",
			ref:      "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675a",
			expected: false,
		},
		{
			name:     "no @ symbol",
			ref:      "actions/checkout",
			expected: false,
		},
		{
			name:     "empty string",
			ref:      "",
			expected: false,
		},
		{
			name:     "only @ symbol",
			ref:      "@",
			expected: false,
		},
		{
			name:     "SHA with non-hex characters",
			ref:      "actions/checkout@g81bbbf8298c0fa03ea29cdc473d45769f953675",
			expected: false,
		},
		{
			name:     "local path with SHA",
			ref:      "./local/action@a81bbbf8298c0fa03ea29cdc473d45769f953675",
			expected: true,
		},
		{
			name:     "docker reference",
			ref:      "docker://alpine:3.8",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFullLengthSha(tt.ref)
			if result != tt.expected {
				t.Errorf("isFullLengthSha(%q) = %v, want %v", tt.ref, result, tt.expected)
			}
		})
	}
}

// TestCommitSha_VisitStep tests the VisitStep method with various scenarios.
func TestCommitSha_VisitStep(t *testing.T) {
	tests := []struct {
		name       string
		step       *ast.Step
		wantError  bool
		errorCount int
	}{
		{
			name: "valid full length SHA",
			step: &ast.Step{
				ID: &ast.String{Value: "checkout"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantError:  false,
			errorCount: 0,
		},
		{
			name: "semantic version reference",
			step: &ast.Step{
				ID: &ast.String{Value: "checkout"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout@v3",
					},
				},
				Pos: &ast.Position{Line: 15, Col: 5},
			},
			wantError:  true,
			errorCount: 1,
		},
		{
			name: "short SHA reference",
			step: &ast.Step{
				ID: &ast.String{Value: "setup"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/setup-node@1a4442c",
					},
				},
				Pos: &ast.Position{Line: 20, Col: 5},
			},
			wantError:  true,
			errorCount: 1,
		},
		{
			name: "branch reference",
			step: &ast.Step{
				ID: &ast.String{Value: "action"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "user/repo@main",
					},
				},
				Pos: &ast.Position{Line: 25, Col: 5},
			},
			wantError:  true,
			errorCount: 1,
		},
		{
			name: "step with run command (not ExecAction)",
			step: &ast.Step{
				ID: &ast.String{Value: "run-script"},
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "echo 'hello'",
					},
				},
				Pos: &ast.Position{Line: 30, Col: 5},
			},
			wantError:  false,
			errorCount: 0,
		},
		{
			name: "full version tag",
			step: &ast.Step{
				ID: &ast.String{Value: "checkout"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout@v3.5.2",
					},
				},
				Pos: &ast.Position{Line: 35, Col: 5},
			},
			wantError:  true,
			errorCount: 1,
		},
		{
			name: "docker reference",
			step: &ast.Step{
				ID: &ast.String{Value: "docker-action"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "docker://alpine:3.8",
					},
				},
				Pos: &ast.Position{Line: 40, Col: 5},
			},
			wantError:  true,
			errorCount: 1,
		},
		{
			name: "local path action without SHA",
			step: &ast.Step{
				ID: &ast.String{Value: "local-action"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "./local/action",
					},
				},
				Pos: &ast.Position{Line: 45, Col: 5},
			},
			// Local actions are part of the same repository and checked out at the same commit,
			// so they have no supply chain risk and do not need commit SHA pinning.
			wantError:  false,
			errorCount: 0,
		},
		{
			name: "local path action with version tag",
			step: &ast.Step{
				ID: &ast.String{Value: "local-action-tagged"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "./local/action@v1",
					},
				},
				Pos: &ast.Position{Line: 50, Col: 5},
			},
			// Local actions (starting with ./) should not be flagged regardless of ref format.
			wantError:  false,
			errorCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CommitShaRule()
			err := rule.VisitStep(tt.step)

			if err != nil {
				t.Errorf("VisitStep() returned unexpected error: %v", err)
			}

			// Check if errors were recorded
			errorCount := len(rule.Errors())
			if tt.wantError && errorCount == 0 {
				t.Errorf("Expected errors to be recorded, but got none")
			}
			if !tt.wantError && errorCount > 0 {
				t.Errorf("Expected no errors, but got %d error(s)", errorCount)
			}
			if errorCount != tt.errorCount {
				t.Errorf("Expected %d error(s), but got %d", tt.errorCount, errorCount)
			}
		})
	}
}

// TestCommitSha_VisitStep_AutoFixer tests that auto-fixer is added when needed.
func TestCommitSha_VisitStep_AutoFixer(t *testing.T) {
	tests := []struct {
		name            string
		step            *ast.Step
		expectAutoFixer bool
		autoFixerCount  int
	}{
		{
			name: "auto-fixer added for non-SHA reference",
			step: &ast.Step{
				ID: &ast.String{Value: "checkout"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout@v3",
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			expectAutoFixer: true,
			autoFixerCount:  1,
		},
		{
			name: "no auto-fixer for full SHA",
			step: &ast.Step{
				ID: &ast.String{Value: "checkout"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
					},
				},
				Pos: &ast.Position{Line: 15, Col: 5},
			},
			expectAutoFixer: false,
			autoFixerCount:  0,
		},
		{
			name: "no auto-fixer for run command",
			step: &ast.Step{
				ID: &ast.String{Value: "run-script"},
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "echo 'hello'",
					},
				},
				Pos: &ast.Position{Line: 20, Col: 5},
			},
			expectAutoFixer: false,
			autoFixerCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CommitShaRule()
			_ = rule.VisitStep(tt.step)

			autoFixerCount := len(rule.AutoFixers())
			if autoFixerCount != tt.autoFixerCount {
				t.Errorf("Expected %d auto-fixer(s), but got %d", tt.autoFixerCount, autoFixerCount)
			}

			if tt.expectAutoFixer && autoFixerCount == 0 {
				t.Error("Expected auto-fixer to be added, but none was added")
			}

			if !tt.expectAutoFixer && autoFixerCount > 0 {
				t.Errorf("Expected no auto-fixer, but %d was added", autoFixerCount)
			}
		})
	}
}

// TestCommitSha_VisitStep_NilChecks tests behavior with nil values.
func TestCommitSha_VisitStep_NilChecks(t *testing.T) {
	tests := []struct {
		name string
		step *ast.Step
	}{
		{
			name: "step with nil Exec",
			step: &ast.Step{
				ID:   &ast.String{Value: "test"},
				Exec: nil,
				Pos:  &ast.Position{Line: 10, Col: 5},
			},
		},
		{
			name: "step with nil ID",
			step: &ast.Step{
				ID: nil,
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout@v3",
					},
				},
				Pos: &ast.Position{Line: 15, Col: 5},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CommitShaRule()
			// Should not panic
			err := rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() returned unexpected error: %v", err)
			}
		})
	}
}

// TestCommitSha_FixStep_InvalidFormat tests FixStep with invalid action reference formats.
func TestCommitSha_FixStep_InvalidFormat(t *testing.T) {
	tests := []struct {
		name      string
		step      *ast.Step
		wantError bool
	}{
		{
			name: "missing @ symbol",
			step: &ast.Step{
				ID: &ast.String{Value: "test"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value:    "actions/checkout",
						BaseNode: &yaml.Node{},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantError: true,
		},
		{
			name: "missing repo name",
			step: &ast.Step{
				ID: &ast.String{Value: "test"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value:    "actions@v3",
						BaseNode: &yaml.Node{},
					},
				},
				Pos: &ast.Position{Line: 15, Col: 5},
			},
			wantError: true,
		},
		{
			name: "multiple @ symbols",
			step: &ast.Step{
				ID: &ast.String{Value: "test"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value:    "actions/checkout@v3@extra",
						BaseNode: &yaml.Node{},
					},
				},
				Pos: &ast.Position{Line: 20, Col: 5},
			},
			wantError: true,
		},
		{
			name: "empty owner/repo",
			step: &ast.Step{
				ID: &ast.String{Value: "test"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value:    "@v3",
						BaseNode: &yaml.Node{},
					},
				},
				Pos: &ast.Position{Line: 25, Col: 5},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CommitShaRule()
			err := rule.FixStep(tt.step)

			if tt.wantError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// TestCommitSha_MultipleSteps tests processing multiple steps.
func TestCommitSha_MultipleSteps(t *testing.T) {
	rule := CommitShaRule()

	steps := []*ast.Step{
		{
			ID: &ast.String{Value: "checkout"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{
					Value: "actions/checkout@v3",
				},
			},
			Pos: &ast.Position{Line: 10, Col: 5},
		},
		{
			ID: &ast.String{Value: "setup-node"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{
					Value: "actions/setup-node@v4",
				},
			},
			Pos: &ast.Position{Line: 15, Col: 5},
		},
		{
			ID: &ast.String{Value: "run-tests"},
			Exec: &ast.ExecRun{
				Run: &ast.String{
					Value: "npm test",
				},
			},
			Pos: &ast.Position{Line: 20, Col: 5},
		},
		{
			ID: &ast.String{Value: "valid-action"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{
					Value: "actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9",
				},
			},
			Pos: &ast.Position{Line: 25, Col: 5},
		},
	}

	for _, step := range steps {
		err := rule.VisitStep(step)
		if err != nil {
			t.Errorf("VisitStep() returned unexpected error: %v", err)
		}
	}

	// Should have 2 errors (checkout@v3 and setup-node@v4)
	expectedErrors := 2
	if len(rule.Errors()) != expectedErrors {
		t.Errorf("Expected %d errors, got %d", expectedErrors, len(rule.Errors()))
	}

	// Should have 2 auto-fixers
	expectedAutoFixers := 2
	if len(rule.AutoFixers()) != expectedAutoFixers {
		t.Errorf("Expected %d auto-fixers, got %d", expectedAutoFixers, len(rule.AutoFixers()))
	}
}

// TestCommitSha_ErrorMessage tests that error messages are properly formatted.
func TestCommitSha_ErrorMessage(t *testing.T) {
	rule := CommitShaRule()

	step := &ast.Step{
		ID: &ast.String{Value: "test-step"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{
				Value: "actions/checkout@v3",
			},
		},
		Pos: &ast.Position{Line: 42, Col: 10},
	}

	err := rule.VisitStep(step)
	if err != nil {
		t.Errorf("VisitStep() returned unexpected error: %v", err)
	}

	if len(rule.Errors()) == 0 {
		t.Fatal("Expected error to be recorded")
	}

	errMsg := rule.Errors()[0].Error()

	// Check that error message contains expected elements
	if !stringContains(errMsg, "commit-sha") {
		t.Error("Error message should contain rule name 'commit-sha'")
	}
	if !stringContains(errMsg, "full length commit SHA") {
		t.Error("Error message should contain 'full length commit SHA'")
	}
}

// Helper function to check if a string contains a substring
func stringContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
