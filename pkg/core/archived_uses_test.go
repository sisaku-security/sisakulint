package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// TestNewArchivedUsesRule tests the ArchivedUsesRule constructor function.
func TestNewArchivedUsesRule(t *testing.T) {
	rule := NewArchivedUsesRule()

	if rule.RuleName != "archived-uses" {
		t.Errorf("Expected RuleName to be 'archived-uses', got '%s'", rule.RuleName)
	}

	expectedDescPrefix := "Detects usage of actions/reusable workflows from archived repositories"
	if !strings.HasPrefix(rule.RuleDesc, expectedDescPrefix) {
		t.Errorf("Expected RuleDesc to start with '%s', got '%s'", expectedDescPrefix, rule.RuleDesc)
	}

	if rule.archivedRepos == nil {
		t.Error("Expected archivedRepos map to be initialized")
	}

	// Verify some known archived repos are in the list
	knownArchived := []string{
		"actions/upload-release-asset",
		"actions/create-release",
		"actions-rs/cargo",
		"actions-rs/toolchain",
	}
	for _, repo := range knownArchived {
		if !rule.isArchivedRepo(strings.Split(repo, "/")[0], strings.Split(repo, "/")[1]) {
			t.Errorf("Expected '%s' to be in archived repos list", repo)
		}
	}
}

// TestParseUsesValue tests the parseUsesValue function.
func TestParseUsesValue(t *testing.T) {
	tests := []struct {
		name          string
		uses          string
		expectedOwner string
		expectedRepo  string
		expectedRef   string
	}{
		{
			name:          "standard action reference",
			uses:          "actions/checkout@v4",
			expectedOwner: "actions",
			expectedRepo:  "checkout",
			expectedRef:   "v4",
		},
		{
			name:          "action with full SHA",
			uses:          "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
			expectedOwner: "actions",
			expectedRepo:  "checkout",
			expectedRef:   "a81bbbf8298c0fa03ea29cdc473d45769f953675",
		},
		{
			name:          "action with subdirectory",
			uses:          "owner/repo/path/to/action@v1",
			expectedOwner: "owner",
			expectedRepo:  "repo",
			expectedRef:   "v1",
		},
		{
			name:          "action without ref",
			uses:          "owner/repo",
			expectedOwner: "owner",
			expectedRepo:  "repo",
			expectedRef:   "",
		},
		{
			name:          "local action",
			uses:          "./local/action",
			expectedOwner: "",
			expectedRepo:  "",
			expectedRef:   "",
		},
		{
			name:          "docker image",
			uses:          "docker://alpine:3.8",
			expectedOwner: "",
			expectedRepo:  "",
			expectedRef:   "",
		},
		{
			name:          "invalid format - no slash",
			uses:          "invalid-format@v1",
			expectedOwner: "",
			expectedRepo:  "",
			expectedRef:   "",
		},
		{
			name:          "reusable workflow with path",
			uses:          "owner/repo/.github/workflows/ci.yml@main",
			expectedOwner: "owner",
			expectedRepo:  "repo",
			expectedRef:   "main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, ref := parseUsesValue(tt.uses)
			if owner != tt.expectedOwner {
				t.Errorf("parseUsesValue(%q) owner = %q, want %q", tt.uses, owner, tt.expectedOwner)
			}
			if repo != tt.expectedRepo {
				t.Errorf("parseUsesValue(%q) repo = %q, want %q", tt.uses, repo, tt.expectedRepo)
			}
			if ref != tt.expectedRef {
				t.Errorf("parseUsesValue(%q) ref = %q, want %q", tt.uses, ref, tt.expectedRef)
			}
		})
	}
}

// TestArchivedUsesRule_IsArchivedRepo tests the isArchivedRepo method.
func TestArchivedUsesRule_IsArchivedRepo(t *testing.T) {
	rule := NewArchivedUsesRule()

	tests := []struct {
		name     string
		owner    string
		repo     string
		expected bool
	}{
		{
			name:     "archived official action",
			owner:    "actions",
			repo:     "upload-release-asset",
			expected: true,
		},
		{
			name:     "archived actions-rs repo",
			owner:    "actions-rs",
			repo:     "cargo",
			expected: true,
		},
		{
			name:     "archived Azure action",
			owner:    "Azure",
			repo:     "container-scan",
			expected: true,
		},
		{
			name:     "maintained action",
			owner:    "actions",
			repo:     "checkout",
			expected: false,
		},
		{
			name:     "unknown action",
			owner:    "someorg",
			repo:     "someaction",
			expected: false,
		},
		{
			name:     "case insensitive - uppercase",
			owner:    "ACTIONS",
			repo:     "UPLOAD-RELEASE-ASSET",
			expected: true,
		},
		{
			name:     "case insensitive - mixed case",
			owner:    "Actions-RS",
			repo:     "Cargo",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rule.isArchivedRepo(tt.owner, tt.repo)
			if result != tt.expected {
				t.Errorf("isArchivedRepo(%q, %q) = %v, want %v", tt.owner, tt.repo, result, tt.expected)
			}
		})
	}
}

// TestArchivedUsesRule_VisitStep tests the VisitStep method.
func TestArchivedUsesRule_VisitStep(t *testing.T) {
	tests := []struct {
		name       string
		step       *ast.Step
		wantError  bool
		errorCount int
	}{
		{
			name: "archived action - actions-rs/toolchain",
			step: &ast.Step{
				ID: &ast.String{Value: "toolchain"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions-rs/toolchain@v1",
						Pos:   &ast.Position{Line: 10, Col: 9},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantError:  true,
			errorCount: 1,
		},
		{
			name: "archived action - actions/create-release",
			step: &ast.Step{
				ID: &ast.String{Value: "release"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/create-release@v1",
						Pos:   &ast.Position{Line: 15, Col: 9},
					},
				},
				Pos: &ast.Position{Line: 15, Col: 5},
			},
			wantError:  true,
			errorCount: 1,
		},
		{
			name: "maintained action - actions/checkout",
			step: &ast.Step{
				ID: &ast.String{Value: "checkout"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout@v4",
						Pos:   &ast.Position{Line: 20, Col: 9},
					},
				},
				Pos: &ast.Position{Line: 20, Col: 5},
			},
			wantError:  false,
			errorCount: 0,
		},
		{
			name: "run step - not an action",
			step: &ast.Step{
				ID: &ast.String{Value: "run-script"},
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "echo 'hello'",
					},
				},
				Pos: &ast.Position{Line: 25, Col: 5},
			},
			wantError:  false,
			errorCount: 0,
		},
		{
			name: "local action",
			step: &ast.Step{
				ID: &ast.String{Value: "local"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "./.github/actions/my-action",
						Pos:   &ast.Position{Line: 30, Col: 9},
					},
				},
				Pos: &ast.Position{Line: 30, Col: 5},
			},
			wantError:  false,
			errorCount: 0,
		},
		{
			name: "docker action",
			step: &ast.Step{
				ID: &ast.String{Value: "docker"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "docker://alpine:3.8",
						Pos:   &ast.Position{Line: 35, Col: 9},
					},
				},
				Pos: &ast.Position{Line: 35, Col: 5},
			},
			wantError:  false,
			errorCount: 0,
		},
		{
			name: "archived action with subdirectory",
			step: &ast.Step{
				ID: &ast.String{Value: "azure-action"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "Azure/container-scan/some/path@v1",
						Pos:   &ast.Position{Line: 40, Col: 9},
					},
				},
				Pos: &ast.Position{Line: 40, Col: 5},
			},
			wantError:  true,
			errorCount: 1,
		},
		{
			name: "case insensitive - archived action uppercase",
			step: &ast.Step{
				ID: &ast.String{Value: "toolchain-upper"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "ACTIONS-RS/TOOLCHAIN@v1",
						Pos:   &ast.Position{Line: 45, Col: 9},
					},
				},
				Pos: &ast.Position{Line: 45, Col: 5},
			},
			wantError:  true,
			errorCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewArchivedUsesRule()
			err := rule.VisitStep(tt.step)

			if err != nil {
				t.Errorf("VisitStep() returned unexpected error: %v", err)
			}

			errorCount := len(rule.Errors())
			if tt.wantError && errorCount == 0 {
				t.Error("Expected errors to be recorded, but got none")
			}
			if !tt.wantError && errorCount > 0 {
				t.Errorf("Expected no errors, but got %d error(s): %v", errorCount, rule.Errors())
			}
			if errorCount != tt.errorCount {
				t.Errorf("Expected %d error(s), but got %d", tt.errorCount, errorCount)
			}
		})
	}
}

// TestArchivedUsesRule_VisitJobPre tests the VisitJobPre method for reusable workflows.
func TestArchivedUsesRule_VisitJobPre(t *testing.T) {
	tests := []struct {
		name       string
		job        *ast.Job
		wantError  bool
		errorCount int
	}{
		{
			name: "archived reusable workflow",
			job: &ast.Job{
				ID: &ast.String{Value: "call-workflow"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{
						Value: "actions-rs/cargo/.github/workflows/ci.yml@main",
						Pos:   &ast.Position{Line: 10, Col: 9},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantError:  true,
			errorCount: 1,
		},
		{
			name: "maintained reusable workflow",
			job: &ast.Job{
				ID: &ast.String{Value: "call-workflow"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{
						Value: "actions/checkout/.github/workflows/release.yml@main",
						Pos:   &ast.Position{Line: 15, Col: 9},
					},
				},
				Pos: &ast.Position{Line: 15, Col: 5},
			},
			wantError:  false,
			errorCount: 0,
		},
		{
			name: "regular job without workflow call",
			job: &ast.Job{
				ID: &ast.String{Value: "build"},
				Steps: []*ast.Step{
					{
						ID: &ast.String{Value: "checkout"},
						Exec: &ast.ExecAction{
							Uses: &ast.String{Value: "actions/checkout@v4"},
						},
					},
				},
				Pos: &ast.Position{Line: 20, Col: 5},
			},
			wantError:  false,
			errorCount: 0,
		},
		{
			name: "job with nil workflow call",
			job: &ast.Job{
				ID:           &ast.String{Value: "test"},
				WorkflowCall: nil,
				Pos:          &ast.Position{Line: 25, Col: 5},
			},
			wantError:  false,
			errorCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewArchivedUsesRule()
			err := rule.VisitJobPre(tt.job)

			if err != nil {
				t.Errorf("VisitJobPre() returned unexpected error: %v", err)
			}

			errorCount := len(rule.Errors())
			if tt.wantError && errorCount == 0 {
				t.Error("Expected errors to be recorded, but got none")
			}
			if !tt.wantError && errorCount > 0 {
				t.Errorf("Expected no errors, but got %d error(s): %v", errorCount, rule.Errors())
			}
			if errorCount != tt.errorCount {
				t.Errorf("Expected %d error(s), but got %d", tt.errorCount, errorCount)
			}
		})
	}
}

// TestArchivedUsesRule_MultipleSteps tests processing multiple steps.
func TestArchivedUsesRule_MultipleSteps(t *testing.T) {
	rule := NewArchivedUsesRule()

	steps := []*ast.Step{
		{
			ID: &ast.String{Value: "step1"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{
					Value: "actions-rs/toolchain@v1",
					Pos:   &ast.Position{Line: 10, Col: 9},
				},
			},
			Pos: &ast.Position{Line: 10, Col: 5},
		},
		{
			ID: &ast.String{Value: "step2"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{
					Value: "actions/checkout@v4",
					Pos:   &ast.Position{Line: 15, Col: 9},
				},
			},
			Pos: &ast.Position{Line: 15, Col: 5},
		},
		{
			ID: &ast.String{Value: "step3"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{
					Value: "actions-rs/cargo@v1",
					Pos:   &ast.Position{Line: 20, Col: 9},
				},
			},
			Pos: &ast.Position{Line: 20, Col: 5},
		},
		{
			ID: &ast.String{Value: "step4"},
			Exec: &ast.ExecRun{
				Run: &ast.String{
					Value: "cargo build",
				},
			},
			Pos: &ast.Position{Line: 25, Col: 5},
		},
		{
			ID: &ast.String{Value: "step5"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{
					Value: "actions/create-release@v1",
					Pos:   &ast.Position{Line: 30, Col: 9},
				},
			},
			Pos: &ast.Position{Line: 30, Col: 5},
		},
	}

	for _, step := range steps {
		err := rule.VisitStep(step)
		if err != nil {
			t.Errorf("VisitStep() returned unexpected error: %v", err)
		}
	}

	// Should have 3 errors (actions-rs/toolchain, actions-rs/cargo, actions/create-release)
	expectedErrors := 3
	if len(rule.Errors()) != expectedErrors {
		t.Errorf("Expected %d errors, got %d", expectedErrors, len(rule.Errors()))
		for i, e := range rule.Errors() {
			t.Logf("Error %d: %v", i+1, e)
		}
	}
}

// TestArchivedUsesRule_ErrorMessage tests that error messages are properly formatted.
func TestArchivedUsesRule_ErrorMessage(t *testing.T) {
	rule := NewArchivedUsesRule()

	step := &ast.Step{
		ID: &ast.String{Value: "test-step"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{
				Value: "actions-rs/toolchain@v1",
				Pos:   &ast.Position{Line: 42, Col: 10},
			},
		},
		Pos: &ast.Position{Line: 42, Col: 5},
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
	if !strings.Contains(errMsg, "actions-rs/toolchain") {
		t.Error("Error message should contain the action name")
	}
	if !strings.Contains(errMsg, "archived") {
		t.Error("Error message should mention 'archived'")
	}
	if !strings.Contains(errMsg, "no longer maintained") {
		t.Error("Error message should mention 'no longer maintained'")
	}
	if !strings.Contains(errMsg, "github.com/actions-rs/toolchain") {
		t.Error("Error message should contain the GitHub URL")
	}
}

// TestArchivedUsesRule_NilChecks tests behavior with nil values.
func TestArchivedUsesRule_NilChecks(t *testing.T) {
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
						Value: "actions-rs/toolchain@v1",
						Pos:   &ast.Position{Line: 15, Col: 9},
					},
				},
				Pos: &ast.Position{Line: 15, Col: 5},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewArchivedUsesRule()
			// Should not panic
			err := rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() returned unexpected error: %v", err)
			}
		})
	}
}

// TestArchivedUsesRule_AllKnownArchivedRepos verifies all known archived repos are detected.
func TestArchivedUsesRule_AllKnownArchivedRepos(t *testing.T) {
	rule := NewArchivedUsesRule()

	// Test a subset of the known archived repos
	knownArchived := []string{
		"actions/upload-release-asset",
		"actions/create-release",
		"actions/setup-ruby",
		"actions/setup-elixir",
		"actions/setup-haskell",
		"actions-rs/cargo",
		"actions-rs/toolchain",
		"Azure/container-scan",
		"gradle/gradle-build-action",
		"grafana/k6-action",
	}

	for _, repo := range knownArchived {
		parts := strings.Split(repo, "/")
		if len(parts) != 2 {
			t.Errorf("Invalid repo format: %s", repo)
			continue
		}

		if !rule.isArchivedRepo(parts[0], parts[1]) {
			t.Errorf("Expected '%s' to be detected as archived", repo)
		}
	}
}
