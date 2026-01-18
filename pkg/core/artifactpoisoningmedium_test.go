package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// TestNewArtifactPoisoningMediumRule tests the constructor function.
func TestNewArtifactPoisoningMediumRule(t *testing.T) {
	rule := NewArtifactPoisoningMediumRule()

	if rule.RuleName != "artifact-poisoning-medium" {
		t.Errorf("Expected RuleName to be 'artifact-poisoning-medium', got '%s'", rule.RuleName)
	}

	expectedDesc := "Detects third-party artifact download actions in workflows with untrusted triggers. These actions may download and extract artifacts unsafely, allowing file overwrites."
	if rule.RuleDesc != expectedDesc {
		t.Errorf("Expected RuleDesc to be '%s', got '%s'", expectedDesc, rule.RuleDesc)
	}
}

// TestIsThirdPartyArtifactAction tests the detection of third-party artifact download actions.
func TestIsThirdPartyArtifactAction(t *testing.T) {
	tests := []struct {
		name       string
		uses       string
		wantDetect bool
	}{
		// Known third-party actions
		{name: "dawidd6/action-download-artifact v2", uses: "dawidd6/action-download-artifact@v2", wantDetect: true},
		{name: "dawidd6/action-download-artifact with SHA", uses: "dawidd6/action-download-artifact@abc123", wantDetect: true},

		// Heuristic detection (contains 'download' and 'artifact')
		{name: "custom download-artifact action", uses: "myorg/download-artifact@v1", wantDetect: true},
		{name: "artifact-download action", uses: "company/artifact-download@v1", wantDetect: true},
		{name: "download artifacts action", uses: "user/download-artifacts-action@v1", wantDetect: true},

		// Official actions (should NOT be detected - handled by critical rule)
		{name: "actions/download-artifact v4", uses: "actions/download-artifact@v4", wantDetect: false},
		{name: "actions/download-artifact v3", uses: "actions/download-artifact@v3", wantDetect: false},
		{name: "actions/download-artifact with SHA", uses: "actions/download-artifact@6b208ae046db98c579e8a3aa621ab581ff575935", wantDetect: false},

		// Unrelated actions
		{name: "actions/checkout", uses: "actions/checkout@v4", wantDetect: false},
		{name: "actions/upload-artifact", uses: "actions/upload-artifact@v4", wantDetect: false},
		{name: "actions/cache", uses: "actions/cache@v3", wantDetect: false},
		{name: "empty uses", uses: "", wantDetect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isThirdPartyArtifactAction(tt.uses)
			if got != tt.wantDetect {
				t.Errorf("isThirdPartyArtifactAction(%q) = %v, want %v", tt.uses, got, tt.wantDetect)
			}
		})
	}
}

// TestArtifactPoisoningMedium_VisitWorkflowPre tests trigger detection.
func TestArtifactPoisoningMedium_VisitWorkflowPre(t *testing.T) {
	tests := []struct {
		name               string
		triggers           []string
		wantUnsafeTriggers int
	}{
		{
			name:               "workflow_run trigger",
			triggers:           []string{"workflow_run"},
			wantUnsafeTriggers: 1,
		},
		{
			name:               "pull_request_target trigger",
			triggers:           []string{"pull_request_target"},
			wantUnsafeTriggers: 1,
		},
		{
			name:               "issue_comment trigger",
			triggers:           []string{"issue_comment"},
			wantUnsafeTriggers: 1,
		},
		{
			name:               "multiple untrusted triggers",
			triggers:           []string{"workflow_run", "pull_request_target"},
			wantUnsafeTriggers: 2,
		},
		{
			name:               "safe trigger (pull_request)",
			triggers:           []string{"pull_request"},
			wantUnsafeTriggers: 0,
		},
		{
			name:               "safe trigger (push)",
			triggers:           []string{"push"},
			wantUnsafeTriggers: 0,
		},
		{
			name:               "mixed safe and unsafe triggers",
			triggers:           []string{"push", "workflow_run"},
			wantUnsafeTriggers: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewArtifactPoisoningMediumRule()
			workflow := &ast.Workflow{On: []ast.Event{}}

			for _, trigger := range tt.triggers {
				workflow.On = append(workflow.On, &ast.WebhookEvent{
					Hook: &ast.String{Value: trigger},
				})
			}

			err := rule.VisitWorkflowPre(workflow)
			if err != nil {
				t.Errorf("VisitWorkflowPre() unexpected error: %v", err)
			}

			if len(rule.unsafeTriggers) != tt.wantUnsafeTriggers {
				t.Errorf("VisitWorkflowPre() got %d unsafe triggers, want %d", len(rule.unsafeTriggers), tt.wantUnsafeTriggers)
			}
		})
	}
}

// TestArtifactPoisoningMedium_VisitStep tests step-level detection.
func TestArtifactPoisoningMedium_VisitStep(t *testing.T) {
	tests := []struct {
		name       string
		triggers   []string
		step       *ast.Step
		wantErrors int
		wantFixers int
	}{
		{
			name:     "dawidd6 action with workflow_run trigger - no path",
			triggers: []string{"workflow_run"},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
			wantFixers: 1,
		},
		{
			name:     "dawidd6 action with workflow_run trigger - safe path",
			triggers: []string{"workflow_run"},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "${{ runner.temp }}/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1, // Still warns about untrusted content
			wantFixers: 0, // No fixer needed when path is already safe
		},
		{
			name:     "third-party download-artifact action with pull_request_target",
			triggers: []string{"pull_request_target"},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "myorg/download-artifact@v1"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
			wantFixers: 1,
		},
		{
			name:     "actions/download-artifact with workflow_run - should NOT trigger",
			triggers: []string{"workflow_run"},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0, // Handled by critical rule
			wantFixers: 0,
		},
		{
			name:     "dawidd6 action with safe trigger (pull_request)",
			triggers: []string{"pull_request"},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0, // Safe trigger
			wantFixers: 0,
		},
		{
			name:     "unrelated action with workflow_run",
			triggers: []string{"workflow_run"},
			step: &ast.Step{
				ID: &ast.String{Value: "checkout"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/checkout@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
			wantFixers: 0,
		},
		{
			name:     "run step with workflow_run",
			triggers: []string{"workflow_run"},
			step: &ast.Step{
				ID: &ast.String{Value: "test"},
				Exec: &ast.ExecRun{
					Run: &ast.String{Value: "echo test"},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
			wantFixers: 0,
		},
		{
			name:     "dawidd6 action with issue_comment trigger",
			triggers: []string{"issue_comment"},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
			wantFixers: 1,
		},
		{
			name:     "third-party action with unsafe path",
			triggers: []string{"workflow_run"},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "."},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
			wantFixers: 1, // Should fix unsafe path
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewArtifactPoisoningMediumRule()

			// Set up workflow triggers
			workflow := &ast.Workflow{On: []ast.Event{}}
			for _, trigger := range tt.triggers {
				workflow.On = append(workflow.On, &ast.WebhookEvent{
					Hook: &ast.String{Value: trigger},
				})
			}
			_ = rule.VisitWorkflowPre(workflow)

			// Visit the step
			err := rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() unexpected error: %v", err)
			}

			errors := rule.Errors()
			if len(errors) != tt.wantErrors {
				t.Errorf("VisitStep() got %d errors, want %d errors", len(errors), tt.wantErrors)
				for i, e := range errors {
					t.Logf("Error %d: %s", i, e.Description)
				}
			}

			fixers := rule.AutoFixers()
			if len(fixers) != tt.wantFixers {
				t.Errorf("VisitStep() got %d fixers, want %d fixers", len(fixers), tt.wantFixers)
			}
		})
	}
}

// TestArtifactPoisoningMedium_FixStep tests the auto-fix functionality.
func TestArtifactPoisoningMedium_FixStep(t *testing.T) {
	tests := []struct {
		name      string
		step      *ast.Step
		wantPath  string
		wantError bool
	}{
		{
			name: "fix step without inputs",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: nil,
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  "${{ runner.temp }}/artifacts",
			wantError: false,
		},
		{
			name: "fix step with empty inputs",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  "${{ runner.temp }}/artifacts",
			wantError: false,
		},
		{
			name: "fix step with existing inputs",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: map[string]*ast.Input{
						"name": {
							Name:  &ast.String{Value: "name"},
							Value: &ast.String{Value: "my-artifact"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  "${{ runner.temp }}/artifacts",
			wantError: false,
		},
		{
			name: "fix step with unsafe path",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "."},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  "${{ runner.temp }}/artifacts",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewArtifactPoisoningMediumRule()
			err := rule.FixStep(tt.step)

			if (err != nil) != tt.wantError {
				t.Errorf("FixStep() error = %v, wantError %v", err, tt.wantError)
				return
			}

			action := tt.step.Exec.(*ast.ExecAction)
			if action.Inputs == nil {
				t.Fatal("FixStep() did not initialize Inputs map")
			}

			pathInput, ok := action.Inputs["path"]
			if !ok {
				t.Fatal("FixStep() did not add path input")
			}

			if pathInput.Value.Value != tt.wantPath {
				t.Errorf("FixStep() path = %v, want %v", pathInput.Value.Value, tt.wantPath)
			}

			if pathInput.Name.Value != "path" {
				t.Errorf("FixStep() path name = %v, want 'path'", pathInput.Name.Value)
			}
		})
	}
}

// TestArtifactPoisoningMedium_Integration tests the full workflow.
func TestArtifactPoisoningMedium_Integration(t *testing.T) {
	tests := []struct {
		name       string
		triggers   []string
		step       *ast.Step
		wantErrors int
		wantFixers int
	}{
		{
			name:     "vulnerable workflow with dawidd6 action",
			triggers: []string{"workflow_run"},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
			wantFixers: 1,
		},
		{
			name:     "safe workflow with actions/download-artifact",
			triggers: []string{"workflow_run"},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0, // Not handled by this rule
			wantFixers: 0,
		},
		{
			name:     "safe workflow with safe trigger",
			triggers: []string{"pull_request"},
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "dawidd6/action-download-artifact@v2"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
			wantFixers: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewArtifactPoisoningMediumRule()

			// Set up workflow
			workflow := &ast.Workflow{On: []ast.Event{}}
			for _, trigger := range tt.triggers {
				workflow.On = append(workflow.On, &ast.WebhookEvent{
					Hook: &ast.String{Value: trigger},
				})
			}
			_ = rule.VisitWorkflowPre(workflow)

			// Visit step
			err := rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() unexpected error: %v", err)
			}

			errors := rule.Errors()
			if len(errors) != tt.wantErrors {
				t.Errorf("got %d errors, want %d errors", len(errors), tt.wantErrors)
			}

			fixers := rule.AutoFixers()
			if len(fixers) != tt.wantFixers {
				t.Errorf("got %d fixers, want %d fixers", len(fixers), tt.wantFixers)
			}

			// Apply fixers if any
			if len(fixers) > 0 {
				for _, fixer := range fixers {
					if err := fixer.Fix(); err != nil {
						t.Errorf("AutoFixer.Fix() error = %v", err)
					}
				}

				// Verify the fix
				action := tt.step.Exec.(*ast.ExecAction)
				if action.Inputs["path"] == nil {
					t.Error("AutoFixer did not add path input")
				} else if action.Inputs["path"].Value.Value != "${{ runner.temp }}/artifacts" {
					t.Errorf("AutoFixer path = %v, want '${{ runner.temp }}/artifacts'", action.Inputs["path"].Value.Value)
				}
			}
		})
	}
}
