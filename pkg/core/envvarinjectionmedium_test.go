package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestEnvVarInjectionMediumRule(t *testing.T) {
	rule := EnvVarInjectionMediumRule(nil)
	if rule.RuleName != "envvar-injection-medium" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "envvar-injection-medium")
	}
}

func TestEnvVarInjectionMedium_NormalTriggers(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "pull_request + GITHUB_ENV",
			trigger:     "pull_request",
			runScript:   `echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"`,
			wantErrors:  1,
			description: "Should detect envvar injection in normal trigger",
		},
		{
			name:        "push + GITHUB_ENV",
			trigger:     "push",
			runScript:   `echo "BODY=${{ github.event.pull_request.body }}" >> $GITHUB_ENV`,
			wantErrors:  1,
			description: "Should detect envvar injection in push trigger",
		},
		{
			name:        "schedule + GITHUB_ENV",
			trigger:     "schedule",
			runScript:   `echo "REF=${{ github.event.pull_request.head.ref }}" >> "$GITHUB_ENV"`,
			wantErrors:  1,
			description: "Should detect envvar injection in schedule trigger",
		},
		{
			name:        "pull_request_target (privileged, not detected by medium)",
			trigger:     "pull_request_target",
			runScript:   `echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"`,
			wantErrors:  0,
			description: "Should not detect for privileged trigger (handled by critical rule)",
		},
		{
			name:    "multiple GITHUB_ENV writes",
			trigger: "pull_request",
			runScript: `echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
echo "BODY=${{ github.event.pull_request.body }}" >> "$GITHUB_ENV"`,
			wantErrors:  2,
			description: "Should detect both envvar injections (one error per untrusted expression)",
		},
		{
			name:        "safe with trusted input",
			trigger:     "pull_request",
			runScript:   `echo "SHA=${{ github.sha }}" >> "$GITHUB_ENV"`,
			wantErrors:  0,
			description: "Should not detect for trusted input",
		},
		{
			name:        "edge case with no space after >>",
			trigger:     "pull_request",
			runScript:   `echo "TITLE=${{ github.event.pull_request.title }}" >>$GITHUB_ENV`,
			wantErrors:  1,
			description: "Should detect GITHUB_ENV write without space after >>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := EnvVarInjectionMediumRule(nil)

			// Create workflow with specified trigger
			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			// Create job with GITHUB_ENV write
			job := &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: tt.runScript,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			// Visit workflow first
			err := rule.VisitWorkflowPre(workflow)
			if err != nil {
				t.Fatalf("VisitWorkflowPre() returned error: %v", err)
			}

			// Then visit job
			err = rule.VisitJobPre(job)
			if err != nil {
				t.Fatalf("VisitJobPre() returned error: %v", err)
			}

			gotErrors := len(rule.Errors())

			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d", tt.description, gotErrors, tt.wantErrors)
				for _, err := range rule.Errors() {
					t.Logf("  error: %s", err.Description)
				}
			}
		})
	}
}

func TestEnvVarInjectionMedium_AutoFix(t *testing.T) {
	rule := EnvVarInjectionMediumRule(nil)

	// Create workflow with normal trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request"},
			},
		},
	}

	// Create job with vulnerable GITHUB_ENV write
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"`,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	// Visit workflow and job
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	errors := rule.Errors()
	if len(errors) == 0 {
		t.Fatal("expected errors but got none")
	}

	// Get the step
	step := job.Steps[0]

	// Apply fix
	err := rule.FixStep(step)
	if err != nil {
		t.Fatalf("FixStep() returned error: %v", err)
	}

	// Verify the fix
	run := step.Exec.(*ast.ExecRun)
	if run.Run == nil {
		t.Fatal("run script is nil")
	}

	// Check that the expression was sanitized with tr -d '\n'
	if !strings.Contains(run.Run.Value, `tr -d '\n'`) {
		t.Errorf("expected sanitization with tr -d '\\n', got: %s", run.Run.Value)
	}

	// Check that env var was added
	if step.Env == nil || len(step.Env.Vars) == 0 {
		t.Error("expected env vars to be added")
	}
}
