package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestEnvVarInjectionCriticalRule(t *testing.T) {
	rule := EnvVarInjectionCriticalRule(nil)
	if rule.RuleName != "envvar-injection-critical" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "envvar-injection-critical")
	}
}

func TestEnvVarInjectionCritical_PrivilegedTriggers(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "pull_request_target + GITHUB_ENV",
			trigger:     "pull_request_target",
			runScript:   `echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"`,
			wantErrors:  1,
			description: "Should detect envvar injection in privileged trigger",
		},
		{
			name:        "issue_comment + GITHUB_ENV",
			trigger:     "issue_comment",
			runScript:   `echo "BODY=${{ github.event.comment.body }}" >> $GITHUB_ENV`,
			wantErrors:  1,
			description: "Should detect envvar injection in issue_comment",
		},
		{
			name:        "pull_request (not privileged)",
			trigger:     "pull_request",
			runScript:   `echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"`,
			wantErrors:  0,
			description: "Should not detect for non-privileged trigger",
		},
		{
			name:    "multiple GITHUB_ENV writes",
			trigger: "pull_request_target",
			runScript: `echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
echo "BODY=${{ github.event.pull_request.body }}" >> "$GITHUB_ENV"`,
			wantErrors:  2,
			description: "Should detect both envvar injections (one error per untrusted expression)",
		},
		{
			name:        "safe with env var",
			trigger:     "pull_request_target",
			runScript:   `echo "SHA=${{ github.sha }}" >> "$GITHUB_ENV"`,
			wantErrors:  0,
			description: "Should not detect for trusted input",
		},
		{
			name:    "safe with heredoc syntax",
			trigger: "pull_request_target",
			runScript: `EOF=$(uuidgen)
echo "BODY<<EOF_$EOF" >> "$GITHUB_ENV"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_ENV"
echo "EOF_$EOF" >> "$GITHUB_ENV"`,
			wantErrors:  1,
			description: "Should still detect untrusted input even with heredoc (partial implementation)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := EnvVarInjectionCriticalRule(nil)

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

func TestEnvVarInjectionCritical_AutoFix(t *testing.T) {
	rule := EnvVarInjectionCriticalRule(nil)

	// Create workflow with privileged trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
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
