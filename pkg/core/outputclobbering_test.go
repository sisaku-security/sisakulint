package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestOutputClobberingCriticalRule(t *testing.T) {
	rule := OutputClobberingCriticalRule()
	if rule.RuleName != "output-clobbering-critical" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "output-clobbering-critical")
	}
}

func TestOutputClobberingMediumRule(t *testing.T) {
	rule := OutputClobberingMediumRule()
	if rule.RuleName != "output-clobbering-medium" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "output-clobbering-medium")
	}
}

func TestOutputClobberingCritical_PrivilegedTriggers(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "pull_request_target + GITHUB_OUTPUT",
			trigger:     "pull_request_target",
			runScript:   `echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"`,
			wantErrors:  1,
			description: "Should detect output clobbering in privileged trigger",
		},
		{
			name:        "issue_comment + GITHUB_OUTPUT",
			trigger:     "issue_comment",
			runScript:   `echo "body=${{ github.event.comment.body }}" >> $GITHUB_OUTPUT`,
			wantErrors:  1,
			description: "Should detect output clobbering in issue_comment",
		},
		{
			name:        "pull_request (not privileged)",
			trigger:     "pull_request",
			runScript:   `echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"`,
			wantErrors:  0,
			description: "Should not detect for non-privileged trigger (critical rule)",
		},
		{
			name:    "multiple GITHUB_OUTPUT writes",
			trigger: "pull_request_target",
			runScript: `echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"
echo "body=${{ github.event.pull_request.body }}" >> "$GITHUB_OUTPUT"`,
			wantErrors:  2,
			description: "Should detect both output clobbering issues",
		},
		{
			name:        "safe with trusted input (github.sha)",
			trigger:     "pull_request_target",
			runScript:   `echo "sha=${{ github.sha }}" >> "$GITHUB_OUTPUT"`,
			wantErrors:  0,
			description: "Should not detect for trusted input",
		},
		{
			name:    "safe with heredoc syntax",
			trigger: "pull_request_target",
			runScript: `{
  echo "body<<EOF"
  echo "${{ github.event.pull_request.body }}"
  echo "EOF"
} >> "$GITHUB_OUTPUT"`,
			wantErrors:  0,
			description: "Should not detect when heredoc syntax is used",
		},
		{
			name:        "workflow_run + GITHUB_OUTPUT with head_ref",
			trigger:     "workflow_run",
			runScript:   `echo "branch=${{ github.head_ref }}" >> "$GITHUB_OUTPUT"`,
			wantErrors:  1,
			description: "Should detect output clobbering in workflow_run",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := OutputClobberingCriticalRule()

			// Create workflow with specified trigger
			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			// Create job with GITHUB_OUTPUT write
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

func TestOutputClobberingMedium_NormalTriggers(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "pull_request + GITHUB_OUTPUT",
			trigger:     "pull_request",
			runScript:   `echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"`,
			wantErrors:  1,
			description: "Should detect output clobbering in normal trigger",
		},
		{
			name:        "push + GITHUB_OUTPUT with commit message",
			trigger:     "push",
			runScript:   `echo "msg=${{ github.event.head_commit.message }}" >> "$GITHUB_OUTPUT"`,
			wantErrors:  1,
			description: "Should detect output clobbering with commit message",
		},
		{
			name:        "pull_request_target (privileged)",
			trigger:     "pull_request_target",
			runScript:   `echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"`,
			wantErrors:  0,
			description: "Should not detect for privileged trigger (medium rule)",
		},
		{
			name:        "safe with trusted input",
			trigger:     "pull_request",
			runScript:   `echo "ref=${{ github.ref }}" >> "$GITHUB_OUTPUT"`,
			wantErrors:  0,
			description: "Should not detect for trusted input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := OutputClobberingMediumRule()

			// Create workflow with specified trigger
			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			// Create job with GITHUB_OUTPUT write
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

func TestOutputClobberingCritical_AutoFix(t *testing.T) {
	rule := OutputClobberingCriticalRule()

	// Create workflow with privileged trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	// Create job with vulnerable GITHUB_OUTPUT write
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"`,
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

	// Check that heredoc syntax was applied
	if !strings.Contains(run.Run.Value, "<<EOF") {
		t.Errorf("expected heredoc syntax with <<EOF, got: %s", run.Run.Value)
	}

	// Check that env var was added
	if step.Env == nil || len(step.Env.Vars) == 0 {
		t.Error("expected env vars to be added")
	}
}

func TestOutputClobberingCritical_EnvVarDefinedInStep(t *testing.T) {
	rule := OutputClobberingCriticalRule()

	// Create workflow with privileged trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	// Create job with env var already defined
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"pr_title": {
							Name:  &ast.String{Value: "PR_TITLE"},
							Value: &ast.String{Value: "${{ github.event.pull_request.title }}"},
						},
					},
				},
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"`,
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
	if len(errors) != 0 {
		t.Errorf("expected no errors when env var is already defined, got %d", len(errors))
		for _, err := range errors {
			t.Logf("  error: %s", err.Description)
		}
	}
}

func TestOutputClobberingCritical_VariousOutputPatterns(t *testing.T) {
	tests := []struct {
		name       string
		runScript  string
		wantErrors int
	}{
		{
			name:       "standard format",
			runScript:  `echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT`,
			wantErrors: 1,
		},
		{
			name:       "double quoted",
			runScript:  `echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"`,
			wantErrors: 1,
		},
		{
			name:       "single quoted",
			runScript:  `echo "title=${{ github.event.pull_request.title }}" >> '$GITHUB_OUTPUT'`,
			wantErrors: 1,
		},
		{
			name:       "with braces",
			runScript:  `echo "title=${{ github.event.pull_request.title }}" >> ${GITHUB_OUTPUT}`,
			wantErrors: 1,
		},
		{
			name:       "no space after >>",
			runScript:  `echo "title=${{ github.event.pull_request.title }}" >>$GITHUB_OUTPUT`,
			wantErrors: 1,
		},
		{
			name:       "printf command",
			runScript:  `printf "title=${{ github.event.pull_request.title }}\n" >> "$GITHUB_OUTPUT"`,
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := OutputClobberingCriticalRule()

			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target"},
					},
				},
			}

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

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("got %d errors, want %d", gotErrors, tt.wantErrors)
				for _, err := range rule.Errors() {
					t.Logf("  error: %s", err.Description)
				}
			}
		})
	}
}

func TestOutputClobberingCritical_HeredocSyntaxSafe(t *testing.T) {
	tests := []struct {
		name       string
		runScript  string
		wantErrors int
	}{
		{
			name: "basic heredoc",
			runScript: `{
  echo "body<<EOF"
  echo "${{ github.event.pull_request.body }}"
  echo "EOF"
} >> "$GITHUB_OUTPUT"`,
			wantErrors: 0,
		},
		{
			name: "heredoc with uuid delimiter",
			runScript: `DELIMITER=$(uuidgen)
{
  echo "body<<$DELIMITER"
  echo "${{ github.event.pull_request.body }}"
  echo "$DELIMITER"
} >> "$GITHUB_OUTPUT"`,
			wantErrors: 0,
		},
		{
			name: "single line heredoc start",
			runScript: `echo "body<<EOF" >> "$GITHUB_OUTPUT"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_OUTPUT"
echo "EOF" >> "$GITHUB_OUTPUT"`,
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := OutputClobberingCriticalRule()

			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target"},
					},
				},
			}

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

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("got %d errors, want %d", gotErrors, tt.wantErrors)
				for _, err := range rule.Errors() {
					t.Logf("  error: %s", err.Description)
				}
			}
		})
	}
}
