package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/core/chain"
)

func TestEnvPathInjectionMediumRule(t *testing.T) {
	t.Parallel()
	rule := EnvPathInjectionMediumRule()
	if rule.RuleName != "envpath-injection-medium" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "envpath-injection-medium")
	}
}

func TestEnvPathInjectionMedium_NormalTriggers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "pull_request + GITHUB_PATH",
			trigger:     "pull_request",
			runScript:   `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  1,
			description: "Should detect PATH injection in pull_request trigger",
		},
		{
			name:        "push + GITHUB_PATH",
			trigger:     "push",
			runScript:   `echo "${{ github.event.head_commit.message }}" >> $GITHUB_PATH`,
			wantErrors:  1,
			description: "Should detect PATH injection in push trigger",
		},
		{
			name:        "pull_request_target (privileged)",
			trigger:     "pull_request_target",
			runScript:   `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  0,
			description: "Should not detect for privileged trigger (critical rule handles this)",
		},
		{
			name:    "multiple GITHUB_PATH writes",
			trigger: "pull_request",
			runScript: `echo "${{ github.event.pull_request.title }}" >> "$GITHUB_PATH"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  2,
			description: "Should detect both PATH injections",
		},
		{
			name:        "safe with trusted input",
			trigger:     "pull_request",
			runScript:   `echo "/usr/local/bin" >> "$GITHUB_PATH"`,
			wantErrors:  0,
			description: "Should not detect for hardcoded path",
		},
		{
			name:        "safe with github.sha",
			trigger:     "pull_request",
			runScript:   `echo "${{ github.sha }}" >> "$GITHUB_PATH"`,
			wantErrors:  0,
			description: "Should not detect for trusted github.sha",
		},
		{
			name:        "untrusted head.ref",
			trigger:     "pull_request",
			runScript:   `echo "${{ github.event.pull_request.head.ref }}" >> "$GITHUB_PATH"`,
			wantErrors:  1,
			description: "Should detect untrusted head.ref",
		},
		{
			name:        "untrusted head.label",
			trigger:     "pull_request",
			runScript:   `echo "${{ github.event.pull_request.head.label }}" >> "$GITHUB_PATH"`,
			wantErrors:  1,
			description: "Should detect untrusted head.label",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := EnvPathInjectionMediumRule()

			// Create workflow with specified trigger
			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			// Create job with GITHUB_PATH write
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

func TestEnvPathInjectionMedium_AutoFix(t *testing.T) {
	t.Parallel()
	rule := EnvPathInjectionMediumRule()

	// Create workflow with normal trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request"},
			},
		},
	}

	// Create job with vulnerable GITHUB_PATH write
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
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

	// Check that the expression was sanitized with realpath
	if !strings.Contains(run.Run.Value, `realpath`) {
		t.Errorf("expected sanitization with realpath, got: %s", run.Run.Value)
	}

	// Check that env var was added
	if step.Env == nil || len(step.Env.Vars) == 0 {
		t.Error("expected env vars to be added")
	}
}

func TestEnvPathInjectionMedium_ErrorMessage(t *testing.T) {
	t.Parallel()
	rule := EnvPathInjectionMediumRule()

	// Create workflow with normal trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request"},
			},
		},
	}

	// Create job with vulnerable GITHUB_PATH write
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
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

	// Check error message contains key information
	errMsg := errors[0].Description
	if !strings.Contains(errMsg, "PATH injection (medium)") {
		t.Errorf("error message should contain 'PATH injection (medium)', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "github.event.pull_request.body") {
		t.Errorf("error message should contain the untrusted path, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "GITHUB_PATH") {
		t.Errorf("error message should mention GITHUB_PATH, got: %s", errMsg)
	}
}

func TestEnvPathInjectionMedium_ScheduleTrigger(t *testing.T) {
	t.Parallel()
	rule := EnvPathInjectionMediumRule()

	// Create workflow with schedule trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.ScheduledEvent{
				Cron: []*ast.String{{Value: "0 0 * * *"}},
			},
		},
	}

	// Create job with PATH write (schedule has no untrusted inputs from events)
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "/opt/bin" >> "$GITHUB_PATH"`,
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
	if gotErrors != 0 {
		t.Errorf("expected no errors for schedule trigger with hardcoded path, got %d", gotErrors)
		for _, err := range rule.Errors() {
			t.Logf("  error: %s", err.Description)
		}
	}
}

// TestEnvPathInjectionMediumPushesSinkRecord verifies that a detected PATH
// injection finding in a normal-trigger workflow is also pushed to the
// chain.SinkCollector for the leakage-path chain visualization (Milestone E
// task 16), with Severity reflecting the medium variant.
func TestEnvPathInjectionMediumPushesSinkRecord(t *testing.T) {
	collector := chain.NewSinkCollector()
	rule := EnvPathInjectionMediumRuleWithCollector(collector)

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
		},
	}
	job := &ast.Job{
		ID: &ast.String{Value: "build"},
		Steps: []*ast.Step{
			{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	if err := rule.VisitWorkflowPre(workflow); err != nil {
		t.Fatalf("VisitWorkflowPre: %v", err)
	}
	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}

	if len(rule.Errors()) != 1 {
		t.Fatalf("expected 1 error, got %d", len(rule.Errors()))
	}

	recs := collector.Records()
	if len(recs) != 1 {
		t.Fatalf("expected 1 SinkRecord pushed, got %d", len(recs))
	}
	r := recs[0]
	if r.SinkKind != chain.SinkExpr {
		t.Errorf("SinkKind = %v, want SinkExpr", r.SinkKind)
	}
	if r.Severity != "medium" {
		t.Errorf("Severity = %q, want %q", r.Severity, "medium")
	}
	if !strings.Contains(r.SourceName, "github.event.pull_request.body") {
		t.Errorf("SourceName = %q, want it to contain %q", r.SourceName, "github.event.pull_request.body")
	}
	if r.JobID != "build" {
		t.Errorf("JobID = %q, want %q", r.JobID, "build")
	}
}
