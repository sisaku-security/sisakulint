package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestCodeInjectionCriticalRule(t *testing.T) {
	rule := CodeInjectionCriticalRule()
	if rule.RuleName != "code-injection-critical" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "code-injection-critical")
	}
}

func TestCodeInjectionCritical_PrivilegedTriggers(t *testing.T) {
	tests := []struct {
		name         string
		trigger      string
		shouldDetect bool
		description  string
	}{
		{
			name:         "pull_request_target is privileged",
			trigger:      "pull_request_target",
			shouldDetect: true,
			description:  "pull_request_target should be detected as privileged",
		},
		{
			name:         "workflow_run is privileged",
			trigger:      "workflow_run",
			shouldDetect: true,
			description:  "workflow_run should be detected as privileged",
		},
		{
			name:         "issue_comment is privileged",
			trigger:      "issue_comment",
			shouldDetect: true,
			description:  "issue_comment should be detected as privileged",
		},
		{
			name:         "issues is privileged",
			trigger:      "issues",
			shouldDetect: true,
			description:  "issues should be detected as privileged",
		},
		{
			name:         "pull_request is not privileged",
			trigger:      "pull_request",
			shouldDetect: false,
			description:  "pull_request should not be detected as privileged",
		},
		{
			name:         "push is not privileged",
			trigger:      "push",
			shouldDetect: false,
			description:  "push should not be detected as privileged",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CodeInjectionCriticalRule()

			// Create workflow with specified trigger
			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			// Create job with untrusted input
			job := &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `echo "${{ github.event.pull_request.title }}"`,
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

			if tt.shouldDetect && gotErrors == 0 {
				t.Errorf("%s: Expected errors but got none", tt.description)
			}
			if !tt.shouldDetect && gotErrors > 0 {
				t.Errorf("%s: Expected no errors but got %d errors: %v", tt.description, gotErrors, rule.Errors())
			}
		})
	}
}

func TestCodeInjectionCritical_RunScript(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "privileged trigger + untrusted input",
			trigger:     "pull_request_target",
			runScript:   `echo "${{ github.event.pull_request.title }}"`,
			wantErrors:  1,
			description: "Should detect untrusted input in privileged trigger",
		},
		{
			name:        "non-privileged trigger + untrusted input",
			trigger:     "pull_request",
			runScript:   `echo "${{ github.event.pull_request.title }}"`,
			wantErrors:  0,
			description: "Should not detect in non-privileged trigger",
		},
		{
			name:        "privileged trigger + trusted input",
			trigger:     "pull_request_target",
			runScript:   `echo "${{ github.sha }}"`,
			wantErrors:  0,
			description: "Should not detect trusted input",
		},
		{
			name:        "privileged trigger + env variable",
			trigger:     "pull_request_target",
			runScript:   `echo "$PR_TITLE"`,
			wantErrors:  0,
			description: "Should not detect when using env variable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CodeInjectionCriticalRule()

			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			step := &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: tt.runScript,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			}

			// Add env if script uses $PR_TITLE
			if tt.runScript == `echo "$PR_TITLE"` {
				step.Env = &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"pr_title": {
							Name: &ast.String{Value: "PR_TITLE"},
							Value: &ast.String{
								Value: "${{ github.event.pull_request.title }}",
							},
						},
					},
				}
			}

			job := &ast.Job{Steps: []*ast.Step{step}}

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestCodeInjectionCritical_GitHubScript(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		script      string
		withEnv     bool
		wantErrors  int
		description string
	}{
		{
			name:        "privileged trigger + untrusted input in script",
			trigger:     "issue_comment",
			script:      `console.log('${{ github.event.comment.body }}')`,
			withEnv:     false,
			wantErrors:  1,
			description: "Should detect untrusted input in github-script",
		},
		{
			name:        "privileged trigger + env variable in script",
			trigger:     "issue_comment",
			script:      `const { COMMENT_BODY } = process.env`,
			withEnv:     true,
			wantErrors:  0,
			description: "Should not detect when using env variable",
		},
		{
			name:        "non-privileged trigger + untrusted input",
			trigger:     "pull_request",
			script:      `console.log('${{ github.event.pull_request.title }}')`,
			withEnv:     false,
			wantErrors:  0,
			description: "Should not detect in non-privileged trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CodeInjectionCriticalRule()

			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			step := &ast.Step{
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/github-script@v6"},
					Inputs: map[string]*ast.Input{
						"script": {
							Name: &ast.String{Value: "script"},
							Value: &ast.String{
								Value: tt.script,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			if tt.withEnv {
				step.Env = &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"comment_body": {
							Name: &ast.String{Value: "COMMENT_BODY"},
							Value: &ast.String{
								Value: "${{ github.event.comment.body }}",
							},
						},
					},
				}
			}

			job := &ast.Job{Steps: []*ast.Step{step}}

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

// TestCodeInjectionCritical_ComplexExpressions tests that complex expressions
// using functions like format(), fromJSON(), join() are also detected
func TestCodeInjectionCritical_ComplexExpressions(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "format function with untrusted input",
			runScript:   "echo ${{ format('{0}', github.event.pull_request.title) }}",
			wantErrors:  1,
			description: "format() should not bypass detection",
		},
		{
			name:        "fromJSON with untrusted input",
			runScript:   "echo ${{ fromJSON(github.event.pull_request.body).key }}",
			wantErrors:  1,
			description: "fromJSON() should not bypass detection",
		},
		{
			name:        "join with untrusted input",
			runScript:   "echo ${{ join(github.event.pull_request.labels.*.name, ', ') }}",
			wantErrors:  1, // Array expansion with untrusted labels is now detected
			description: "join() with array expansion - detected",
		},
		{
			name:        "toJSON with untrusted input",
			runScript:   "echo ${{ toJSON(github.event.pull_request) }}",
			wantErrors:  1, // Whole object containing untrusted properties is now detected
			description: "toJSON() with whole object - detected",
		},
		{
			name:        "nested expression with untrusted input",
			runScript:   "echo ${{ format('Title: {0}', github.event.issue.title) }}",
			wantErrors:  1,
			description: "nested expressions should be detected",
		},
		{
			name:        "contains with untrusted input",
			runScript:   "echo ${{ contains(github.event.pull_request.title, 'feat') }}",
			wantErrors:  1,
			description: "contains() should detect untrusted input",
		},
		{
			name:        "complex expression with trusted input",
			runScript:   "echo ${{ format('{0}', github.sha) }}",
			wantErrors:  0,
			description: "trusted inputs should not trigger errors",
		},
		{
			name:        "nested function calls with untrusted object",
			runScript:   "echo ${{ format('{0}', toJSON(github.event.pull_request)) }}",
			wantErrors:  1,
			description: "nested functions with whole untrusted object should be detected",
		},
		{
			name:        "deeply nested function calls",
			runScript:   "echo ${{ format('{0}', format('{0}', github.event.pull_request.title)) }}",
			wantErrors:  1,
			description: "deeply nested functions should detect untrusted input",
		},
		{
			name:        "multiple untrusted arguments in function",
			runScript:   "echo ${{ format('{0} - {1}', github.event.pull_request.title, github.event.issue.title) }}",
			wantErrors:  1,
			description: "multiple untrusted inputs are reported together in a single error",
		},
		{
			name:        "array expansion with labels description",
			runScript:   "echo ${{ join(github.event.pull_request.labels.*.description, ', ') }}",
			wantErrors:  1,
			description: "array expansion with labels.*.description should be detected",
		},
		{
			name:        "toJSON with nested untrusted object",
			runScript:   "echo ${{ toJSON(github.event) }}",
			wantErrors:  1,
			description: "toJSON with parent object containing untrusted properties should be detected",
		},
		{
			name:        "function with mixed trusted and untrusted args",
			runScript:   "echo ${{ format('{0} - {1}', github.sha, github.event.pull_request.title) }}",
			wantErrors:  1,
			description: "function with mixed inputs should detect only untrusted ones",
		},
		{
			name:        "join with trusted array",
			runScript:   "echo ${{ join(github.event.commits.*.sha, ', ') }}",
			wantErrors:  0,
			description: "join with trusted array (commit SHAs) should not trigger error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CodeInjectionCriticalRule()

			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target"},
					},
				},
			}

			step := &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: tt.runScript,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

// TestCodeInjectionCritical_FuncArgDepthReset tests that funcArgDepth is correctly
// reset between different expressions and steps to ensure no state leakage.
func TestCodeInjectionCritical_FuncArgDepthReset(t *testing.T) {
	rule := CodeInjectionCriticalRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	// Create multiple steps with different patterns to test state isolation
	step1 := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: "echo ${{ toJSON(github.event.pull_request) }}",
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
	}

	step2 := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: "echo ${{ github.event.pull_request.title }}",
				Pos:   &ast.Position{Line: 2, Col: 1},
			},
		},
	}

	step3 := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: "echo ${{ format('{0}', toJSON(github.event.issue)) }}",
				Pos:   &ast.Position{Line: 3, Col: 1},
			},
		},
	}

	job := &ast.Job{Steps: []*ast.Step{step1, step2, step3}}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	// Should detect 3 untrusted usages (one per step)
	gotErrors := len(rule.Errors())
	wantErrors := 3

	if gotErrors != wantErrors {
		t.Errorf("funcArgDepth reset test: got %d errors, want %d", gotErrors, wantErrors)
		for i, err := range rule.Errors() {
			t.Logf("Error %d: %s", i+1, err.Description)
		}
	}

	// Verify each step's error is detected correctly
	errors := rule.Errors()
	if len(errors) >= 3 {
		// First error should be about the intermediate node in function
		if !strings.Contains(errors[0].Description, "github.event.pull_request") {
			t.Errorf("First error should mention github.event.pull_request, got: %s", errors[0].Description)
		}

		// Second error should be a normal leaf node detection
		if !strings.Contains(errors[1].Description, "github.event.pull_request.title") {
			t.Errorf("Second error should mention github.event.pull_request.title, got: %s", errors[1].Description)
		}

		// Third error should be about intermediate node in nested function
		if !strings.Contains(errors[2].Description, "github.event.issue") {
			t.Errorf("Third error should mention github.event.issue, got: %s", errors[2].Description)
		}
	}
}
