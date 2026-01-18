package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestCodeInjectionMediumRule(t *testing.T) {
	rule := CodeInjectionMediumRule()
	if rule.RuleName != "code-injection-medium" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "code-injection-medium")
	}
}

func TestCodeInjectionMedium_NormalTriggers(t *testing.T) {
	tests := []struct {
		name         string
		trigger      string
		shouldDetect bool
		description  string
	}{
		{
			name:         "pull_request is normal trigger",
			trigger:      "pull_request",
			shouldDetect: true,
			description:  "pull_request should be detected by medium",
		},
		{
			name:         "push is normal trigger",
			trigger:      "push",
			shouldDetect: true,
			description:  "push should be detected by medium",
		},
		{
			name:         "schedule is normal trigger",
			trigger:      "schedule",
			shouldDetect: true,
			description:  "schedule should be detected by medium",
		},
		{
			name:         "pull_request_target is privileged (skip)",
			trigger:      "pull_request_target",
			shouldDetect: false,
			description:  "pull_request_target should not be detected by medium",
		},
		{
			name:         "workflow_run is privileged (skip)",
			trigger:      "workflow_run",
			shouldDetect: false,
			description:  "workflow_run should not be detected by medium",
		},
		{
			name:         "issue_comment is privileged (skip)",
			trigger:      "issue_comment",
			shouldDetect: false,
			description:  "issue_comment should not be detected by medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CodeInjectionMediumRule()

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

func TestCodeInjectionMedium_RunScript(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "normal trigger + untrusted input",
			trigger:     "pull_request",
			runScript:   `echo "${{ github.event.pull_request.title }}"`,
			wantErrors:  1,
			description: "Should detect untrusted input in normal trigger",
		},
		{
			name:        "privileged trigger + untrusted input",
			trigger:     "pull_request_target",
			runScript:   `echo "${{ github.event.pull_request.title }}"`,
			wantErrors:  0,
			description: "Should not detect in privileged trigger (handled by critical)",
		},
		{
			name:        "normal trigger + trusted input",
			trigger:     "pull_request",
			runScript:   `echo "${{ github.sha }}"`,
			wantErrors:  0,
			description: "Should not detect trusted input",
		},
		{
			name:        "normal trigger + env variable",
			trigger:     "pull_request",
			runScript:   `echo "$PR_TITLE"`,
			wantErrors:  0,
			description: "Should not detect when using env variable",
		},
		{
			name:    "normal trigger + multiple untrusted inputs",
			trigger: "push",
			runScript: `echo "${{ github.event.pull_request.title }}"
echo "${{ github.event.pull_request.body }}"`,
			wantErrors:  2,
			description: "Should detect multiple untrusted inputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CodeInjectionMediumRule()

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

func TestCodeInjectionMedium_GitHubScript(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		script      string
		withEnv     bool
		wantErrors  int
		description string
	}{
		{
			name:        "normal trigger + untrusted input in script",
			trigger:     "pull_request",
			script:      `console.log('${{ github.event.pull_request.title }}')`,
			withEnv:     false,
			wantErrors:  1,
			description: "Should detect untrusted input in github-script",
		},
		{
			name:        "normal trigger + env variable in script",
			trigger:     "pull_request",
			script:      `const { PR_TITLE } = process.env`,
			withEnv:     true,
			wantErrors:  0,
			description: "Should not detect when using env variable",
		},
		{
			name:        "privileged trigger + untrusted input",
			trigger:     "issue_comment",
			script:      `console.log('${{ github.event.comment.body }}')`,
			withEnv:     false,
			wantErrors:  0,
			description: "Should not detect in privileged trigger (handled by critical)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := CodeInjectionMediumRule()

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

func TestCodeInjectionMedium_NoOverlapWithCritical(t *testing.T) {
	// Test that medium and critical don't overlap
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
						Value: `echo "${{ github.event.pull_request.title }}"`,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	criticalRule := CodeInjectionCriticalRule()
	mediumRule := CodeInjectionMediumRule()

	// Visit with critical rule
	_ = criticalRule.VisitWorkflowPre(workflow)
	_ = criticalRule.VisitJobPre(job)

	// Visit with medium rule
	_ = mediumRule.VisitWorkflowPre(workflow)
	_ = mediumRule.VisitJobPre(job)

	criticalErrors := len(criticalRule.Errors())
	mediumErrors := len(mediumRule.Errors())

	if criticalErrors == 0 {
		t.Error("Critical rule should detect privileged trigger")
	}
	if mediumErrors != 0 {
		t.Errorf("Medium rule should NOT detect privileged trigger, but got %d errors: %v",
			mediumErrors, mediumRule.Errors())
	}
}
