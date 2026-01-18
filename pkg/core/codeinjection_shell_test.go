package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestCodeInjection_ShellMetacharacterInjection_Unquoted(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		envVars     map[string]string
		wantErrors  int
		description string
	}{
		{
			name:      "unquoted env var with untrusted input - critical",
			trigger:   "pull_request_target",
			runScript: "echo $PR_TITLE",
			envVars: map[string]string{
				"PR_TITLE": "${{ github.event.pull_request.title }}",
			},
			wantErrors:  1,
			description: "Should detect unquoted env var with untrusted input",
		},
		{
			name:      "quoted env var with untrusted input - safe",
			trigger:   "pull_request_target",
			runScript: `echo "$PR_TITLE"`,
			envVars: map[string]string{
				"PR_TITLE": "${{ github.event.pull_request.title }}",
			},
			wantErrors:  0,
			description: "Should not detect properly quoted env var",
		},
		{
			name:      "unquoted env var with untrusted input - medium",
			trigger:   "pull_request",
			runScript: "echo $PR_TITLE",
			envVars: map[string]string{
				"PR_TITLE": "${{ github.event.pull_request.title }}",
			},
			wantErrors:  1,
			description: "Should detect unquoted env var in medium trigger",
		},
		{
			name:      "env var with trusted input unquoted - safe",
			trigger:   "pull_request_target",
			runScript: "echo $SHA",
			envVars: map[string]string{
				"SHA": "${{ github.sha }}",
			},
			wantErrors:  0,
			description: "Should not detect trusted input even when unquoted",
		},
		{
			name:      "multiple usages - mixed",
			trigger:   "pull_request_target",
			runScript: `echo $PR_TITLE; echo "$PR_TITLE"`,
			envVars: map[string]string{
				"PR_TITLE": "${{ github.event.pull_request.title }}",
			},
			wantErrors:  1,
			description: "Should detect only the unquoted usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := newCodeInjectionRule("critical", tt.trigger == "pull_request_target")
			if tt.trigger != "pull_request_target" {
				rule = newCodeInjectionRule("medium", false)
			}

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
						Pos:   &ast.Position{Line: 10, Col: 5},
					},
				},
			}

			if len(tt.envVars) > 0 {
				step.Env = &ast.Env{
					Vars: make(map[string]*ast.EnvVar),
				}
				for name, value := range tt.envVars {
					step.Env.Vars[strings.ToLower(name)] = &ast.EnvVar{
						Name:  &ast.String{Value: name, Pos: &ast.Position{Line: 1, Col: 1}},
						Value: &ast.String{Value: value, Pos: &ast.Position{Line: 1, Col: 1}},
					}
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

func TestCodeInjection_ShellMetacharacterInjection_Eval(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		envVars     map[string]string
		wantErrors  int
		description string
	}{
		{
			name:      "eval with quoted untrusted env var",
			trigger:   "pull_request_target",
			runScript: `eval "echo $PR_TITLE"`,
			envVars: map[string]string{
				"PR_TITLE": "${{ github.event.pull_request.title }}",
			},
			wantErrors:  2, // Both shell metachar detection and eval pattern detection
			description: "Should detect eval with untrusted input even when quoted",
		},
		{
			name:      "eval with untrusted expression directly",
			trigger:   "pull_request_target",
			runScript: `eval "echo ${{ github.event.pull_request.title }}"`,
			wantErrors:  2, // Both direct injection and eval pattern
			description: "Should detect eval with direct untrusted input",
		},
		{
			name:      "eval with trusted input",
			trigger:   "pull_request_target",
			runScript: `eval "echo $SHA"`,
			envVars: map[string]string{
				"SHA": "${{ github.sha }}",
			},
			wantErrors:  0,
			description: "Should not detect eval with trusted input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := newCodeInjectionRule("critical", true)

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
						Pos:   &ast.Position{Line: 10, Col: 5},
					},
				},
			}

			if len(tt.envVars) > 0 {
				step.Env = &ast.Env{
					Vars: make(map[string]*ast.EnvVar),
				}
				for name, value := range tt.envVars {
					step.Env.Vars[strings.ToLower(name)] = &ast.EnvVar{
						Name:  &ast.String{Value: name, Pos: &ast.Position{Line: 1, Col: 1}},
						Value: &ast.String{Value: value, Pos: &ast.Position{Line: 1, Col: 1}},
					}
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

func TestCodeInjection_ShellMetacharacterInjection_ShellCommand(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		envVars     map[string]string
		wantErrors  int
		description string
	}{
		{
			name:      "sh -c with quoted untrusted env var",
			trigger:   "pull_request_target",
			runScript: `sh -c "echo $PR_TITLE"`,
			envVars: map[string]string{
				"PR_TITLE": "${{ github.event.pull_request.title }}",
			},
			wantErrors:  2, // Both shell metachar detection and sh -c pattern detection
			description: "Should detect sh -c with untrusted input even when quoted",
		},
		{
			name:      "bash -c with quoted untrusted env var",
			trigger:   "pull_request_target",
			runScript: `bash -c "echo $PR_TITLE"`,
			envVars: map[string]string{
				"PR_TITLE": "${{ github.event.pull_request.title }}",
			},
			wantErrors:  2, // Both shell metachar detection and bash -c pattern detection
			description: "Should detect bash -c with untrusted input",
		},
		{
			name:      "bash -c with untrusted expression directly",
			trigger:   "pull_request_target",
			runScript: `bash -c "echo ${{ github.event.pull_request.title }}"`,
			wantErrors:  2, // Both direct injection and shell command pattern
			description: "Should detect bash -c with direct untrusted input",
		},
		{
			name:      "sh -c with trusted input",
			trigger:   "pull_request_target",
			runScript: `sh -c "echo $SHA"`,
			envVars: map[string]string{
				"SHA": "${{ github.sha }}",
			},
			wantErrors:  0,
			description: "Should not detect sh -c with trusted input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := newCodeInjectionRule("critical", true)

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
						Pos:   &ast.Position{Line: 10, Col: 5},
					},
				},
			}

			if len(tt.envVars) > 0 {
				step.Env = &ast.Env{
					Vars: make(map[string]*ast.EnvVar),
				}
				for name, value := range tt.envVars {
					step.Env.Vars[strings.ToLower(name)] = &ast.EnvVar{
						Name:  &ast.String{Value: name, Pos: &ast.Position{Line: 1, Col: 1}},
						Value: &ast.String{Value: value, Pos: &ast.Position{Line: 1, Col: 1}},
					}
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

func TestCodeInjection_ShellMetacharacterInjection_CommandSubstitution(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		envVars     map[string]string
		wantErrors  int
		description string
	}{
		{
			name:      "command substitution with untrusted env var",
			trigger:   "pull_request_target",
			runScript: `result=$(echo $PR_TITLE)`,
			envVars: map[string]string{
				"PR_TITLE": "${{ github.event.pull_request.title }}",
			},
			wantErrors:  1,
			description: "Should detect command substitution with untrusted input",
		},
		{
			name:      "backtick substitution with untrusted env var",
			trigger:   "pull_request_target",
			runScript: "result=`echo $PR_TITLE`",
			envVars: map[string]string{
				"PR_TITLE": "${{ github.event.pull_request.title }}",
			},
			wantErrors:  1,
			description: "Should detect backtick substitution with untrusted input",
		},
		{
			name:      "command substitution with trusted input",
			trigger:   "pull_request_target",
			runScript: `result=$(echo $SHA)`,
			envVars: map[string]string{
				"SHA": "${{ github.sha }}",
			},
			wantErrors:  0,
			description: "Should not detect command substitution with trusted input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := newCodeInjectionRule("critical", true)

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
						Pos:   &ast.Position{Line: 10, Col: 5},
					},
				},
			}

			if len(tt.envVars) > 0 {
				step.Env = &ast.Env{
					Vars: make(map[string]*ast.EnvVar),
				}
				for name, value := range tt.envVars {
					step.Env.Vars[strings.ToLower(name)] = &ast.EnvVar{
						Name:  &ast.String{Value: name, Pos: &ast.Position{Line: 1, Col: 1}},
						Value: &ast.String{Value: value, Pos: &ast.Position{Line: 1, Col: 1}},
					}
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

func TestCodeInjection_ErrorMessages(t *testing.T) {
	// Test that error messages contain appropriate information
	rule := newCodeInjectionRule("critical", true)

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
				Value: "echo $PR_TITLE",
				Pos:   &ast.Position{Line: 10, Col: 5},
			},
		},
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"pr_title": {
					Name:  &ast.String{Value: "PR_TITLE", Pos: &ast.Position{Line: 1, Col: 1}},
					Value: &ast.String{Value: "${{ github.event.pull_request.title }}", Pos: &ast.Position{Line: 1, Col: 1}},
				},
			},
		},
	}

	job := &ast.Job{Steps: []*ast.Step{step}}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	errors := rule.Errors()
	if len(errors) == 0 {
		t.Fatal("Expected at least one error")
	}

	errMsg := errors[0].Description

	// Check that error message contains key information
	if !strings.Contains(errMsg, "shell metacharacters") {
		t.Error("Error message should mention 'shell metacharacters'")
	}
	if !strings.Contains(errMsg, "PR_TITLE") {
		t.Error("Error message should mention the variable name")
	}
	if !strings.Contains(errMsg, "github.event.pull_request.title") {
		t.Error("Error message should mention the untrusted input path")
	}
	if !strings.Contains(errMsg, "without double quotes") {
		t.Error("Error message should explain the issue")
	}
}
