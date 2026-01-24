package core

import (
	"io"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestNewReusableWorkflowTaintRule(t *testing.T) {
	cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
	rule := NewReusableWorkflowTaintRule("/test/workflow.yml", cache)

	if rule.RuleName != "reusable-workflow-taint" {
		t.Errorf("NewReusableWorkflowTaintRule() RuleName = %v, want %v", rule.RuleName, "reusable-workflow-taint")
	}

	if rule.workflowPath != "/test/workflow.yml" {
		t.Errorf("NewReusableWorkflowTaintRule() workflowPath = %v, want %v", rule.workflowPath, "/test/workflow.yml")
	}

	if rule.cache != cache {
		t.Errorf("NewReusableWorkflowTaintRule() cache mismatch")
	}
}

func TestReusableWorkflowTaintRule_VisitWorkflowPre(t *testing.T) {
	tests := []struct {
		name                     string
		workflow                 *ast.Workflow
		wantIsReusable           bool
		wantHasPrivilegedTrigger bool
	}{
		{
			name: "reusable workflow with workflow_call",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WorkflowCallEvent{
						Pos: &ast.Position{Line: 3, Col: 3},
					},
				},
			},
			wantIsReusable:           true,
			wantHasPrivilegedTrigger: false,
		},
		{
			name: "workflow with pull_request trigger",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request"},
					},
				},
			},
			wantIsReusable:           false,
			wantHasPrivilegedTrigger: false,
		},
		{
			name: "workflow with pull_request_target trigger",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target"},
					},
				},
			},
			wantIsReusable:           false,
			wantHasPrivilegedTrigger: true,
		},
		{
			name: "reusable workflow with privileged trigger",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WorkflowCallEvent{
						Pos: &ast.Position{Line: 3, Col: 3},
					},
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "issue_comment"},
					},
				},
			},
			wantIsReusable:           true,
			wantHasPrivilegedTrigger: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			rule := NewReusableWorkflowTaintRule("/test/workflow.yml", cache)

			err := rule.VisitWorkflowPre(tt.workflow)
			if err != nil {
				t.Fatalf("VisitWorkflowPre() error = %v", err)
			}

			if rule.isReusableWorkflow != tt.wantIsReusable {
				t.Errorf("VisitWorkflowPre() isReusableWorkflow = %v, want %v", rule.isReusableWorkflow, tt.wantIsReusable)
			}

			if rule.hasPrivilegedTrigger != tt.wantHasPrivilegedTrigger {
				t.Errorf("VisitWorkflowPre() hasPrivilegedTrigger = %v, want %v", rule.hasPrivilegedTrigger, tt.wantHasPrivilegedTrigger)
			}
		})
	}
}

func TestReusableWorkflowTaintRule_checkWorkflowCallInputs(t *testing.T) {
	tests := []struct {
		name       string
		workflow   *ast.Workflow
		job        *ast.Job
		wantErrors int
	}{
		{
			name: "workflow call with safe input",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "push"},
					},
				},
			},
			job: &ast.Job{
				ID: &ast.String{Value: "call-workflow"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{Value: "./reusable.yml", Pos: &ast.Position{Line: 5, Col: 10}},
					Inputs: map[string]*ast.WorkflowCallInput{
						"message": {
							Name:  &ast.String{Value: "message", Pos: &ast.Position{Line: 6, Col: 10}},
							Value: &ast.String{Value: "Hello World", Pos: &ast.Position{Line: 6, Col: 20}},
						},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name: "workflow call with untrusted input (medium severity)",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request"},
					},
				},
			},
			job: &ast.Job{
				ID: &ast.String{Value: "call-workflow"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{Value: "./reusable.yml", Pos: &ast.Position{Line: 5, Col: 10}},
					Inputs: map[string]*ast.WorkflowCallInput{
						"title": {
							Name:  &ast.String{Value: "title", Pos: &ast.Position{Line: 6, Col: 10}},
							Value: &ast.String{Value: "${{ github.event.pull_request.title }}", Pos: &ast.Position{Line: 6, Col: 17}},
						},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "workflow call with untrusted input (critical severity)",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target"},
					},
				},
			},
			job: &ast.Job{
				ID: &ast.String{Value: "call-workflow"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{Value: "./reusable.yml", Pos: &ast.Position{Line: 5, Col: 10}},
					Inputs: map[string]*ast.WorkflowCallInput{
						"body": {
							Name:  &ast.String{Value: "body", Pos: &ast.Position{Line: 6, Col: 10}},
							Value: &ast.String{Value: "${{ github.event.pull_request.body }}", Pos: &ast.Position{Line: 6, Col: 16}},
						},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "workflow call with multiple untrusted inputs",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "issue_comment"},
					},
				},
			},
			job: &ast.Job{
				ID: &ast.String{Value: "call-workflow"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{Value: "./reusable.yml", Pos: &ast.Position{Line: 5, Col: 10}},
					Inputs: map[string]*ast.WorkflowCallInput{
						"comment": {
							Name:  &ast.String{Value: "comment", Pos: &ast.Position{Line: 6, Col: 10}},
							Value: &ast.String{Value: "${{ github.event.comment.body }}", Pos: &ast.Position{Line: 6, Col: 19}},
						},
						"author": {
							Name:  &ast.String{Value: "author", Pos: &ast.Position{Line: 7, Col: 10}},
							Value: &ast.String{Value: "${{ github.event.head_commit.author.name }}", Pos: &ast.Position{Line: 7, Col: 18}},
						},
					},
				},
			},
			wantErrors: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			rule := NewReusableWorkflowTaintRule("/test/workflow.yml", cache)
			rule.EnableDebugOutput(io.Discard)

			err := rule.VisitWorkflowPre(tt.workflow)
			if err != nil {
				t.Fatalf("VisitWorkflowPre() error = %v", err)
			}

			err = rule.VisitJobPre(tt.job)
			if err != nil {
				t.Fatalf("VisitJobPre() error = %v", err)
			}

			errors := rule.Errors()
			if len(errors) != tt.wantErrors {
				t.Errorf("checkWorkflowCallInputs() error count = %v, want %v", len(errors), tt.wantErrors)
				for i, e := range errors {
					t.Logf("Error %d: %s", i+1, e.Description)
				}
			}
		})
	}
}

func TestReusableWorkflowTaintRule_checkTaintedInputUsage(t *testing.T) {
	tests := []struct {
		name       string
		workflow   *ast.Workflow
		job        *ast.Job
		wantErrors int
	}{
		{
			name: "reusable workflow with safe input usage",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WorkflowCallEvent{
						Pos:    &ast.Position{Line: 3, Col: 3},
						Inputs: []*ast.WorkflowCallEventInput{},
					},
				},
			},
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: "echo 'Hello World'",
								Pos:   &ast.Position{Line: 10, Col: 10},
							},
						},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name: "reusable workflow with inputs.* in run script",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WorkflowCallEvent{
						Pos: &ast.Position{Line: 3, Col: 3},
						Inputs: []*ast.WorkflowCallEventInput{
							{
								Name: &ast.String{Value: "title"},
								ID:   "title",
							},
						},
					},
				},
			},
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: "echo ${{ inputs.title }}",
								Pos:   &ast.Position{Line: 10, Col: 10},
							},
						},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "reusable workflow with inputs.* in env (safe)",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WorkflowCallEvent{
						Pos: &ast.Position{Line: 3, Col: 3},
						Inputs: []*ast.WorkflowCallEventInput{
							{
								Name: &ast.String{Value: "title"},
								ID:   "title",
							},
						},
					},
				},
			},
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Steps: []*ast.Step{
					{
						Env: &ast.Env{
							Vars: map[string]*ast.EnvVar{
								"title": {
									Name:  &ast.String{Value: "TITLE"},
									Value: &ast.String{Value: "${{ inputs.title }}", Pos: &ast.Position{Line: 11, Col: 15}},
								},
							},
						},
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: "echo $TITLE",
								Pos:   &ast.Position{Line: 12, Col: 10},
							},
						},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name: "reusable workflow with inputs.* in github-script",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WorkflowCallEvent{
						Pos: &ast.Position{Line: 3, Col: 3},
						Inputs: []*ast.WorkflowCallEventInput{
							{
								Name: &ast.String{Value: "message"},
								ID:   "message",
							},
						},
					},
				},
			},
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecAction{
							Uses: &ast.String{Value: "actions/github-script@v7"},
							Inputs: map[string]*ast.Input{
								"script": {
									Name: &ast.String{Value: "script"},
									Value: &ast.String{
										Value: "console.log('${{ inputs.message }}')",
										Pos:   &ast.Position{Line: 10, Col: 10},
									},
								},
							},
						},
					},
				},
			},
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			rule := NewReusableWorkflowTaintRule("/test/workflow.yml", cache)
			rule.EnableDebugOutput(io.Discard)

			err := rule.VisitWorkflowPre(tt.workflow)
			if err != nil {
				t.Fatalf("VisitWorkflowPre() error = %v", err)
			}

			err = rule.VisitJobPre(tt.job)
			if err != nil {
				t.Fatalf("VisitJobPre() error = %v", err)
			}

			errors := rule.Errors()
			if len(errors) != tt.wantErrors {
				t.Errorf("checkTaintedInputUsage() error count = %v, want %v", len(errors), tt.wantErrors)
				for i, e := range errors {
					t.Logf("Error %d: %s", i+1, e.Description)
				}
			}
		})
	}
}

func TestReusableWorkflowTaintRule_findInputReferences(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		wantRefs []string
	}{
		{
			name:     "simple inputs.title",
			expr:     "inputs.title",
			wantRefs: []string{"inputs.title"},
		},
		{
			name:     "no inputs reference",
			expr:     "github.event.pull_request.title",
			wantRefs: nil,
		},
		{
			name:     "inputs in function call",
			expr:     "contains(inputs.labels, 'bug')",
			wantRefs: []string{"inputs.labels"},
		},
		{
			name:     "multiple inputs references",
			expr:     "format('{0}: {1}', inputs.title, inputs.body)",
			wantRefs: []string{"inputs.title", "inputs.body"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			rule := NewReusableWorkflowTaintRule("/test/workflow.yml", cache)

			refs := rule.findInputReferences(tt.expr)

			if len(refs) != len(tt.wantRefs) {
				t.Errorf("findInputReferences() got %v refs, want %v", len(refs), len(tt.wantRefs))
				t.Logf("Got: %v", refs)
				t.Logf("Want: %v", tt.wantRefs)
				return
			}

			for i, ref := range refs {
				if ref != tt.wantRefs[i] {
					t.Errorf("findInputReferences() ref[%d] = %v, want %v", i, ref, tt.wantRefs[i])
				}
			}
		})
	}
}

func TestReusableWorkflowTaintRule_generateEnvVarName(t *testing.T) {
	tests := []struct {
		name      string
		inputName string
		want      string
	}{
		{
			name:      "simple name",
			inputName: "title",
			want:      "INPUT_TITLE",
		},
		{
			name:      "name with hyphen",
			inputName: "pr-title",
			want:      "INPUT_PR_TITLE",
		},
		{
			name:      "name with dots",
			inputName: "commit.message",
			want:      "INPUT_COMMIT_MESSAGE",
		},
		{
			name:      "empty name",
			inputName: "",
			want:      "UNTRUSTED_INPUT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			rule := NewReusableWorkflowTaintRule("/test/workflow.yml", cache)

			got := rule.generateEnvVarName(tt.inputName)
			if got != tt.want {
				t.Errorf("generateEnvVarName(%q) = %v, want %v", tt.inputName, got, tt.want)
			}
		})
	}
}

func TestReusableWorkflowTaintRule_findUntrustedExpressionsInString(t *testing.T) {
	tests := []struct {
		name      string
		str       *ast.String
		wantPaths []string
	}{
		{
			name: "untrusted github.event.pull_request.title",
			str: &ast.String{
				Value: "${{ github.event.pull_request.title }}",
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
			wantPaths: []string{"github.event.pull_request.title"},
		},
		{
			name: "safe expression",
			str: &ast.String{
				Value: "${{ github.ref }}",
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
			wantPaths: nil,
		},
		{
			name: "multiple untrusted expressions",
			str: &ast.String{
				Value: "${{ github.event.pull_request.title }} - ${{ github.event.pull_request.body }}",
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
			wantPaths: []string{"github.event.pull_request.title", "github.event.pull_request.body"},
		},
		{
			name: "head_ref is untrusted",
			str: &ast.String{
				Value: "${{ github.head_ref }}",
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
			wantPaths: []string{"github.head_ref"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			rule := NewReusableWorkflowTaintRule("/test/workflow.yml", cache)

			paths := rule.findUntrustedExpressionsInString(tt.str)

			if len(paths) != len(tt.wantPaths) {
				t.Errorf("findUntrustedExpressionsInString() got %v paths, want %v", len(paths), len(tt.wantPaths))
				t.Logf("Got: %v", paths)
				t.Logf("Want: %v", tt.wantPaths)
				return
			}

			for i, path := range paths {
				if path != tt.wantPaths[i] {
					t.Errorf("findUntrustedExpressionsInString() path[%d] = %v, want %v", i, path, tt.wantPaths[i])
				}
			}
		})
	}
}

func TestIsPrivilegedTrigger(t *testing.T) {
	tests := []struct {
		name      string
		eventName string
		want      bool
	}{
		{"pull_request_target", "pull_request_target", true},
		{"workflow_run", "workflow_run", true},
		{"issue_comment", "issue_comment", true},
		{"issues", "issues", true},
		{"discussion_comment", "discussion_comment", true},
		{"pull_request", "pull_request", false},
		{"push", "push", false},
		{"schedule", "schedule", false},
		{"workflow_dispatch", "workflow_dispatch", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrivilegedTrigger(tt.eventName)
			if got != tt.want {
				t.Errorf("isPrivilegedTrigger(%q) = %v, want %v", tt.eventName, got, tt.want)
			}
		})
	}
}
