package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestArgumentInjectionCriticalRule(t *testing.T) {
	t.Parallel()
	rule := ArgumentInjectionCriticalRule()
	if rule.RuleName != "argument-injection-critical" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "argument-injection-critical")
	}
}

func TestArgumentInjectionMediumRule(t *testing.T) {
	t.Parallel()
	rule := ArgumentInjectionMediumRule()
	if rule.RuleName != "argument-injection-medium" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "argument-injection-medium")
	}
}

func TestArgumentInjection_PrivilegedTriggers(t *testing.T) {
	t.Parallel()
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
			name:         "pull_request is not privileged",
			trigger:      "pull_request",
			shouldDetect: false,
			description:  "pull_request should not be detected as privileged (critical rule)",
		},
		{
			name:         "push is not privileged",
			trigger:      "push",
			shouldDetect: false,
			description:  "push should not be detected as privileged (critical rule)",
		},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ArgumentInjectionCriticalRule()

			// Create workflow with specified trigger
			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			// Create job with untrusted input in git command
			job := &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `git diff ${{ github.event.pull_request.head.ref }}`,
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

func TestArgumentInjection_DangerousCommands(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "git diff with untrusted ref",
			runScript:   `git diff ${{ github.event.pull_request.head.ref }}`,
			wantErrors:  1,
			description: "Should detect argument injection in git diff",
		},
		{
			name:        "git fetch with untrusted ref",
			runScript:   `git fetch origin ${{ github.head_ref }}`,
			wantErrors:  1,
			description: "Should detect argument injection in git fetch",
		},
		{
			name:        "curl with untrusted URL",
			runScript:   `curl https://api.example.com/${{ github.event.pull_request.title }}`,
			wantErrors:  1,
			description: "Should detect argument injection in curl",
		},
		{
			name:        "wget with untrusted path",
			runScript:   `wget -O file.txt https://example.com/${{ github.event.pull_request.head.label }}`,
			wantErrors:  1,
			description: "Should detect argument injection in wget",
		},
		{
			name:        "tar with untrusted path",
			runScript:   `tar -xf archive.tar -C ${{ github.event.pull_request.head.ref }}`,
			wantErrors:  1,
			description: "Should detect argument injection in tar",
		},
		{
			name:        "npm with untrusted package",
			runScript:   `npm install ${{ github.event.issue.title }}`,
			wantErrors:  1,
			description: "Should detect argument injection in npm",
		},
		{
			name:        "docker with untrusted tag",
			runScript:   `docker run myimage:${{ github.event.pull_request.head.ref }}`,
			wantErrors:  1,
			description: "Should detect argument injection in docker",
		},
		{
			name:        "kubectl with untrusted namespace",
			runScript:   `kubectl get pods -n ${{ github.event.pull_request.title }}`,
			wantErrors:  1,
			description: "Should detect argument injection in kubectl",
		},
		{
			name:        "aws with untrusted bucket",
			runScript:   `aws s3 ls s3://${{ github.event.pull_request.title }}`,
			wantErrors:  1,
			description: "Should detect argument injection in aws",
		},
		{
			name:        "gh with untrusted input",
			runScript:   `gh pr view ${{ github.event.issue.title }}`,
			wantErrors:  1,
			description: "Should detect argument injection in gh",
		},
		{
			name:        "rsync with untrusted destination",
			runScript:   `rsync -av ./src/ ${{ github.event.pull_request.head.ref }}/`,
			wantErrors:  1,
			description: "Should detect argument injection in rsync",
		},
		{
			name:        "make with untrusted target",
			runScript:   `make ${{ github.event.issue.title }}`,
			wantErrors:  1,
			description: "Should detect argument injection in make",
		},
		{
			name:        "python with untrusted script",
			runScript:   `python ${{ github.event.issue.body }}`,
			wantErrors:  1,
			description: "Should detect argument injection in python",
		},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ArgumentInjectionCriticalRule()

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
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestArgumentInjection_SafePatterns(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		runScript   string
		env         *ast.Env
		wantErrors  int
		description string
	}{
		{
			name:        "end-of-options marker",
			runScript:   `git diff -- ${{ github.event.pull_request.head.ref }}`,
			env:         nil,
			wantErrors:  0,
			description: "Should not detect when -- marker is used",
		},
		{
			name:      "environment variable",
			runScript: `git diff "$PR_REF"`,
			env: &ast.Env{
				Vars: map[string]*ast.EnvVar{
					"pr_ref": {
						Name:  &ast.String{Value: "PR_REF"},
						Value: &ast.String{Value: "${{ github.event.pull_request.head.ref }}"},
					},
				},
			},
			wantErrors:  0,
			description: "Should not detect when using env variable",
		},
		{
			name:        "trusted input",
			runScript:   `git checkout ${{ github.sha }}`,
			env:         nil,
			wantErrors:  0,
			description: "Should not detect trusted inputs like github.sha",
		},
		{
			name:        "trusted repository input",
			runScript:   `echo ${{ github.repository }}`,
			env:         nil,
			wantErrors:  0,
			description: "Should not detect trusted inputs like github.repository",
		},
		{
			name:        "non-dangerous command",
			runScript:   `echo ${{ github.event.pull_request.head.ref }}`,
			env:         nil,
			wantErrors:  0,
			description: "Should not detect echo (not in dangerous commands list)",
		},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ArgumentInjectionCriticalRule()

			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target"},
					},
				},
			}

			step := &ast.Step{
				Env: tt.env,
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
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestArgumentInjection_MultilineScript(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name: "multiple vulnerable commands",
			runScript: `git checkout ${{ github.event.pull_request.head.ref }}
git log ${{ github.head_ref }}
curl -s ${{ github.event.pull_request.title }}`,
			wantErrors:  3,
			description: "Should detect all vulnerable commands in multiline script",
		},
		{
			name: "mixed safe and unsafe",
			runScript: `git checkout ${{ github.sha }}
git diff ${{ github.event.pull_request.head.ref }}
echo "done"`,
			wantErrors:  1,
			description: "Should only detect unsafe commands",
		},
		{
			name: "comment lines ignored",
			runScript: `# git diff ${{ github.event.pull_request.head.ref }}
echo "safe"`,
			wantErrors:  0,
			description: "Should ignore commented lines",
		},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ArgumentInjectionCriticalRule()

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
						Value:   tt.runScript,
						Pos:     &ast.Position{Line: 1, Col: 1},
						Literal: true,
					},
				},
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

func TestArgumentInjection_MediumRule(t *testing.T) {
	t.Parallel()
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
			runScript:   `git diff ${{ github.event.pull_request.head.ref }}`,
			wantErrors:  1,
			description: "Should detect argument injection in pull_request trigger",
		},
		{
			name:        "push trigger + untrusted input",
			trigger:     "push",
			runScript:   `git log ${{ github.head_ref }}`,
			wantErrors:  1,
			description: "Should detect argument injection in push trigger",
		},
		{
			name:        "privileged trigger should not trigger medium rule",
			trigger:     "pull_request_target",
			runScript:   `git diff ${{ github.event.pull_request.head.ref }}`,
			wantErrors:  0,
			description: "Should not detect in privileged triggers (that's for critical rule)",
		},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ArgumentInjectionMediumRule()

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

func TestArgumentInjection_ErrorMessages(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		trigger            string
		runScript          string
		expectedSubstrings []string
		description        string
	}{
		{
			name:      "critical severity message",
			trigger:   "pull_request_target",
			runScript: `git diff ${{ github.event.pull_request.head.ref }}`,
			expectedSubstrings: []string{
				"argument injection (critical)",
				"github.event.pull_request.head.ref",
				"git",
				"--output=/etc/passwd",
			},
			description: "Critical error message should include all relevant info",
		},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ArgumentInjectionCriticalRule()

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

			job := &ast.Job{Steps: []*ast.Step{step}}

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			errors := rule.Errors()
			if len(errors) == 0 {
				t.Fatalf("%s: Expected errors but got none", tt.description)
			}

			errorMsg := errors[0].Description
			for _, substring := range tt.expectedSubstrings {
				if !strings.Contains(errorMsg, substring) {
					t.Errorf("%s: Expected error message to contain %q, got: %s",
						tt.description, substring, errorMsg)
				}
			}
		})
	}
}

func TestArgumentInjection_GenerateEnvVarName(t *testing.T) {
	t.Parallel()
	rule := ArgumentInjectionCriticalRule()

	tests := []struct {
		path     string
		expected string
		desc     string
	}{
		{
			path:     "github.event.pull_request.head.ref",
			expected: "PR_REF",
			desc:     "Should generate PR_REF from pull_request.head.ref",
		},
		{
			path:     "github.event.issue.title",
			expected: "ISSUE_TITLE",
			desc:     "Should generate ISSUE_TITLE from issue.title",
		},
		{
			path:     "github.event.comment.body",
			expected: "COMMENT_BODY",
			desc:     "Should generate COMMENT_BODY from comment.body",
		},
		{
			path:     "github.head_ref",
			expected: "HEAD_REF",
			desc:     "Should generate HEAD_REF from github.head_ref",
		},
		{
			path:     "some.custom.path",
			expected: "PATH",
			desc:     "Should use last part for unknown paths",
		},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()
			result := rule.generateEnvVarName(tt.path)
			if result != tt.expected {
				t.Errorf("generateEnvVarName(%q) = %q, want %q",
					tt.path, result, tt.expected)
			}
		})
	}
}
