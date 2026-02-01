package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestRequestForgeryCriticalRule(t *testing.T) {
	rule := RequestForgeryCriticalRule()
	if rule.RuleName != "request-forgery-critical" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "request-forgery-critical")
	}
}

func TestRequestForgeryMediumRule(t *testing.T) {
	rule := RequestForgeryMediumRule()
	if rule.RuleName != "request-forgery-medium" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "request-forgery-medium")
	}
}

func TestRequestForgeryCritical_PrivilegedTriggers(t *testing.T) {
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
			rule := RequestForgeryCriticalRule()

			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			job := &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `curl "${{ github.event.issue.body }}"`,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			err := rule.VisitWorkflowPre(workflow)
			if err != nil {
				t.Fatalf("VisitWorkflowPre() returned error: %v", err)
			}

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

func TestRequestForgery_NetworkCommands(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "curl with untrusted URL",
			trigger:     "issue_comment",
			runScript:   `curl "${{ github.event.comment.body }}"`,
			wantErrors:  1,
			description: "Should detect curl with untrusted input as URL",
		},
		{
			name:        "wget with untrusted URL",
			trigger:     "issue_comment",
			runScript:   `wget "${{ github.event.comment.body }}"`,
			wantErrors:  1,
			description: "Should detect wget with untrusted input",
		},
		{
			name:        "curl with untrusted host",
			trigger:     "pull_request_target",
			runScript:   `curl "https://${{ github.event.pull_request.title }}/api"`,
			wantErrors:  1,
			description: "Should detect curl with untrusted host",
		},
		{
			name:        "curl with trusted input",
			trigger:     "issue_comment",
			runScript:   `curl "https://api.github.com/repos/${{ github.repository }}"`,
			wantErrors:  0,
			description: "Should not detect curl with trusted input",
		},
		{
			name:        "curl with env variable",
			trigger:     "issue_comment",
			runScript:   `curl "$TARGET_URL"`,
			wantErrors:  0,
			description: "Should not detect curl with env variable",
		},
		{
			name:        "non-privileged trigger with untrusted input",
			trigger:     "pull_request",
			runScript:   `curl "${{ github.event.pull_request.body }}"`,
			wantErrors:  0,
			description: "Critical rule should not detect in non-privileged triggers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := RequestForgeryCriticalRule()

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

func TestRequestForgery_CloudMetadataDetection(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "AWS metadata URL",
			runScript:   `curl http://169.254.169.254/latest/meta-data/`,
			wantErrors:  1,
			description: "Should detect AWS metadata service URL",
		},
		{
			name:        "GCP metadata URL",
			runScript:   `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/`,
			wantErrors:  1,
			description: "Should detect GCP metadata service URL",
		},
		{
			name:        "AWS ECS metadata URL",
			runScript:   `curl http://169.254.170.2/v2/credentials`,
			wantErrors:  1,
			description: "Should detect AWS ECS metadata service URL",
		},
		{
			name:        "Safe URL",
			runScript:   `curl https://api.github.com/`,
			wantErrors:  0,
			description: "Should not detect safe URLs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := RequestForgeryCriticalRule()

			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "issue_comment"},
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

func TestRequestForgery_GitHubScript(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		script      string
		wantErrors  int
		description string
	}{
		{
			name:        "fetch with untrusted URL in github-script",
			trigger:     "issue_comment",
			script:      `await fetch('${{ github.event.comment.body }}')`,
			wantErrors:  1,
			description: "Should detect fetch with untrusted URL in github-script",
		},
		{
			name:        "axios.get with untrusted URL",
			trigger:     "issue_comment",
			script:      `axios.get('${{ github.event.comment.body }}')`,
			wantErrors:  1,
			description: "Should detect axios.get with untrusted URL",
		},
		{
			name:        "fetch with process.env",
			trigger:     "issue_comment",
			script:      `await fetch(process.env.TARGET_URL)`,
			wantErrors:  0,
			description: "Should not detect fetch with process.env",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := RequestForgeryCriticalRule()

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

func TestRequestForgeryMedium_NormalTriggers(t *testing.T) {
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
			description:  "pull_request should be detected by medium rule",
		},
		{
			name:         "push is normal trigger",
			trigger:      "push",
			shouldDetect: true,
			description:  "push should be detected by medium rule",
		},
		{
			name:         "schedule is normal trigger",
			trigger:      "schedule",
			shouldDetect: true,
			description:  "schedule should be detected by medium rule",
		},
		{
			name:         "pull_request_target is privileged",
			trigger:      "pull_request_target",
			shouldDetect: false,
			description:  "pull_request_target should not be detected by medium rule",
		},
		{
			name:         "issue_comment is privileged",
			trigger:      "issue_comment",
			shouldDetect: false,
			description:  "issue_comment should not be detected by medium rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := RequestForgeryMediumRule()

			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			job := &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `curl "${{ github.event.pull_request.body }}"`,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

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

func TestRequestForgery_SeverityDetermination(t *testing.T) {
	tests := []struct {
		name             string
		runScript        string
		expectedSeverity RequestForgerySeverity
		description      string
	}{
		{
			name:             "Full URL as untrusted input",
			runScript:        `curl ${{ github.event.issue.body }}`,
			expectedSeverity: RequestForgerySeverityURL,
			description:      "Full URL should be highest severity",
		},
		{
			name:             "Host as untrusted input",
			runScript:        `curl https://${{ github.event.issue.title }}/api`,
			expectedSeverity: RequestForgerySeverityHost,
			description:      "Host should be high severity",
		},
		{
			name:             "Path as untrusted input",
			runScript:        `curl https://api.example.com/${{ github.event.issue.body }}`,
			expectedSeverity: RequestForgerySeverityPath,
			description:      "Path should be medium severity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := RequestForgeryCriticalRule()

			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "issue_comment"},
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

			if len(rule.stepsWithUntrusted) == 0 {
				t.Errorf("%s: Expected untrusted step to be recorded", tt.description)
				return
			}

			for _, stepInfo := range rule.stepsWithUntrusted {
				for _, exprInfo := range stepInfo.untrustedExprs {
					if exprInfo.severity != tt.expectedSeverity {
						t.Errorf("%s: got severity %d, want %d",
							tt.description, exprInfo.severity, tt.expectedSeverity)
					}
				}
			}
		})
	}
}

func TestRequestForgery_EnvVarName(t *testing.T) {
	rule := RequestForgeryCriticalRule()

	tests := []struct {
		path     string
		expected string
	}{
		{"github.event.issue.body", "ISSUE_BODY"},
		{"github.event.pull_request.title", "PR_TITLE"},
		{"github.event.comment.body", "COMMENT_BODY"},
		{"github.head_ref", "HEAD_REF"},
		{"some.unknown.path", "PATH"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := rule.generateEnvVarName(tt.path)
			if result != tt.expected {
				t.Errorf("generateEnvVarName(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestRequestForgery_DetectNetworkCommand(t *testing.T) {
	rule := RequestForgeryCriticalRule()

	tests := []struct {
		line     string
		expected string
	}{
		{`curl https://example.com`, "curl"},
		{`wget https://example.com`, "wget"},
		{`curl -X POST -H "Content-Type: application/json" https://example.com`, "curl"},
		{`wget -q https://example.com`, "wget"},
		{`fetch('https://example.com')`, "fetch"},
		{`axios.get('https://example.com')`, "axios"},
		{`axios.post('https://example.com', data)`, "axios"},
		{`echo "hello"`, ""},
		{`cat file.txt`, ""},
		{`Invoke-WebRequest -Uri "https://example.com"`, "Invoke-WebRequest"},
		{`iwr "https://example.com"`, "iwr"},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			result := rule.detectNetworkCommand(tt.line)
			if result != tt.expected {
				t.Errorf("detectNetworkCommand(%q) = %q, want %q", tt.line, result, tt.expected)
			}
		})
	}
}

// TestRequestForgery_MultipleUntrustedInputs tests detection of multiple untrusted inputs
func TestRequestForgery_MultipleUntrustedInputs(t *testing.T) {
	rule := RequestForgeryCriticalRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "issue_comment"},
			},
		},
	}

	// Multiple untrusted inputs in same script
	step := &ast.Step{
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: `curl "${{ github.event.comment.body }}"
wget "${{ github.event.issue.title }}"`,
				Pos: &ast.Position{Line: 1, Col: 1},
			},
		},
	}

	job := &ast.Job{Steps: []*ast.Step{step}}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	// Should detect both untrusted inputs
	gotErrors := len(rule.Errors())
	if gotErrors != 2 {
		t.Errorf("Expected 2 errors for multiple untrusted inputs, got %d. Errors: %v",
			gotErrors, rule.Errors())
	}
}
