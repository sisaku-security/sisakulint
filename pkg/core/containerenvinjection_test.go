package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestContainerEnvInjectionCritical_RuleName(t *testing.T) {
	t.Parallel()
	rule := ContainerEnvInjectionCriticalRule()
	if rule.RuleName != "container-env-injection-critical" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "container-env-injection-critical")
	}
}

func TestContainerEnvInjectionMedium_RuleName(t *testing.T) {
	t.Parallel()
	rule := ContainerEnvInjectionMediumRule()
	if rule.RuleName != "container-env-injection-medium" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "container-env-injection-medium")
	}
}

// buildContainerEnvJob builds a Job with container.env set to the given expression value.
func buildContainerEnvJob(envVarValue string) *ast.Job {
	pos := &ast.Position{Line: 1, Col: 1}
	return &ast.Job{
		Container: &ast.Container{
			Image: &ast.String{Value: "node:18"},
			Env: &ast.Env{
				Vars: map[string]*ast.EnvVar{
					"branch": {
						Name:  &ast.String{Value: "BRANCH", Pos: pos},
						Value: &ast.String{Value: envVarValue, Pos: pos},
					},
				},
			},
		},
	}
}

// buildServiceEnvJob builds a Job with services.<id>.container.env set to the given expression value.
func buildServiceEnvJob(serviceName, envVarValue string) *ast.Job {
	pos := &ast.Position{Line: 1, Col: 1}
	return &ast.Job{
		Services: map[string]*ast.Service{
			serviceName: {
				Name: &ast.String{Value: serviceName},
				Container: &ast.Container{
					Image: &ast.String{Value: "redis"},
					Env: &ast.Env{
						Vars: map[string]*ast.EnvVar{
							"custom": {
								Name:  &ast.String{Value: "CUSTOM", Pos: pos},
								Value: &ast.String{Value: envVarValue, Pos: pos},
							},
						},
					},
				},
			},
		},
	}
}

func buildWorkflowWithTrigger(trigger string) *ast.Workflow {
	return &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: trigger},
			},
		},
	}
}

func TestContainerEnvInjectionCritical_ContainerEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		trigger    string
		envValue   string
		wantErrors int
		desc       string
	}{
		{
			name:       "privileged trigger + untrusted container.env",
			trigger:    "pull_request_target",
			envValue:   "${{ github.event.pull_request.head.ref }}",
			wantErrors: 1,
			desc:       "should detect untrusted input in container.env with privileged trigger",
		},
		{
			name:       "privileged trigger + trusted container.env",
			trigger:    "pull_request_target",
			envValue:   "${{ github.sha }}",
			wantErrors: 0,
			desc:       "should not detect trusted input in container.env",
		},
		{
			name:       "non-privileged trigger + untrusted container.env (critical rule skips)",
			trigger:    "pull_request",
			envValue:   "${{ github.event.pull_request.head.ref }}",
			wantErrors: 0,
			desc:       "critical rule should not fire on non-privileged trigger",
		},
		{
			name:       "workflow_run trigger + untrusted container.env",
			trigger:    "workflow_run",
			envValue:   "${{ github.event.workflow_run.head_branch }}",
			wantErrors: 1,
			desc:       "workflow_run is a privileged trigger",
		},
		{
			name:       "issue_comment trigger + untrusted container.env",
			trigger:    "issue_comment",
			envValue:   "${{ github.event.comment.body }}",
			wantErrors: 1,
			desc:       "issue_comment is a privileged trigger",
		},
		{
			name:       "no expression in container.env",
			trigger:    "pull_request_target",
			envValue:   "static-value",
			wantErrors: 0,
			desc:       "static values should not be flagged",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ContainerEnvInjectionCriticalRule()
			workflow := buildWorkflowWithTrigger(tt.trigger)
			job := buildContainerEnvJob(tt.envValue)

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			if got := len(rule.Errors()); got != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d. Errors: %v", tt.desc, got, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestContainerEnvInjectionCritical_ServiceEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		trigger    string
		envValue   string
		wantErrors int
		desc       string
	}{
		{
			name:       "privileged trigger + untrusted services env",
			trigger:    "pull_request_target",
			envValue:   "${{ github.event.issue.body }}",
			wantErrors: 1,
			desc:       "should detect untrusted input in services.*.container.env with privileged trigger",
		},
		{
			name:       "privileged trigger + trusted services env",
			trigger:    "pull_request_target",
			envValue:   "${{ github.sha }}",
			wantErrors: 0,
			desc:       "should not detect trusted input in services env",
		},
		{
			name:       "non-privileged trigger + untrusted services env (critical skips)",
			trigger:    "push",
			envValue:   "${{ github.event.head_commit.message }}",
			wantErrors: 0,
			desc:       "critical rule should not fire on non-privileged trigger",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ContainerEnvInjectionCriticalRule()
			workflow := buildWorkflowWithTrigger(tt.trigger)
			job := buildServiceEnvJob("redis", tt.envValue)

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			if got := len(rule.Errors()); got != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d. Errors: %v", tt.desc, got, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestContainerEnvInjectionMedium_ContainerEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		trigger    string
		envValue   string
		wantErrors int
		desc       string
	}{
		{
			name:       "normal trigger + untrusted container.env",
			trigger:    "pull_request",
			envValue:   "${{ github.event.pull_request.head.ref }}",
			wantErrors: 1,
			desc:       "medium rule should detect untrusted input with normal trigger",
		},
		{
			name:       "push trigger + untrusted container.env",
			trigger:    "push",
			envValue:   "${{ github.event.head_commit.message }}",
			wantErrors: 1,
			desc:       "push trigger should be detected by medium rule",
		},
		{
			name:       "privileged trigger + untrusted (medium rule skips to avoid duplicate)",
			trigger:    "pull_request_target",
			envValue:   "${{ github.event.pull_request.head.ref }}",
			wantErrors: 0,
			desc:       "medium rule should not fire on privileged trigger (critical rule handles it)",
		},
		{
			name:       "normal trigger + trusted container.env",
			trigger:    "pull_request",
			envValue:   "${{ github.sha }}",
			wantErrors: 0,
			desc:       "trusted input should not be flagged",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ContainerEnvInjectionMediumRule()
			workflow := buildWorkflowWithTrigger(tt.trigger)
			job := buildContainerEnvJob(tt.envValue)

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			if got := len(rule.Errors()); got != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d. Errors: %v", tt.desc, got, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestContainerEnvInjectionMedium_ServiceEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		trigger    string
		envValue   string
		wantErrors int
		desc       string
	}{
		{
			name:       "normal trigger + untrusted services env",
			trigger:    "pull_request",
			envValue:   "${{ github.event.pull_request.title }}",
			wantErrors: 1,
			desc:       "medium rule should detect untrusted input in services env with normal trigger",
		},
		{
			name:       "privileged trigger + untrusted services env (medium skips)",
			trigger:    "issue_comment",
			envValue:   "${{ github.event.comment.body }}",
			wantErrors: 0,
			desc:       "medium rule should not fire on privileged trigger",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := ContainerEnvInjectionMediumRule()
			workflow := buildWorkflowWithTrigger(tt.trigger)
			job := buildServiceEnvJob("redis", tt.envValue)

			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			if got := len(rule.Errors()); got != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d. Errors: %v", tt.desc, got, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestContainerEnvInjection_NoContainer(t *testing.T) {
	t.Parallel()

	rule := ContainerEnvInjectionCriticalRule()
	workflow := buildWorkflowWithTrigger("pull_request_target")
	// Job with no container
	job := &ast.Job{
		Steps: []*ast.Step{
			{Exec: &ast.ExecRun{Run: &ast.String{Value: "echo hello"}}},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	if got := len(rule.Errors()); got != 0 {
		t.Errorf("job without container: got %d errors, want 0", got)
	}
}

func TestContainerEnvInjection_ErrorMessageContainsUntrustedPath(t *testing.T) {
	t.Parallel()

	rule := ContainerEnvInjectionCriticalRule()
	workflow := buildWorkflowWithTrigger("pull_request_target")
	job := buildContainerEnvJob("${{ github.event.pull_request.head.ref }}")

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	errs := rule.Errors()
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}

	msg := errs[0].Description
	if msg == "" {
		t.Error("error description should not be empty")
	}
}
