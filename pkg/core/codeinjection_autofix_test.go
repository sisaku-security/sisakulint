package core

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

func TestCodeInjectionCritical_AutoFix_YAMLOutput(t *testing.T) {
	tests := []struct {
		name          string
		trigger       string
		stepName      string
		runScript     string
		wantEnvVar    string
		wantEnvValue  string
		wantRunScript string
	}{
		{
			name:          "PR title auto-fix in run script",
			trigger:       "pull_request_target",
			stepName:      "Test",
			runScript:     `echo "${{ github.event.pull_request.title }}"`,
			wantEnvVar:    "PR_TITLE",
			wantEnvValue:  "${{ github.event.pull_request.title }}",
			wantRunScript: `echo "$PR_TITLE"`,
		},
		{
			name:          "Comment body auto-fix in run script",
			trigger:       "issue_comment",
			stepName:      "Process",
			runScript:     `echo "${{ github.event.comment.body }}"`,
			wantEnvVar:    "COMMENT_BODY",
			wantEnvValue:  "${{ github.event.comment.body }}",
			wantRunScript: `echo "$COMMENT_BODY"`,
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
				Name: &ast.String{Value: tt.stepName},
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: tt.runScript,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
				BaseNode: &yaml.Node{
					Kind: yaml.MappingNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Value: "name"},
						{Kind: yaml.ScalarNode, Value: tt.stepName},
						{Kind: yaml.ScalarNode, Value: "run"},
						{Kind: yaml.ScalarNode, Value: tt.runScript},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}

			// Visit workflow and job
			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			// Should detect the vulnerability
			if len(rule.Errors()) == 0 {
				t.Fatal("Expected errors but got none")
			}

			// Apply auto-fix
			if err := rule.FixStep(step); err != nil {
				t.Fatalf("FixStep() error = %v", err)
			}

			// Verify AST was updated
			if step.Env == nil {
				t.Fatal("step.Env should not be nil after fix")
			}
			if _, exists := step.Env.Vars[strings.ToLower(tt.wantEnvVar)]; !exists {
				t.Errorf("Expected env var %q not found in AST", tt.wantEnvVar)
			}

			// Verify YAML output
			var buf bytes.Buffer
			enc := yaml.NewEncoder(&buf)
			if err := enc.Encode(step.BaseNode); err != nil {
				t.Fatalf("Failed to encode YAML: %v", err)
			}
			yamlOutput := buf.String()

			// Check that env section exists in YAML
			if !strings.Contains(yamlOutput, "env:") {
				t.Errorf("YAML output should contain 'env:' section, got:\n%s", yamlOutput)
			}

			// Check that the environment variable is in YAML
			if !strings.Contains(yamlOutput, tt.wantEnvVar+":") {
				t.Errorf("YAML output should contain env var %q, got:\n%s", tt.wantEnvVar, yamlOutput)
			}

			// Check that the environment variable value is in YAML
			if !strings.Contains(yamlOutput, tt.wantEnvValue) {
				t.Errorf("YAML output should contain env value %q, got:\n%s", tt.wantEnvValue, yamlOutput)
			}

			// Check that run script was replaced
			if !strings.Contains(yamlOutput, tt.wantRunScript) {
				t.Errorf("YAML output should contain replaced run script %q, got:\n%s", tt.wantRunScript, yamlOutput)
			}
		})
	}
}

func TestCodeInjectionMedium_AutoFix_YAMLOutput(t *testing.T) {
	tests := []struct {
		name          string
		trigger       string
		stepName      string
		runScript     string
		wantEnvVar    string
		wantEnvValue  string
		wantRunScript string
	}{
		{
			name:          "PR title auto-fix in normal trigger",
			trigger:       "pull_request",
			stepName:      "Test",
			runScript:     `echo "${{ github.event.pull_request.title }}"`,
			wantEnvVar:    "PR_TITLE",
			wantEnvValue:  "${{ github.event.pull_request.title }}",
			wantRunScript: `echo "$PR_TITLE"`,
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
				Name: &ast.String{Value: tt.stepName},
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: tt.runScript,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
				BaseNode: &yaml.Node{
					Kind: yaml.MappingNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Value: "name"},
						{Kind: yaml.ScalarNode, Value: tt.stepName},
						{Kind: yaml.ScalarNode, Value: "run"},
						{Kind: yaml.ScalarNode, Value: tt.runScript},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}

			// Visit workflow and job
			_ = rule.VisitWorkflowPre(workflow)
			_ = rule.VisitJobPre(job)

			// Should detect the vulnerability
			if len(rule.Errors()) == 0 {
				t.Fatal("Expected errors but got none")
			}

			// Apply auto-fix
			if err := rule.FixStep(step); err != nil {
				t.Fatalf("FixStep() error = %v", err)
			}

			// Verify YAML output
			var buf bytes.Buffer
			enc := yaml.NewEncoder(&buf)
			if err := enc.Encode(step.BaseNode); err != nil {
				t.Fatalf("Failed to encode YAML: %v", err)
			}
			yamlOutput := buf.String()

			// Check that env section exists in YAML
			if !strings.Contains(yamlOutput, "env:") {
				t.Errorf("YAML output should contain 'env:' section, got:\n%s", yamlOutput)
			}

			// Check that the environment variable is in YAML
			if !strings.Contains(yamlOutput, tt.wantEnvVar+":") {
				t.Errorf("YAML output should contain env var %q, got:\n%s", tt.wantEnvVar, yamlOutput)
			}

			// Check that run script was replaced
			if !strings.Contains(yamlOutput, tt.wantRunScript) {
				t.Errorf("YAML output should contain replaced run script %q, got:\n%s", tt.wantRunScript, yamlOutput)
			}
		})
	}
}

func TestCodeInjectionCritical_AutoFix_GitHubScript_YAMLOutput(t *testing.T) {
	rule := CodeInjectionCriticalRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "issue_comment"},
			},
		},
	}

	scriptValue := `console.log('${{ github.event.comment.body }}')`
	step := &ast.Step{
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/github-script@v6"},
			Inputs: map[string]*ast.Input{
				"script": {
					Name: &ast.String{Value: "script"},
					Value: &ast.String{
						Value: scriptValue,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
		BaseNode: &yaml.Node{
			Kind: yaml.MappingNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "uses"},
				{Kind: yaml.ScalarNode, Value: "actions/github-script@v6"},
				{Kind: yaml.ScalarNode, Value: "with"},
				{
					Kind: yaml.MappingNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Value: "script"},
						{Kind: yaml.ScalarNode, Value: scriptValue},
					},
				},
			},
		},
	}

	job := &ast.Job{Steps: []*ast.Step{step}}

	// Visit workflow and job
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	// Should detect the vulnerability
	if len(rule.Errors()) == 0 {
		t.Fatal("Expected errors but got none")
	}

	// Apply auto-fix
	if err := rule.FixStep(step); err != nil {
		t.Fatalf("FixStep() error = %v", err)
	}

	// Verify YAML output
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	if err := enc.Encode(step.BaseNode); err != nil {
		t.Fatalf("Failed to encode YAML: %v", err)
	}
	yamlOutput := buf.String()

	// Check that env section exists in YAML
	if !strings.Contains(yamlOutput, "env:") {
		t.Errorf("YAML output should contain 'env:' section, got:\n%s", yamlOutput)
	}

	// Check that the environment variable is in YAML
	if !strings.Contains(yamlOutput, "COMMENT_BODY:") {
		t.Errorf("YAML output should contain env var COMMENT_BODY, got:\n%s", yamlOutput)
	}

	// Check that script was replaced with process.env
	if !strings.Contains(yamlOutput, "process.env.COMMENT_BODY") {
		t.Errorf("YAML output should contain process.env.COMMENT_BODY, got:\n%s", yamlOutput)
	}
}
