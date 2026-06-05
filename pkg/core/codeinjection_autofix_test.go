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
			rule := CodeInjectionCriticalRule(nil)

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
			rule := CodeInjectionMediumRule(nil)

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

func TestCodeInjectionMedium_AutoFix_DependencyReviewOutput(t *testing.T) {
	rule := CodeInjectionMediumRule(nil)
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request"},
			},
		},
	}
	runScript := `echo '${{ steps.review.outputs.dependency-changes }}'`
	runStep := &ast.Step{
		Name: &ast.String{Value: "Use review output"},
		Exec: &ast.ExecRun{
			Run: &ast.String{
				Value: runScript,
				Pos:   &ast.Position{Line: 1, Col: 1},
			},
		},
		BaseNode: &yaml.Node{
			Kind: yaml.MappingNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "name"},
				{Kind: yaml.ScalarNode, Value: "Use review output"},
				{Kind: yaml.ScalarNode, Value: "run"},
				{Kind: yaml.ScalarNode, Value: runScript},
			},
		},
	}
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				ID: &ast.String{Value: "review"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/dependency-review-action@v4"},
				},
			},
			runStep,
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	if len(rule.Errors()) == 0 {
		t.Fatal("Expected errors but got none")
	}
	if err := rule.FixStep(runStep); err != nil {
		t.Fatalf("FixStep() error = %v", err)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	if err := enc.Encode(runStep.BaseNode); err != nil {
		t.Fatalf("Failed to encode YAML: %v", err)
	}
	yamlOutput := buf.String()
	if !strings.Contains(yamlOutput, "DEPENDENCY_CHANGES:") {
		t.Fatalf("YAML output should contain sanitized env var DEPENDENCY_CHANGES, got:\n%s", yamlOutput)
	}
	if strings.Contains(yamlOutput, "TAINTED") || strings.Contains(yamlOutput, "dependency-changes:") {
		t.Fatalf("YAML output should not derive env var name from taint annotation or raw hyphenated output, got:\n%s", yamlOutput)
	}
	if !strings.Contains(yamlOutput, "${{ steps.review.outputs.dependency-changes }}") {
		t.Fatalf("YAML output should preserve original expression as env value, got:\n%s", yamlOutput)
	}
	if !strings.Contains(yamlOutput, `echo "$DEPENDENCY_CHANGES"`) {
		t.Fatalf("YAML output should replace direct interpolation with env var reference, got:\n%s", yamlOutput)
	}
}

func TestCodeInjectionCritical_AutoFix_GitHubScript_YAMLOutput(t *testing.T) {
	rule := CodeInjectionCriticalRule(nil)

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
	if strings.Contains(yamlOutput, "'process.env.COMMENT_BODY'") || strings.Contains(yamlOutput, `"process.env.COMMENT_BODY"`) {
		t.Errorf("YAML output should use process.env.COMMENT_BODY as a JS expression, got:\n%s", yamlOutput)
	}
	if !strings.Contains(yamlOutput, "console.log(process.env.COMMENT_BODY)") {
		t.Errorf("YAML output should strip string-literal quotes around process.env.COMMENT_BODY, got:\n%s", yamlOutput)
	}

	action := step.Exec.(*ast.ExecAction)
	gotScript := action.Inputs["script"].Value.Value
	if gotScript != "console.log(process.env.COMMENT_BODY)" {
		t.Errorf("AST script = %q, want %q", gotScript, "console.log(process.env.COMMENT_BODY)")
	}
}

func TestCodeInjectionCritical_AutoFix_GitHubScript_ObjectKey(t *testing.T) {
	rule := CodeInjectionCriticalRule(nil)

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "issue_comment"},
			},
		},
	}

	scriptValue := `const headers = { '${{ github.event.issue.body }}': 'x' }`
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

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	if len(rule.Errors()) == 0 {
		t.Fatal("Expected errors but got none")
	}
	if err := rule.FixStep(step); err != nil {
		t.Fatalf("FixStep() error = %v", err)
	}

	wantScript := `const headers = { [process.env.ISSUE_BODY]: 'x' }`
	action := step.Exec.(*ast.ExecAction)
	if gotScript := action.Inputs["script"].Value.Value; gotScript != wantScript {
		t.Errorf("AST script = %q, want %q", gotScript, wantScript)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	if err := enc.Encode(step.BaseNode); err != nil {
		t.Fatalf("Failed to encode YAML: %v", err)
	}
	yamlOutput := buf.String()
	if !strings.Contains(yamlOutput, "[process.env.ISSUE_BODY]") {
		t.Errorf("YAML output should contain computed key [process.env.ISSUE_BODY], got:\n%s", yamlOutput)
	}
	if strings.Contains(yamlOutput, "{ process.env.ISSUE_BODY:") {
		t.Errorf("YAML output should not emit process.env.ISSUE_BODY as a bare object key, got:\n%s", yamlOutput)
	}
}
