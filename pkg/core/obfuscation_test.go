package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

func TestNewObfuscationRule(t *testing.T) {
	t.Parallel()
	rule := NewObfuscationRule()
	if rule.RuleName != "obfuscation" {
		t.Errorf("expected rule name 'obfuscation', got '%s'", rule.RuleName)
	}
	if rule.RuleDesc == "" {
		t.Error("expected non-empty rule description")
	}
}

func TestCheckUsesPathObfuscation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		usesValue  string
		wantIssues int
	}{
		{
			name:       "normal action reference",
			usesValue:  "actions/checkout@v4",
			wantIssues: 0,
		},
		{
			name:       "action with subpath",
			usesValue:  "github/codeql-action/init@v2",
			wantIssues: 0,
		},
		{
			name:       "contains dot component",
			usesValue:  "actions/checkout/./@v4",
			wantIssues: 2, // . and empty component after /./
		},
		{
			name:       "contains double dot component",
			usesValue:  "actions/cache/save/../save@v4",
			wantIssues: 1,
		},
		{
			name:       "contains empty component (consecutive slashes)",
			usesValue:  "actions/checkout////@v4",
			wantIssues: 4, // four empty components after checkout/
		},
		{
			name:       "multiple obfuscation patterns",
			usesValue:  "actions/checkout/./..@v4",
			wantIssues: 2, // . and ..
		},
		{
			name:       "github codeql with dot",
			usesValue:  "github/codeql-action/./init@v2",
			wantIssues: 1,
		},
		{
			name:       "no @ reference",
			usesValue:  "actions/checkout",
			wantIssues: 0, // no @ means no path to check
		},
		{
			name:       "docker reference",
			usesValue:  "docker://alpine:3.14",
			wantIssues: 0, // docker refs are not checked for path obfuscation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			annotations := checkUsesPathObfuscation(tt.usesValue)
			if len(annotations) != tt.wantIssues {
				t.Errorf("checkUsesPathObfuscation(%q) = %d issues, want %d issues; annotations: %v",
					tt.usesValue, len(annotations), tt.wantIssues, annotations)
			}
		})
	}
}

func TestNormalizeUsesPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		usesValue  string
		wantResult string
	}{
		{
			name:       "already normalized",
			usesValue:  "actions/checkout@v4",
			wantResult: "actions/checkout@v4",
		},
		{
			name:       "remove dot component",
			usesValue:  "github/codeql-action/./init@v2",
			wantResult: "github/codeql-action/init@v2",
		},
		{
			name:       "resolve double dot",
			usesValue:  "actions/cache/save/../save@v4",
			wantResult: "actions/cache/save@v4",
		},
		{
			name:       "remove consecutive slashes",
			usesValue:  "actions/checkout////@v4",
			wantResult: "actions/checkout@v4",
		},
		{
			name:       "complex obfuscation",
			usesValue:  "github/codeql-action/a/../init@v2",
			wantResult: "github/codeql-action/init@v2",
		},
		{
			name:       "no @ symbol",
			usesValue:  "actions/checkout",
			wantResult: "",
		},
		{
			name:       "path escaping repo - should fail",
			usesValue:  "actions/checkout/../../malicious@v4",
			wantResult: "", // cannot normalize - escapes repo
		},
		{
			name:       "subpath becomes empty after normalize",
			usesValue:  "actions/checkout/.@v4",
			wantResult: "actions/checkout@v4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := normalizeUsesPath(tt.usesValue)
			if result != tt.wantResult {
				t.Errorf("normalizeUsesPath(%q) = %q, want %q", tt.usesValue, result, tt.wantResult)
			}
		})
	}
}

func TestObfuscationRule_VisitStep_UsesPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		step       *ast.Step
		wantErrors int
	}{
		{
			name: "normal action reference",
			step: &ast.Step{
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout@v4",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 5, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "obfuscated path with dot",
			step: &ast.Step{
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout/./@v4",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 5, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "obfuscated path with double dot",
			step: &ast.Step{
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/cache/save/../save@v4",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 5, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "run step - no uses check",
			step: &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "echo hello",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 5, Col: 5},
			},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewObfuscationRule()
			err := rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() error = %v", err)
			}
			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("VisitStep() errors = %d, want %d", len(rule.Errors()), tt.wantErrors)
			}
		})
	}
}

func TestObfuscationRule_VisitStep_ShellCmd(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		step       *ast.Step
		wantErrors int
	}{
		{
			name: "shell bash",
			step: &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "echo hello",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
					Shell: &ast.String{
						Value: "bash",
						Pos:   &ast.Position{Line: 6, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 5, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "shell powershell",
			step: &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "Write-Host 'hello'",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
					Shell: &ast.String{
						Value: "pwsh",
						Pos:   &ast.Position{Line: 6, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 5, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "shell cmd - obfuscation warning",
			step: &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "echo hello",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
					Shell: &ast.String{
						Value: "cmd",
						Pos:   &ast.Position{Line: 6, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 5, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "shell CMD (uppercase) - obfuscation warning",
			step: &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "echo hello",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
					Shell: &ast.String{
						Value: "CMD",
						Pos:   &ast.Position{Line: 6, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 5, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "no shell specified",
			step: &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "echo hello",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 5, Col: 5},
			},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewObfuscationRule()
			err := rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() error = %v", err)
			}
			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("VisitStep() errors = %d, want %d", len(rule.Errors()), tt.wantErrors)
			}
		})
	}
}

func TestObfuscationRule_VisitJobPre_Defaults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		job        *ast.Job
		wantErrors int
	}{
		{
			name: "job defaults shell bash",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Defaults: &ast.Defaults{
					Run: &ast.DefaultsRun{
						Shell: &ast.String{
							Value: "bash",
							Pos:   &ast.Position{Line: 5, Col: 10},
						},
					},
				},
				Pos: &ast.Position{Line: 3, Col: 3},
			},
			wantErrors: 0,
		},
		{
			name: "job defaults shell cmd",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				Defaults: &ast.Defaults{
					Run: &ast.DefaultsRun{
						Shell: &ast.String{
							Value: "cmd",
							Pos:   &ast.Position{Line: 5, Col: 10},
						},
					},
				},
				Pos: &ast.Position{Line: 3, Col: 3},
			},
			wantErrors: 1,
		},
		{
			name: "job without defaults",
			job: &ast.Job{
				ID:  &ast.String{Value: "test-job"},
				Pos: &ast.Position{Line: 3, Col: 3},
			},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewObfuscationRule()
			err := rule.VisitJobPre(tt.job)
			if err != nil {
				t.Errorf("VisitJobPre() error = %v", err)
			}
			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("VisitJobPre() errors = %d, want %d", len(rule.Errors()), tt.wantErrors)
			}
		})
	}
}

func TestObfuscationRule_VisitJobPre_WorkflowCall(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		job        *ast.Job
		wantErrors int
	}{
		{
			name: "workflow call normal",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{
						Value: "owner/repo/.github/workflows/ci.yml@main",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 3, Col: 3},
			},
			wantErrors: 0,
		},
		{
			name: "workflow call obfuscated path",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{
						Value: "owner/repo/.github/workflows/./ci.yml@main",
						Pos:   &ast.Position{Line: 5, Col: 10},
					},
				},
				Pos: &ast.Position{Line: 3, Col: 3},
			},
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewObfuscationRule()
			err := rule.VisitJobPre(tt.job)
			if err != nil {
				t.Errorf("VisitJobPre() error = %v", err)
			}
			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("VisitJobPre() errors = %d, want %d", len(rule.Errors()), tt.wantErrors)
			}
		})
	}
}

func TestObfuscationRule_VisitWorkflowPre(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		workflow   *ast.Workflow
		wantErrors int
	}{
		{
			name: "workflow defaults shell bash",
			workflow: &ast.Workflow{
				Defaults: &ast.Defaults{
					Run: &ast.DefaultsRun{
						Shell: &ast.String{
							Value: "bash",
							Pos:   &ast.Position{Line: 5, Col: 10},
						},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name: "workflow defaults shell cmd",
			workflow: &ast.Workflow{
				Defaults: &ast.Defaults{
					Run: &ast.DefaultsRun{
						Shell: &ast.String{
							Value: "cmd",
							Pos:   &ast.Position{Line: 5, Col: 10},
						},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name:       "workflow without defaults",
			workflow:   &ast.Workflow{},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewObfuscationRule()
			err := rule.VisitWorkflowPre(tt.workflow)
			if err != nil {
				t.Errorf("VisitWorkflowPre() error = %v", err)
			}
			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("VisitWorkflowPre() errors = %d, want %d", len(rule.Errors()), tt.wantErrors)
			}
		})
	}
}

func TestObfuscationRule_FixStep(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		usesValue  string
		wantResult string
	}{
		{
			name:       "normalize dot component",
			usesValue:  "github/codeql-action/./init@v2",
			wantResult: "github/codeql-action/init@v2",
		},
		{
			name:       "normalize double dot",
			usesValue:  "actions/cache/save/../save@v4",
			wantResult: "actions/cache/save@v4",
		},
		{
			name:       "normalize consecutive slashes",
			usesValue:  "actions/checkout////@v4",
			wantResult: "actions/checkout@v4",
		},
		{
			name:       "already normalized - no change",
			usesValue:  "actions/checkout@v4",
			wantResult: "actions/checkout@v4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create a YAML node structure for the step
			yamlContent := "uses: " + tt.usesValue

			var node yaml.Node
			if err := yaml.Unmarshal([]byte(yamlContent), &node); err != nil {
				t.Fatalf("failed to parse YAML: %v", err)
			}

			if len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
				t.Fatal("expected mapping node")
			}
			mappingNode := node.Content[0]

			// Create the step with proper AST structure
			step := &ast.Step{
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value:    tt.usesValue,
						BaseNode: mappingNode.Content[1], // value node
						Pos:      &ast.Position{Line: 1, Col: 7},
					},
				},
				BaseNode: mappingNode,
				Pos:      &ast.Position{Line: 1, Col: 1},
			}

			rule := NewObfuscationRule()
			err := rule.FixStep(step)
			if err != nil {
				t.Errorf("FixStep() error = %v", err)
			}

			// Check the result
			action := step.Exec.(*ast.ExecAction)
			if action.Uses.Value != tt.wantResult {
				t.Errorf("FixStep() result = %q, want %q", action.Uses.Value, tt.wantResult)
			}
			if action.Uses.BaseNode.Value != tt.wantResult {
				t.Errorf("FixStep() BaseNode.Value = %q, want %q", action.Uses.BaseNode.Value, tt.wantResult)
			}
		})
	}
}

func TestObfuscationRule_FixJob(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		usesValue  string
		wantResult string
	}{
		{
			name:       "normalize workflow call path",
			usesValue:  "owner/repo/.github/workflows/./ci.yml@main",
			wantResult: "owner/repo/.github/workflows/ci.yml@main",
		},
		{
			name:       "already normalized - no change",
			usesValue:  "owner/repo/.github/workflows/ci.yml@main",
			wantResult: "owner/repo/.github/workflows/ci.yml@main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create a YAML node structure
			yamlContent := "uses: " + tt.usesValue

			var node yaml.Node
			if err := yaml.Unmarshal([]byte(yamlContent), &node); err != nil {
				t.Fatalf("failed to parse YAML: %v", err)
			}

			if len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
				t.Fatal("expected mapping node")
			}
			mappingNode := node.Content[0]

			// Create the job with proper AST structure
			job := &ast.Job{
				ID: &ast.String{Value: "test-job"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{
						Value:    tt.usesValue,
						BaseNode: mappingNode.Content[1], // value node
						Pos:      &ast.Position{Line: 1, Col: 7},
					},
				},
				BaseNode: mappingNode,
				Pos:      &ast.Position{Line: 1, Col: 1},
			}

			rule := NewObfuscationRule()
			err := rule.FixJob(job)
			if err != nil {
				t.Errorf("FixJob() error = %v", err)
			}

			// Check the result
			if job.WorkflowCall.Uses.Value != tt.wantResult {
				t.Errorf("FixJob() result = %q, want %q", job.WorkflowCall.Uses.Value, tt.wantResult)
			}
			if job.WorkflowCall.Uses.BaseNode.Value != tt.wantResult {
				t.Errorf("FixJob() BaseNode.Value = %q, want %q", job.WorkflowCall.Uses.BaseNode.Value, tt.wantResult)
			}
		})
	}
}

func TestIsPathObfuscated(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		usesValue string
		want      bool
	}{
		{
			name:      "normal path",
			usesValue: "actions/checkout@v4",
			want:      false,
		},
		{
			name:      "normal path with subpath",
			usesValue: "github/codeql-action/init@v2",
			want:      false,
		},
		{
			name:      "obfuscated with dot",
			usesValue: "actions/checkout/./@v4",
			want:      true,
		},
		{
			name:      "obfuscated with double dot",
			usesValue: "actions/cache/save/../save@v4",
			want:      true,
		},
		{
			name:      "obfuscated with empty components",
			usesValue: "actions/checkout////@v4",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isPathObfuscated(tt.usesValue)
			if result != tt.want {
				t.Errorf("isPathObfuscated(%q) = %v, want %v", tt.usesValue, result, tt.want)
			}
		})
	}
}
