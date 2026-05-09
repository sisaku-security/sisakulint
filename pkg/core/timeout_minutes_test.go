package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

func TestTimeoutMinuteRule(t *testing.T) {
	tests := []struct {
		name string
		want *TimeoutMinutesRule
	}{
		{
			name: "create timeout minutes rule",
			want: &TimeoutMinutesRule{
				BaseRule: BaseRule{
					RuleName: "missing-timeout-minutes",
					RuleDesc: "This rule checks missing timeout-minutes in job level.",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TimeoutMinuteRule()
			if got.RuleName != tt.want.RuleName || got.RuleDesc != tt.want.RuleDesc {
				t.Errorf("TimeoutMinuteRule() = %v, want %v", got, tt.want)
			}
			if !got.IsOptIn() {
				t.Errorf("TimeoutMinuteRule().IsOptIn() = false, want true (rule is opt-in)")
			}
		})
	}
}

func TestTimeoutMinutesRule_VisitJobPre(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		node *ast.Job
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantErr    bool
		wantErrors int
	}{
		{
			name: "job with timeout-minutes set",
			fields: fields{
				BaseRule: BaseRule{
					RuleName: "missing-timeout-minutes",
					RuleDesc: "This rule checks missing timeout-minutes in job level.",
				},
			},
			args: args{
				node: &ast.Job{
					ID: &ast.String{
						Value: "test-job",
					},
					TimeoutMinutes: &ast.Float{
						Value: 30.0,
					},
					Pos: &ast.Position{
						Line: 5,
						Col:  3,
					},
				},
			},
			wantErr:    false,
			wantErrors: 0,
		},
		{
			name: "job without timeout-minutes",
			fields: fields{
				BaseRule: BaseRule{
					RuleName: "missing-timeout-minutes",
					RuleDesc: "This rule checks missing timeout-minutes in job level.",
				},
			},
			args: args{
				node: &ast.Job{
					ID: &ast.String{
						Value: "test-job",
					},
					TimeoutMinutes: nil,
					Pos: &ast.Position{
						Line: 5,
						Col:  3,
					},
				},
			},
			wantErr:    false,
			wantErrors: 1,
		},
		{
			name: "job with zero timeout-minutes",
			fields: fields{
				BaseRule: BaseRule{
					RuleName: "missing-timeout-minutes",
					RuleDesc: "This rule checks missing timeout-minutes in job level.",
				},
			},
			args: args{
				node: &ast.Job{
					ID: &ast.String{
						Value: "test-job",
					},
					TimeoutMinutes: &ast.Float{
						Value: 0.0,
					},
					Pos: &ast.Position{
						Line: 5,
						Col:  3,
					},
				},
			},
			wantErr:    false,
			wantErrors: 0,
		},
		{
			name: "job with expression in timeout-minutes",
			fields: fields{
				BaseRule: BaseRule{
					RuleName: "missing-timeout-minutes",
					RuleDesc: "This rule checks missing timeout-minutes in job level.",
				},
			},
			args: args{
				node: &ast.Job{
					ID: &ast.String{
						Value: "test-job",
					},
					TimeoutMinutes: &ast.Float{
						Expression: &ast.String{
							Value: "${{ vars.TIMEOUT }}",
						},
					},
					Pos: &ast.Position{
						Line: 5,
						Col:  3,
					},
				},
			},
			wantErr:    false,
			wantErrors: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &TimeoutMinutesRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitJobPre(tt.args.node); (err != nil) != tt.wantErr {
				t.Errorf("TimeoutMinutesRule.VisitJobPre() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("TimeoutMinutesRule.VisitJobPre() errors count = %d, want %d", len(rule.Errors()), tt.wantErrors)
			}
		})
	}
}

func TestTimeoutMinutesRule_VisitStep(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		node *ast.Step
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantErr    bool
		wantErrors int
	}{
		{
			name: "step with timeout-minutes set",
			fields: fields{
				BaseRule: BaseRule{
					RuleName: "missing-timeout-minutes",
					RuleDesc: "This rule checks missing timeout-minutes in job level.",
				},
			},
			args: args{
				node: &ast.Step{
					ID: &ast.String{
						Value: "test-step",
					},
					TimeoutMinutes: &ast.Float{
						Value: 10.0,
					},
					Pos: &ast.Position{
						Line: 10,
						Col:  5,
					},
				},
			},
			wantErr:    false,
			wantErrors: 0,
		},
		{
			name: "step without timeout-minutes",
			fields: fields{
				BaseRule: BaseRule{
					RuleName: "missing-timeout-minutes",
					RuleDesc: "This rule checks missing timeout-minutes in job level.",
				},
			},
			args: args{
				node: &ast.Step{
					ID: &ast.String{
						Value: "test-step",
					},
					TimeoutMinutes: nil,
					Pos: &ast.Position{
						Line: 10,
						Col:  5,
					},
				},
			},
			wantErr:    false,
			wantErrors: 1,
		},
		{
			name: "step with uses action and no timeout",
			fields: fields{
				BaseRule: BaseRule{
					RuleName: "missing-timeout-minutes",
					RuleDesc: "This rule checks missing timeout-minutes in job level.",
				},
			},
			args: args{
				node: &ast.Step{
					Exec: &ast.ExecAction{
						Uses: &ast.String{
							Value: "actions/checkout@v3",
						},
					},
					TimeoutMinutes: nil,
					Pos: &ast.Position{
						Line: 10,
						Col:  5,
					},
				},
			},
			wantErr:    false,
			wantErrors: 1,
		},
		{
			name: "step with run command and no timeout",
			fields: fields{
				BaseRule: BaseRule{
					RuleName: "missing-timeout-minutes",
					RuleDesc: "This rule checks missing timeout-minutes in job level.",
				},
			},
			args: args{
				node: &ast.Step{
					Exec: &ast.ExecRun{
						Run: &ast.String{
							Value: "echo 'test'",
						},
					},
					TimeoutMinutes: nil,
					Pos: &ast.Position{
						Line: 10,
						Col:  5,
					},
				},
			},
			wantErr:    false,
			wantErrors: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &TimeoutMinutesRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitStep(tt.args.node); (err != nil) != tt.wantErr {
				t.Errorf("TimeoutMinutesRule.VisitStep() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("TimeoutMinutesRule.VisitStep() errors count = %d, want %d", len(rule.Errors()), tt.wantErrors)
			}
		})
	}
}

func TestTimeoutMinutesRule_FixJob(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantKey     string
		wantValue   string
	}{
		{
			name: "add timeout-minutes before steps",
			yamlContent: `
runs-on: ubuntu-latest
steps:
  - uses: actions/checkout@v3
`,
			wantKey:   "timeout-minutes",
			wantValue: "5",
		},
		{
			name: "add timeout-minutes before runs-on when no steps",
			yamlContent: `
runs-on: ubuntu-latest
`,
			wantKey:   "timeout-minutes",
			wantValue: "5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(tt.yamlContent), &node); err != nil {
				t.Fatalf("failed to parse YAML: %v", err)
			}

			// Get the mapping node (first content node)
			if len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
				t.Fatal("expected mapping node")
			}
			mappingNode := node.Content[0]

			job := &ast.Job{
				ID: &ast.String{
					Value: "test-job",
				},
				BaseNode: mappingNode,
			}

			rule := TimeoutMinuteRule()
			if err := rule.FixJob(job); err != nil {
				t.Errorf("TimeoutMinutesRule.FixJob() error = %v", err)
			}

			// Check if timeout-minutes was added
			found := false
			for i := 0; i < len(mappingNode.Content); i += 2 {
				if mappingNode.Content[i].Value == tt.wantKey {
					found = true
					if mappingNode.Content[i+1].Value != tt.wantValue {
						t.Errorf("TimeoutMinutesRule.FixJob() value = %v, want %v", mappingNode.Content[i+1].Value, tt.wantValue)
					}
					break
				}
			}
			if !found {
				t.Errorf("TimeoutMinutesRule.FixJob() did not add timeout-minutes key")
			}
		})
	}
}

func TestTimeoutMinutesRule_FixStep(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantKey     string
		wantValue   string
	}{
		{
			name: "add timeout-minutes before run",
			yamlContent: `
name: Test step
run: echo "test"
`,
			wantKey:   "timeout-minutes",
			wantValue: "5",
		},
		{
			name: "add timeout-minutes before uses when no run",
			yamlContent: `
uses: actions/checkout@v3
with:
  ref: main
`,
			wantKey:   "timeout-minutes",
			wantValue: "5",
		},
		{
			name: "add timeout-minutes at end when no run or uses",
			yamlContent: `
name: Test step
`,
			wantKey:   "timeout-minutes",
			wantValue: "5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(tt.yamlContent), &node); err != nil {
				t.Fatalf("failed to parse YAML: %v", err)
			}

			// Get the mapping node (first content node)
			if len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
				t.Fatal("expected mapping node")
			}
			mappingNode := node.Content[0]

			step := &ast.Step{
				BaseNode: mappingNode,
			}

			rule := TimeoutMinuteRule()
			if err := rule.FixStep(step); err != nil {
				t.Errorf("TimeoutMinutesRule.FixStep() error = %v", err)
			}

			// Check if timeout-minutes was added
			found := false
			for i := 0; i < len(mappingNode.Content); i += 2 {
				if mappingNode.Content[i].Value == tt.wantKey {
					found = true
					if mappingNode.Content[i+1].Value != tt.wantValue {
						t.Errorf("TimeoutMinutesRule.FixStep() value = %v, want %v", mappingNode.Content[i+1].Value, tt.wantValue)
					}
					break
				}
			}
			if !found {
				t.Errorf("TimeoutMinutesRule.FixStep() did not add timeout-minutes key")
			}
		})
	}
}

func Test_addTimeoutMinutes(t *testing.T) {
	tests := []struct {
		name         string
		yamlContent  string
		candidate1   string
		candidate2   string
		wantKey      string
		wantValue    string
		wantPosition string // "before_candidate1", "before_candidate2", "at_end"
	}{
		{
			name: "add before first candidate",
			yamlContent: `
name: Test
steps:
  - run: echo "test"
`,
			candidate1:   "steps",
			candidate2:   "runs-on",
			wantKey:      "timeout-minutes",
			wantValue:    "5",
			wantPosition: "before_candidate1",
		},
		{
			name: "add before second candidate when first not found",
			yamlContent: `
name: Test
runs-on: ubuntu-latest
`,
			candidate1:   "steps",
			candidate2:   "runs-on",
			wantKey:      "timeout-minutes",
			wantValue:    "5",
			wantPosition: "before_candidate2",
		},
		{
			name: "add at end when no candidates found",
			yamlContent: `
name: Test
`,
			candidate1:   "steps",
			candidate2:   "runs-on",
			wantKey:      "timeout-minutes",
			wantValue:    "5",
			wantPosition: "at_end",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(tt.yamlContent), &node); err != nil {
				t.Fatalf("failed to parse YAML: %v", err)
			}

			// Get the mapping node
			if len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
				t.Fatal("expected mapping node")
			}
			mappingNode := node.Content[0]

			addTimeoutMinutes(mappingNode, tt.candidate1, tt.candidate2)

			// Check if timeout-minutes was added
			found := false
			var foundIndex int
			for i := 0; i < len(mappingNode.Content); i += 2 {
				if mappingNode.Content[i].Value == tt.wantKey {
					found = true
					foundIndex = i
					if mappingNode.Content[i+1].Value != tt.wantValue {
						t.Errorf("addTimeoutMinutes() value = %v, want %v", mappingNode.Content[i+1].Value, tt.wantValue)
					}
					break
				}
			}
			if !found {
				t.Errorf("addTimeoutMinutes() did not add timeout-minutes key")
				return
			}

			// Verify position
			switch tt.wantPosition {
			case "before_candidate1":
				// Find candidate1 position
				for i := 0; i < len(mappingNode.Content); i += 2 {
					if mappingNode.Content[i].Value == tt.candidate1 {
						if foundIndex >= i {
							t.Errorf("addTimeoutMinutes() timeout-minutes not before %s", tt.candidate1)
						}
						break
					}
				}
			case "before_candidate2":
				// Find candidate2 position
				for i := 0; i < len(mappingNode.Content); i += 2 {
					if mappingNode.Content[i].Value == tt.candidate2 {
						if foundIndex >= i {
							t.Errorf("addTimeoutMinutes() timeout-minutes not before %s", tt.candidate2)
						}
						break
					}
				}
			case "at_end":
				// Should be at or near the end
				if foundIndex < len(mappingNode.Content)-4 {
					t.Errorf("addTimeoutMinutes() timeout-minutes not at end, found at index %d, total length %d", foundIndex, len(mappingNode.Content))
				}
			}
		})
	}
}
