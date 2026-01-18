package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestNewSelfHostedRunnersRule(t *testing.T) {
	rule := NewSelfHostedRunnersRule()

	if rule.RuleName != "self-hosted-runner" {
		t.Errorf("RuleName = %v, want %v", rule.RuleName, "self-hosted-runner")
	}

	if rule.RuleDesc == "" {
		t.Error("RuleDesc should not be empty")
	}
}

func TestSelfHostedRunnersRule_VisitJobPre_DirectLabel(t *testing.T) {
	tests := []struct {
		name       string
		job        *ast.Job
		wantErrors int
	}{
		{
			name: "direct self-hosted label",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					Labels: []*ast.String{
						{Value: "self-hosted", Pos: &ast.Position{Line: 5, Col: 10}},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 1,
		},
		{
			name: "self-hosted with labels",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					Labels: []*ast.String{
						{Value: "self-hosted", Pos: &ast.Position{Line: 5, Col: 10}},
						{Value: "linux", Pos: &ast.Position{Line: 5, Col: 23}},
						{Value: "x64", Pos: &ast.Position{Line: 5, Col: 30}},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 1,
		},
		{
			name: "self-hosted case insensitive",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					Labels: []*ast.String{
						{Value: "Self-Hosted", Pos: &ast.Position{Line: 5, Col: 10}},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 1,
		},
		{
			name: "github-hosted ubuntu-latest",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					Labels: []*ast.String{
						{Value: "ubuntu-latest", Pos: &ast.Position{Line: 5, Col: 10}},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 0,
		},
		{
			name: "github-hosted macos-latest",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					Labels: []*ast.String{
						{Value: "macos-latest", Pos: &ast.Position{Line: 5, Col: 10}},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 0,
		},
		{
			name: "github-hosted windows-latest",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					Labels: []*ast.String{
						{Value: "windows-latest", Pos: &ast.Position{Line: 5, Col: 10}},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 0,
		},
		{
			name: "nil runs-on",
			job: &ast.Job{
				ID:     &ast.String{Value: "test-job"},
				RunsOn: nil,
				Pos:    &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSelfHostedRunnersRule()
			err := rule.VisitJobPre(tt.job)
			if err != nil {
				t.Errorf("VisitJobPre() error = %v", err)
			}
			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("VisitJobPre() errors count = %d, want %d", len(rule.Errors()), tt.wantErrors)
				for _, e := range rule.Errors() {
					t.Logf("Error: %s", e.Description)
				}
			}
		})
	}
}

func TestSelfHostedRunnersRule_VisitJobPre_RunnerGroup(t *testing.T) {
	tests := []struct {
		name       string
		job        *ast.Job
		wantErrors int
	}{
		{
			name: "runner group specified",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					Group: &ast.String{Value: "my-self-hosted-runners", Pos: &ast.Position{Line: 5, Col: 10}},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 1,
		},
		{
			name: "runner group with labels",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					Labels: []*ast.String{
						{Value: "linux", Pos: &ast.Position{Line: 6, Col: 10}},
					},
					Group: &ast.String{Value: "production-runners", Pos: &ast.Position{Line: 5, Col: 10}},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 1,
		},
		{
			name: "empty runner group",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					Labels: []*ast.String{
						{Value: "ubuntu-latest", Pos: &ast.Position{Line: 5, Col: 10}},
					},
					Group: &ast.String{Value: "", Pos: &ast.Position{Line: 5, Col: 10}},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSelfHostedRunnersRule()
			err := rule.VisitJobPre(tt.job)
			if err != nil {
				t.Errorf("VisitJobPre() error = %v", err)
			}
			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("VisitJobPre() errors count = %d, want %d", len(rule.Errors()), tt.wantErrors)
				for _, e := range rule.Errors() {
					t.Logf("Error: %s", e.Description)
				}
			}
		})
	}
}

func TestSelfHostedRunnersRule_VisitJobPost_MatrixExpansion(t *testing.T) {
	tests := []struct {
		name       string
		job        *ast.Job
		wantErrors int
	}{
		{
			name: "matrix with self-hosted value",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					LabelsExpr: &ast.String{Value: "${{ matrix.runner }}", Pos: &ast.Position{Line: 5, Col: 10}},
				},
				Strategy: &ast.Strategy{
					Matrix: &ast.Matrix{
						Rows: map[string]*ast.MatrixRow{
							"runner": {
								Name: &ast.String{Value: "runner"},
								Values: []ast.RawYAMLValue{
									&ast.RawYAMLString{Value: "ubuntu-latest", Posi: &ast.Position{Line: 8, Col: 10}},
									&ast.RawYAMLString{Value: "self-hosted", Posi: &ast.Position{Line: 8, Col: 25}},
								},
							},
						},
						Pos: &ast.Position{Line: 7, Col: 5},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 1,
		},
		{
			name: "matrix without self-hosted",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					LabelsExpr: &ast.String{Value: "${{ matrix.os }}", Pos: &ast.Position{Line: 5, Col: 10}},
				},
				Strategy: &ast.Strategy{
					Matrix: &ast.Matrix{
						Rows: map[string]*ast.MatrixRow{
							"os": {
								Name: &ast.String{Value: "os"},
								Values: []ast.RawYAMLValue{
									&ast.RawYAMLString{Value: "ubuntu-latest", Posi: &ast.Position{Line: 8, Col: 10}},
									&ast.RawYAMLString{Value: "macos-latest", Posi: &ast.Position{Line: 8, Col: 25}},
								},
							},
						},
						Pos: &ast.Position{Line: 7, Col: 5},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 0,
		},
		{
			name: "matrix expression (cannot analyze)",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					LabelsExpr: &ast.String{Value: "${{ matrix.runner }}", Pos: &ast.Position{Line: 5, Col: 10}},
				},
				Strategy: &ast.Strategy{
					Matrix: &ast.Matrix{
						Expression: &ast.String{Value: "${{ fromJson(needs.setup.outputs.matrix) }}"},
						Pos:        &ast.Position{Line: 7, Col: 5},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 0,
		},
		{
			name: "matrix row expression (cannot analyze)",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					LabelsExpr: &ast.String{Value: "${{ matrix.runner }}", Pos: &ast.Position{Line: 5, Col: 10}},
				},
				Strategy: &ast.Strategy{
					Matrix: &ast.Matrix{
						Rows: map[string]*ast.MatrixRow{
							"runner": {
								Name:       &ast.String{Value: "runner"},
								Expression: &ast.String{Value: "${{ fromJson(needs.setup.outputs.runners) }}"},
							},
						},
						Pos: &ast.Position{Line: 7, Col: 5},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 0,
		},
		{
			name: "matrix with array containing self-hosted",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				RunsOn: &ast.Runner{
					LabelsExpr: &ast.String{Value: "${{ matrix.runner }}", Pos: &ast.Position{Line: 5, Col: 10}},
				},
				Strategy: &ast.Strategy{
					Matrix: &ast.Matrix{
						Rows: map[string]*ast.MatrixRow{
							"runner": {
								Name: &ast.String{Value: "runner"},
								Values: []ast.RawYAMLValue{
									&ast.RawYAMLArray{
										Elems: []ast.RawYAMLValue{
											&ast.RawYAMLString{Value: "self-hosted", Posi: &ast.Position{Line: 8, Col: 10}},
											&ast.RawYAMLString{Value: "linux", Posi: &ast.Position{Line: 8, Col: 23}},
										},
										Posi: &ast.Position{Line: 8, Col: 8},
									},
								},
							},
						},
						Pos: &ast.Position{Line: 7, Col: 5},
					},
				},
				Pos: &ast.Position{Line: 4, Col: 3},
			},
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSelfHostedRunnersRule()
			// Visit pre to set up context
			err := rule.VisitJobPre(tt.job)
			if err != nil {
				t.Errorf("VisitJobPre() error = %v", err)
			}
			// Visit post for matrix checking
			err = rule.VisitJobPost(tt.job)
			if err != nil {
				t.Errorf("VisitJobPost() error = %v", err)
			}
			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("errors count = %d, want %d", len(rule.Errors()), tt.wantErrors)
				for _, e := range rule.Errors() {
					t.Logf("Error: %s", e.Description)
				}
			}
		})
	}
}

func TestSelfHostedRunnersRule_hasSelfHostedLabel(t *testing.T) {
	rule := NewSelfHostedRunnersRule()

	tests := []struct {
		name   string
		runner *ast.Runner
		want   bool
	}{
		{
			name:   "nil labels",
			runner: &ast.Runner{Labels: nil},
			want:   false,
		},
		{
			name:   "empty labels",
			runner: &ast.Runner{Labels: []*ast.String{}},
			want:   false,
		},
		{
			name: "self-hosted first label",
			runner: &ast.Runner{
				Labels: []*ast.String{
					{Value: "self-hosted"},
				},
			},
			want: true,
		},
		{
			name: "self-hosted in middle",
			runner: &ast.Runner{
				Labels: []*ast.String{
					{Value: "linux"},
					{Value: "self-hosted"},
					{Value: "x64"},
				},
			},
			want: true,
		},
		{
			name: "no self-hosted",
			runner: &ast.Runner{
				Labels: []*ast.String{
					{Value: "ubuntu-latest"},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.hasSelfHostedLabel(tt.runner)
			if got != tt.want {
				t.Errorf("hasSelfHostedLabel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSelfHostedRunnersRule_isSelfHostedValue(t *testing.T) {
	rule := NewSelfHostedRunnersRule()

	tests := []struct {
		name string
		val  ast.RawYAMLValue
		want bool
	}{
		{
			name: "string self-hosted",
			val:  &ast.RawYAMLString{Value: "self-hosted"},
			want: true,
		},
		{
			name: "string Self-Hosted uppercase",
			val:  &ast.RawYAMLString{Value: "Self-Hosted"},
			want: true,
		},
		{
			name: "string ubuntu-latest",
			val:  &ast.RawYAMLString{Value: "ubuntu-latest"},
			want: false,
		},
		{
			name: "array with self-hosted",
			val: &ast.RawYAMLArray{
				Elems: []ast.RawYAMLValue{
					&ast.RawYAMLString{Value: "self-hosted"},
					&ast.RawYAMLString{Value: "linux"},
				},
			},
			want: true,
		},
		{
			name: "array without self-hosted",
			val: &ast.RawYAMLArray{
				Elems: []ast.RawYAMLValue{
					&ast.RawYAMLString{Value: "ubuntu-latest"},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.isSelfHostedValue(tt.val)
			if got != tt.want {
				t.Errorf("isSelfHostedValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
