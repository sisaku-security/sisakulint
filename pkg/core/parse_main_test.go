package core

import (
	"strings"
	"testing"
)

func TestParse_EnvironmentDeploymentKey(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    bool
		errContains string
	}{
		{
			name: "object environment with deployment: false",
			input: `name: Test
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      deployment: false
    steps:
      - run: echo test
`,
			wantErr: false,
		},
		{
			name: "object environment with deployment expression",
			input: `name: Test
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      deployment: ${{ github.ref == 'refs/heads/main' }}
    steps:
      - run: echo test
`,
			wantErr: false,
		},
		{
			name: "object environment with deployment: true and url",
			input: `name: Test
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://example.com
      deployment: true
    steps:
      - run: echo test
`,
			wantErr: false,
		},
		{
			name: "string environment still works",
			input: `name: Test
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: echo test
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, errs := Parse([]byte(tt.input))

			if tt.wantErr {
				if len(errs) == 0 {
					t.Fatalf("Parse() expected errors but got none")
				}
				if tt.errContains != "" {
					found := false
					for _, e := range errs {
						if strings.Contains(e.Description, tt.errContains) {
							found = true
							break
						}
					}
					if !found {
						t.Fatalf("Parse() errors %v do not contain %q", errs, tt.errContains)
					}
				}
				return
			}

			for _, e := range errs {
				if e.Type == "syntax" {
					t.Fatalf("Parse() got unexpected syntax error: %v", e)
				}
			}
			if workflow == nil {
				t.Fatalf("Parse() returned nil workflow")
			}

			job := workflow.Jobs["deploy"]
			if job == nil {
				t.Fatalf("Parse() Jobs[deploy] = nil")
			}
			if job.Environment == nil {
				t.Fatalf("Parse() Environment = nil")
			}
			if job.Environment.Name == nil || job.Environment.Name.Value != "production" {
				t.Fatalf("Parse() Environment.Name = %v, want production", job.Environment.Name)
			}
		})
	}
}

func TestParse_WorkflowDescription(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantDesc    string
		wantErr     bool
		errContains string
	}{
		{
			name: "workflow with description",
			input: `name: Test Workflow
description: This is a test workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`,
			wantDesc: "This is a test workflow",
			wantErr:  false,
		},
		{
			name: "workflow without description",
			input: `name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`,
			wantDesc: "",
			wantErr:  false,
		},
		{
			name: "workflow with all top-level fields",
			input: `name: Complete Workflow
description: A complete workflow with all fields
run-name: Run ${{ github.run_number }}
on: push
permissions:
  contents: read
env:
  MY_VAR: value
defaults:
  run:
    shell: bash
concurrency:
  group: ${{ github.ref }}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`,
			wantDesc: "A complete workflow with all fields",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, errs := Parse([]byte(tt.input))

			if tt.wantErr {
				if len(errs) == 0 {
					t.Errorf("Parse() expected errors but got none")
					return
				}
				return
			}

			// Filter out errors that are not about unexpected keys
			syntaxErrors := make([]*LintingError, 0)
			for _, e := range errs {
				if e.Type == "syntax" {
					syntaxErrors = append(syntaxErrors, e)
				}
			}

			if len(syntaxErrors) > 0 {
				t.Errorf("Parse() got unexpected syntax errors: %v", syntaxErrors)
				return
			}

			if workflow == nil {
				t.Errorf("Parse() returned nil workflow")
				return
			}

			if tt.wantDesc != "" {
				if workflow.Description == nil {
					t.Errorf("Parse() Description = nil, want %q", tt.wantDesc)
					return
				}
				if workflow.Description.Value != tt.wantDesc {
					t.Errorf("Parse() Description = %q, want %q", workflow.Description.Value, tt.wantDesc)
				}
			} else {
				if workflow.Description != nil {
					t.Errorf("Parse() Description = %q, want nil", workflow.Description.Value)
				}
			}
		})
	}
}
