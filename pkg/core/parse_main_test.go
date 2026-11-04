package core

import (
	"strings"
	"testing"
)

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

func TestParse_ConcurrencyQueue(t *testing.T) {
	input := `name: Test Workflow
on: push
concurrency:
  group: my-group
  queue: max
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`

	workflow, errs := Parse([]byte(input))

	for _, e := range errs {
		if e.Type == "syntax" {
			t.Errorf("Parse() got unexpected syntax error for \"queue\" key: %v", e)
		}
	}

	if workflow == nil {
		t.Fatal("Parse() returned nil workflow")
	}
	if workflow.Concurrency == nil {
		t.Fatal("Parse() Concurrency = nil, want non-nil")
	}
	if workflow.Concurrency.Queue == nil || workflow.Concurrency.Queue.Value != "max" {
		t.Errorf("Parse() Concurrency.Queue = %v, want \"max\"", workflow.Concurrency.Queue)
	}
}

func TestParse_ConcurrencyQueueJobLevel(t *testing.T) {
	input := `name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    concurrency:
      group: my-group
      queue: single
    steps:
      - run: echo test
`

	_, errs := Parse([]byte(input))

	for _, e := range errs {
		if e.Type == "syntax" {
			t.Errorf("Parse() got unexpected syntax error for job-level \"queue\" key: %v", e)
		}
	}
}

func TestParse_ConcurrencyQueueInvalidValue(t *testing.T) {
	input := `name: Test Workflow
on: push
concurrency:
  group: my-group
  queue: unlimited
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`

	_, errs := Parse([]byte(input))

	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "invalid") && strings.Contains(e.Error(), "queue") {
			found = true
		}
	}
	if !found {
		t.Errorf("Parse() expected an error rejecting invalid \"queue\" value, got errs: %v", errs)
	}
}

func TestParse_ConcurrencyQueueMaxWithCancelInProgress(t *testing.T) {
	input := `name: Test Workflow
on: push
concurrency:
  group: my-group
  queue: max
  cancel-in-progress: true
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`

	_, errs := Parse([]byte(input))

	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "queue: max") && strings.Contains(e.Error(), "cancel-in-progress: true") {
			found = true
		}
	}
	if !found {
		t.Errorf("Parse() expected an error rejecting \"queue: max\" combined with \"cancel-in-progress: true\", got errs: %v", errs)
	}
}
