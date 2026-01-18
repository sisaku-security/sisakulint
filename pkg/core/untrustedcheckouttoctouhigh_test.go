package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestUntrustedCheckoutTOCTOUHighRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		errMsg  string
	}{
		{
			name: "Vulnerable: pull_request_target with environment and mutable head.ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "TOCTOU vulnerability",
		},
		{
			name: "Vulnerable: pull_request_target with environment and github.head_ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`,
			wantErr: true,
			errMsg:  "TOCTOU vulnerability",
		},
		{
			name: "Vulnerable: pull_request with environment and mutable ref",
			yaml: `
name: Test
on: pull_request
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "TOCTOU vulnerability",
		},
		{
			name: "Vulnerable: environment with url",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://example.com
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "TOCTOU vulnerability",
		},
		{
			name: "Safe: pull_request_target with environment but immutable sha",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target without environment",
			yaml: `
name: Test
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with environment but no checkout",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: echo "deploying"
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with environment but checkout without ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with environment but literal ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
`,
			wantErr: false,
		},
		{
			name: "Safe: push trigger with environment (not PR related)",
			yaml: `
name: Test
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: false,
		},
		{
			name: "Safe: workflow_dispatch with environment",
			yaml: `
name: Test
on: workflow_dispatch
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`,
			wantErr: false,
		},
		{
			name: "Multiple jobs: only one with environment vulnerable",
			yaml: `
name: Test
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
  deploy:
    runs-on: ubuntu-latest
    environment: production
    needs: build
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "TOCTOU vulnerability",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			workflow, errs := Parse([]byte(tt.yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			rule := NewUntrustedCheckoutTOCTOUHighRule()
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			ruleErrs := rule.Errors()
			if tt.wantErr {
				if len(ruleErrs) == 0 {
					t.Errorf("Expected error but got none")
				} else {
					found := false
					for _, err := range ruleErrs {
						if tt.errMsg != "" && containsString(err.Description, tt.errMsg) {
							found = true
							break
						}
					}
					if !found && tt.errMsg != "" {
						t.Errorf("Expected error message to contain %q, but got: %v", tt.errMsg, ruleErrs[0].Description)
					}
				}
			} else {
				if len(ruleErrs) > 0 {
					t.Errorf("Unexpected error: %v", ruleErrs[0].Description)
				}
			}
		})
	}
}

func TestUntrustedCheckoutTOCTOUHighAutoFixer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		yaml           string
		expectAutoFix  bool
		autoFixerCount int
	}{
		{
			name: "Auto-fixer added for vulnerable pattern",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			expectAutoFix:  true,
			autoFixerCount: 1,
		},
		{
			name: "No auto-fixer for safe pattern",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			expectAutoFix:  false,
			autoFixerCount: 0,
		},
		{
			name: "Multiple auto-fixers for multiple vulnerable checkouts",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`,
			expectAutoFix:  true,
			autoFixerCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			workflow, errs := Parse([]byte(tt.yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			rule := NewUntrustedCheckoutTOCTOUHighRule()
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			autoFixerCount := len(rule.AutoFixers())
			if autoFixerCount != tt.autoFixerCount {
				t.Errorf("Expected %d auto-fixer(s), but got %d", tt.autoFixerCount, autoFixerCount)
			}

			if tt.expectAutoFix && autoFixerCount == 0 {
				t.Error("Expected auto-fixer to be added, but none was added")
			}

			if !tt.expectAutoFix && autoFixerCount > 0 {
				t.Errorf("Expected no auto-fixer, but %d was added", autoFixerCount)
			}
		})
	}
}

func TestUntrustedCheckoutTOCTOUHighFixStep(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		yaml        string
		expectedRef string
		expectError bool
	}{
		{
			name: "Fix head.ref to head.sha",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			expectedRef: "${{ github.event.pull_request.head.sha }}",
			expectError: false,
		},
		{
			name: "Fix github.head_ref to head.sha",
			yaml: `
name: Test
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`,
			expectedRef: "${{ github.event.pull_request.head.sha }}",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			workflow, errs := Parse([]byte(tt.yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			rule := NewUntrustedCheckoutTOCTOUHighRule()
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			autoFixers := rule.AutoFixers()
			if len(autoFixers) == 0 {
				t.Fatal("No auto-fixer was added")
			}

			if err := autoFixers[0].Fix(); err != nil {
				if !tt.expectError {
					t.Errorf("Fix() unexpected error = %v", err)
				}
				return
			}

			if tt.expectError {
				t.Error("Expected error but got none")
				return
			}

			var foundJob *ast.Job
			for _, job := range workflow.Jobs {
				if job.Environment != nil {
					foundJob = job
					break
				}
			}
			if foundJob == nil {
				t.Fatal("No job with environment found in workflow")
			}

			if len(foundJob.Steps) == 0 {
				t.Fatal("No steps found in job")
			}

			step := foundJob.Steps[0]
			action, ok := step.Exec.(*ast.ExecAction)
			if !ok {
				t.Fatal("Step is not an ExecAction")
			}

			refInput, exists := action.Inputs["ref"]
			if !exists {
				t.Fatal("No ref input found")
			}

			if refInput.Value.Value != tt.expectedRef {
				t.Errorf("Expected ref to be %q, but got %q", tt.expectedRef, refInput.Value.Value)
			}
		})
	}
}
