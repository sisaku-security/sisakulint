package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestUntrustedCheckoutRule(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		errMsg  string
	}{
		{
			name: "Safe: pull_request trigger with checkout",
			yaml: `
name: Test
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target without checkout",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with checkout of base branch",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.sha }}
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with checkout without ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with literal ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
`,
			wantErr: false,
		},
		{
			name: "Vulnerable: pull_request_target with PR HEAD SHA",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Vulnerable: pull_request_target with PR HEAD ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Vulnerable: issue_comment with PR checkout",
			yaml: `
name: Test
on: issue_comment
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Vulnerable: workflow_run with PR checkout",
			yaml: `
name: Test
on: workflow_run
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Vulnerable: workflow_call with PR checkout",
			yaml: `
name: Test
on: workflow_call
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Safe: Multiple triggers with only safe ones",
			yaml: `
name: Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: false,
		},
		{
			name: "Vulnerable: Multiple triggers including dangerous one",
			yaml: `
name: Test
on: [push, pull_request_target]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Safe: Multiple jobs, no dangerous checkouts",
			yaml: `
name: Test
on: pull_request_target
jobs:
  job1:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  job2:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`,
			wantErr: false,
		},
		{
			name: "Vulnerable: Multiple jobs, one with dangerous checkout",
			yaml: `
name: Test
on: pull_request_target
jobs:
  job1:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  job2:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Safe: Using other actions, not checkout",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
`,
			wantErr: false,
		},
		{
			name: "Vulnerable: Mixed literal and expression in ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: pr-${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Vulnerable: PR HEAD SHA with extra whitespace",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{   github.event.pull_request.head.sha   }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Vulnerable: Multiple dangerous checkouts in different steps",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "test"
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Vulnerable: Using head.sha in concatenated string",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/heads/${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Safe: Using github.sha in concatenated string",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/heads/${{ github.sha }}
`,
			wantErr: false,
		},
		{
			name: "Vulnerable: Using github.event.pull_request.head.number",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.number }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the workflow
			workflow, errs := Parse([]byte(tt.yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewUntrustedCheckoutRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Check errors
			ruleErrs := rule.Errors()
			if tt.wantErr {
				if len(ruleErrs) == 0 {
					t.Errorf("Expected error but got none")
				} else {
					// Verify error message contains expected text
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

func TestUntrustedCheckoutDetectsAllDangerousTriggers(t *testing.T) {
	dangerousTriggers := []string{
		"pull_request_target",
		"issue_comment",
		"workflow_run",
		"workflow_call",
	}

	for _, trigger := range dangerousTriggers {
		t.Run(trigger, func(t *testing.T) {
			yaml := `
name: Test
on: ` + trigger + `
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`
			// Parse the workflow
			workflow, errs := Parse([]byte(yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewUntrustedCheckoutRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Check that error was found
			ruleErrs := rule.Errors()
			if len(ruleErrs) == 0 {
				t.Errorf("Expected error for dangerous trigger %q but got none", trigger)
			}
		})
	}
}

func TestUntrustedCheckoutDetectsAllDangerousRefPatterns(t *testing.T) {
	dangerousRefs := []struct {
		ref  string
		desc string
	}{
		{
			ref:  "${{ github.event.pull_request.head.sha }}",
			desc: "PR HEAD SHA",
		},
		{
			ref:  "${{ github.event.pull_request.head.ref }}",
			desc: "PR HEAD ref",
		},
	}

	for _, refCase := range dangerousRefs {
		t.Run(refCase.desc, func(t *testing.T) {
			yaml := `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ` + refCase.ref + `
`
			// Parse the workflow
			workflow, errs := Parse([]byte(yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewUntrustedCheckoutRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Check that error was found
			ruleErrs := rule.Errors()
			if len(ruleErrs) == 0 {
				t.Errorf("Expected error for dangerous ref pattern %q but got none", refCase.ref)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestUntrustedCheckoutAutoFixer tests that auto-fixer is added when needed
func TestUntrustedCheckoutAutoFixer(t *testing.T) {
	tests := []struct {
		name           string
		yaml           string
		expectAutoFix  bool
		autoFixerCount int
	}{
		{
			name: "Auto-fixer added for pull_request_target with dangerous ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			expectAutoFix:  true,
			autoFixerCount: 1,
		},
		{
			name: "No auto-fixer for safe pull_request trigger",
			yaml: `
name: Test
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			expectAutoFix:  false,
			autoFixerCount: 0,
		},
		{
			name: "No auto-fixer for pull_request_target without ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			expectAutoFix:  false,
			autoFixerCount: 0,
		},
		{
			name: "Auto-fixer added for issue_comment with dangerous ref",
			yaml: `
name: Test
on: issue_comment
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			expectAutoFix:  true,
			autoFixerCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the workflow
			workflow, errs := Parse([]byte(tt.yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewUntrustedCheckoutRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Check auto-fixer count
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

// TestUntrustedCheckoutFixStep tests the FixStep method
func TestUntrustedCheckoutFixStep(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		expectedRef string
		expectError bool
	}{
		{
			name: "Fix dangerous ref by replacing with github.sha",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			expectedRef: "${{ github.sha }}",
			expectError: false,
		},
		{
			name: "Fix another dangerous ref pattern",
			yaml: `
name: Test
on: issue_comment
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			expectedRef: "${{ github.sha }}",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the workflow
			workflow, errs := Parse([]byte(tt.yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewUntrustedCheckoutRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow to detect issues and add auto-fixers
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Get auto-fixers
			autoFixers := rule.AutoFixers()
			if len(autoFixers) == 0 {
				t.Fatal("No auto-fixer was added")
			}

			// Apply the fix
			if err := autoFixers[0].Fix(); err != nil {
				if !tt.expectError {
					t.Errorf("FixStep() unexpected error = %v", err)
				}
				return
			}

			if tt.expectError {
				t.Error("Expected error but got none")
				return
			}

			// Verify the fix was applied
			// Navigate to the step and check the ref value
			var foundJob *ast.Job
			for _, job := range workflow.Jobs {
				foundJob = job
				break
			}
			if foundJob == nil {
				t.Fatal("No job found in workflow")
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

// TestUntrustedCheckoutJobIfConditionFiltering tests that when a job has an if condition
// that filters out some triggers, the diagnostic points to the correct trigger.
func TestUntrustedCheckoutJobIfConditionFiltering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		yaml                string
		expectedTriggerName string
		wantErr             bool
	}{
		{
			name: "Multiple triggers - job if filters to issue_comment only",
			yaml: `
name: Test
on:
  pull_request_target:
  issue_comment:
jobs:
  test:
    if: github.event_name == 'issue_comment'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			expectedTriggerName: "issue_comment",
			wantErr:             true,
		},
		{
			name: "Multiple triggers - job if filters to pull_request_target only",
			yaml: `
name: Test
on:
  pull_request_target:
  issue_comment:
  workflow_run:
jobs:
  test:
    if: github.event_name == 'pull_request_target'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			expectedTriggerName: "pull_request_target",
			wantErr:             true,
		},
		{
			name: "Multiple triggers - job if filters out all dangerous triggers",
			yaml: `
name: Test
on:
  pull_request_target:
  pull_request:
jobs:
  test:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			expectedTriggerName: "",
			wantErr:             false,
		},
		{
			name: "Multiple triggers - job if with contains filters to workflow_run",
			yaml: `
name: Test
on:
  pull_request_target:
  issue_comment:
  workflow_run:
jobs:
  test:
    if: contains(fromJson('["workflow_run"]'), github.event_name)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			expectedTriggerName: "workflow_run",
			wantErr:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Parse the workflow
			workflow, errs := Parse([]byte(tt.yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewUntrustedCheckoutRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Check errors
			ruleErrs := rule.Errors()
			if tt.wantErr {
				if len(ruleErrs) == 0 {
					t.Errorf("Expected error but got none")
					return
				}

				// Verify the error message contains the expected trigger name
				errMsg := ruleErrs[0].Description
				if tt.expectedTriggerName != "" && !containsString(errMsg, tt.expectedTriggerName) {
					t.Errorf("Expected error message to mention trigger %q, but got: %s",
						tt.expectedTriggerName, errMsg)
				}
			} else {
				if len(ruleErrs) > 0 {
					t.Errorf("Unexpected error: %v", ruleErrs[0].Description)
				}
			}
		})
	}
}
