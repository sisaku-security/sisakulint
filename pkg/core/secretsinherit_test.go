package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/core/chain"
)

func TestNewSecretsInheritRule(t *testing.T) {
	t.Parallel()

	rule := NewSecretsInheritRule()

	if rule.RuleName != "secrets-inherit" {
		t.Errorf("Expected RuleName to be 'secrets-inherit', got '%s'", rule.RuleName)
	}

	expectedDesc := "Detects excessive secret inheritance using 'secrets: inherit' in reusable workflow calls"
	if rule.RuleDesc != expectedDesc {
		t.Errorf("Expected RuleDesc to be '%s', got '%s'", expectedDesc, rule.RuleDesc)
	}
}

func TestSecretsInheritRule_VisitJobPre_DetectsInherit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		workflow    string
		expectError bool
	}{
		{
			name: "secrets: inherit should be detected",
			workflow: `
on: push
jobs:
  call-workflow:
    uses: ./.github/workflows/called.yml
    secrets: inherit
`,
			expectError: true,
		},
		{
			name: "explicit secrets should not be detected",
			workflow: `
on: push
jobs:
  call-workflow:
    uses: ./.github/workflows/called.yml
    secrets:
      TOKEN: ${{ secrets.TOKEN }}
`,
			expectError: false,
		},
		{
			name: "no secrets should not be detected",
			workflow: `
on: push
jobs:
  call-workflow:
    uses: ./.github/workflows/called.yml
`,
			expectError: false,
		},
		{
			name: "external workflow with inherit should be detected",
			workflow: `
on: push
jobs:
  call-workflow:
    uses: owner/repo/.github/workflows/workflow.yml@v1
    secrets: inherit
`,
			expectError: true,
		},
		{
			name: "regular job without workflow call should not be detected",
			workflow: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewSecretsInheritRule()
			workflow, errs := Parse([]byte(tt.workflow))
			if len(errs) > 0 {
				t.Fatalf("failed to parse workflow: %v", errs)
			}

			v := NewSyntaxTreeVisitor()
			v.AddVisitor(rule)
			if err := v.VisitTree(workflow); err != nil {
				t.Fatalf("failed to visit tree: %v", err)
			}

			errors := rule.Errors()
			if tt.expectError && len(errors) == 0 {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && len(errors) > 0 {
				t.Errorf("Expected no error but got: %v", errors[0].Description)
			}
		})
	}
}

func TestSecretsInheritRule_ErrorMessage(t *testing.T) {
	t.Parallel()

	workflow := `
on: push
jobs:
  call-workflow:
    uses: ./.github/workflows/called.yml
    secrets: inherit
`
	rule := NewSecretsInheritRule()
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(errors))
	}

	errMsg := errors[0].Description
	if !strings.Contains(errMsg, "secrets: inherit") {
		t.Errorf("Error message should contain 'secrets: inherit', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "principle of least authority") {
		t.Errorf("Error message should mention 'principle of least authority', got: %s", errMsg)
	}
}

// TestSecretsInheritRule_PushesSinkRecord verifies that a detected
// 'secrets: inherit' usage is also pushed to the chain.SinkCollector for the
// leakage-path chain visualization feature (Milestone E task 16).
func TestSecretsInheritRule_PushesSinkRecord(t *testing.T) {
	t.Parallel()

	workflow := `
on: push
jobs:
  call-workflow:
    uses: ./.github/workflows/called.yml
    secrets: inherit
`
	collector := chain.NewSinkCollector()
	rule := NewSecretsInheritRuleWithCacheAndCollector(nil, collector)
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	if len(rule.Errors()) != 1 {
		t.Fatalf("expected 1 error, got %d", len(rule.Errors()))
	}

	recs := collector.Records()
	if len(recs) != 1 {
		t.Fatalf("expected 1 SinkRecord pushed, got %d", len(recs))
	}
	r := recs[0]
	if r.SinkKind != chain.SinkBoundary {
		t.Errorf("SinkKind = %v, want SinkBoundary", r.SinkKind)
	}
	if r.SourceKind != chain.SourceSecret {
		t.Errorf("SourceKind = %v, want SourceSecret", r.SourceKind)
	}
	if r.JobID != "call-workflow" {
		t.Errorf("JobID = %q, want %q", r.JobID, "call-workflow")
	}
	if r.RuleName == "" || r.StepPos == nil {
		t.Error("RuleName/StepPos must be populated")
	}
}
