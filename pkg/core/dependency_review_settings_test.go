package core

import (
	"io"
	"strings"
	"testing"
)

func TestDependencyReviewSettingsRule_CommentSummaryRequiresPullRequestsWrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		workflow     string
		wantFindings int
	}{
		{
			name: "comment summary always without pull-requests write",
			workflow: `
name: dependency review
on: pull_request
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: always
`,
			wantFindings: 1,
		},
		{
			name: "comment summary on-failure without pull-requests write",
			workflow: `
name: dependency review
on: pull_request
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: on-failure
`,
			wantFindings: 1,
		},
		{
			name: "comment summary without explicit permissions",
			workflow: `
name: dependency review
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: always
`,
			wantFindings: 1,
		},
		{
			name: "workflow-level pull-requests write allows comment summary",
			workflow: `
name: dependency review
on: pull_request
permissions:
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: always
`,
			wantFindings: 0,
		},
		{
			name: "job-level pull-requests write allows comment summary",
			workflow: `
name: dependency review
on: pull_request
permissions:
  contents: read
jobs:
  review:
    permissions:
      pull-requests: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: always
`,
			wantFindings: 0,
		},
		{
			name: "job-level permissions override workflow pull-requests write",
			workflow: `
name: dependency review
on: pull_request
permissions:
  pull-requests: write
jobs:
  review:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: always
`,
			wantFindings: 1,
		},
		{
			name: "comment summary never is ignored",
			workflow: `
name: dependency review
on: pull_request
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: never
`,
			wantFindings: 0,
		},
		{
			name: "missing comment summary setting is ignored",
			workflow: `
name: dependency review
on: pull_request
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
`,
			wantFindings: 0,
		},
		{
			name: "write-all allows comment summary",
			workflow: `
name: dependency review
on: pull_request
permissions: write-all
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: always
`,
			wantFindings: 0,
		},
		{
			name: "other action is ignored",
			workflow: `
name: dependency review
on: pull_request
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          comment-summary-in-pr: always
`,
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewDependencyReviewSettingsRule()
			workflow, parseErrs := Parse([]byte(tt.workflow))
			if len(parseErrs) > 0 {
				t.Fatalf("Parse() errors = %v", parseErrs)
			}

			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("VisitTree() error = %v", err)
			}

			gotFindings := countDependencyReviewCommentSummaryFindings(rule)
			if gotFindings != tt.wantFindings {
				t.Fatalf("findings = %d, want %d; errors = %v", gotFindings, tt.wantFindings, rule.Errors())
			}
		})
	}
}

func TestDependencyReviewSettingsRule_LinterIntegration(t *testing.T) {
	t.Parallel()

	workflow := `
name: dependency review
on: pull_request
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: always
`
	linter, err := NewLinter(io.Discard, &LinterOptions{})
	if err != nil {
		t.Fatalf("NewLinter() error = %v", err)
	}
	result, err := linter.Lint("<test>", []byte(workflow), nil)
	if err != nil {
		t.Fatalf("Lint() error = %v", err)
	}

	found := false
	for _, err := range result.Errors {
		if err.Type == "dependency-review-settings" &&
			strings.Contains(err.Description, "comment-summary-in-pr") &&
			strings.Contains(err.Description, "pull-requests: write") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected dependency-review-settings finding, got errors = %v", result.Errors)
	}
}

func TestDependencyReviewSettingsRule_DetectsDisabledSecurityGates(t *testing.T) {
	t.Parallel()

	workflow := `
name: dependency review
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          warn-only: true
          vulnerability-check: disable
          license-check: disable
          fail-on-severity: high
          fail-on-scopes: runtime
          allow-licenses: MIT
`
	rule := runDependencyReviewSettingsRule(t, workflow)

	assertDependencyReviewFinding(t, rule, "warn-only", "warning")
	assertDependencyReviewFinding(t, rule, "vulnerability-check", "disable", "warning")
	assertDependencyReviewFinding(t, rule, "license-check", "disable", "info")
}

func TestDependencyReviewSettingsRule_DetectsFalseSecurityGates(t *testing.T) {
	t.Parallel()

	workflow := `
name: dependency review
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          vulnerability-check: false
          license-check: false
          fail-on-severity: high
          fail-on-scopes: runtime
          allow-licenses: MIT
`
	rule := runDependencyReviewSettingsRule(t, workflow)

	assertDependencyReviewFinding(t, rule, "vulnerability-check", "false", "warning")
	assertDependencyReviewFinding(t, rule, "license-check", "false", "info")
}

func TestDependencyReviewSettingsRule_ConfigFileSkipsMissingInlineRecommendations(t *testing.T) {
	t.Parallel()

	workflow := `
name: dependency review
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          config-file: ./.github/dependency-review.yml
          warn-only: true
`
	rule := runDependencyReviewSettingsRule(t, workflow)

	assertDependencyReviewFinding(t, rule, "warn-only", "warning")
	assertNoDependencyReviewFinding(t, rule, "fail-on-severity")
	assertNoDependencyReviewFinding(t, rule, "fail-on-scopes")
	assertNoDependencyReviewFinding(t, rule, "does not define a license policy")
}

func TestDependencyReviewSettingsRule_DisabledGatesSkipRelatedMissingRecommendations(t *testing.T) {
	t.Parallel()

	workflow := `
name: dependency review
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          vulnerability-check: false
          license-check: false
`
	rule := runDependencyReviewSettingsRule(t, workflow)

	assertDependencyReviewFinding(t, rule, "vulnerability-check", "false", "warning")
	assertDependencyReviewFinding(t, rule, "license-check", "false", "info")
	assertNoDependencyReviewFinding(t, rule, "fail-on-severity")
	assertNoDependencyReviewFinding(t, rule, "fail-on-scopes")
	assertNoDependencyReviewFinding(t, rule, "does not define a license policy")
}

func TestDependencyReviewSettingsRule_DetectsMissingRecommendedSettings(t *testing.T) {
	t.Parallel()

	workflow := `
name: dependency review
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          warn-only: false
          vulnerability-check: true
`
	rule := runDependencyReviewSettingsRule(t, workflow)

	assertDependencyReviewFinding(t, rule, "fail-on-severity", "info")
	assertDependencyReviewFinding(t, rule, "fail-on-scopes", "info")
	assertDependencyReviewFinding(t, rule, "license policy", "info")
}

func TestDependencyReviewSettingsRule_DetectsLargeAllowLists(t *testing.T) {
	t.Parallel()

	workflow := `
name: dependency review
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: high
          fail-on-scopes: runtime
          deny-licenses: GPL-3.0
          allow-ghsas: GHSA-1111-2222-3333, GHSA-2222-3333-4444, GHSA-3333-4444-5555, GHSA-4444-5555-6666, GHSA-5555-6666-7777
          allow-dependencies-licenses: pkg:npm/a@1.0.0, pkg:npm/b@1.0.0, pkg:npm/c@1.0.0, pkg:npm/d@1.0.0, pkg:npm/e@1.0.0
`
	rule := runDependencyReviewSettingsRule(t, workflow)

	assertDependencyReviewFinding(t, rule, "allow-ghsas", "warning")
	assertDependencyReviewFinding(t, rule, "allow-dependencies-licenses", "info")
}

func TestDependencyReviewSettingsRule_SafeConfigurationDoesNotWarn(t *testing.T) {
	t.Parallel()

	workflow := `
name: dependency review
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          warn-only: false
          vulnerability-check: true
          license-check: true
          fail-on-severity: high
          fail-on-scopes: runtime
          allow-licenses: MIT, Apache-2.0
          allow-ghsas: GHSA-1111-2222-3333, GHSA-2222-3333-4444
          allow-dependencies-licenses: pkg:npm/a@1.0.0, pkg:npm/b@1.0.0
`
	rule := runDependencyReviewSettingsRule(t, workflow)

	for _, err := range rule.Errors() {
		if strings.Contains(err.Description, "(warning)") || strings.Contains(err.Description, "(info)") {
			t.Fatalf("expected no #489 settings findings, got errors = %v", rule.Errors())
		}
	}
}

func TestDependencyReviewSettingsRule_DynamicInputsAreConservative(t *testing.T) {
	t.Parallel()

	workflow := `
name: dependency review
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          warn-only: ${{ inputs.warn_only }}
          vulnerability-check: ${{ inputs.vulnerability_check }}
          license-check: ${{ inputs.license_check }}
          fail-on-severity: ${{ vars.FAIL_ON_SEVERITY }}
          fail-on-scopes: ${{ vars.FAIL_ON_SCOPES }}
          allow-licenses: ${{ vars.ALLOW_LICENSES }}
          allow-ghsas: ${{ format('GHSA-1111-2222-3333, GHSA-2222-3333-4444, GHSA-3333-4444-5555, GHSA-4444-5555-6666, GHSA-5555-6666-7777') }}
          allow-dependencies-licenses: ${{ format('pkg:npm/a@1.0.0, pkg:npm/b@1.0.0, pkg:npm/c@1.0.0, pkg:npm/d@1.0.0, pkg:npm/e@1.0.0') }}
`
	rule := runDependencyReviewSettingsRule(t, workflow)

	for _, err := range rule.Errors() {
		if strings.Contains(err.Description, "(warning)") || strings.Contains(err.Description, "(info)") {
			t.Fatalf("expected dynamic settings to be treated conservatively, got errors = %v", rule.Errors())
		}
	}
}

func TestDependencyReviewSettingsRule_IgnoresOtherActionsForSettingsChecks(t *testing.T) {
	t.Parallel()

	workflow := `
name: dependency review
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          warn-only: true
          vulnerability-check: disable
          allow-ghsas: GHSA-1111-2222-3333, GHSA-2222-3333-4444, GHSA-3333-4444-5555, GHSA-4444-5555-6666, GHSA-5555-6666-7777
`
	rule := runDependencyReviewSettingsRule(t, workflow)

	if len(rule.Errors()) != 0 {
		t.Fatalf("expected other action to be ignored, got errors = %v", rule.Errors())
	}
}

func countDependencyReviewCommentSummaryFindings(rule *DependencyReviewSettingsRule) int {
	count := 0
	for _, err := range rule.Errors() {
		if err.Type == "dependency-review-settings" &&
			strings.Contains(err.Description, "comment-summary-in-pr") &&
			strings.Contains(err.Description, "pull-requests: write") {
			count++
		}
	}
	return count
}

func runDependencyReviewSettingsRule(t *testing.T, workflowText string) *DependencyReviewSettingsRule {
	t.Helper()

	rule := NewDependencyReviewSettingsRule()
	workflow, parseErrs := Parse([]byte(workflowText))
	if len(parseErrs) > 0 {
		t.Fatalf("Parse() errors = %v", parseErrs)
	}

	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("VisitTree() error = %v", err)
	}

	return rule
}

func assertDependencyReviewFinding(t *testing.T, rule *DependencyReviewSettingsRule, contains ...string) {
	t.Helper()

	for _, err := range rule.Errors() {
		if err.Type != "dependency-review-settings" {
			continue
		}
		matches := true
		for _, want := range contains {
			if !strings.Contains(err.Description, want) {
				matches = false
				break
			}
		}
		if matches {
			return
		}
	}
	t.Fatalf("expected dependency-review-settings finding containing %v, got errors = %v", contains, rule.Errors())
}

func assertNoDependencyReviewFinding(t *testing.T, rule *DependencyReviewSettingsRule, contains ...string) {
	t.Helper()

	for _, err := range rule.Errors() {
		if err.Type != "dependency-review-settings" {
			continue
		}
		matches := true
		for _, want := range contains {
			if !strings.Contains(err.Description, want) {
				matches = false
				break
			}
		}
		if matches {
			t.Fatalf("expected no dependency-review-settings finding containing %v, got errors = %v", contains, rule.Errors())
		}
	}
}
