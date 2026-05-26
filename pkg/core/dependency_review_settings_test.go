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
