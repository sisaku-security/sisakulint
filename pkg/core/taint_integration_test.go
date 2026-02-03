package core

import (
	"io"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

func TestCodeInjectionRule_TaintPropagation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		workflow       string
		expectError    bool
		expectContains string
	}{
		{
			name: "detect tainted step output via env var - shell metacharacter",
			workflow: `name: Test
on: issue_comment

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - id: get-ref
        run: echo "ref=${{ github.event.comment.body }}" >> $GITHUB_OUTPUT

      - env:
          BRANCH: ${{ steps.get-ref.outputs.ref }}
        run: |
          git push origin HEAD:${BRANCH}
`,
			expectError:    true,
			expectContains: "tainted via",
		},
		{
			name: "detect tainted step output with head_ref",
			workflow: `name: Test
on: issue_comment

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - id: comment-branch
        run: |
          echo "head_ref=${{ github.head_ref }}" >> $GITHUB_OUTPUT

      - env:
          BRANCH_NAME: ${{ steps.comment-branch.outputs.head_ref }}
        run: |
          git push origin HEAD:${BRANCH_NAME}
`,
			expectError:    true,
			expectContains: "tainted via",
		},
		{
			name: "safe step output should not trigger",
			workflow: `name: Test
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - id: get-sha
        run: echo "sha=${{ github.sha }}" >> $GITHUB_OUTPUT

      - env:
          COMMIT: ${{ steps.get-sha.outputs.sha }}
        run: |
          git checkout $COMMIT
`,
			expectError:    false,
			expectContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			linter, lintErr := NewLinter(io.Discard, &LinterOptions{})
			if lintErr != nil {
				t.Fatalf("failed to create linter: %v", lintErr)
			}
			// Only enable code-injection-critical rule for this test
			result, lintErr := linter.Lint("<test>", []byte(tt.workflow), nil)
			if lintErr != nil {
				t.Fatalf("failed to lint: %v", lintErr)
			}

			// Filter for code-injection errors with taint
			var taintErrors []string
			for _, err := range result.Errors {
				if strings.Contains(err.Description, "tainted via") {
					t.Logf("Found taint error: %s", err.Description)
					taintErrors = append(taintErrors, err.Description)
				} else if strings.Contains(err.Description, "code injection") && strings.Contains(err.Description, "steps.") {
					t.Logf("Found steps code injection error: %s", err.Description)
					taintErrors = append(taintErrors, err.Description)
				}
			}

			if tt.expectError && len(taintErrors) == 0 {
				t.Errorf("expected taint propagation error containing %q, but got none", tt.expectContains)
				for _, e := range result.Errors {
					t.Logf("Error: %s", e.Description)
				}
			}

			if !tt.expectError && len(taintErrors) > 0 {
				t.Errorf("expected no taint propagation errors, but got: %v", taintErrors)
			}

			if tt.expectError && tt.expectContains != "" {
				found := false
				for _, err := range taintErrors {
					if strings.Contains(err, tt.expectContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing %q, but none found in: %v", tt.expectContains, taintErrors)
				}
			}
		})
	}
}

func TestTaintTracker_IntegrationWithNodeParsing(t *testing.T) {
	t.Parallel()

	// Test that IsTainted works with parsed expression nodes
	tracker := NewTaintTracker()
	tracker.taintedOutputs["get-ref"] = map[string][]string{
		"ref": {"github.event.comment.body"},
	}

	// Parse an expression like "steps.get-ref.outputs.ref"
	exprStr := "steps.get-ref.outputs.ref"
	l := expressions.NewTokenizer(exprStr + "}}")
	p := expressions.NewMiniParser()
	node, err := p.Parse(l)
	if err != nil {
		t.Fatalf("failed to parse expression: %v", err)
	}

	tainted, sources := tracker.IsTainted(node)
	if !tainted {
		t.Errorf("expected expression to be tainted, but it was not")
		t.Logf("Node type: %T", node)
		t.Logf("Node string: %s", tracker.nodeToString(node))
	}

	if len(sources) == 0 {
		t.Error("expected taint sources, but got none")
	} else {
		t.Logf("Taint sources: %v", sources)
	}
}
