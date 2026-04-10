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

func TestCrossJobTaintPropagation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		workflow       string
		expectError    bool
		expectContains string
	}{
		{
			name: "直接参照: pull_request_target + 2ジョブ構成で検出される",
			workflow: `name: Test
on: pull_request_target

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      pr_title: ${{ steps.meta.outputs.title }}
    steps:
      - id: meta
        run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT

  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: echo "Processing ${{ needs.extract.outputs.pr_title }}"
`,
			expectError:    true,
			expectContains: "tainted via",
		},
		{
			name: "3ジョブチェーン: multi-hop で検出される",
			workflow: `name: Test
on: pull_request_target

jobs:
  job-a:
    runs-on: ubuntu-latest
    outputs:
      title: ${{ steps.get.outputs.title }}
    steps:
      - id: get
        run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT

  job-b:
    needs: job-a
    runs-on: ubuntu-latest
    outputs:
      processed: ${{ needs.job-a.outputs.title }}
    steps:
      - run: echo "pass-through"

  job-c:
    needs: job-b
    runs-on: ubuntu-latest
    steps:
      - run: echo "Final ${{ needs.job-b.outputs.processed }}"
`,
			expectError:    true,
			expectContains: "tainted via",
		},
		{
			name: "誤検知なし: 定数値ジョブ出力は報告しない",
			workflow: `name: Test
on: pull_request_target

jobs:
  safe-job:
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.get-version.outputs.version }}
    steps:
      - id: get-version
        run: echo "version=1.0.0" >> $GITHUB_OUTPUT

  consumer:
    needs: safe-job
    runs-on: ubuntu-latest
    steps:
      - run: echo "Version ${{ needs.safe-job.outputs.version }}"
`,
			expectError:    false,
			expectContains: "",
		},
		{
			name: "Medium: 通常トリガーでも検出される",
			workflow: `name: Test
on: pull_request

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      pr_title: ${{ steps.meta.outputs.title }}
    steps:
      - id: meta
        run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT

  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: echo "Processing ${{ needs.extract.outputs.pr_title }}"
`,
			expectError:    true,
			expectContains: "tainted via",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			linter, err := NewLinter(io.Discard, &LinterOptions{})
			if err != nil {
				t.Fatalf("failed to create linter: %v", err)
			}

			result, err := linter.Lint("<test>", []byte(tt.workflow), nil)
			if err != nil {
				t.Fatalf("failed to lint: %v", err)
			}

			var crossJobErrors []string
			for _, e := range result.Errors {
				if strings.Contains(e.Description, "tainted via") {
					crossJobErrors = append(crossJobErrors, e.Description)
				}
			}

			if tt.expectError && len(crossJobErrors) == 0 {
				t.Errorf("expected cross-job taint error containing %q, but got none", tt.expectContains)
				for _, e := range result.Errors {
					t.Logf("Error: %s", e.Description)
				}
			}

			if !tt.expectError && len(crossJobErrors) > 0 {
				t.Errorf("expected no cross-job taint errors, but got: %v", crossJobErrors)
			}

			if tt.expectError && tt.expectContains != "" {
				found := false
				for _, e := range crossJobErrors {
					if strings.Contains(e, tt.expectContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing %q, but none found in: %v", tt.expectContains, crossJobErrors)
				}
			}
		})
	}
}

func TestCrossJobTaintPropagation_ReverseOrder(t *testing.T) {
	t.Parallel()

	// yaml に逆順で記述されていても検出されること（pending 機構の検証）
	workflow := `name: Test
on: pull_request_target

jobs:
  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: echo "Processing ${{ needs.extract.outputs.pr_title }}"

  extract:
    runs-on: ubuntu-latest
    outputs:
      pr_title: ${{ steps.meta.outputs.title }}
    steps:
      - id: meta
        run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
`

	linter, err := NewLinter(io.Discard, &LinterOptions{})
	if err != nil {
		t.Fatalf("failed to create linter: %v", err)
	}

	result, err := linter.Lint("<test>", []byte(workflow), nil)
	if err != nil {
		t.Fatalf("failed to lint: %v", err)
	}

	var crossJobErrors []string
	for _, e := range result.Errors {
		if strings.Contains(e.Description, "tainted via") {
			crossJobErrors = append(crossJobErrors, e.Description)
		}
	}

	if len(crossJobErrors) == 0 {
		t.Error("expected cross-job taint error even with reverse yaml order, but got none")
		for _, e := range result.Errors {
			t.Logf("Error: %s", e.Description)
		}
	}
}

func TestCrossJobTaintPropagation_EnvVarInjection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		workflow       string
		expectError    bool
		expectContains string
	}{
		{
			name: "needs output の汚染値を GITHUB_ENV に書き込み - critical",
			workflow: `name: Test
on: pull_request_target

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      pr_title: ${{ steps.meta.outputs.title }}
    steps:
      - id: meta
        run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT

  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: echo "TITLE=${{ needs.extract.outputs.pr_title }}" >> $GITHUB_ENV
`,
			expectError:    true,
			expectContains: "environment variable injection",
		},
		{
			name: "定数値 needs output は GITHUB_ENV に書いても安全",
			workflow: `name: Test
on: pull_request_target

jobs:
  safe-job:
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.v.outputs.version }}
    steps:
      - id: v
        run: echo "version=1.0.0" >> $GITHUB_OUTPUT

  consumer:
    needs: safe-job
    runs-on: ubuntu-latest
    steps:
      - run: echo "VER=${{ needs.safe-job.outputs.version }}" >> $GITHUB_ENV
`,
			expectError:    false,
			expectContains: "",
		},
		{
			name: "needs output の汚染値を GITHUB_ENV に書き込み - medium (pull_request)",
			workflow: `name: Test
on: pull_request

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      pr_title: ${{ steps.meta.outputs.title }}
    steps:
      - id: meta
        run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT

  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: echo "TITLE=${{ needs.extract.outputs.pr_title }}" >> $GITHUB_ENV
`,
			expectError:    true,
			expectContains: "environment variable injection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			linter, err := NewLinter(io.Discard, &LinterOptions{})
			if err != nil {
				t.Fatalf("failed to create linter: %v", err)
			}

			result, err := linter.Lint("<test>", []byte(tt.workflow), nil)
			if err != nil {
				t.Fatalf("failed to lint: %v", err)
			}

			var matchingErrors []string
			for _, e := range result.Errors {
				if strings.Contains(e.Description, "tainted via") && strings.Contains(e.Description, "environment variable injection") {
					matchingErrors = append(matchingErrors, e.Description)
				}
			}

			if tt.expectError && len(matchingErrors) != 1 {
				t.Errorf("expected exactly 1 error containing %q, but got %d: %v", tt.expectContains, len(matchingErrors), matchingErrors)
				for _, e := range result.Errors {
					t.Logf("Error: %s", e.Description)
				}
			}

			if !tt.expectError && len(matchingErrors) > 0 {
				t.Errorf("expected no matching errors, but got: %v", matchingErrors)
			}
		})
	}
}

func TestCrossJobTaintPropagation_ArgumentInjection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		workflow       string
		expectError    bool
		expectContains string
	}{
		{
			name: "needs output の汚染値をコマンド引数に展開 - critical",
			workflow: `name: Test
on: pull_request_target

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      branch: ${{ steps.meta.outputs.branch }}
    steps:
      - id: meta
        run: echo "branch=${{ github.head_ref }}" >> $GITHUB_OUTPUT

  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: git checkout ${{ needs.extract.outputs.branch }}
`,
			expectError:    true,
			expectContains: "argument injection",
		},
		{
			name: "定数値 needs output をコマンド引数に使っても安全",
			workflow: `name: Test
on: pull_request_target

jobs:
  safe-job:
    runs-on: ubuntu-latest
    outputs:
      tag: ${{ steps.v.outputs.tag }}
    steps:
      - id: v
        run: echo "tag=v1.0.0" >> $GITHUB_OUTPUT

  consumer:
    needs: safe-job
    runs-on: ubuntu-latest
    steps:
      - run: git checkout ${{ needs.safe-job.outputs.tag }}
`,
			expectError:    false,
			expectContains: "",
		},
		{
			name: "needs output の汚染値をコマンド引数に展開 - medium (pull_request)",
			workflow: `name: Test
on: pull_request

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      branch: ${{ steps.meta.outputs.branch }}
    steps:
      - id: meta
        run: echo "branch=${{ github.head_ref }}" >> $GITHUB_OUTPUT

  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: git checkout ${{ needs.extract.outputs.branch }}
`,
			expectError:    true,
			expectContains: "argument injection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			linter, err := NewLinter(io.Discard, &LinterOptions{})
			if err != nil {
				t.Fatalf("failed to create linter: %v", err)
			}

			result, err := linter.Lint("<test>", []byte(tt.workflow), nil)
			if err != nil {
				t.Fatalf("failed to lint: %v", err)
			}

			var matchingErrors []string
			for _, e := range result.Errors {
				if strings.Contains(e.Description, "tainted via") && strings.Contains(e.Description, "argument injection") {
					matchingErrors = append(matchingErrors, e.Description)
				}
			}

			if tt.expectError && len(matchingErrors) != 1 {
				t.Errorf("expected exactly 1 error containing %q, but got %d: %v", tt.expectContains, len(matchingErrors), matchingErrors)
				for _, e := range result.Errors {
					t.Logf("Error: %s", e.Description)
				}
			}

			if !tt.expectError && len(matchingErrors) > 0 {
				t.Errorf("expected no matching errors, but got: %v", matchingErrors)
			}
		})
	}
}

func TestCrossJobTaintPropagation_RequestForgery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		workflow       string
		expectError    bool
		expectContains string
	}{
		{
			name: "needs output の汚染値を curl URL に使用 - critical",
			workflow: `name: Test
on: pull_request_target

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      api_url: ${{ steps.meta.outputs.url }}
    steps:
      - id: meta
        run: echo "url=${{ github.event.pull_request.body }}" >> $GITHUB_OUTPUT

  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: curl ${{ needs.extract.outputs.api_url }}
`,
			expectError:    true,
			expectContains: "request forgery",
		},
		{
			name: "定数値 needs output を curl に使っても安全",
			workflow: `name: Test
on: pull_request_target

jobs:
  safe-job:
    runs-on: ubuntu-latest
    outputs:
      url: ${{ steps.v.outputs.url }}
    steps:
      - id: v
        run: echo "url=https://api.github.com" >> $GITHUB_OUTPUT

  consumer:
    needs: safe-job
    runs-on: ubuntu-latest
    steps:
      - run: curl ${{ needs.safe-job.outputs.url }}
`,
			expectError:    false,
			expectContains: "",
		},
		{
			name: "needs output の汚染値を curl URL に使用 - medium (pull_request)",
			workflow: `name: Test
on: pull_request

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      api_url: ${{ steps.meta.outputs.url }}
    steps:
      - id: meta
        run: echo "url=${{ github.event.pull_request.body }}" >> $GITHUB_OUTPUT

  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: curl ${{ needs.extract.outputs.api_url }}
`,
			expectError:    true,
			expectContains: "request forgery",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			linter, err := NewLinter(io.Discard, &LinterOptions{})
			if err != nil {
				t.Fatalf("failed to create linter: %v", err)
			}

			result, err := linter.Lint("<test>", []byte(tt.workflow), nil)
			if err != nil {
				t.Fatalf("failed to lint: %v", err)
			}

			var matchingErrors []string
			for _, e := range result.Errors {
				if strings.Contains(e.Description, "tainted via") && strings.Contains(e.Description, "request forgery") {
					matchingErrors = append(matchingErrors, e.Description)
				}
			}

			if tt.expectError && len(matchingErrors) != 1 {
				t.Errorf("expected exactly 1 error containing %q, but got %d: %v", tt.expectContains, len(matchingErrors), matchingErrors)
				for _, e := range result.Errors {
					t.Logf("Error: %s", e.Description)
				}
			}

			if !tt.expectError && len(matchingErrors) > 0 {
				t.Errorf("expected no matching errors, but got: %v", matchingErrors)
			}
		})
	}
}
