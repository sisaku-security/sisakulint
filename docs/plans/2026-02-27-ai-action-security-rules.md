# AI Action Security Rules Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Issue #345 に対応し、AI エージェント系アクション（claude-code-action 等）の危険な設定を検出する 3 つのルールを TDD で実装する。

**Architecture:** 既存の `ArgumentInjectionRule` / `CodeInjectionRule` のパターンに倣い、`VisitStep` で AI アクションの `with:` パラメータを検査する Rule を 3 つ追加する。Rule 3（ai-prompt-injection）は既存の `ExprSemanticsChecker` を再利用して untrusted 入力を検出する。

**Tech Stack:** Go 1.25, `pkg/core/` の Rule パターン, `pkg/expressions/` の ExprSemanticsChecker, `pkg/ast/` の ExecAction

**背景（Clinejection 攻撃）:**
2026/02/17 に Cline リポジトリで発生したサプライチェーン攻撃。`allowed_non_write_users: "*"` + `claude_args: --allowedTools "Bash,..."` + `prompt: ${{ github.event.issue.title }}` の組み合わせにより、任意の GitHub ユーザーが Issue を投稿するだけで AI エージェントに任意シェルコマンドを実行させ、NPM_RELEASE_TOKEN を窃取できた。

---

## Task 1: Rule 1 — `ai-action-unrestricted-trigger` のテスト作成

`allowed_non_write_users: "*"` を既知の AI アクションで使っている場合に検出する。

**Files:**
- Create: `pkg/core/aiaction_unrestricted_trigger.go`
- Create: `pkg/core/aiaction_unrestricted_trigger_test.go`
- Create: `script/actions/ai-action-unrestricted-trigger-vulnerable.yaml`
- Create: `script/actions/ai-action-unrestricted-trigger-safe.yaml`

**Step 1: 脆弱なワークフローサンプルを作成**

`script/actions/ai-action-unrestricted-trigger-vulnerable.yaml`:
```yaml
name: Vulnerable AI Triage

on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

`script/actions/ai-action-unrestricted-trigger-safe.yaml`:
```yaml
name: Safe AI Triage

on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          # allowed_non_write_users を設定しない、または組織メンバーのみに制限
```

**Step 2: 失敗するテストを書く**

`pkg/core/aiaction_unrestricted_trigger_test.go`:
```go
package core

import (
	"testing"
)

func TestAIActionUnrestrictedTrigger_DetectsWildcard(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnrestrictedTriggerRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	errs := testRule(t, rule, workflow)
	if len(errs) == 0 {
		t.Fatal("expected error for allowed_non_write_users: \"*\", got none")
	}
	assertContains(t, errs[0].Message, "ai-action-unrestricted-trigger")
}

func TestAIActionUnrestrictedTrigger_IgnoresSafeConfig(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnrestrictedTriggerRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	errs := testRule(t, rule, workflow)
	if len(errs) != 0 {
		t.Fatalf("expected no errors for safe config, got %d: %v", len(errs), errs)
	}
}

func TestAIActionUnrestrictedTrigger_IgnoresNonAIAction(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnrestrictedTriggerRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          allowed_non_write_users: "*"
`
	errs := testRule(t, rule, workflow)
	if len(errs) != 0 {
		t.Fatalf("expected no errors for non-AI action, got %d", len(errs))
	}
}
```

**Step 3: テストを実行して失敗を確認**

```bash
cd /Users/atsushi.sada/go/src/github.com/sisaku-security/sisakulint
go test ./pkg/core/ -run TestAIActionUnrestrictedTrigger -v
```
期待: `FAIL` (関数が未定義)

---

## Task 2: Rule 1 の実装

**Step 1: Rule 実装を書く**

`pkg/core/aiaction_unrestricted_trigger.go`:
```go
package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// knownAIActions は検査対象の AI エージェントアクションのプレフィックスリスト
var knownAIActions = []string{
	"anthropics/claude-code-action",
	"github/copilot-swe-agent",
	"openai/openai-actions",
}

// AIActionUnrestrictedTriggerRule は allowed_non_write_users: "*" を検出する
type AIActionUnrestrictedTriggerRule struct {
	BaseRule
}

// NewAIActionUnrestrictedTriggerRule は新しいルールインスタンスを返す
func NewAIActionUnrestrictedTriggerRule() *AIActionUnrestrictedTriggerRule {
	r := &AIActionUnrestrictedTriggerRule{}
	r.RuleName = "ai-action-unrestricted-trigger"
	r.RuleDescription = "AI action allows any GitHub user to trigger agent execution"
	r.RuleSeverity = "critical"
	return r
}

func (r *AIActionUnrestrictedTriggerRule) VisitStep(node *ast.Step) error {
	if node.Exec == nil || node.Exec.Kind() != ast.ExecKindAction {
		return nil
	}
	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	if !isKnownAIAction(action.Uses.Value) {
		return nil
	}

	// with.allowed_non_write_users が "*" かどうかを検査
	if val, exists := action.Inputs["allowed_non_write_users"]; exists {
		if val.Value == "*" || strings.TrimSpace(val.Value) == "*" {
			r.Errorf(
				node.Pos,
				`ai-action-unrestricted-trigger: action %q has "allowed_non_write_users: \"*\"" which allows any GitHub user to trigger AI agent execution with full tool access. Restrict to specific users or organization members.`,
				action.Uses.Value,
			)
		}
	}

	return nil
}

// isKnownAIAction は uses の値が既知の AI アクションかどうかを確認する
func isKnownAIAction(uses string) bool {
	usesLower := strings.ToLower(uses)
	for _, prefix := range knownAIActions {
		if strings.HasPrefix(usesLower, prefix) {
			return true
		}
	}
	return false
}
```

**Step 2: テストを実行して成功を確認**

```bash
go test ./pkg/core/ -run TestAIActionUnrestrictedTrigger -v
```
期待: `PASS`

**Step 3: linter.go に登録**

`pkg/core/linter.go` の `makeRules` 関数の末尾（`NewCacheBloatRule()` の後）に追加:
```go
NewAIActionUnrestrictedTriggerRule(), // Detects AI actions with unrestricted user access
```

**Step 4: 全テスト実行**
```bash
go test ./pkg/core/ -v -count=1 2>&1 | tail -20
```

**Step 5: コミット**
```bash
git add pkg/core/aiaction_unrestricted_trigger.go \
        pkg/core/aiaction_unrestricted_trigger_test.go \
        pkg/core/linter.go \
        script/actions/ai-action-unrestricted-trigger-vulnerable.yaml \
        script/actions/ai-action-unrestricted-trigger-safe.yaml
git commit -m "feat(rule): add ai-action-unrestricted-trigger rule (issue #345)"
```

---

## Task 3: Rule 2 — `ai-action-excessive-tools` のテスト作成

`claude_args: --allowedTools "Bash,..."` などで危険なツールが許可されている場合に検出する。特に `issues` / `issue_comment` トリガーとの組み合わせで Critical。

**Files:**
- Create: `pkg/core/aiaction_excessive_tools.go`
- Create: `pkg/core/aiaction_excessive_tools_test.go`
- Create: `script/actions/ai-action-excessive-tools-vulnerable.yaml`
- Create: `script/actions/ai-action-excessive-tools-safe.yaml`

**Step 1: サンプルワークフロー作成**

`script/actions/ai-action-excessive-tools-vulnerable.yaml`:
```yaml
name: Vulnerable AI Agent

on:
  issues:
    types: [opened]
  issue_comment:
    types: [created]

jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

`script/actions/ai-action-excessive-tools-safe.yaml`:
```yaml
name: Safe AI Triage

on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Read,Glob,Grep"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

**Step 2: 失敗するテストを書く**

`pkg/core/aiaction_excessive_tools_test.go`:
```go
package core

import (
	"testing"
)

func TestAIActionExcessiveTools_DetectsBashWithIssuesTrigger(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExcessiveToolsRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Bash,Read,Write"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	errs := testRule(t, rule, workflow)
	if len(errs) == 0 {
		t.Fatal("expected error for Bash tool with issues trigger, got none")
	}
	assertContains(t, errs[0].Message, "ai-action-excessive-tools")
}

func TestAIActionExcessiveTools_AllowsReadOnlyTools(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExcessiveToolsRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Read,Glob,Grep"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	errs := testRule(t, rule, workflow)
	if len(errs) != 0 {
		t.Fatalf("expected no errors for read-only tools, got %d", len(errs))
	}
}

func TestAIActionExcessiveTools_AllowsBashWithPushTrigger(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExcessiveToolsRule()

	workflow := `
on:
  push:
    branches: [main]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Bash,Read"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	errs := testRule(t, rule, workflow)
	if len(errs) != 0 {
		t.Fatalf("expected no errors for Bash with trusted trigger, got %d", len(errs))
	}
}
```

**Step 3: テストを実行して失敗を確認**
```bash
go test ./pkg/core/ -run TestAIActionExcessiveTools -v
```
期待: `FAIL`

---

## Task 4: Rule 2 の実装

**Step 1: Rule 実装を書く**

`pkg/core/aiaction_excessive_tools.go`:
```go
package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// dangerousAITools はシェル実行や書き込みができる危険なツール
var dangerousAITools = []string{
	"Bash", "Write", "Edit", "NotebookEdit",
}

// untrustedTriggers は任意のユーザーがトリガーできるイベント
var aiExcessiveToolsUntrustedTriggers = map[string]bool{
	"issues":        true,
	"issue_comment": true,
	"discussion":    true,
}

// AIActionExcessiveToolsRule は AI アクションで危険なツールが
// 外部ユーザーがトリガーできるイベントと組み合わせて使われている場合に検出する
type AIActionExcessiveToolsRule struct {
	BaseRule
	triggers map[string]bool
}

// NewAIActionExcessiveToolsRule は新しいルールインスタンスを返す
func NewAIActionExcessiveToolsRule() *AIActionExcessiveToolsRule {
	r := &AIActionExcessiveToolsRule{
		triggers: make(map[string]bool),
	}
	r.RuleName = "ai-action-excessive-tools"
	r.RuleDescription = "AI action grants dangerous tools (Bash/Write/Edit) in workflow triggered by untrusted users"
	r.RuleSeverity = "critical"
	return r
}

func (r *AIActionExcessiveToolsRule) VisitWorkflowPre(node *ast.Workflow) error {
	for _, event := range node.On {
		if wh, ok := event.(*ast.WebhookEvent); ok {
			r.triggers[wh.Hook.Value] = true
		}
	}
	return nil
}

func (r *AIActionExcessiveToolsRule) VisitStep(node *ast.Step) error {
	if node.Exec == nil || node.Exec.Kind() != ast.ExecKindAction {
		return nil
	}
	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}
	if !isKnownAIAction(action.Uses.Value) {
		return nil
	}

	// untrusted トリガーがない場合はスキップ
	if !r.hasUntrustedTrigger() {
		return nil
	}

	// claude_args に危険なツールが含まれるか検査
	claudeArgs, exists := action.Inputs["claude_args"]
	if !exists {
		return nil
	}

	foundTools := r.findDangerousTools(claudeArgs.Value)
	if len(foundTools) == 0 {
		return nil
	}

	r.Errorf(
		node.Pos,
		"ai-action-excessive-tools: action %q grants dangerous tools [%s] in workflow triggered by untrusted users (%s). Restrict to read-only tools (Read, Glob, Grep) for triage workflows.",
		action.Uses.Value,
		strings.Join(foundTools, ", "),
		r.triggersString(),
	)

	return nil
}

func (r *AIActionExcessiveToolsRule) hasUntrustedTrigger() bool {
	for trigger := range r.triggers {
		if aiExcessiveToolsUntrustedTriggers[trigger] {
			return true
		}
	}
	return false
}

func (r *AIActionExcessiveToolsRule) findDangerousTools(claudeArgsValue string) []string {
	var found []string
	for _, tool := range dangerousAITools {
		if strings.Contains(claudeArgsValue, tool) {
			found = append(found, tool)
		}
	}
	return found
}

func (r *AIActionExcessiveToolsRule) triggersString() string {
	var triggers []string
	for t := range r.triggers {
		if aiExcessiveToolsUntrustedTriggers[t] {
			triggers = append(triggers, t)
		}
	}
	return strings.Join(triggers, ", ")
}
```

**Step 2: テストを実行して成功を確認**
```bash
go test ./pkg/core/ -run TestAIActionExcessiveTools -v
```
期待: `PASS`

**Step 3: linter.go に登録**

```go
NewAIActionExcessiveToolsRule(),       // Detects AI actions with dangerous tools in untrusted triggers
```

**Step 4: コミット**
```bash
git add pkg/core/aiaction_excessive_tools.go \
        pkg/core/aiaction_excessive_tools_test.go \
        pkg/core/linter.go \
        script/actions/ai-action-excessive-tools-vulnerable.yaml \
        script/actions/ai-action-excessive-tools-safe.yaml
git commit -m "feat(rule): add ai-action-excessive-tools rule (issue #345)"
```

---

## Task 5: Rule 3 — `ai-prompt-injection` のテスト作成

AI アクションの `prompt:` / `direct_prompt:` パラメータに `${{ github.event.issue.title }}` 等の untrusted 入力が展開されている場合に検出する。

**Files:**
- Create: `pkg/core/aiaction_prompt_injection.go`
- Create: `pkg/core/aiaction_prompt_injection_test.go`
- Create: `script/actions/ai-action-prompt-injection-vulnerable.yaml`
- Create: `script/actions/ai-action-prompt-injection-safe.yaml`

**Step 1: サンプルワークフロー作成**

`script/actions/ai-action-prompt-injection-vulnerable.yaml`:
```yaml
name: Vulnerable AI Prompt Injection

on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: |
            Please triage this issue:
            Title: ${{ github.event.issue.title }}
            Body: ${{ github.event.issue.body }}
```

`script/actions/ai-action-prompt-injection-safe.yaml`:
```yaml
name: Safe AI Triage

on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
          ISSUE_BODY: ${{ github.event.issue.body }}
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          # prompt はハードコードのみ。issue データは env 経由で渡す
          prompt: "Please triage the issue described in the environment variables ISSUE_TITLE and ISSUE_BODY."
```

**Step 2: 失敗するテストを書く**

`pkg/core/aiaction_prompt_injection_test.go`:
```go
package core

import (
	"testing"
)

func TestAIPromptInjection_DetectsIssueTitleInPrompt(t *testing.T) {
	t.Parallel()
	rule := NewAIPromptInjectionRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: |
            Title: ${{ github.event.issue.title }}
`
	errs := testRule(t, rule, workflow)
	if len(errs) == 0 {
		t.Fatal("expected error for untrusted input in prompt, got none")
	}
	assertContains(t, errs[0].Message, "ai-prompt-injection")
}

func TestAIPromptInjection_DetectsIssueBodyInDirectPrompt(t *testing.T) {
	t.Parallel()
	rule := NewAIPromptInjectionRule()

	workflow := `
on:
  issue_comment:
    types: [created]
jobs:
  respond:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          direct_prompt: "Respond to: ${{ github.event.comment.body }}"
`
	errs := testRule(t, rule, workflow)
	if len(errs) == 0 {
		t.Fatal("expected error for untrusted input in direct_prompt, got none")
	}
}

func TestAIPromptInjection_AllowsStaticPrompt(t *testing.T) {
	t.Parallel()
	rule := NewAIPromptInjectionRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: "Please triage the issue using the ISSUE_TITLE environment variable."
`
	errs := testRule(t, rule, workflow)
	if len(errs) != 0 {
		t.Fatalf("expected no errors for static prompt, got %d", len(errs))
	}
}

func TestAIPromptInjection_AllowsTrustedInputInPrompt(t *testing.T) {
	t.Parallel()
	rule := NewAIPromptInjectionRule()

	// secrets や github.repository 等の信頼できる値は許可
	workflow := `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: "Triage issue #${{ github.event.issue.number }} in ${{ github.repository }}"
`
	errs := testRule(t, rule, workflow)
	if len(errs) != 0 {
		t.Fatalf("expected no errors for trusted input, got %d: %v", len(errs), errs)
	}
}
```

**Step 3: テストを実行して失敗を確認**
```bash
go test ./pkg/core/ -run TestAIPromptInjection -v
```
期待: `FAIL`

---

## Task 6: Rule 3 の実装

**Step 1: Rule 実装を書く**

`pkg/core/aiaction_prompt_injection.go`:
```go
package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// aiPromptInputParams は AI アクションのプロンプト系パラメータ名
var aiPromptInputParams = []string{
	"prompt",
	"direct_prompt",
	"custom_instructions",
	"system_prompt",
}

// expressionPattern は ${{ ... }} を抽出する正規表現
var expressionPattern = regexp.MustCompile(`\$\{\{\s*([^}]+)\s*\}\}`)

// AIPromptInjectionRule は AI アクションの prompt パラメータに
// untrusted input が展開されている場合に検出する
type AIPromptInjectionRule struct {
	BaseRule
}

// NewAIPromptInjectionRule は新しいルールインスタンスを返す
func NewAIPromptInjectionRule() *AIPromptInjectionRule {
	r := &AIPromptInjectionRule{}
	r.RuleName = "ai-prompt-injection"
	r.RuleDescription = "Untrusted user input is directly interpolated into AI agent prompt, enabling prompt injection attacks"
	r.RuleSeverity = "critical"
	return r
}

func (r *AIPromptInjectionRule) VisitStep(node *ast.Step) error {
	if node.Exec == nil || node.Exec.Kind() != ast.ExecKindAction {
		return nil
	}
	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}
	if !isKnownAIAction(action.Uses.Value) {
		return nil
	}

	for _, paramName := range aiPromptInputParams {
		paramVal, exists := action.Inputs[paramName]
		if !exists {
			continue
		}

		untrustedExprs := r.findUntrustedExpressions(paramVal.Value)
		for _, expr := range untrustedExprs {
			r.Errorf(
				node.Pos,
				"ai-prompt-injection: untrusted expression %q is directly interpolated into AI agent %q parameter of %q. This enables prompt injection: an attacker can craft issue/comment content to control AI behavior. Pass untrusted data via environment variables instead.",
				expr,
				paramName,
				action.Uses.Value,
			)
		}
	}

	return nil
}

// findUntrustedExpressions はプロンプト文字列から untrusted な ${{ }} 式を抽出する
func (r *AIPromptInjectionRule) findUntrustedExpressions(promptValue string) []string {
	var untrusted []string

	matches := expressionPattern.FindAllStringSubmatch(promptValue, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		exprContent := strings.TrimSpace(match[1])

		if r.isUntrustedExpression(exprContent) {
			untrusted = append(untrusted, match[0])
		}
	}

	return untrusted
}

// isUntrustedExpression は既存の ExprSemanticsChecker を再利用して
// 式が untrusted かどうかを判定する
func (r *AIPromptInjectionRule) isUntrustedExpression(exprContent string) bool {
	l := expressions.NewTokenizer(exprContent + "}}")
	p := expressions.NewMiniParser()
	node, err := p.Parse(l)
	if err != nil {
		return false
	}

	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(node)

	for _, e := range errs {
		if strings.Contains(e.Message, "potentially untrusted") {
			return true
		}
	}
	return false
}
```

**Step 2: テストを実行して成功を確認**
```bash
go test ./pkg/core/ -run TestAIPromptInjection -v
```
期待: `PASS`

**Step 3: linter.go に登録**

```go
NewAIPromptInjectionRule(),            // Detects untrusted input in AI agent prompt parameters (prompt injection)
```

**Step 4: 全テスト実行**
```bash
go test ./pkg/core/ -v -count=1 2>&1 | tail -30
```

**Step 5: コミット**
```bash
git add pkg/core/aiaction_prompt_injection.go \
        pkg/core/aiaction_prompt_injection_test.go \
        pkg/core/linter.go \
        script/actions/ai-action-prompt-injection-vulnerable.yaml \
        script/actions/ai-action-prompt-injection-safe.yaml
git commit -m "feat(rule): add ai-prompt-injection rule (issue #345)"
```

---

## Task 7: Cline の実際のワークフローで検証

**Step 1: 実際の攻撃ワークフローを再現**

`script/actions/clinejection-vulnerable.yaml` を作成:
```yaml
name: Issue Triage (Clinejection Pattern)

on:
  issues:
    types: [opened, edited]

jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          claude_args: --allowedTools "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch"
          prompt: |
            Please triage this issue:
            Title: ${{ github.event.issue.title }}
            Body: ${{ github.event.issue.body }}
            Author: ${{ github.event.issue.user.login }}
```

**Step 2: sisakulint でスキャン**
```bash
go build ./cmd/sisakulint
./sisakulint script/actions/clinejection-vulnerable.yaml
```

期待する出力（3つのルールが全て検出）:
```
script/actions/clinejection-vulnerable.yaml:...: ai-action-unrestricted-trigger: ...
script/actions/clinejection-vulnerable.yaml:...: ai-action-excessive-tools: ...
script/actions/clinejection-vulnerable.yaml:...: ai-prompt-injection: ...
```

**Step 3: コミット**
```bash
git add script/actions/clinejection-vulnerable.yaml
git commit -m "test: add clinejection attack pattern verification workflow"
```

---

## Task 8: CLAUDE.md とドキュメントの更新

**Step 1: CLAUDE.md のルールリストに追記**

`CLAUDE.md` の「Implemented Rules」セクションに以下を追加:
```markdown
- **AIActionUnrestrictedTriggerRule** - Detects AI agent actions (claude-code-action, etc.) configured with `allowed_non_write_users: "*"` allowing any GitHub user to trigger AI execution (auto-fix not applicable)
- **AIActionExcessiveToolsRule** - Detects AI agent actions with dangerous tools (Bash/Write/Edit) enabled in workflows triggered by untrusted users (issues, issue_comment, discussion) (auto-fix not applicable)
- **AIPromptInjectionRule** - Detects untrusted user input (github.event.issue.title, github.event.comment.body, etc.) directly interpolated into AI agent prompt parameters, enabling prompt injection attacks (auto-fix supported)
```

**Step 2: コミット**
```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with AI action security rules"
```

---

## Task 9: golangci-lint とビルド確認

**Step 1: lint 実行**
```bash
golangci-lint run ./pkg/core/aiaction_unrestricted_trigger.go \
                   ./pkg/core/aiaction_excessive_tools.go \
                   ./pkg/core/aiaction_prompt_injection.go
```

エラーがあれば修正してコミット。

**Step 2: ビルド確認**
```bash
go build ./cmd/sisakulint
```

**Step 3: 全テスト確認**
```bash
go test ./... 2>&1 | tail -10
```

---

## 完了基準

- [ ] `sisakulint script/actions/clinejection-vulnerable.yaml` で 3 種類のエラーが全て出力される
- [ ] `sisakulint script/actions/ai-action-*-safe.yaml` でエラーが出ない
- [ ] `go test ./pkg/core/ -run "TestAIAction|TestAIPromptInjection"` が全 PASS
- [ ] `golangci-lint run` がエラーなし
- [ ] CLAUDE.md に 3 ルールが記載されている

---

## 次フェーズ: Tree-of-AST 対応（別計画）

Rule 1・2・3 の実装完了後、以下を別計画ドキュメントとして作成する:
- Phase 1: `WorkflowFlowGraph` によるクロスジョブ TaintTracker 拡張
- Phase 2: `ArgumentInjectionRule` / `RequestForgeryRule` への TaintTracker 統合
- Phase 3: `-deep-flow` フラグによる LLM 補助 Sink-to-Source エンジン
