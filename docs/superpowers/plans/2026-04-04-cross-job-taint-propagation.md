# Cross-Job Taint Propagation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `needs.*.outputs.*` を通じたクロスジョブの taint 伝播を検出し、CodeInjectionCritical/Medium ルールで報告する。

**Architecture:** `WorkflowTaintMap`（新規）をワークフローレベルの taint ストアとして新設し、`TaintTracker`（既存・変更なし）がジョブ内ステップ出力の taint を追跡する。`linter.go` で1つの `WorkflowTaintMap` インスタンスを生成して Critical/Medium 両ルールに渡す。`VisitJobPre` でジョブ出力を登録し、下流ジョブの式チェック時に参照する。逆順記述のワークフロー対応として `VisitWorkflowPost` でリトライする。

**Tech Stack:** Go, `pkg/core` パッケージ, `pkg/ast`, `pkg/expressions`

---

## File Structure

| ファイル | 変更種別 | 責務 |
|---------|---------|------|
| `pkg/core/workflow_taint.go` | 新規作成 | WorkflowTaintMap 本体 |
| `pkg/core/workflow_taint_test.go` | 新規作成 | WorkflowTaintMap 単体テスト |
| `pkg/core/taint.go` | 修正（リファクタ） | `nodeToString` を package-level 関数に抽出 |
| `pkg/core/codeinjection.go` | 修正 | workflowTaintMap フィールド追加、Visit メソッド拡張 |
| `pkg/core/codeinjectioncritical.go` | 修正 | factory に `*WorkflowTaintMap` 引数追加 |
| `pkg/core/codeinjectionmedium.go` | 修正 | factory に `*WorkflowTaintMap` 引数追加 |
| `pkg/core/linter.go` | 修正 | `makeRules` で WorkflowTaintMap を生成・注入 |
| `pkg/core/taint_integration_test.go` | 修正 | クロスジョブテストケース追加 |
| `script/actions/cross-job-taint.yaml` | 新規作成 | 脆弱パターンの例 |
| `script/actions/cross-job-taint-safe.yaml` | 新規作成 | 安全パターンの例 |

---

## Task 1: package-level `exprNodeToString` ヘルパーを抽出する

`taint.go` の `nodeToString` / `buildObjectDerefString` / `buildIndexAccessString` は `TaintTracker` の状態を使わない純粋関数。これを package-level に抽出し、`WorkflowTaintMap` でも再利用できるようにする。

**Files:**
- Modify: `pkg/core/taint.go`

- [ ] **Step 1: 既存の nodeToString 関連メソッドを確認する**

Run: `grep -n "func (t \*TaintTracker) nodeToString\|buildObjectDerefString\|buildIndexAccessString" pkg/core/taint.go`

- [ ] **Step 2: package-level 関数として `exprNodeToString` を追加する**

`pkg/core/taint.go` の末尾（`GetTaintedOutputs` の後）に以下を追加：

```go
// exprNodeToString converts an expression AST node to its dot-separated string representation.
// Examples:
//   - needs.extract.outputs.pr_title → "needs.extract.outputs.pr_title"
//   - steps.get-ref.outputs.ref → "steps.get-ref.outputs.ref"
//   - github.event.pull_request.title → "github.event.pull_request.title"
func exprNodeToString(node expressions.ExprNode) string {
	switch n := node.(type) {
	case *expressions.ObjectDerefNode:
		return buildExprObjectDerefString(n)
	case *expressions.IndexAccessNode:
		return buildExprIndexAccessString(n)
	case *expressions.VariableNode:
		return n.Name
	default:
		return ""
	}
}

func buildExprObjectDerefString(node *expressions.ObjectDerefNode) string {
	var parts []string
	var current expressions.ExprNode = node
	for current != nil {
		switch n := current.(type) {
		case *expressions.ObjectDerefNode:
			parts = append([]string{n.Property}, parts...)
			current = n.Receiver
		case *expressions.VariableNode:
			parts = append([]string{n.Name}, parts...)
			current = nil
		default:
			current = nil
		}
	}
	return strings.Join(parts, ".")
}

func buildExprIndexAccessString(node *expressions.IndexAccessNode) string {
	operandStr := exprNodeToString(node.Operand)
	if operandStr == "" {
		return ""
	}
	if strNode, ok := node.Index.(*expressions.StringNode); ok {
		return operandStr + "." + strNode.Value
	}
	return operandStr
}
```

- [ ] **Step 3: TaintTracker の nodeToString を exprNodeToString の委譲に変更する**

`pkg/core/taint.go` の `nodeToString` メソッドを以下に変更：

```go
// nodeToString converts an expression AST node to its string representation.
func (t *TaintTracker) nodeToString(node expressions.ExprNode) string {
	return exprNodeToString(node)
}
```

- [ ] **Step 4: テストを実行して既存テストが通ることを確認する**

Run: `go test ./pkg/core/... -run TestTaint -v`
Expected: すべての既存 taint テストが PASS

- [ ] **Step 5: コミットする**

```bash
git add pkg/core/taint.go
git commit -m "refactor(taint): extract exprNodeToString as package-level helper"
```

---

## Task 2: WorkflowTaintMap の基本構造を実装する

**Files:**
- Create: `pkg/core/workflow_taint.go`
- Create: `pkg/core/workflow_taint_test.go`

- [ ] **Step 1: 失敗するテストを書く**

`pkg/core/workflow_taint_test.go` を新規作成：

```go
package core

import (
	"testing"
)

func TestWorkflowTaintMap_NewAndRegister(t *testing.T) {
	t.Parallel()

	m := NewWorkflowTaintMap()
	if m == nil {
		t.Fatal("NewWorkflowTaintMap() returned nil")
	}

	// 未登録ジョブは registered=false
	sources, registered := m.IsTaintedNeedsOutput("extract", "pr_title")
	if registered {
		t.Errorf("unregistered job should return registered=false")
	}
	if len(sources) > 0 {
		t.Errorf("unregistered job should return no sources")
	}
}

func TestWorkflowTaintMap_RegisterAndResolve(t *testing.T) {
	t.Parallel()

	m := NewWorkflowTaintMap()

	// 手動で taint を登録
	m.setJobOutputTaint("extract", "pr_title", []string{"github.event.pull_request.title"})

	sources, registered := m.IsTaintedNeedsOutput("extract", "pr_title")
	if !registered {
		t.Errorf("registered job should return registered=true")
	}
	if len(sources) == 0 {
		t.Errorf("tainted output should return sources")
	}
	if sources[0] != "github.event.pull_request.title" {
		t.Errorf("got source %q, want %q", sources[0], "github.event.pull_request.title")
	}
}

func TestWorkflowTaintMap_RegisterCleanOutput(t *testing.T) {
	t.Parallel()

	m := NewWorkflowTaintMap()

	// クリーンな出力（taint なし）を登録
	m.markJobAsRegistered("safe-job")

	sources, registered := m.IsTaintedNeedsOutput("safe-job", "sha")
	if !registered {
		t.Errorf("registered job should return registered=true even for clean output")
	}
	if len(sources) > 0 {
		t.Errorf("clean output should return no sources, got: %v", sources)
	}
}

func TestWorkflowTaintMap_IdempotentRegister(t *testing.T) {
	t.Parallel()

	m := NewWorkflowTaintMap()

	m.setJobOutputTaint("extract", "pr_title", []string{"github.event.pull_request.title"})
	m.setJobOutputTaint("extract", "pr_title", []string{"github.event.pull_request.title"})

	sources, _ := m.IsTaintedNeedsOutput("extract", "pr_title")
	// 重複登録でも sources は1つ
	if len(sources) != 1 {
		t.Errorf("idempotent register should not duplicate sources, got: %v", sources)
	}
}
```

- [ ] **Step 2: テストを実行して失敗することを確認する**

Run: `go test ./pkg/core/... -run TestWorkflowTaintMap -v`
Expected: FAIL - "undefined: NewWorkflowTaintMap"

- [ ] **Step 3: WorkflowTaintMap の基本構造を実装する**

`pkg/core/workflow_taint.go` を新規作成：

```go
package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// WorkflowTaintMap tracks taint propagation across job boundaries via needs.*.outputs.*.
// It is created once per workflow analysis and shared between CodeInjectionCritical and
// CodeInjectionMedium rules via a pointer.
//
// Example of tracked vulnerability:
//
//	jobs:
//	  extract:
//	    outputs:
//	      pr_title: ${{ steps.meta.outputs.title }}   # tainted via github.event.pull_request.title
//	    steps:
//	      - id: meta
//	        run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
//	  process:
//	    needs: extract
//	    steps:
//	      - run: echo "${{ needs.extract.outputs.pr_title }}"  # detected!
type WorkflowTaintMap struct {
	// jobOutputTaints: jobID (lowercase) -> outputName (lowercase) -> []taintSource
	// A job that is registered but has no tainted outputs is represented by an empty inner map.
	jobOutputTaints map[string]map[string][]string
}

// NewWorkflowTaintMap creates a new WorkflowTaintMap instance.
func NewWorkflowTaintMap() *WorkflowTaintMap {
	return &WorkflowTaintMap{
		jobOutputTaints: make(map[string]map[string][]string),
	}
}

// Reset clears all registered job outputs. Called in VisitWorkflowPre to reset per workflow.
func (m *WorkflowTaintMap) Reset() {
	m.jobOutputTaints = make(map[string]map[string][]string)
}

// markJobAsRegistered marks a job as processed even if it has no tainted outputs.
// This allows IsTaintedNeedsOutput to distinguish "job not yet processed" from "job has clean outputs".
func (m *WorkflowTaintMap) markJobAsRegistered(jobID string) {
	jobID = strings.ToLower(jobID)
	if _, exists := m.jobOutputTaints[jobID]; !exists {
		m.jobOutputTaints[jobID] = make(map[string][]string)
	}
}

// setJobOutputTaint records a tainted output for a job. Idempotent: duplicate sources are deduplicated.
func (m *WorkflowTaintMap) setJobOutputTaint(jobID, outputName string, sources []string) {
	jobID = strings.ToLower(jobID)
	outputName = strings.ToLower(outputName)

	if m.jobOutputTaints[jobID] == nil {
		m.jobOutputTaints[jobID] = make(map[string][]string)
	}

	existing := m.jobOutputTaints[jobID][outputName]
	merged := append(existing, sources...)
	m.jobOutputTaints[jobID][outputName] = deduplicateStrings(merged)
}

// IsTaintedNeedsOutput checks if needs.jobID.outputs.outputName carries taint.
// Returns (sources, registered):
//   - len(sources) > 0, true  → output is tainted
//   - nil, true               → job is registered but output is clean (safe)
//   - nil, false              → job has not been processed yet (caller should add to pending)
func (m *WorkflowTaintMap) IsTaintedNeedsOutput(jobID, outputName string) (sources []string, registered bool) {
	jobID = strings.ToLower(jobID)
	outputName = strings.ToLower(outputName)

	outputs, exists := m.jobOutputTaints[jobID]
	if !exists {
		return nil, false
	}

	return outputs[outputName], true
}

// ResolveFromExprNode extracts needs.X.outputs.Y from an AST node and looks up taint.
// Returns taint sources if the expression is a tainted needs reference, nil otherwise.
// Returns (sources, pending) where pending=true means the job isn't registered yet.
func (m *WorkflowTaintMap) ResolveFromExprNode(node expressions.ExprNode) (sources []string, pending bool) {
	exprStr := exprNodeToString(node)
	return m.resolveFromExprStr(exprStr)
}

// resolveFromExprStr parses needs.X.outputs.Y and looks up taint.
func (m *WorkflowTaintMap) resolveFromExprStr(exprStr string) (sources []string, pending bool) {
	lower := strings.ToLower(exprStr)
	parts := strings.Split(lower, ".")

	// needs.jobID.outputs.outputName
	if len(parts) < 4 || parts[0] != "needs" || parts[2] != "outputs" {
		return nil, false
	}

	jobID := parts[1]
	outputName := parts[3]

	src, registered := m.IsTaintedNeedsOutput(jobID, outputName)
	if !registered {
		return nil, true // pending
	}
	return src, false
}
```

- [ ] **Step 4: テストを実行して通ることを確認する**

Run: `go test ./pkg/core/... -run TestWorkflowTaintMap -v`
Expected: PASS - 4件のテストがすべて通る

- [ ] **Step 5: コミットする**

```bash
git add pkg/core/workflow_taint.go pkg/core/workflow_taint_test.go
git commit -m "feat(taint): add WorkflowTaintMap for cross-job taint tracking"
```

---

## Task 3: RegisterJobOutputs を実装する

**Files:**
- Modify: `pkg/core/workflow_taint.go`
- Modify: `pkg/core/workflow_taint_test.go`

- [ ] **Step 1: RegisterJobOutputs のテストを追加する**

`pkg/core/workflow_taint_test.go` に以下を追加：

```go
func TestWorkflowTaintMap_RegisterJobOutputs_StepsRef(t *testing.T) {
	t.Parallel()

	// TaintTracker に steps.meta.outputs.title が tainted であることを設定
	tracker := NewTaintTracker()
	tracker.GetTaintedOutputs()["meta"] = map[string][]string{
		"title": {"github.event.pull_request.title"},
	}

	m := NewWorkflowTaintMap()

	outputs := map[string]*ast.Output{
		"pr_title": {
			Name:  &ast.String{Value: "pr_title"},
			Value: &ast.String{Value: "${{ steps.meta.outputs.title }}"},
		},
	}

	m.RegisterJobOutputs("extract", tracker, outputs)

	sources, registered := m.IsTaintedNeedsOutput("extract", "pr_title")
	if !registered {
		t.Fatal("job should be registered after RegisterJobOutputs")
	}
	if len(sources) == 0 {
		t.Fatal("output should be tainted")
	}
	if sources[0] != "github.event.pull_request.title" {
		t.Errorf("got %q, want %q", sources[0], "github.event.pull_request.title")
	}
}

func TestWorkflowTaintMap_RegisterJobOutputs_CleanOutput(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()
	// tracker に taint なし（クリーン）

	m := NewWorkflowTaintMap()

	outputs := map[string]*ast.Output{
		"sha": {
			Name:  &ast.String{Value: "sha"},
			Value: &ast.String{Value: "${{ steps.get-sha.outputs.sha }}"},
		},
	}

	m.RegisterJobOutputs("safe-job", tracker, outputs)

	sources, registered := m.IsTaintedNeedsOutput("safe-job", "sha")
	if !registered {
		t.Fatal("job should be registered even for clean outputs")
	}
	if len(sources) > 0 {
		t.Errorf("clean output should have no taint sources, got: %v", sources)
	}
}

func TestWorkflowTaintMap_RegisterJobOutputs_NilOutput(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()
	m := NewWorkflowTaintMap()

	// nil outputs でパニックしないこと
	m.RegisterJobOutputs("empty-job", tracker, nil)

	_, registered := m.IsTaintedNeedsOutput("empty-job", "anything")
	if !registered {
		t.Error("job should be registered even with nil outputs")
	}
}
```

- [ ] **Step 2: テストを実行して失敗することを確認する**

Run: `go test ./pkg/core/... -run TestWorkflowTaintMap_RegisterJobOutputs -v`
Expected: FAIL - "undefined: m.RegisterJobOutputs"

- [ ] **Step 3: RegisterJobOutputs を実装する**

`pkg/core/workflow_taint.go` に以下を追加（`ResolveFromExprNode` の前に挿入）：

```go
// RegisterJobOutputs analyzes a job's outputs and records any that are tainted.
// It checks two patterns in output value expressions:
//   1. ${{ steps.X.outputs.Y }} → looks up in tracker (intra-job taint)
//   2. ${{ needs.X.outputs.Y }} → looks up in self (cross-job taint for multi-hop)
//
// After calling this, IsTaintedNeedsOutput(jobID, *) will return registered=true.
func (m *WorkflowTaintMap) RegisterJobOutputs(jobID string, tracker *TaintTracker, outputs map[string]*ast.Output) {
	// Always mark the job as registered, even if it has no tainted outputs.
	m.markJobAsRegistered(jobID)

	for outputName, output := range outputs {
		if output == nil || output.Value == nil || output.Value.Value == "" {
			continue
		}

		value := output.Value.Value
		sources := m.extractTaintSourcesFromValue(value, tracker)

		if len(sources) > 0 {
			m.setJobOutputTaint(jobID, outputName, sources)
		}
	}
}

// extractTaintSourcesFromValue extracts taint sources from an output value expression string.
// Handles both steps.X.outputs.Y (via tracker) and needs.X.outputs.Y (via self).
func (m *WorkflowTaintMap) extractTaintSourcesFromValue(value string, tracker *TaintTracker) []string {
	var sources []string

	// Find all ${{ expr }} patterns
	exprPattern := exprExtractRegexp
	matches := exprPattern.FindAllStringSubmatch(value, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		exprContent := strings.TrimSpace(match[1])
		lower := strings.ToLower(exprContent)

		// Pattern 1: steps.X.outputs.Y → check TaintTracker
		if strings.HasPrefix(lower, "steps.") {
			if tainted, taintSources := tracker.IsTaintedExpr(exprContent); tainted {
				sources = append(sources, taintSources...)
			}
			continue
		}

		// Pattern 2: needs.X.outputs.Y → check self (multi-hop)
		if strings.HasPrefix(lower, "needs.") {
			if selfSources, _ := m.resolveFromExprStr(exprContent); len(selfSources) > 0 {
				sources = append(sources, selfSources...)
			}
		}
	}

	return sources
}
```

また、`workflow_taint.go` の import セクションと `exprExtractRegexp` の定義を追加：

```go
import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// exprExtractRegexp matches ${{ expr }} patterns in strings.
var exprExtractRegexp = regexp.MustCompile(`\$\{\{\s*([^}]+)\s*\}\}`)
```

`workflow_taint_test.go` の import に `ast` を追加：

```go
import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)
```

- [ ] **Step 4: テストを実行して通ることを確認する**

Run: `go test ./pkg/core/... -run TestWorkflowTaintMap -v`
Expected: PASS

- [ ] **Step 5: コミットする**

```bash
git add pkg/core/workflow_taint.go pkg/core/workflow_taint_test.go
git commit -m "feat(taint): implement RegisterJobOutputs for cross-job output analysis"
```

---

## Task 4: multi-hop チェーンのテストと ResolveFromExprNode のテストを追加する

**Files:**
- Modify: `pkg/core/workflow_taint_test.go`

- [ ] **Step 1: multi-hop と ResolveFromExprNode のテストを追加する**

`pkg/core/workflow_taint_test.go` に以下を追加：

```go
func TestWorkflowTaintMap_MultiHopChain(t *testing.T) {
	t.Parallel()

	// job-A: untrusted → steps output
	trackerA := NewTaintTracker()
	trackerA.GetTaintedOutputs()["meta"] = map[string][]string{
		"title": {"github.event.pull_request.title"},
	}

	// job-B: steps output from job-A passed through as job output
	trackerB := NewTaintTracker() // job-B 自体の steps には taint なし

	m := NewWorkflowTaintMap()

	// job-A を登録
	outputsA := map[string]*ast.Output{
		"pr_title": {
			Name:  &ast.String{Value: "pr_title"},
			Value: &ast.String{Value: "${{ steps.meta.outputs.title }}"},
		},
	}
	m.RegisterJobOutputs("job-a", trackerA, outputsA)

	// job-B を登録（job-A の出力を参照している）
	outputsB := map[string]*ast.Output{
		"processed": {
			Name:  &ast.String{Value: "processed"},
			Value: &ast.String{Value: "${{ needs.job-a.outputs.pr_title }}"},
		},
	}
	m.RegisterJobOutputs("job-b", trackerB, outputsB)

	// job-C が needs.job-b.outputs.processed を参照したとき tainted になるはず
	sources, registered := m.IsTaintedNeedsOutput("job-b", "processed")
	if !registered {
		t.Fatal("job-b should be registered")
	}
	if len(sources) == 0 {
		t.Fatal("multi-hop: job-b.processed should be tainted via job-a")
	}
	if sources[0] != "github.event.pull_request.title" {
		t.Errorf("got source %q, want original source %q", sources[0], "github.event.pull_request.title")
	}
}

func TestWorkflowTaintMap_ResolveFromExprStr_NeedsPattern(t *testing.T) {
	t.Parallel()

	m := NewWorkflowTaintMap()
	m.setJobOutputTaint("extract", "pr_title", []string{"github.event.pull_request.title"})

	tests := []struct {
		name     string
		expr     string
		wantTaint bool
		wantPending bool
	}{
		{
			name:      "tainted needs reference",
			expr:      "needs.extract.outputs.pr_title",
			wantTaint: true,
		},
		{
			name:      "clean needs reference (registered job, clean output)",
			expr:      "needs.extract.outputs.sha",
			wantTaint: false,
		},
		{
			name:        "unregistered job → pending",
			expr:        "needs.unknown-job.outputs.x",
			wantPending: true,
		},
		{
			name:      "not a needs expression",
			expr:      "steps.foo.outputs.bar",
			wantTaint: false,
		},
		{
			name:      "github context → not needs",
			expr:      "github.event.pull_request.title",
			wantTaint: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sources, pending := m.resolveFromExprStr(tt.expr)
			if tt.wantTaint && len(sources) == 0 {
				t.Errorf("expected taint sources for %q, got none", tt.expr)
			}
			if !tt.wantTaint && len(sources) > 0 {
				t.Errorf("expected no taint sources for %q, got: %v", tt.expr, sources)
			}
			if tt.wantPending != pending {
				t.Errorf("pending=%v, want %v for %q", pending, tt.wantPending, tt.expr)
			}
		})
	}
}
```

- [ ] **Step 2: テストを実行して通ることを確認する**

Run: `go test ./pkg/core/... -run TestWorkflowTaintMap -v`
Expected: PASS

- [ ] **Step 3: コミットする**

```bash
git add pkg/core/workflow_taint_test.go
git commit -m "test(taint): add multi-hop chain and ResolveFromExprStr tests"
```

---

## Task 5: CodeInjectionRule に WorkflowTaintMap を統合する

**Files:**
- Modify: `pkg/core/codeinjection.go`
- Modify: `pkg/core/codeinjectioncritical.go`
- Modify: `pkg/core/codeinjectionmedium.go`
- Modify: `pkg/core/linter.go`

- [ ] **Step 1: CodeInjectionRule 構造体に workflowTaintMap フィールドを追加する**

`pkg/core/codeinjection.go` の `CodeInjectionRule` 構造体を以下のように変更：

```go
type CodeInjectionRule struct {
	BaseRule
	severityLevel      string
	checkPrivileged    bool
	stepsWithUntrusted []*stepWithUntrustedInput
	workflow           *ast.Workflow
	taintTracker       *TaintTracker
	workflowTriggers   []string
	jobHasMatchingTriggers bool
	// workflowTaintMap is shared between Critical and Medium rule instances.
	// Nil if cross-job taint propagation is disabled (e.g., in unit tests).
	workflowTaintMap *WorkflowTaintMap
	// currentJobID is set in VisitJobPre to track which job is being analyzed.
	currentJobID string
	// pendingCrossJobChecks holds checks that couldn't be resolved because the upstream
	// job hadn't been processed yet (reverse yaml order). Flushed in VisitWorkflowPost.
	pendingCrossJobChecks []pendingCrossJobCheck
}

// pendingCrossJobCheck stores a cross-job taint check that needs to be retried in VisitWorkflowPost.
type pendingCrossJobCheck struct {
	expr       parsedExpression
	needsJobID string
	outputName string
}
```

- [ ] **Step 2: newCodeInjectionRule に workflowTaintMap 引数を追加する**

`pkg/core/codeinjection.go` の `newCodeInjectionRule` を以下に変更：

```go
func newCodeInjectionRule(severityLevel string, checkPrivileged bool, wfTaintMap *WorkflowTaintMap) *CodeInjectionRule {
	var desc string
	if checkPrivileged {
		desc = "Checks for code injection vulnerabilities when untrusted input is used directly in run scripts or script actions with privileged workflow triggers (pull_request_target, workflow_run, issue_comment). See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/"
	} else {
		desc = "Checks for code injection vulnerabilities when untrusted input is used directly in run scripts or script actions with normal workflow triggers (pull_request, push, etc.). See https://sisaku-security.github.io/lint/docs/rules/codeinjectionmedium/"
	}

	return &CodeInjectionRule{
		BaseRule: BaseRule{
			RuleName: "code-injection-" + severityLevel,
			RuleDesc: desc,
		},
		severityLevel:      severityLevel,
		checkPrivileged:    checkPrivileged,
		stepsWithUntrusted: make([]*stepWithUntrustedInput, 0),
		workflowTaintMap:   wfTaintMap,
	}
}
```

- [ ] **Step 3: factory 関数を更新する**

`pkg/core/codeinjectioncritical.go` を以下に変更：

```go
package core

type CodeInjectionCritical = CodeInjectionRule

func CodeInjectionCriticalRule(wfTaintMap *WorkflowTaintMap) *CodeInjectionRule {
	return newCodeInjectionRule("critical", true, wfTaintMap)
}
```

`pkg/core/codeinjectionmedium.go` を以下に変更：

```go
package core

func CodeInjectionMediumRule(wfTaintMap *WorkflowTaintMap) *CodeInjectionRule {
	return newCodeInjectionRule("medium", false, wfTaintMap)
}
```

- [ ] **Step 4: linter.go の makeRules を更新する**

`pkg/core/linter.go` の `makeRules` 関数の先頭で WorkflowTaintMap を生成し、両ルールに渡す。現在の：

```go
func makeRules(filePath string, isRemote bool, localActions *LocalActionsMetadataCache, localReusableWorkflow *LocalReusableWorkflowCache) []Rule {
	return []Rule{
		...
		CodeInjectionCriticalRule(),
		CodeInjectionMediumRule(),
```

を以下に変更：

```go
func makeRules(filePath string, isRemote bool, localActions *LocalActionsMetadataCache, localReusableWorkflow *LocalReusableWorkflowCache) []Rule {
	// WorkflowTaintMap is shared between Critical and Medium rules to enable
	// cross-job taint propagation tracking via needs.*.outputs.*
	wfTaintMap := NewWorkflowTaintMap()

	return []Rule{
		...
		CodeInjectionCriticalRule(wfTaintMap),
		CodeInjectionMediumRule(wfTaintMap),
```

- [ ] **Step 5: 既存テストの factory 呼び出しを `nil` 引数に更新する**

以下のファイルで `CodeInjectionCriticalRule()` → `CodeInjectionCriticalRule(nil)` 、`CodeInjectionMediumRule()` → `CodeInjectionMediumRule(nil)` に置換する（`nil` を渡すとクロスジョブ機能が無効になり既存テストの動作は変わらない）：

```bash
# 対象ファイル確認
grep -rn "CodeInjectionCriticalRule()\|CodeInjectionMediumRule()" pkg/core/
```

変更が必要なファイル:
- `pkg/core/codeinjectioncritical_test.go`: `CodeInjectionCriticalRule()` → `CodeInjectionCriticalRule(nil)`
- `pkg/core/codeinjectionmedium_test.go`: `CodeInjectionMediumRule()` → `CodeInjectionMediumRule(nil)`
- `pkg/core/codeinjection_autofix_test.go`: 両方の factory を nil 引数に変更
- `pkg/core/codeinjection_shell_test.go`: 同上

- [ ] **Step 6: ビルドが通ることを確認する**

Run: `go build ./pkg/core/...`
Expected: コンパイルエラーなし

- [ ] **Step 7: コミットする**

```bash
git add pkg/core/codeinjection.go pkg/core/codeinjectioncritical.go pkg/core/codeinjectionmedium.go pkg/core/linter.go pkg/core/codeinjectioncritical_test.go pkg/core/codeinjectionmedium_test.go pkg/core/codeinjection_autofix_test.go pkg/core/codeinjection_shell_test.go
git commit -m "feat(codeinjection): wire WorkflowTaintMap into CodeInjectionRule"
```

---

## Task 6: VisitWorkflowPre と VisitJobPre に WorkflowTaintMap を統合する

**Files:**
- Modify: `pkg/core/codeinjection.go`

- [ ] **Step 1: VisitWorkflowPre を更新する**

`pkg/core/codeinjection.go` の `VisitWorkflowPre` 末尾（`return nil` の前）に以下を追加：

```go
// Reset WorkflowTaintMap for this workflow
if rule.workflowTaintMap != nil {
	rule.workflowTaintMap.Reset()
	rule.pendingCrossJobChecks = nil
}
```

- [ ] **Step 2: VisitJobPre に currentJobID の設定と RegisterJobOutputs の呼び出しを追加する**

`pkg/core/codeinjection.go` の `VisitJobPre` 内、ジョブスキップ判定（`if !rule.jobHasMatchingTriggers`）の前に以下を追加：

```go
// Track current job ID for cross-job taint registration
if node.ID != nil {
	rule.currentJobID = node.ID.Value
}
```

また、`VisitJobPre` の末尾（`return nil` の直前）に以下を追加：

```go
// Register this job's outputs into WorkflowTaintMap for downstream jobs.
// This must happen even for jobs that don't match our trigger criteria,
// because downstream jobs may be tainted via outputs from any job.
if rule.workflowTaintMap != nil && node.ID != nil {
	rule.workflowTaintMap.RegisterJobOutputs(node.ID.Value, rule.taintTracker, node.Outputs)
}
```

注意: `taintTracker` がジョブスキップ時（`!rule.jobHasMatchingTriggers`）に `nil` になる可能性があります。スキップ時にも `RegisterJobOutputs` を呼べるよう、スキップ分岐の前でも TaintTracker を初期化して steps を解析する必要があります。

`VisitJobPre` のスキップ判定部分を以下のように変更：

```go
// Initialize taint tracker for every job (needed for RegisterJobOutputs even if skipping)
rule.taintTracker = NewTaintTracker()
for _, s := range node.Steps {
	rule.taintTracker.AnalyzeStep(s)
}

// Register outputs regardless of trigger matching
if rule.workflowTaintMap != nil && node.ID != nil {
	rule.workflowTaintMap.RegisterJobOutputs(node.ID.Value, rule.taintTracker, node.Outputs)
}

// Skip injection checks if this job doesn't match our trigger criteria
if !rule.jobHasMatchingTriggers {
	return nil
}

// Second pass: check for code injection vulnerabilities (existing code)
for _, s := range node.Steps {
	...
```

また、元の `rule.taintTracker = NewTaintTracker()` と first pass の `for` ループ（TaintTracker.AnalyzeStep を呼んでいる部分）はすでに上記で統合されるため、重複を削除する。

- [ ] **Step 3: ビルドが通ることを確認する**

Run: `go build ./pkg/core/...`
Expected: コンパイルエラーなし

- [ ] **Step 4: 既存テストが壊れていないことを確認する**

Run: `go test ./pkg/core/... -run TestCodeInjection -v -count=1`
Expected: すべて PASS

- [ ] **Step 5: コミットする**

```bash
git add pkg/core/codeinjection.go
git commit -m "feat(codeinjection): register job outputs in WorkflowTaintMap on VisitJobPre"
```

---

## Task 7: checkUntrustedInputWithTaint を拡張して needs 参照を検出する

**Files:**
- Modify: `pkg/core/codeinjection.go`

- [ ] **Step 1: checkUntrustedInputWithTaint に WorkflowTaintMap チェックを追加する**

`pkg/core/codeinjection.go` の `checkUntrustedInputWithTaint` を以下に変更：

```go
func (rule *CodeInjectionRule) checkUntrustedInputWithTaint(expr parsedExpression) []string {
	// Check built-in untrusted inputs
	paths := rule.checkUntrustedInput(expr)

	// Check intra-job tainted step outputs
	if rule.taintTracker != nil {
		if tainted, sources := rule.taintTracker.IsTainted(expr.node); tainted {
			for _, source := range sources {
				taintPath := fmt.Sprintf("%s (tainted via %s)", expr.raw, source)
				paths = append(paths, taintPath)
			}
		}
	}

	// Check cross-job tainted needs outputs
	if rule.workflowTaintMap != nil {
		sources, pending := rule.workflowTaintMap.ResolveFromExprNode(expr.node)
		if pending {
			// Upstream job not yet processed; defer to VisitWorkflowPost
			// (parse needs.X.outputs.Y from the raw expression string)
			rule.addPendingCrossJobCheck(expr)
		} else if len(sources) > 0 {
			for _, source := range sources {
				taintPath := fmt.Sprintf("%s (tainted via %s)", expr.raw, source)
				paths = append(paths, taintPath)
			}
		}
	}

	return paths
}
```

- [ ] **Step 2: addPendingCrossJobCheck ヘルパーを追加する**

`pkg/core/codeinjection.go` に以下のメソッドを追加：

```go
// addPendingCrossJobCheck parses expr.raw for needs.X.outputs.Y and stores a pending check.
func (rule *CodeInjectionRule) addPendingCrossJobCheck(expr parsedExpression) {
	exprStr := exprNodeToString(expr.node)
	lower := strings.ToLower(exprStr)
	parts := strings.Split(lower, ".")
	if len(parts) < 4 || parts[0] != "needs" || parts[2] != "outputs" {
		return
	}
	rule.pendingCrossJobChecks = append(rule.pendingCrossJobChecks, pendingCrossJobCheck{
		expr:       expr,
		needsJobID: parts[1],
		outputName: parts[3],
	})
	// Note: auto-fix is not supported for pending checks (reverse yaml order).
	// Auto-fix works for the normal (non-pending) case via the existing stepUntrusted mechanism.
}
```

- [ ] **Step 3: ビルドが通ることを確認する**

Run: `go build ./pkg/core/...`
Expected: コンパイルエラーなし

- [ ] **Step 4: 既存テストが壊れていないことを確認する**

Run: `go test ./pkg/core/... -run TestCodeInjection -v -count=1`
Expected: PASS

- [ ] **Step 5: コミットする**

```bash
git add pkg/core/codeinjection.go
git commit -m "feat(codeinjection): detect needs.*.outputs.* cross-job taint in checkUntrustedInputWithTaint"
```

---

## Task 8: VisitWorkflowPost で pending チェックを解決する

**Files:**
- Modify: `pkg/core/codeinjection.go`

- [ ] **Step 1: VisitWorkflowPost を追加する**

`pkg/core/codeinjection.go` に `VisitJobPost` の後（または `VisitWorkflowPre` の後）に以下を追加：

```go
// VisitWorkflowPost is called after all jobs have been visited.
// It flushes pending cross-job taint checks that couldn't be resolved during VisitJobPre
// (e.g., when a downstream job appears before its upstream job in the yaml file).
func (rule *CodeInjectionRule) VisitWorkflowPost(node *ast.Workflow) error {
	if rule.workflowTaintMap == nil || len(rule.pendingCrossJobChecks) == 0 {
		return nil
	}

	for _, pending := range rule.pendingCrossJobChecks {
		sources, stillPending := rule.workflowTaintMap.ResolveFromExprNode(pending.expr.node)
		if stillPending || len(sources) == 0 {
			continue
		}

		for _, source := range sources {
			taintPath := fmt.Sprintf("%s (tainted via %s)", pending.expr.raw, source)
			if rule.checkPrivileged {
				rule.Errorf(
					pending.expr.pos,
					"code injection (critical): \"%s\" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/",
					taintPath,
				)
			} else {
				rule.Errorf(
					pending.expr.pos,
					"code injection (medium): \"%s\" is potentially untrusted. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectionmedium/",
					taintPath,
				)
			}
		}
	}

	rule.pendingCrossJobChecks = nil
	return nil
}
```

- [ ] **Step 2: ビルドが通ることを確認する**

Run: `go build ./pkg/core/...`
Expected: コンパイルエラーなし

- [ ] **Step 3: 既存テストが通ることを確認する**

Run: `go test ./pkg/core/... -count=1`
Expected: すべて PASS

- [ ] **Step 4: コミットする**

```bash
git add pkg/core/codeinjection.go
git commit -m "feat(codeinjection): flush pending cross-job taint checks in VisitWorkflowPost"
```

---

## Task 9: クロスジョブ taint の統合テストを追加する

**Files:**
- Modify: `pkg/core/taint_integration_test.go`

- [ ] **Step 1: 統合テストを追加する**

`pkg/core/taint_integration_test.go` の末尾に以下を追加：

```go
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
```

- [ ] **Step 2: テストを実行して通ることを確認する**

Run: `go test ./pkg/core/... -run TestCrossJobTaint -v -count=1`
Expected: PASS

Run: `go test ./pkg/core/... -count=1`
Expected: すべての既存テストも PASS

- [ ] **Step 3: コミットする**

```bash
git add pkg/core/taint_integration_test.go
git commit -m "test(taint): add cross-job taint propagation integration tests"
```

---

## Task 10: サンプルワークフローファイルと lint を追加する

**Files:**
- Create: `script/actions/cross-job-taint.yaml`
- Create: `script/actions/cross-job-taint-safe.yaml`
- Modify: `script/README.md`

- [ ] **Step 1: 脆弱パターンのサンプルを作成する**

`script/actions/cross-job-taint.yaml` を新規作成：

```yaml
# cross-job-taint.yaml
# Demonstrates cross-job taint propagation via needs.*.outputs.*
# Expected: code-injection-critical (needs.extract.outputs.pr_title is tainted)
name: Cross-Job Taint Example (Vulnerable)

on: pull_request_target

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      pr_title: ${{ steps.meta.outputs.title }}
      pr_body: ${{ steps.meta.outputs.body }}
    steps:
      - id: meta
        run: |
          echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
          echo "body=${{ github.event.pull_request.body }}" >> $GITHUB_OUTPUT

  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      # Vulnerable: needs.extract.outputs.pr_title is tainted via github.event.pull_request.title
      - run: echo "Processing PR: ${{ needs.extract.outputs.pr_title }}"
      - run: echo "Body: ${{ needs.extract.outputs.pr_body }}"
```

- [ ] **Step 2: 安全パターンのサンプルを作成する**

`script/actions/cross-job-taint-safe.yaml` を新規作成：

```yaml
# cross-job-taint-safe.yaml
# Shows the safe pattern: use env: to pass needs outputs
name: Cross-Job Taint Example (Safe)

on: pull_request_target

jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      pr_title: ${{ steps.meta.outputs.title }}
    steps:
      - id: meta
        run: |
          echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT

  process:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      # Safe: untrusted needs output is passed via env variable
      - env:
          PR_TITLE: ${{ needs.extract.outputs.pr_title }}
        run: echo "Processing PR: $PR_TITLE"
```

- [ ] **Step 3: sisakulint で脆弱パターンが検出されることを確認する**

Run: `go run ./cmd/sisakulint script/actions/cross-job-taint.yaml`
Expected: `code-injection-critical` エラーが `needs.extract.outputs.pr_title` に対して報告される

Run: `go run ./cmd/sisakulint script/actions/cross-job-taint-safe.yaml`
Expected: エラーなし（0件）

- [ ] **Step 4: script/README.md に追記する**

`script/README.md` の該当セクションに以下を追記：

```markdown
| cross-job-taint.yaml | cross-job-taint-safe.yaml | Cross-job taint via needs.*.outputs.* (code-injection-critical) |
```

- [ ] **Step 5: lint を実行する**

Run: `go vet ./pkg/core/...`
Expected: エラーなし

Run: `golangci-lint run ./pkg/core/... --timeout 5m`
Expected: エラーなし

- [ ] **Step 6: コミットする**

```bash
git add script/actions/cross-job-taint.yaml script/actions/cross-job-taint-safe.yaml script/README.md
git commit -m "feat(examples): add cross-job taint propagation example workflows"
```

---

## Task 11: 全テスト・lint パスの確認とプッシュ

- [ ] **Step 1: 全テストを実行する**

Run: `go test ./... -count=1 -race`
Expected: PASS

- [ ] **Step 2: golangci-lint を実行する**

Run: `golangci-lint run ./... --timeout 10m`
Expected: エラーなし

- [ ] **Step 3: sisakulint 自身のワークフローファイルを解析してみる**

Run: `go run ./cmd/sisakulint .github/workflows/`
Expected: 新しい誤検知がないこと（既存のエラーのみ）

- [ ] **Step 4: 設計ドキュメントをコミットする**

```bash
git add docs/superpowers/specs/2026-04-04-cross-job-taint-propagation-design.md docs/superpowers/plans/2026-04-04-cross-job-taint-propagation.md
git commit -m "docs: add design spec and implementation plan for cross-job taint propagation (#391)"
```

- [ ] **Step 5: プッシュする**

```bash
git push origin main
```

---

## 注意事項

### WorkflowTaintMap の Reset() について

`WorkflowTaintMap` は `makeRules` で1回生成され、同じインスタンスが複数ファイルの解析に使い回される可能性があります。`VisitWorkflowPre` での `Reset()` 呼び出しは Critical と Medium の両ルールから行われますが、どちらが先に呼ばれても冪等です（2回リセットするだけ）。

### pending のスレッドセーフ性

`pendingCrossJobChecks` は各ルールインスタンスのフィールドです（WorkflowTaintMap には置かない）。Critical と Medium は別インスタンスなので競合しません。

### テスト時の WorkflowTaintMap

既存の単体テスト（`CodeInjectionCriticalRule()` を直接呼び出しているもの）は引数なしで呼ばれているため、factory 変更後にコンパイルエラーになります。Task 5 でのファクトリ変更時に既存テストの呼び出し箇所も `CodeInjectionCriticalRule(nil)` に更新してください（`nil` を渡すとクロスジョブ機能が無効になり、既存テストの動作は変わらない）。

既存テストの修正が必要なファイル:
- `pkg/core/codeinjectioncritical_test.go`
- `pkg/core/codeinjectionmedium_test.go`
- `pkg/core/codeinjection_autofix_test.go`
- `pkg/core/codeinjection_shell_test.go`
- `pkg/core/taint_integration_test.go`（`NewLinter` 経由なので変更不要）
