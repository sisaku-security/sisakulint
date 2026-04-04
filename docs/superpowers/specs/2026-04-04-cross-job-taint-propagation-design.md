# Design: Cross-Job Taint Propagation via needs.*.outputs.*

**Issue**: #391  
**Date**: 2026-04-04  
**Status**: Approved

---

## 概要

`TaintTracker` を拡張し、`jobs.<job_id>.outputs` → `needs.<job_id>.outputs.*` を通じたクロスジョブのテイント伝播を検出できるようにする。現在の `TaintTracker` は単一ジョブ内（`steps.*.outputs.*` 経由）の taint 追跡しか行っておらず、ジョブ境界をまたぐ間接的なインジェクションベクターを見逃している。

**スコープ（今回）**: CodeInjectionCritical/Medium ルールへの統合  
**スコープ外（将来）**: EnvVarInjection / ArgumentInjection 等への展開

---

## 検出対象パターン

### 現在見逃しているケース

```yaml
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
      # 現在 sisakulint では未検出 → 追加後は検出
      - run: echo "Processing: ${{ needs.extract.outputs.pr_title }}"
```

### 3ジョブ以上のチェーン（深さ無制限）

```
job-A: github.event.pull_request.title → $GITHUB_OUTPUT (title)
  ↓ needs
job-B: needs.A.outputs.title → 加工して別の $GITHUB_OUTPUT (processed)
  ↓ needs
job-C: needs.B.outputs.processed → run スクリプトで使用  ← ここで検出
```

---

## アーキテクチャ

### アプローチ: トポロジカルソート + WorkflowTaintMap（アプローチ B）

`visitor.go` の既存フローを変更せず、`VisitWorkflowPre` / `VisitJobPre` / `VisitWorkflowPost` の拡張で実現する。

### 処理フロー

```
VisitWorkflowPre
  └─ needs DAG を AST から構築 → WorkflowTaintMap に保存

VisitJobPre（各ジョブで実行）
  ├─ 1. TaintTracker（既存・変更なし）でジョブ内 step taint を収集
  ├─ 2. needs.X.outputs.Y を参照する式を検出
  │      └─ WorkflowTaintMap.ResolveNeedsExpr(jobID="X", output="Y")
  │           ├─ X の出力 Y が tainted → taint source を返す
  │           └─ X がまだ未登録（逆順記述）→ pending に積む
  ├─ 3. エラー報告（checkUntrustedInputWithTaint を拡張）
  └─ 4. 自ジョブの出力 taint を WorkflowTaintMap に登録

VisitWorkflowPost
  └─ pending に残った未解決参照をリトライして最終エラー報告
```

---

## データ構造

### WorkflowTaintMap（新規: `pkg/core/workflow_taint.go`）

```go
type WorkflowTaintMap struct {
    // jobID -> outputName -> []taintSource
    // 例: {"extract": {"pr_title": ["github.event.pull_request.title"]}}
    jobOutputTaints map[string]map[string][]string

    // needs DAG: jobID -> []dependsOnJobID
    jobNeeds map[string][]string

    // 処理順序の問題で未解決だった参照（VisitWorkflowPost でリトライ）
    pending []pendingResolution
}

type pendingResolution struct {
    jobID      string
    outputName string
    // エラー登録のためのコールバック
    callback func(sources []string)
}
```

### 主要メソッド

| メソッド | 説明 |
|---------|------|
| `NewWorkflowTaintMap()` | インスタンス作成 |
| `BuildFromWorkflow(node *ast.Workflow)` | needs DAG を構築 |
| `RegisterJobOutputs(jobID string, tracker *TaintTracker, outputs ast.Outputs)` | ジョブの出力 taint を登録 |
| `ResolveNeedsExpr(jobID, outputName string) ([]string, bool)` | jobID・outputName を直接指定して taint source を返す（未登録なら false） |
| `ResolveFromExprNode(node ast.ExprNode) []string` | AST ノードから needs.X.outputs.Y を抽出して taint source を返す（`checkUntrustedInputWithTaint` から呼ぶ） |
| `AddPending(jobID, outputName string, callback func([]string))` | 未解決参照を pending に追加 |
| `FlushPending()` | pending を全件リトライ |

---

## ファイル変更一覧

| ファイル | 変更種別 | 内容 |
|---------|---------|------|
| `pkg/core/workflow_taint.go` | 新規作成 | WorkflowTaintMap 本体 |
| `pkg/core/codeinjection.go` | 既存に追記 | フィールド追加・VisitWorkflowPre/VisitJobPre 拡張・checkUntrustedInputWithTaint 拡張（約30行） |
| `pkg/core/linter.go` | 既存に追記 | `wfTaintMap` 生成・コンストラクタに渡す（数行） |
| `pkg/core/taint.go` | 変更なし | — |
| `pkg/core/visitor.go` | 変更なし | — |
| `pkg/core/workflow_taint_test.go` | 新規作成 | WorkflowTaintMap 単体テスト |
| `pkg/core/codeinjection_test.go` | 既存に追記 | クロスジョブテストケース追加 |
| `script/actions/cross-job-taint.yaml` | 新規作成 | 脆弱パターンの例 |
| `script/actions/cross-job-taint-safe.yaml` | 新規作成 | 安全パターンの例 |

---

## codeinjection.go への変更詳細

### フィールド追加

```go
type CodeInjectionRule struct {
    BaseRule
    // ... 既存フィールド ...
    workflowTaintMap *WorkflowTaintMap  // 追加
}
```

### VisitWorkflowPre 拡張

```go
func (rule *CodeInjectionRule) VisitWorkflowPre(node *ast.Workflow) error {
    // ... 既存コード ...

    // WorkflowTaintMap の初期化（Linter から渡された場合）
    if rule.workflowTaintMap != nil {
        rule.workflowTaintMap.BuildFromWorkflow(node)
    }
    return nil
}
```

### VisitJobPre 拡張

```go
func (rule *CodeInjectionRule) VisitJobPre(node *ast.Job) error {
    // ... 既存コード（TaintTracker 初期化・2パス処理）...

    // WorkflowTaintMap にこのジョブの出力 taint を登録
    if rule.workflowTaintMap != nil {
        rule.workflowTaintMap.RegisterJobOutputs(node.ID.Value, rule.taintTracker, node.Outputs)
    }
    return nil
}
```

### checkUntrustedInputWithTaint 拡張

```go
func (rule *CodeInjectionRule) checkUntrustedInputWithTaint(expr parsedExpression) []string {
    // 既存: 組み込み untrusted 入力チェック
    paths := rule.checkUntrustedInput(expr)

    // 既存: ジョブ内 TaintTracker チェック
    if rule.taintTracker != nil {
        if tainted, sources := rule.taintTracker.IsTainted(expr.node); tainted {
            paths = append(paths, sources...)
        }
    }

    // 追加: クロスジョブ WorkflowTaintMap チェック
    if rule.workflowTaintMap != nil {
        if sources := rule.workflowTaintMap.ResolveFromExprNode(expr.node); len(sources) > 0 {
            paths = append(paths, sources...)
        }
    }

    return paths
}
```

---

## linter.go への変更

```go
// createRules 内
wfTaintMap := NewWorkflowTaintMap()
rules := []Rule{
    // ...
    CodeInjectionCriticalRule(wfTaintMap),
    CodeInjectionMediumRule(wfTaintMap),
    // ...
}
```

---

## エラーメッセージ形式

```
expression "needs.extract.outputs.pr_title" is potentially untrusted
(tainted via github.event.pull_request.title in job "extract")
```

3ジョブ以上のチェーンでも、最初の untrusted ソースのみを表示する（中間ジョブは省略）。

---

## auto-fix

既存の CodeInjection auto-fix パターンを再利用する。

```yaml
# Before（脆弱）
- run: echo "Processing: ${{ needs.extract.outputs.pr_title }}"

# After（auto-fix 適用後）
- env:
    NEEDS_EXTRACT_OUTPUTS_PR_TITLE: ${{ needs.extract.outputs.pr_title }}
  run: echo "Processing: $NEEDS_EXTRACT_OUTPUTS_PR_TITLE"
```

---

## テスト戦略

### `workflow_taint_test.go`（新規）

| テスト名 | 検証内容 |
|---------|---------|
| `TestRegisterAndResolve` | 登録した taint が正しく解決される |
| `TestMultiHopChain` | 3ジョブ以上のチェーンで最初のソースまで追跡される |
| `TestPendingFlush` | 逆順記述のワークフローで pending → リトライが機能する |
| `TestIdempotentRegister` | 同じジョブを2回登録しても冪等 |
| `TestNoTaintForConstantOutput` | 定数値のジョブ出力は tainted にならない |

### `codeinjection_test.go`（追記）

| テスト名 | 検証内容 |
|---------|---------|
| `TestCrossJobTaintPropagation_DirectNeeds` | pull_request_target + 2ジョブ構成で検出される |
| `TestCrossJobTaintPropagation_MultiHop` | 3ジョブチェーンで検出される |
| `TestCrossJobTaintPropagation_NoFalsePositive` | 定数値ジョブ出力は誤検知しない |
| `TestCrossJobTaintPropagation_AutoFix` | auto-fix が env: 経由に変換される |
| `TestCrossJobTaintPropagation_ReverseOrder` | 逆順記述でも検出される（pending 機構） |
| `TestCrossJobTaintPropagation_MediumTrigger` | 通常トリガー（pull_request）でも Medium として検出される |

---

## 将来の展開

`WorkflowTaintMap` は `Linter` レベルで生成・共有される汎用コンポーネントとして設計する。将来の対応ルールへは `WorkflowTaintMap` ポインタを渡すだけで展開可能。

**Group 1（低コスト）**: EnvVarInjection / EnvPathInjection / OutputClobbering / ArgumentInjection / RequestForgery の各 Critical/Medium（計10ルール）

**Group 2（追加設計必要）**: ReusableWorkflowTaintRule / UntrustedCheckoutRule / CachePoisoningRule / AIActionPromptInjectionRule（計4ルール）

詳細は memory: `project_workflow_taint_map.md` を参照。
