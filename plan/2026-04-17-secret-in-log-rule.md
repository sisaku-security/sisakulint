# secret-in-log ルール 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `${{ secrets.* }}` から派生したシェル変数を `echo`/`printf` でビルドログに出力する脆弱パターンを検出する新規ルール `secret-in-log` を実装する（Issue #388）。**goat case11（`script/actions/goat-secret-in-build-log.yml` の `PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')` → `echo "GCP Private Key: $PRIVATE_KEY"`）を確実に DETECTED にする**ことを最優先の受け入れ基準とする。

**Architecture:** `pkg/shell` のシェル AST 解析を活用し、「secret を源流とする env 変数」→「シェル変数への代入による伝播（taint 伝播）」→「`echo`/`printf` での出力」というデータフローを単一 step 内で追跡する。検出時は `::add-mask::` を利用した auto-fix を提供する（既存 `unmasked-secret-exposure` と同等の UX）。

**Scope（MVP = 選択肢 C を採用）:**
- MVP は **単一 step 内** の taint 伝播に限定する（goat case11 をカバー）。
- **クロスジョブ伝播（`needs.*.outputs.*` 経由）と reusable workflow 跨ぎ（`workflow_call` 経由）はこのプランではやらない**。理由は以下：
  - `WorkflowTaintMap`（#391 / PR #420）は現状 *untrusted input* 用。secret 用 taint（意味論が逆: 機密が「外へ漏れる」方向の追跡）は別のマップで設計すべきで、インフラは共有できるが初回実装で混ぜるとスコープが膨らむ。
  - Reusable workflow 跨ぎ（#392）はまだ OPEN で、callee 側の `inputs.*` に secret taint を引き継ぐかは #392 の設計決定に従う必要がある。
- ただし **将来 `WorkflowSecretTaintMap` を受け取れるコンストラクタ shape** にしておき、#419/#426 の DI パターン（`makeRules()` で生成 → ルールに注入）に合流できる拡張ポイントを Task 9 と Task 11 で明示的に残す。
- 後続作業として **follow-up issue を本プラン末尾で起票する**（クロスジョブ secret 伝播 / reusable workflow 跨ぎ secret 伝播）。

**Tech Stack:**
- Go（既存ルール実装と同じ）
- `pkg/ast` / `pkg/core` / `pkg/shell`（`mvdan.cc/sh/v3/syntax` ベースのシェルパーサ）
- `pkg/core/autofixer.go` の `StepFixer` インターフェース
- 将来参照: `pkg/core/workflow_taint.go`（`WorkflowTaintMap` — PR #420 で導入、#426 で 4 ルールに展開済み）

**前提の設計判断:**
- ルール名は `secret-in-log`（既存 `secret-exposure` / `unmasked-secret-exposure` / `secret-exfiltration` と衝突せず、Issue のテーマに最も忠実）。
- Issue 記載の Approach 1（taint tracking）+ Approach 3（`add-mask` auto-fix）を採用。Approach 2 は偽陽性が高いため不採用。
- Severity は `warning` 相当（プロダクションログに出るだけでネットワーク外送はされないため `critical` ではない）。メッセージ末尾に mitigation を示す。
- 対象コマンドは `echo` と `printf` のみ（stdout 出力の最も一般的な手段）。`cat <<<` 等はスコープ外。
- shell AST 解析で実装し、正規表現フォールバックは使わない（将来の拡張性と精度のため）。
- **ファクトリの shape は将来 DI 可能な形にする**: `NewSecretInLogRule()` は現時点では引数なしだが、`makeRules()` での共有リソース（`WorkflowSecretTaintMap` 予定）を後から注入しやすいよう、構造体フィールド `workflowSecretTaintMap *WorkflowSecretTaintMap` の nil 受け入れを最初から持たせる（Task 3 で定義、当面 nil）。

---

## File Structure

- Create: `pkg/core/secretinlog.go` — ルール本体（検出ロジック + auto-fixer）
- Create: `pkg/core/secretinlog_test.go` — ユニットテスト
- Create: `script/actions/secret-in-log-vulnerable.yaml` — 脆弱パターンのサンプル
- Create: `script/actions/secret-in-log-safe.yaml` — 安全パターン（negative test）
- Create: `docs/secretinlogrule.md` — ルールドキュメント
- Modify: `pkg/core/linter.go` — `makeRules` にルール登録（`NewSecretExfiltrationRule()` の直後を想定）
- Modify: `CLAUDE.md` — 「Implemented Rules」「Auto-Fix Implementations」セクション更新
- Modify: `script/README.md` — 新規サンプルの記述追加
- Modify: `docs/goat/case11-secret-in-log.md` — Verdict を「DETECTED」に更新

---

## データモデル（全タスク共通の参照）

以下の型は `pkg/core/secretinlog.go` 内に定義する：

```go
// secretInLogRule は secret 由来のシェル変数がログ出力される箇所を検出する。
type SecretInLogRule struct {
    BaseRule
    currentStep *ast.Step
    // workflowSecretTaintMap はクロスジョブ secret taint 用の将来拡張フック。
    // 現 MVP では常に nil。follow-up issue で WorkflowSecretTaintMap 型を導入し、
    // makeRules() から共有ポインタを注入する計画（#391/#420 の WorkflowTaintMap と同じ DI パターン）。
    workflowSecretTaintMap interface{} // 将来: *WorkflowSecretTaintMap
}

// taintedShellVar は taint 伝播の追跡結果を表す。
type taintedShellVar struct {
    Name   string // 変数名
    Origin string // 伝播元（"env:SECRET_NAME" or "shellvar:OTHER" 形式）
}

// echoLeakOccurrence は検出された echo/printf 出力箇所を表す。
type echoLeakOccurrence struct {
    VarName    string       // 出力された変数名
    Origin     string       // 伝播元（エラーメッセージ用）
    Position   *ast.Position
    Command    string       // "echo" or "printf"
}
```

---

## 主要関数シグネチャ（Task 間で一貫して使う）

```go
// NewSecretInLogRule は新しいルールインスタンスを返す。
// 現 MVP は引数なし。クロスジョブ secret taint を追加する際には
// NewSecretInLogRuleWithTaintMap(*WorkflowSecretTaintMap) を別途追加し、
// NewSecretInLogRule() はそれを nil 引数で呼ぶ薄いラッパに置き換える（backward compat）。
func NewSecretInLogRule() *SecretInLogRule

// collectSecretEnvVars は step.Env から secret 由来の env 変数名を抽出する。
// 戻り値のキーは env 変数名、値は "secrets.NAME" 形式の出典。
func (rule *SecretInLogRule) collectSecretEnvVars(env *ast.Env) map[string]string

// propagateTaint はシェルスクリプトの AST を走査して初期 taint 集合から
// 派生シェル変数の taint 集合を構築する。初期集合はコピーされ、結果に含まれる。
func (rule *SecretInLogRule) propagateTaint(file *syntax.File, initialTainted map[string]string) map[string]string

// findEchoLeaks は taint 集合を使って echo/printf による出力箇所を抽出する。
func (rule *SecretInLogRule) findEchoLeaks(file *syntax.File, tainted map[string]string, script string, runStr *ast.String) []echoLeakOccurrence

// hasAddMaskFor はスクリプト内に該当変数の ::add-mask:: 呼び出しがあれば true。
func hasAddMaskFor(script, varName string) bool
```

---

## Task 1: 脆弱 / 安全サンプルワークフローの作成

**Files:**
- Create: `script/actions/secret-in-log-vulnerable.yaml`
- Create: `script/actions/secret-in-log-safe.yaml`

**目的:** TDD の前に「何を検出すべきか」の仕様をサンプルで固定する。テストの期待値はこのサンプルに対応する。

- [ ] **Step 1: 脆弱サンプルを作成**

`script/actions/secret-in-log-vulnerable.yaml` を 2 ケースで作成する（jq 派生ケースは既存の `goat-secret-in-build-log.yml` と機能的に重複するため、そちらを external corpus として活用し DRY に保つ）：

```yaml
name: Secret In Log (Vulnerable Samples)

# jq による派生 → echo のケースは goat-secret-in-build-log.yml で
# 別途カバー（Case 11 external verification corpus）。
# ここでは goat 側で扱っていない 2 ケース（チェーン伝播 / 直接 echo）のみ扱う。

on:
  workflow_dispatch:

jobs:
  # Case A: 中間変数を介したチェーン伝播
  leak-via-chained-assignment:
    runs-on: ubuntu-latest
    steps:
      - name: Chained assignment
        env:
          TOKEN: ${{ secrets.API_TOKEN }}
        run: |
          STEP1="$TOKEN"
          STEP2=$(echo "$STEP1")
          printf "Token: %s\n" "$STEP2"

  # Case B: echo で env 変数を直接出力（derivation なし）
  leak-direct-echo:
    runs-on: ubuntu-latest
    steps:
      - name: Direct echo of secret env
        env:
          SECRET: ${{ secrets.PLAIN_SECRET }}
        run: |
          echo "The value is $SECRET"
```

- [ ] **Step 2: 安全サンプルを作成**

`script/actions/secret-in-log-safe.yaml`：

```yaml
name: Secret In Log (Safe Samples)

on:
  workflow_dispatch:

jobs:
  # Safe 1: add-mask で明示的にマスク
  safe-with-add-mask:
    runs-on: ubuntu-latest
    steps:
      - name: Extract with add-mask
        env:
          GCP_SERVICE_ACCOUNT_KEY: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}
        run: |
          PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')
          echo "::add-mask::$PRIVATE_KEY"
          echo "GCP Private Key: $PRIVATE_KEY"

  # Safe 2: echo に secret 由来ではない変数を渡す
  safe-unrelated-echo:
    runs-on: ubuntu-latest
    steps:
      - name: Unrelated echo
        env:
          TOKEN: ${{ secrets.API_TOKEN }}
        run: |
          MSG="hello world"
          echo "$MSG"

  # Safe 3: secret を secret-scoped な CLI に渡すのみ（echo しない）
  safe-no-echo:
    runs-on: ubuntu-latest
    steps:
      - name: Use without echo
        env:
          TOKEN: ${{ secrets.API_TOKEN }}
        run: |
          curl -H "Authorization: Bearer $TOKEN" https://api.github.com/user
```

- [ ] **Step 3: 構文チェック**

Run: `sisakulint script/actions/secret-in-log-vulnerable.yaml script/actions/secret-in-log-safe.yaml`
Expected: まだルール未登録のため YAML としてパースされ、既存ルール以外の出力はなし（失敗しても OK — 他ルールの警告は許容）。

- [ ] **Step 4: Commit**

```bash
git add script/actions/secret-in-log-vulnerable.yaml script/actions/secret-in-log-safe.yaml
git commit -m "test(secret-in-log): add vulnerable and safe workflow samples"
```

---

## Task 2: 失敗するテスト（`collectSecretEnvVars`）を書く

**Files:**
- Create: `pkg/core/secretinlog_test.go`

**目的:** env ブロックから secret 由来の env 変数名を抽出する関数をテストする。

- [ ] **Step 1: テストを書く**

`pkg/core/secretinlog_test.go` を作成：

```go
package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestNewSecretInLogRule(t *testing.T) {
	t.Parallel()

	rule := NewSecretInLogRule()
	if rule.RuleName != "secret-in-log" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "secret-in-log")
	}
	if !strings.Contains(rule.RuleDesc, "log") {
		t.Errorf("RuleDesc should mention 'log', got %q", rule.RuleDesc)
	}
}

func TestSecretInLog_CollectSecretEnvVars(t *testing.T) {
	t.Parallel()

	env := &ast.Env{
		Vars: map[string]*ast.EnvVar{
			"token": {
				Name:  &ast.String{Value: "TOKEN"},
				Value: &ast.String{Value: "${{ secrets.API_TOKEN }}"},
			},
			"other": {
				Name:  &ast.String{Value: "OTHER"},
				Value: &ast.String{Value: "${{ github.event.inputs.x }}"},
			},
		},
	}

	rule := NewSecretInLogRule()
	got := rule.collectSecretEnvVars(env)

	if len(got) != 1 {
		t.Fatalf("expected 1 secret env var, got %d: %v", len(got), got)
	}
	if got["TOKEN"] != "secrets.API_TOKEN" {
		t.Errorf("expected TOKEN -> secrets.API_TOKEN, got %q", got["TOKEN"])
	}
}
```

- [ ] **Step 2: テストを実行して失敗を確認**

Run: `go test -run TestSecretInLog -v ./pkg/core/...`
Expected: FAIL — `NewSecretInLogRule` / `collectSecretEnvVars` が未定義。

---

## Task 3: 最小実装（`collectSecretEnvVars`）

**Files:**
- Create: `pkg/core/secretinlog.go`

- [ ] **Step 1: 最小実装**

```go
package core

import (
	"regexp"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

type SecretInLogRule struct {
	BaseRule
	currentStep *ast.Step
	// workflowSecretTaintMap はクロスジョブ secret taint 伝播用の将来拡張フック。
	// MVP では未使用。follow-up issue（クロスジョブ secret 伝播）で *WorkflowSecretTaintMap に
	// 置換予定。interface{} にしているのは型未導入のため。
	workflowSecretTaintMap interface{}
}

// NewSecretInLogRule は新規ルールインスタンスを返す。
// NOTE: クロスジョブ伝播対応時は NewSecretInLogRuleWithTaintMap を追加し、
// この関数はそれに nil を渡すラッパへ段階移行する。
func NewSecretInLogRule() *SecretInLogRule {
	return &SecretInLogRule{
		BaseRule: BaseRule{
			RuleName: "secret-in-log",
			RuleDesc: "Detects secret values being printed to build logs via echo/printf of " +
				"shell variables derived from secret-sourced environment variables. " +
				"See https://sisaku-security.github.io/lint/docs/rules/secretinlogrule/",
		},
	}
}

var secretEnvRefRe = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

func (rule *SecretInLogRule) collectSecretEnvVars(env *ast.Env) map[string]string {
	result := make(map[string]string)
	if env == nil || env.Vars == nil {
		return result
	}
	for key, envVar := range env.Vars {
		if envVar == nil || envVar.Value == nil {
			continue
		}
		m := secretEnvRefRe.FindStringSubmatch(envVar.Value.Value)
		if len(m) < 2 {
			continue
		}
		name := key
		if envVar.Name != nil && envVar.Name.Value != "" {
			name = envVar.Name.Value
		}
		result[name] = "secrets." + m[1]
	}
	return result
}
```

- [ ] **Step 2: テストを実行して成功を確認**

Run: `go test -run TestSecretInLog -v ./pkg/core/...`
Expected: PASS（`TestNewSecretInLogRule`, `TestSecretInLog_CollectSecretEnvVars`）。

- [ ] **Step 3: Commit**

```bash
git add pkg/core/secretinlog.go pkg/core/secretinlog_test.go
git commit -m "feat(secret-in-log): scaffold rule with secret env var collection"
```

---

## Task 4: 失敗するテスト（`propagateTaint`）

**Files:**
- Modify: `pkg/core/secretinlog_test.go`

**目的:** シェル AST を走査して代入（`VAR=$(...)` / `VAR="$OTHER"`）による taint 伝播を構築する。

- [ ] **Step 1: テスト追加**

以下を `secretinlog_test.go` に追加：

```go
import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"mvdan.cc/sh/v3/syntax"
)

func parseShellForTest(t *testing.T, script string) *syntax.File {
	t.Helper()
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(script), "")
	if err != nil {
		t.Fatalf("failed to parse shell script: %v", err)
	}
	return file
}

func TestSecretInLog_PropagateTaint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		script   string
		initial  map[string]string
		expected map[string]bool // 期待される tainted 変数名
	}{
		{
			name: "command substitution with jq",
			script: `PRIVATE_KEY=$(echo "$GCP_KEY" | jq -r '.private_key')
echo "$PRIVATE_KEY"`,
			initial:  map[string]string{"GCP_KEY": "secrets.GCP"},
			expected: map[string]bool{"GCP_KEY": true, "PRIVATE_KEY": true},
		},
		{
			name: "chained assignment",
			script: `STEP1="$TOKEN"
STEP2=$(echo "$STEP1")`,
			initial:  map[string]string{"TOKEN": "secrets.T"},
			expected: map[string]bool{"TOKEN": true, "STEP1": true, "STEP2": true},
		},
		{
			name: "untainted variables stay untainted",
			script: `MSG="hello"
SAFE=$(date)`,
			initial:  map[string]string{"TOKEN": "secrets.T"},
			expected: map[string]bool{"TOKEN": true},
		},
		{
			name: "assignment from untainted source does not taint",
			script: `NOT_TAINTED=$(ls /tmp)`,
			initial:  map[string]string{"TOKEN": "secrets.T"},
			expected: map[string]bool{"TOKEN": true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rule := NewSecretInLogRule()
			file := parseShellForTest(t, tc.script)
			got := rule.propagateTaint(file, tc.initial)
			if len(got) != len(tc.expected) {
				t.Fatalf("tainted set size = %d (%v), want %d (%v)", len(got), got, len(tc.expected), tc.expected)
			}
			for name := range tc.expected {
				if _, ok := got[name]; !ok {
					t.Errorf("expected %q to be tainted, was not. got=%v", name, got)
				}
			}
		})
	}
}
```

- [ ] **Step 2: テスト失敗を確認**

Run: `go test -run TestSecretInLog_PropagateTaint -v ./pkg/core/...`
Expected: FAIL — `propagateTaint` 未定義。

---

## Task 5: `propagateTaint` を実装

**Files:**
- Modify: `pkg/core/secretinlog.go`

**設計:** AST を不動点反復（変化がなくなるまで繰り返し）で走査する。複数回代入やトポロジカル順でない代入にも対応するため。

- [ ] **Step 1: 実装追加**

`pkg/core/secretinlog.go` に追記：

```go
import (
	"regexp"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"mvdan.cc/sh/v3/syntax"
)

// propagateTaint は初期 taint 集合から不動点反復でシェル変数の taint 伝播を計算する。
func (rule *SecretInLogRule) propagateTaint(file *syntax.File, initialTainted map[string]string) map[string]string {
	tainted := make(map[string]string, len(initialTainted))
	for k, v := range initialTainted {
		tainted[k] = v
	}
	if file == nil {
		return tainted
	}

	for {
		added := false
		syntax.Walk(file, func(node syntax.Node) bool {
			assign, ok := node.(*syntax.Assign)
			if !ok || assign.Name == nil {
				return true
			}
			lhs := assign.Name.Value
			if _, already := tainted[lhs]; already {
				return true
			}
			if assign.Value == nil {
				return true
			}
			if rule.wordReferencesTainted(assign.Value, tainted) {
				tainted[lhs] = "shellvar:" + rule.firstTaintedVarIn(assign.Value, tainted)
				added = true
			}
			return true
		})
		if !added {
			break
		}
	}
	return tainted
}

// wordReferencesTainted は Word 内で tainted 集合に属する変数が参照されていれば true。
func (rule *SecretInLogRule) wordReferencesTainted(word *syntax.Word, tainted map[string]string) bool {
	var found bool
	syntax.Walk(word, func(node syntax.Node) bool {
		pe, ok := node.(*syntax.ParamExp)
		if !ok || pe.Param == nil {
			return true
		}
		if _, t := tainted[pe.Param.Value]; t {
			found = true
			return false
		}
		return true
	})
	return found
}

// firstTaintedVarIn は Word 内で最初に見つかった tainted 変数名を返す（メッセージ用）。
func (rule *SecretInLogRule) firstTaintedVarIn(word *syntax.Word, tainted map[string]string) string {
	var name string
	syntax.Walk(word, func(node syntax.Node) bool {
		pe, ok := node.(*syntax.ParamExp)
		if !ok || pe.Param == nil {
			return true
		}
		if _, t := tainted[pe.Param.Value]; t {
			name = pe.Param.Value
			return false
		}
		return true
	})
	return name
}
```

- [ ] **Step 2: テスト成功を確認**

Run: `go test -run TestSecretInLog_PropagateTaint -v ./pkg/core/...`
Expected: PASS（4 サブテストすべて）。

- [ ] **Step 3: Commit**

```bash
git add pkg/core/secretinlog.go pkg/core/secretinlog_test.go
git commit -m "feat(secret-in-log): implement shell variable taint propagation"
```

---

## Task 6: 失敗するテスト（`findEchoLeaks`）

**Files:**
- Modify: `pkg/core/secretinlog_test.go`

**目的:** taint 集合を使って `echo`/`printf` 呼び出しを検出する。

- [ ] **Step 1: テスト追加**

```go
func TestSecretInLog_FindEchoLeaks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		script   string
		tainted  map[string]string
		wantHits []struct {
			varName string
			command string
		}
	}{
		{
			name: "echo of tainted var",
			script: `echo "Key: $PRIVATE_KEY"
`,
			tainted: map[string]string{"PRIVATE_KEY": "shellvar:GCP_KEY"},
			wantHits: []struct {
				varName string
				command string
			}{{"PRIVATE_KEY", "echo"}},
		},
		{
			name: "printf of tainted var",
			script: `printf "%s\n" "$TOKEN"
`,
			tainted: map[string]string{"TOKEN": "secrets.API"},
			wantHits: []struct {
				varName string
				command string
			}{{"TOKEN", "printf"}},
		},
		{
			name: "echo of untainted var",
			script: `echo "$MSG"
`,
			tainted:  map[string]string{"TOKEN": "secrets.API"},
			wantHits: nil,
		},
		{
			name: "add-mask suppresses echo",
			script: `echo "::add-mask::$TOKEN"
echo "Value: $TOKEN"
`,
			tainted:  map[string]string{"TOKEN": "secrets.API"},
			wantHits: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rule := NewSecretInLogRule()
			file := parseShellForTest(t, tc.script)
			runStr := &ast.String{Value: tc.script, Pos: &ast.Position{Line: 1, Col: 1}}
			got := rule.findEchoLeaks(file, tc.tainted, tc.script, runStr)
			if len(got) != len(tc.wantHits) {
				t.Fatalf("found %d leaks, want %d. got=%v", len(got), len(tc.wantHits), got)
			}
			for i, want := range tc.wantHits {
				if got[i].VarName != want.varName || got[i].Command != want.command {
					t.Errorf("hit[%d]: got {%s,%s}, want {%s,%s}",
						i, got[i].VarName, got[i].Command, want.varName, want.command)
				}
			}
		})
	}
}
```

- [ ] **Step 2: テスト失敗を確認**

Run: `go test -run TestSecretInLog_FindEchoLeaks -v ./pkg/core/...`
Expected: FAIL — `findEchoLeaks` 未定義。

---

## Task 7: `findEchoLeaks` と `hasAddMaskFor` を実装

**Files:**
- Modify: `pkg/core/secretinlog.go`

- [ ] **Step 1: 実装**

```go
// echoLeakOccurrence は検出された echo/printf 出力箇所を表す。
type echoLeakOccurrence struct {
	VarName  string
	Origin   string
	Position *ast.Position
	Command  string
}

// findEchoLeaks は echo/printf の引数に tainted 変数が含まれる箇所を収集する。
// add-mask 済みの変数はスキップする。
func (rule *SecretInLogRule) findEchoLeaks(file *syntax.File, tainted map[string]string, script string, runStr *ast.String) []echoLeakOccurrence {
	if file == nil {
		return nil
	}
	var leaks []echoLeakOccurrence

	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		cmdName := firstWordLiteral(call.Args[0])
		if cmdName != "echo" && cmdName != "printf" {
			return true
		}
		for _, arg := range call.Args[1:] {
			rule.collectLeakedVars(arg, tainted, script, runStr, cmdName, &leaks)
		}
		return true
	})
	return leaks
}

// collectLeakedVars は単一の引数内で tainted 変数参照をすべて報告リストに追加する。
func (rule *SecretInLogRule) collectLeakedVars(
	arg *syntax.Word,
	tainted map[string]string,
	script string,
	runStr *ast.String,
	cmdName string,
	leaks *[]echoLeakOccurrence,
) {
	syntax.Walk(arg, func(node syntax.Node) bool {
		pe, ok := node.(*syntax.ParamExp)
		if !ok || pe.Param == nil {
			return true
		}
		name := pe.Param.Value
		origin, ok := tainted[name]
		if !ok {
			return true
		}
		if hasAddMaskFor(script, name) {
			return true
		}
		pos := offsetToPosition(runStr, script, int(pe.Pos().Offset()))
		*leaks = append(*leaks, echoLeakOccurrence{
			VarName:  name,
			Origin:   origin,
			Position: pos,
			Command:  cmdName,
		})
		return true
	})
}

// firstWordLiteral は Word の先頭リテラル（コマンド名）を取り出す。
func firstWordLiteral(word *syntax.Word) string {
	if word == nil || len(word.Parts) == 0 {
		return ""
	}
	if lit, ok := word.Parts[0].(*syntax.Lit); ok {
		return lit.Value
	}
	return ""
}

// hasAddMaskFor は script 内に該当変数への ::add-mask:: 呼び出しがあれば true。
// 現状は文字列検索（"::add-mask::$NAME" または "::add-mask::${NAME}"）。
func hasAddMaskFor(script, varName string) bool {
	patterns := []string{
		"::add-mask::$" + varName,
		"::add-mask::${" + varName + "}",
	}
	for _, p := range patterns {
		if strings.Contains(script, p) {
			return true
		}
	}
	return false
}

// offsetToPosition は script 内のバイトオフセットを ast.Position に変換する。
func offsetToPosition(runStr *ast.String, script string, offset int) *ast.Position {
	if offset < 0 || offset > len(script) {
		offset = 0
	}
	prefix := script[:offset]
	line := strings.Count(prefix, "\n")
	col := offset
	if lastNL := strings.LastIndex(prefix, "\n"); lastNL >= 0 {
		col = offset - lastNL - 1
	}
	pos := &ast.Position{
		Line: runStr.Pos.Line + line,
		Col:  col + 1,
	}
	if runStr.Literal {
		pos.Line++
	}
	return pos
}
```

ファイル先頭の import に `"strings"` を追加する（Task 3 時点の import に追記）。

- [ ] **Step 2: テスト成功を確認**

Run: `go test -run TestSecretInLog -v ./pkg/core/...`
Expected: PASS（`TestNewSecretInLogRule`, `TestSecretInLog_CollectSecretEnvVars`, `TestSecretInLog_PropagateTaint`, `TestSecretInLog_FindEchoLeaks`）。

- [ ] **Step 3: Commit**

```bash
git add pkg/core/secretinlog.go pkg/core/secretinlog_test.go
git commit -m "feat(secret-in-log): implement echo/printf leak detection with add-mask suppression"
```

---

## Task 8: 失敗するテスト（Visitor 経由のエンドツーエンド）

**Files:**
- Modify: `pkg/core/secretinlog_test.go`

**目的:** `VisitJobPre` を通した 1 ステップ完結の統合テスト。3 つの脆弱ケース＋3 つの安全ケースを含む。

- [ ] **Step 1: テスト追加**

```go
func TestSecretInLog_VisitJob_Integration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		envVars    map[string]string
		runScript  string
		wantErrors int
	}{
		{
			name:       "jq-derived key leaked via echo",
			envVars:    map[string]string{"GCP_KEY": "${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}"},
			runScript:  "PRIVATE_KEY=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"key: $PRIVATE_KEY\"",
			wantErrors: 1,
		},
		{
			name:       "chained assignment leaked via printf",
			envVars:    map[string]string{"TOKEN": "${{ secrets.API_TOKEN }}"},
			runScript:  "STEP1=\"$TOKEN\"\nSTEP2=$(echo \"$STEP1\")\nprintf 'val=%s\\n' \"$STEP2\"",
			wantErrors: 1,
		},
		{
			name:       "direct echo of secret env",
			envVars:    map[string]string{"SECRET": "${{ secrets.PLAIN }}"},
			runScript:  "echo \"val=$SECRET\"",
			wantErrors: 1,
		},
		{
			// goat case11 の元シナリオをそのまま固定化するゴールデンテスト。
			// script/actions/goat-secret-in-build-log.yml の該当 step と同等。
			name:    "goat case11 golden: GCP private key via jq",
			envVars: map[string]string{"GCP_SERVICE_ACCOUNT_KEY": "${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}"},
			runScript: "# Extracting the private key from the GCP service account key\n" +
				"PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')\n\n" +
				"# Simulate using the private key\n" +
				"echo \"Using the private key for some operation\"\n\n" +
				"# Log the private key (simulating a mistake)\n" +
				"echo \"GCP Private Key: $PRIVATE_KEY\"",
			wantErrors: 1,
		},
		{
			name:       "add-mask before use (safe)",
			envVars:    map[string]string{"GCP_KEY": "${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}"},
			runScript:  "PRIVATE_KEY=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"::add-mask::$PRIVATE_KEY\"\necho \"key: $PRIVATE_KEY\"",
			wantErrors: 0,
		},
		{
			name:       "unrelated echo (safe)",
			envVars:    map[string]string{"TOKEN": "${{ secrets.API_TOKEN }}"},
			runScript:  "MSG=\"hello\"\necho \"$MSG\"",
			wantErrors: 0,
		},
		{
			name:       "secret used with curl but not echo (safe)",
			envVars:    map[string]string{"TOKEN": "${{ secrets.API_TOKEN }}"},
			runScript:  "curl -H \"Authorization: Bearer $TOKEN\" https://api.github.com/user",
			wantErrors: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rule := NewSecretInLogRule()

			envVars := map[string]*ast.EnvVar{}
			for name, val := range tc.envVars {
				envVars[strings.ToLower(name)] = &ast.EnvVar{
					Name:  &ast.String{Value: name},
					Value: &ast.String{Value: val},
				}
			}

			step := &ast.Step{
				Env: &ast.Env{Vars: envVars},
				Exec: &ast.ExecRun{
					Run: &ast.String{Value: tc.runScript, Pos: &ast.Position{Line: 1, Col: 1}},
				},
			}
			job := &ast.Job{Steps: []*ast.Step{step}}

			if err := rule.VisitJobPre(job); err != nil {
				t.Fatalf("VisitJobPre returned err: %v", err)
			}
			if got := len(rule.Errors()); got != tc.wantErrors {
				t.Errorf("errors = %d, want %d. details=%v", got, tc.wantErrors, rule.Errors())
			}
		})
	}
}
```

- [ ] **Step 2: テスト失敗を確認**

Run: `go test -run TestSecretInLog_VisitJob_Integration -v ./pkg/core/...`
Expected: FAIL — `VisitJobPre` が `BaseRule` のデフォルトしか持たないため全ケースで 0 エラー。

---

## Task 9: Visitor メソッドを実装して統合する

**Files:**
- Modify: `pkg/core/secretinlog.go`

- [ ] **Step 1: `VisitJobPre` と `checkStep` を追加**

```go
func (rule *SecretInLogRule) VisitJobPre(node *ast.Job) error {
	for _, step := range node.Steps {
		rule.currentStep = step
		rule.checkStep(step)
	}
	return nil
}

func (rule *SecretInLogRule) checkStep(step *ast.Step) {
	if step == nil || step.Exec == nil {
		return
	}
	execRun, ok := step.Exec.(*ast.ExecRun)
	if !ok || execRun.Run == nil {
		return
	}
	script := execRun.Run.Value
	if script == "" {
		return
	}

	initialTainted := rule.collectSecretEnvVars(step.Env)
	if len(initialTainted) == 0 {
		return
	}

	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(script), "")
	if err != nil || file == nil {
		return // パース失敗時は解析をスキップ（他ルールの管轄）
	}

	tainted := rule.propagateTaint(file, initialTainted)
	leaks := rule.findEchoLeaks(file, tainted, script, execRun.Run)

	for _, leak := range leaks {
		rule.reportLeak(leak)
		rule.addAutoFixer(step, leak)
	}
}

func (rule *SecretInLogRule) reportLeak(leak echoLeakOccurrence) {
	rule.Errorf(
		leak.Position,
		"secret in log: variable $%s (origin: %s) is printed via '%s' without masking. "+
			"GitHub Actions only masks direct secrets.* values; values derived via shell expansion or "+
			"tools like jq are not masked and will appear in plaintext in build logs. "+
			"Add 'echo \"::add-mask::$%s\"' before any usage, or avoid printing the value. "+
			"See https://sisaku-security.github.io/lint/docs/rules/secretinlogrule/",
		leak.VarName, leak.Origin, leak.Command, leak.VarName,
	)
}

// addAutoFixer は add-mask 行を run スクリプト冒頭に挿入する auto-fixer を登録する。
func (rule *SecretInLogRule) addAutoFixer(step *ast.Step, leak echoLeakOccurrence) {
	fixer := &secretInLogFixer{
		step:     step,
		varName:  leak.VarName,
		ruleName: rule.RuleName,
	}
	rule.AddAutoFixer(NewStepFixer(step, fixer))
}

type secretInLogFixer struct {
	step     *ast.Step
	varName  string
	ruleName string
}

func (f *secretInLogFixer) RuleNames() string { return f.ruleName }

func (f *secretInLogFixer) FixStep(node *ast.Step) error {
	if node == nil || node.Exec == nil {
		return nil
	}
	execRun, ok := node.Exec.(*ast.ExecRun)
	if !ok || execRun.Run == nil {
		return nil
	}
	script := execRun.Run.Value
	if hasAddMaskFor(script, f.varName) {
		return nil
	}

	addMask := `echo "::add-mask::$` + f.varName + `"`
	var updated string
	if strings.HasPrefix(script, "#!") {
		nl := strings.Index(script, "\n")
		if nl == -1 {
			updated = script + "\n" + addMask
		} else {
			updated = script[:nl] + "\n" + addMask + "\n" + script[nl+1:]
		}
	} else {
		updated = addMask + "\n" + script
	}
	execRun.Run.Value = updated
	if execRun.Run.BaseNode != nil {
		execRun.Run.BaseNode.Value = updated
	}
	return nil
}
```

- [ ] **Step 2: テスト成功を確認**

Run: `go test -run TestSecretInLog -v ./pkg/core/...`
Expected: PASS（`TestSecretInLog_VisitJob_Integration` を含む全サブテスト）。

- [ ] **Step 3: Commit**

```bash
git add pkg/core/secretinlog.go pkg/core/secretinlog_test.go
git commit -m "feat(secret-in-log): implement VisitJobPre with add-mask auto-fixer"
```

---

## Task 10: 失敗するテスト（Auto-fix 動作）

**Files:**
- Modify: `pkg/core/secretinlog_test.go`

**目的:** `FixStep` によって add-mask 行が挿入されることを検証する。

- [ ] **Step 1: テスト追加**

```go
func TestSecretInLog_AutoFix_InsertsAddMask(t *testing.T) {
	t.Parallel()

	original := "PRIVATE_KEY=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"key: $PRIVATE_KEY\""
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"gcp_key": {
				Name:  &ast.String{Value: "GCP_KEY"},
				Value: &ast.String{Value: "${{ secrets.GCP }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: original, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}

	rule := NewSecretInLogRule()
	if err := rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}}); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if len(rule.AutoFixers()) == 0 {
		t.Fatal("expected at least one auto-fixer")
	}
	for _, f := range rule.AutoFixers() {
		if err := f.Fix(); err != nil {
			t.Fatalf("Fix: %v", err)
		}
	}

	got := step.Exec.(*ast.ExecRun).Run.Value
	if !strings.HasPrefix(got, `echo "::add-mask::$PRIVATE_KEY"`) {
		t.Errorf("expected add-mask prefix, got: %q", got)
	}
	if !strings.Contains(got, original) {
		t.Errorf("original script should remain, got: %q", got)
	}
}

func TestSecretInLog_AutoFix_SkipsWhenAlreadyMasked(t *testing.T) {
	t.Parallel()

	original := "PRIVATE_KEY=$(echo \"$GCP_KEY\" | jq -r '.private_key')\necho \"::add-mask::$PRIVATE_KEY\"\necho \"$PRIVATE_KEY\""
	step := &ast.Step{
		Env: &ast.Env{Vars: map[string]*ast.EnvVar{
			"gcp_key": {
				Name:  &ast.String{Value: "GCP_KEY"},
				Value: &ast.String{Value: "${{ secrets.GCP }}"},
			},
		}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: original, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}

	rule := NewSecretInLogRule()
	_ = rule.VisitJobPre(&ast.Job{Steps: []*ast.Step{step}})
	if len(rule.Errors()) != 0 {
		t.Errorf("expected 0 errors (already masked), got %d", len(rule.Errors()))
	}
}
```

- [ ] **Step 2: テスト実行**

Run: `go test -run TestSecretInLog_AutoFix -v ./pkg/core/...`
Expected: PASS（Task 9 で `addAutoFixer` と `hasAddMaskFor` をすでに実装済みのため、追加実装なしで成功する想定。失敗した場合は Task 9 の実装に戻って修正する）。

- [ ] **Step 3: Commit**

```bash
git add pkg/core/secretinlog_test.go
git commit -m "test(secret-in-log): cover auto-fix insertion and already-masked cases"
```

---

## Task 11: ルールを `linter.go` に登録する

**Files:**
- Modify: `pkg/core/linter.go`（行 557 `NewSecretExfiltrationRule()` の直後）

- [ ] **Step 1: 登録行を追加**

`pkg/core/linter.go` の `NewSecretExfiltrationRule()` の登録直後に以下を追加：

```go
		NewSecretInLogRule(),                                          // Detects secret values printed to build logs via echo/printf of derived shell vars (single-step scope; cross-job follow-up tracked separately)
```

具体的な置換（Edit tool 想定）：

```
old:
		NewSecretExfiltrationRule(),                                   // Detects secret exfiltration via network commands
		NewReusableWorkflowTaintRule(filePath, localReusableWorkflow), // Detects untrusted inputs passed to reusable workflows
new:
		NewSecretExfiltrationRule(),                                   // Detects secret exfiltration via network commands
		NewSecretInLogRule(),                                          // Detects secret values printed to build logs via echo/printf of derived shell vars (single-step scope; cross-job follow-up tracked separately)
		NewReusableWorkflowTaintRule(filePath, localReusableWorkflow), // Detects untrusted inputs passed to reusable workflows
```

**注記（将来拡張への伏線）**: `WorkflowTaintMap`（`wfTaintMap` 変数、行 509 付近）は *untrusted input* 用のため、secret 用とは混在させない。クロスジョブ secret 伝播を追加する際は、`makeRules()` 冒頭で `wfSecretTaintMap := NewWorkflowSecretTaintMap()` を追加し、`NewSecretInLogRuleWithTaintMap(wfSecretTaintMap)` に切り替える（#419/#426 と同じ DI パターン）。この行のコメントに `follow-up: cross-job` の記載を残しておくことで将来の実装者への道しるべとする。

- [ ] **Step 2: ビルドと全テストを実行**

Run: `go build ./cmd/sisakulint && go test ./...`
Expected: ビルド成功、全テスト PASS。

- [ ] **Step 3: 実ファイルで動作確認**

Run: `./sisakulint script/actions/secret-in-log-vulnerable.yaml`
Expected: 2 ステップ分の `secret-in-log` エラーが出力される（Case A: `STEP2` を printf / Case B: `SECRET` を echo）。

Run: `./sisakulint script/actions/secret-in-log-safe.yaml`
Expected: `secret-in-log` エラーは 0 件（他ルールの警告は許容）。

Run: `./sisakulint script/actions/goat-secret-in-build-log.yml`
Expected: `secret-in-log` エラーが 1 件（`PRIVATE_KEY` の echo）。

- [ ] **Step 4: Auto-fix dry-run 確認**

Run: `./sisakulint -fix dry-run script/actions/secret-in-log-vulnerable.yaml`
Expected: 各脆弱ステップの先頭に `echo "::add-mask::$VAR"` が挿入される diff が表示される。

- [ ] **Step 5: Commit**

```bash
git add pkg/core/linter.go
git commit -m "feat(secret-in-log): register rule in linter"
```

---

## Task 12: 既存の `goat/case11-secret-in-log.md` を更新

**Files:**
- Modify: `docs/goat/case11-secret-in-log.md`

- [ ] **Step 1: Verdict セクションを更新**

以下の old → new 置換：

```
old:
## Verdict: NOT DETECTED
new:
## Verdict: DETECTED

Detected by the `secret-in-log` rule (added in response to Issue #388).
```

また、「Future Improvement Ideas」セクションの内容を現状の実装概要に置き換える：

```
old:
## Future Improvement Ideas

- Detect `echo $SECRET_VAR` patterns in shell scripts
- Track `jq`-derived values from secrets environment variables
new:
## Detection Implementation

The `secret-in-log` rule tracks taint propagation from `${{ secrets.* }}`-sourced
environment variables through shell variable assignments (including command
substitutions like `$(jq ...)`) and reports `echo`/`printf` calls that reference
any tainted variable. The auto-fix inserts `echo "::add-mask::$VAR"` before the
first use.
```

- [ ] **Step 2: Commit**

```bash
git add docs/goat/case11-secret-in-log.md
git commit -m "docs(goat): mark case11 as DETECTED with secret-in-log rule"
```

---

## Task 13: ルールドキュメントを追加

**Files:**
- Create: `docs/secretinlogrule.md`

既存 `docs/unmaskedsecretexposure.md` など（存在しない場合は `docs/unmasked_secret_exposure.md`）と同じ体裁に合わせる。

- [ ] **Step 1: ドキュメント作成**

既存の `docs/*.md` からフォーマットを確認してから作成する：

```bash
ls docs/*.md | head -20
```

その上で `docs/secretinlogrule.md` を既存スタイルに合わせて作成する（以下は雛形）：

```markdown
+++
title = 'secret-in-log'
+++

# secret-in-log

Detects secret values being printed to build logs via `echo` / `printf` of
shell variables derived from secret-sourced environment variables.

## Why it matters

GitHub Actions automatically masks values of `secrets.*` in logs. However, when
a secret is parsed or transformed using shell tools (e.g. `jq`, `sed`, `awk`),
the derived value is stored in a shell variable that is **not** masked. Printing
it to stdout via `echo` or `printf` exposes the secret in plaintext in build
logs.

## Vulnerable Pattern

\```yaml
env:
  GCP_SERVICE_ACCOUNT_KEY: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}
run: |
  PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')
  echo "GCP Private Key: $PRIVATE_KEY"
\```

## Safe Pattern

\```yaml
run: |
  PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')
  echo "::add-mask::$PRIVATE_KEY"
  echo "GCP Private Key: $PRIVATE_KEY"
\```

## Auto-fix

This rule inserts an `echo "::add-mask::$VAR"` line before any usage of the
tainted variable in the same `run:` block.

## Related

- [unmasked-secret-exposure](./unmaskedsecretexposure/) - `fromJson()` derivation
- [secret-exfiltration](./secretexfiltration/) - network-based exfiltration
```

(上記コードブロック中の `\```` はエスケープ — 実ファイルでは通常の backtick。)

- [ ] **Step 2: Commit**

```bash
git add docs/secretinlogrule.md
git commit -m "docs(secret-in-log): add rule documentation"
```

---

## Task 14: CLAUDE.md / script/README.md を更新

**Files:**
- Modify: `CLAUDE.md`（`Implemented Rules` と `Current Auto-Fix Implementations` セクション）
- Modify: `script/README.md`（存在する場合）

- [ ] **Step 1: `CLAUDE.md` の「Implemented Rules」に追加**

`RequestForgeryMediumRule` の直後、`CacheBloatRule` の直前あたりに：

```markdown
- **SecretInLogRule** - Detects secret values printed to build logs via `echo`/`printf` of shell variables derived from secret-sourced environment variables (e.g., `jq`-derived values) (auto-fix supported)
```

- [ ] **Step 2: `CLAUDE.md` の「Current Auto-Fix Implementations」に追加**

```markdown
- **SecretInLogRule** (`secretinlog.go`) - Inserts `echo "::add-mask::$VAR"` before any usage of tainted shell variables
```

- [ ] **Step 3: `script/README.md` を確認して必要なら追記**

Run: `cat script/README.md 2>/dev/null | head -30`

存在すれば既存サンプルの記法に合わせて `secret-in-log-vulnerable.yaml` / `secret-in-log-safe.yaml` の説明を追加。

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md script/README.md
git commit -m "docs: register secret-in-log rule in CLAUDE.md and script/README.md"
```

---

## Task 15: lint と最終確認

- [ ] **Step 1: 全テスト・全ビルド**

Run:
```bash
go build ./cmd/sisakulint
go test ./...
```
Expected: すべて成功。

- [ ] **Step 2: lint 実行（更新ファイルに限定）**

Run:
```bash
golangci-lint run --fix --config ~/.golangci.yml pkg/core/secretinlog.go pkg/core/secretinlog_test.go pkg/core/linter.go
```
Expected: エラーなし。警告があれば修正してから進む。

- [ ] **Step 3: Goat workflow 実測**

Run: `./sisakulint script/actions/goat-secret-in-build-log.yml`
Expected: `secret-in-log` で Line 29（`echo "GCP Private Key: $PRIVATE_KEY"`）が検出される。

- [ ] **Step 4: 既存テストへの回帰がないか確認**

Run: `go test -count=1 ./pkg/core/... ./pkg/shell/...`
Expected: 全 PASS。

- [ ] **Step 5: lint 修正があった場合のみ Commit**

```bash
git status
# 変更があれば：
git add <files>
git commit -m "chore(secret-in-log): address lint feedback"
```

---

## Task 16: Follow-up issue を起票する（クロスジョブ / reusable workflow 跨ぎ）

**Files:** （コード変更なし。`gh issue create` のみ。）

**目的:** MVP では対応しないクロスジョブ secret 伝播と reusable workflow 跨ぎ secret 伝播について、本プランの実装直後に follow-up issue を起票し、忘却を防ぐ。

- [ ] **Step 1: Issue 1 を起票（クロスジョブ secret 伝播）**

```bash
gh issue create \
  --title "feat(secret-in-log): cross-job secret taint propagation via needs.*.outputs.*" \
  --label enhancement \
  --body "## 背景

#388 で導入した \`secret-in-log\` ルールは MVP として単一 step 内の taint 伝播のみを扱っている。ジョブ境界を越える secret 派生値のログ漏洩は未検出のまま。

## 未検出パターン

\`\`\`yaml
jobs:
  extract:
    outputs:
      decoded: \${{ steps.x.outputs.val }}
    steps:
      - id: x
        env:
          KEY: \${{ secrets.GCP }}
        run: |
          DECODED=\$(echo \$KEY | jq -r .private_key)
          echo \"val=\$DECODED\" >> \$GITHUB_OUTPUT
  leak:
    needs: extract
    steps:
      - run: echo \"Got: \${{ needs.extract.outputs.decoded }}\"
\`\`\`

## 提案設計

#391 / PR #420 で導入された \`WorkflowTaintMap\`（untrusted input 用）と同じ DI パターンで \`WorkflowSecretTaintMap\` を新規追加する：

1. \`pkg/core/workflow_secret_taint.go\` に \`WorkflowSecretTaintMap\` を実装（\`map[jobID]map[outputName]secretOrigin\`）
2. \`secret-in-log\` ルールに Phase 4 相当を追加: step 内で派生した secret taint が \`>> \$GITHUB_OUTPUT\` / \`>> \$GITHUB_ENV\` に書き込まれたら job output として登録
3. \`needs.*.outputs.*\` を参照する step で \`WorkflowSecretTaintMap.Resolve\` し、echo/printf に渡る場合は報告
4. \`makeRules()\` で \`wfSecretTaintMap := NewWorkflowSecretTaintMap()\` を追加、\`NewSecretInLogRuleWithTaintMap(wfSecretTaintMap)\` に差し替え

## 参照

- #388 (MVP 実装)
- #391 / PR #420 (WorkflowTaintMap の参考実装)
- #419 / PR #426 (DI 拡張パターンの参考)
- \`pkg/core/workflow_taint.go\` (model reference)
- \`plan/2026-04-17-secret-in-log-rule.md\` (Scope 節)"
```

- [ ] **Step 2: Issue 2 を起票（reusable workflow 跨ぎ secret 伝播）**

```bash
gh issue create \
  --title "feat(secret-in-log): cross-file secret taint via reusable workflow (workflow_call)" \
  --label enhancement \
  --body "## 背景

#388 で導入した \`secret-in-log\` は単一 workflow ファイル内に限定。caller 側で secret を \`with:\` や \`secrets: inherit\` 経由で callee に渡し、callee 側で \`inputs.*\` を echo するパターンは未検出。

## 未検出パターン

**Caller** (\`ci.yml\`):
\`\`\`yaml
jobs:
  build:
    uses: ./.github/workflows/reusable.yml
    secrets:
      token: \${{ secrets.API_TOKEN }}
\`\`\`

**Callee** (\`reusable.yml\`):
\`\`\`yaml
on:
  workflow_call:
    secrets:
      token:
        required: true
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - env:
          T: \${{ secrets.token }}
        run: |
          DECODED=\$(echo \$T | base64 -d)
          echo \"Decoded: \$DECODED\"
\`\`\`

## 依存

#392 (Cross-File Taint Tracking for Reusable Workflow Chains) の設計決定を待つ。
\`LocalReusableWorkflowCache\` を拡張して secret taint のメタデータも保持する方向で整合させる。

## 参照

- #388 (MVP 実装)
- #392 (reusable workflow taint 追跡の包括的設計)
- \`pkg/core/reusable_workflow_taint_rule.go\`
- \`plan/2026-04-17-secret-in-log-rule.md\` (Scope 節)"
```

- [ ] **Step 3: 起票確認（コミット不要）**

Run: `gh issue list --label enhancement --search "secret-in-log" --state open`
Expected: 上記 2 件が表示される。

---

## Self-Review チェックリスト

- [x] **Spec coverage:**
  - Approach 1 (shell variable taint tracking) → Task 4-7
  - Approach 3 (add-mask recommendation as auto-fix) → Task 9-10
  - goat workflow (`goat-secret-in-build-log.yml`) の検出 → Task 8（ゴールデンテスト）, Task 11 Step 3（実ファイル）, Task 12（docs 更新で NOT DETECTED → DETECTED に遷移）, Task 15 Step 3（回帰なし確認）
  - Issue で示された 3 つの検出パターン（jq 経由 / チェーン代入 / 直接 echo）すべてカバー: jq 派生は `goat-secret-in-build-log.yml`（Task 11 Step 3 + Task 8 ゴールデンテスト）、チェーン代入と直接 echo は `secret-in-log-vulnerable.yaml`（Task 1）
  - クロスジョブ伝播 (#391/#420) / ルール横展開 (#419/#426) / reusable workflow 跨ぎ (#392) → 本プランでは **Scope で明示的に除外**し、Task 16 で follow-up issue として追跡。DI 拡張ポイント（`workflowSecretTaintMap` フィールドと `NewSecretInLogRuleWithTaintMap` への将来リネーム）を Task 3 / Task 11 でコード上にコメントとして残す。
- [x] **Placeholder scan:** TBD / TODO / "handle edge cases" の記述なし。全コード例は完結した実装。
- [x] **Type consistency:**
  - `echoLeakOccurrence` は Task 6/7/9 で同一定義
  - `secretInLogFixer.FixStep` / `RuleNames` は Task 9 の実装のみで使用
  - `NewSecretInLogRule()` は Task 3 で初出、Task 11 で登録、テストで一貫して使用
  - `workflowSecretTaintMap` フィールドは Task 3 でのみ導入、MVP 実装では参照しない（将来拡張用）

## スコープ外（このプランでは扱わない — follow-up で対応）

| 項目 | 理由 | トラッキング |
|------|------|--------------|
| クロスジョブ secret 伝播（`needs.*.outputs.*` 経由） | `WorkflowSecretTaintMap` の新規設計が必要。インフラは #391/#420 の `WorkflowTaintMap` を参考にできるが意味論（*secret が漏れる方向*）が逆のため別マップが妥当。MVP では拡張ポイントのみ残す。 | Task 16 Step 1 で follow-up issue 起票 |
| Reusable workflow 跨ぎ secret 伝播（`workflow_call` / `secrets: inherit` 経由） | #392 の設計決定（`LocalReusableWorkflowCache` 拡張方針）に依存。 | Task 16 Step 2 で follow-up issue 起票（#392 依存） |
| `bash -c "echo ..."` / ヒアドキュメント経由のログ出力 | shell AST の多重パース対応が必要。低優先。 | 将来 issue（未起票） |
| `tee` / `printenv` / `env` / `cat` 等の間接出力コマンド | 偽陽性リスクが高く、個別の legit パターン整理が必要。 | 将来 issue（未起票） |
| `>> $GITHUB_OUTPUT` / `>> $GITHUB_STEP_SUMMARY` への書き出し | これが先に Task 16 Step 1 の Phase 4 で必要になる（クロスジョブ伝播の起点）。 | Task 16 Step 1 に包含 |

---

## Execution Handoff

**Plan complete and saved to `plan/2026-04-17-secret-in-log-rule.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
