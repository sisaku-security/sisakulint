# #448 TaintTracker 関数引数 taint 伝播 実装プラン

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `pkg/shell/taint.go::PropagateTaint` の内部 walker を **lazy walk + per-call body 展開** 方式に切り替え、関数本体内の `$1`/`$2`/`${1}`/`$@`/`$*` を呼び出しサイトの実引数 taint に基づいて解決する。`secret-in-log` の autofix を positional 名 → upstream 名に対応させる。

**Architecture:** 仕様書 `docs/superpowers/specs/2026-04-27-448-tainttracker-function-args-design.md` の §2-§7 に従い、(1) FuncDecl 出現時には body を walk せず関数テーブル登録のみ、(2) CallExpr 検出時に call-site の args の taint state を `tainted["1"]/["2"]/.../["@"]/["*"]` として inject、(3) 複数 call-site は visibleAt[stmt] を保守的 union、(4) 再帰は visited map で depth=1 制限、(5) `*ScopedTaint` の公開 API は不変。`pkg/core/taint.go` は変更不要、`pkg/core/secretinlog.go` は autofix のみ修正。

**Tech Stack:** Go 1.x, `mvdan.cc/sh/v3/syntax` (bash AST), 既存の `pkg/shell/taint.go` (#446 / #447 で AST 化・スコープ対応済み)。

**Branch:** `feature/448-taint-tracker-function-args` (このブランチで作業)

---

## File Structure

| Path | 役割 | 状態 |
|---|---|---|
| `pkg/shell/taint.go` | walker 拡張 (`buildArgBinding`, `recordVisibleAt`, `mergeSources`, `callCommandName`, FuncDecl/CallExpr ケース変更) | 既存改修 |
| `pkg/shell/taint_test.go` | `TestPropagateTaint_FunctionArgs` 新規 (テーブル駆動)、`_NilFile` `_RecursionGuardDecrement` 追加 | 既存追記 |
| `pkg/core/taint.go` | **変更なし** (`scoped.At(stmt)` 経由で透過対応) | 確認のみ |
| `pkg/core/taint_test.go` | `TestTaintTracker_RedirWriteInFunctionBody`, `TestTaintTracker_FunctionArg_ChainExpansion` 追加 | 既存追記 |
| `pkg/core/secretinlog.go` | `secretInLogFixer.FixStep` に `resolveMaskTarget` ヘルパを追加、autofix 経路修正 | 既存改修 |
| `pkg/core/secretinlog_test.go` | 4 ケース追加 | 既存追記 |
| `script/actions/taint-args-vulnerable.yaml` | fixture | 新規 |
| `script/actions/taint-args-safe.yaml` | fixture | 新規 |
| `script/README.md` | fixture 説明追加 | 既存追記 |
| `CLAUDE.md` | TaintTracker scope 説明に #448 対応点を追記 | 既存追記 |

---

## Common Test Commands

```bash
# 該当パッケージのみ
go test ./pkg/shell/...
go test ./pkg/core/...

# 単一テスト関数
go test -v ./pkg/shell -run TestPropagateTaint_FunctionArgs
go test -v ./pkg/core -run TestSecretInLog_PositionalArgFromShellVar

# 全体回帰
go test ./...
```

---

## Task 1: walker クロージャ署名のリファクタ (semantics 不変)

**Files:**
- Modify: `pkg/shell/taint.go:283-336` (`makeWalkFn`)
- Modify: `pkg/shell/taint.go:258-278` (`PropagateTaint` の `makeWalkFn` 呼び出し)

**Goal:** `makeWalkFn` シグネチャに `funcTable map[string]*syntax.FuncDecl` と `visited map[string]int` を closure 引数として追加する。挙動は変えない。今後のタスクで lazy walk を組み込むための準備。

- [ ] **Step 1: 既存テストが緑であることを確認**

```bash
go test ./pkg/shell/... ./pkg/core/...
```

Expected: PASS

- [ ] **Step 2: `makeWalkFn` シグネチャを変更**

`pkg/shell/taint.go` の `makeWalkFn` 関数定義を以下に変更。

```go
// makeWalkFn は scope frame stack を維持しつつ walk するクロージャを返す。
// `current` は現在の frame を指す pointer-to-pointer で、subshell/funcdecl 入退場時に
// 書き換える。
// funcTable は関数登録テーブル (#448 lazy walk)。CallExpr 解決で参照する。
// visited は再帰展開ガード (#448 lazy walk)。同一関数の再入を防ぐ。
func makeWalkFn(current **scopeFrame, result *ScopedTaint, funcTable map[string]*syntax.FuncDecl, visited map[string]int) func(syntax.Node) bool {
	return func(node syntax.Node) bool {
		if node == nil {
			return false
		}
		switch n := node.(type) {
		case *syntax.Subshell:
			child := &scopeFrame{kind: scopeSubshell, parent: *current, local: maps.Clone((*current).visible())}
			*current = child
			for _, stmt := range n.Stmts {
				syntax.Walk(stmt, makeWalkFn(current, result, funcTable, visited))
			}
			*current = (*current).parent
			return false
		case *syntax.CmdSubst:
			child := &scopeFrame{kind: scopeCmdSubst, parent: *current, local: maps.Clone((*current).visible())}
			*current = child
			for _, stmt := range n.Stmts {
				syntax.Walk(stmt, makeWalkFn(current, result, funcTable, visited))
			}
			*current = (*current).parent
			return false
		case *syntax.FuncDecl:
			if n.Body == nil {
				return false
			}
			child := &scopeFrame{kind: scopeFunc, parent: *current, local: make(map[string]Entry)}
			prev := *current
			*current = child
			syntax.Walk(n.Body, makeWalkFn(current, result, funcTable, visited))
			*current = prev
			return false
		case *syntax.Stmt:
			// 各 Stmt 入口で visibleAt を記録
			result.visibleAt[n] = (*current).visible()
			return true
		case *syntax.DeclClause:
			processDeclClause(*current, n)
			for _, a := range n.Args {
				if a.Value != nil {
					syntax.Walk(a.Value, makeWalkFn(current, result, funcTable, visited))
				}
			}
			return false
		case *syntax.Assign:
			processAssign(*current, n)
			return true
		}
		return true
	}
}
```

- [ ] **Step 3: `PropagateTaint` 内の `makeWalkFn` 呼び出しを更新**

`pkg/shell/taint.go:273` 付近:

```go
	root := &scopeFrame{kind: scopeRoot, local: maps.Clone(initial)}
	if root.local == nil {
		root.local = make(map[string]Entry)
	}
	current := root
	funcTable := make(map[string]*syntax.FuncDecl)
	visited := make(map[string]int)
	syntax.Walk(file, makeWalkFn(&current, result, funcTable, visited))
```

- [ ] **Step 4: 既存テスト全体を実行して回帰がないことを確認**

```bash
go test ./pkg/shell/... ./pkg/core/...
```

Expected: PASS (signature 変更のみ、挙動不変)

- [ ] **Step 5: Commit**

```bash
git add pkg/shell/taint.go
git commit -m "$(cat <<'EOF'
refactor(taint): #448 walker に funcTable / visited closure 引数を追加

#448 lazy walk 実装の準備として、makeWalkFn シグネチャに関数登録テーブルと
再帰展開ガード用の map を持たせる。本タスクは挙動不変のリファクタ。
EOF
)"
```

---

## Task 2: `mergeSources` private ヘルパ追加

**Files:**
- Modify: `pkg/shell/taint.go` (末尾に private 関数追加)

**Goal:** `pkg/core/taint.go::mergeUnique` と同等の「順序保持・重複なし merge」ヘルパを `pkg/shell` 内に追加する。後続タスクの `buildArgBinding` / `recordVisibleAt` で使う。`pkg/core` に依存させない (cyclic import 回避)。

- [ ] **Step 1: ヘルパ関数を追加**

`pkg/shell/taint.go` の末尾 (ファイル最終行 `}` の後) に追加:

```go
// mergeSources は順序保持で重複なしの slice merge。
// 後続タスクの buildArgBinding / recordVisibleAt から呼び出す内部ヘルパ。
// pkg/core/taint.go::mergeUnique と同等のロジック (cyclic import 回避のため複製)。
func mergeSources(dst, src []string) []string {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[string]struct{}, len(dst)+len(src))
	for _, s := range dst {
		seen[s] = struct{}{}
	}
	out := dst
	for _, s := range src {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
```

- [ ] **Step 2: ビルドが通ることを確認**

```bash
go build ./pkg/shell/...
go test ./pkg/shell/...
```

Expected: PASS (まだ呼び出し箇所なしだが unused 関数は private ヘルパなので linter は許容)

- [ ] **Step 3: Commit**

```bash
git add pkg/shell/taint.go
git commit -m "feat(taint): #448 mergeSources ヘルパを追加

後続タスクの buildArgBinding / recordVisibleAt から使う、順序保持の slice merge。
pkg/core の mergeUnique と同等のロジックを cyclic import 回避のため pkg/shell に複製。
"
```

---

## Task 3: `callCommandName` private ヘルパ追加

**Files:**
- Modify: `pkg/shell/taint.go`

**Goal:** CallExpr の第 1 引数を literal command name として抽出するヘルパを追加。動的 dispatch (`$cmd`) は空文字を返し、後続の funcTable lookup で自然に "未登録扱い" となる。

- [ ] **Step 1: ヘルパ関数を追加**

`pkg/shell/taint.go` 末尾の `mergeSources` の後に追加:

```go
// callCommandName は CallExpr の第1引数を literal command name として返す。
// 第1引数が変数経由 ($cmd 等) の場合は空文字を返す → funcTable 未登録扱いで
// 静的解決スキップとなる。
func callCommandName(call *syntax.CallExpr) string {
	if call == nil || len(call.Args) == 0 {
		return ""
	}
	return wordLitPrefix(call.Args[0])
}
```

- [ ] **Step 2: ビルドが通ることを確認**

```bash
go build ./pkg/shell/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/shell/taint.go
git commit -m "feat(taint): #448 callCommandName ヘルパを追加

CallExpr の第1引数を literal command name として抽出。動的 dispatch (\$cmd) は
空文字を返し、後続 lazy walk で未登録扱いとなる。
"
```

---

## Task 4: `buildArgBinding` 関数を追加

**Files:**
- Modify: `pkg/shell/taint.go`

**Goal:** CallExpr の args から `tainted["1"]/["2"]/.../["@"]/["*"]` の binding map を構築するヘルパを追加。仕様書 §4.4 に従う。

- [ ] **Step 1: import 追加 (`strconv`)**

`pkg/shell/taint.go` の import ブロック (現状 7-13 行目) を以下に変更:

```go
import (
	"maps"
	"path"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)
```

- [ ] **Step 2: `buildArgBinding` 関数を追加**

`pkg/shell/taint.go` 末尾 (`callCommandName` の後) に追加:

```go
// buildArgBinding は CallExpr の args から call-site の taint state を抽出し、
// 関数本体内の $1 / $2 / ... / $@ / $* に対応する binding map を返す。
//
// セマンティクス (#448):
//   - tainted な shell var を参照する arg のみを binding に登録 (untainted arg は skip)
//   - binding["1"], ["2"], ... には Sources = ["shellvar:UPSTREAM_NAME"] (processAssign と同形式)
//   - binding["@"] / ["*"] には全 tainted args の Sources を union (chain そのまま)
//   - すべて Offset = -1 (env-like、body 内 sink から見て常に "before" 扱い)
//
// $@ / $* は「いずれかが tainted なら tainted」(issue 案明記)。
//
// visible は call-site の現在 frame で見える tainted vars (= currentFrame.visible())。
func buildArgBinding(call *syntax.CallExpr, visible map[string]Entry) map[string]Entry {
	binding := make(map[string]Entry)
	if call == nil || len(call.Args) <= 1 {
		return binding
	}
	var atSources []string
	for i, arg := range call.Args[1:] {
		upstream, ok := WordReferencesEntry(arg, visible)
		if !ok {
			continue
		}
		binding[strconv.Itoa(i+1)] = Entry{
			Sources: []string{"shellvar:" + upstream},
			Offset:  -1,
		}
		if e, ok := visible[upstream]; ok {
			atSources = mergeSources(atSources, e.Sources)
		}
	}
	if len(atSources) > 0 {
		binding["@"] = Entry{Sources: atSources, Offset: -1}
		binding["*"] = binding["@"]
	}
	return binding
}
```

- [ ] **Step 3: ビルドが通ることを確認**

```bash
go build ./pkg/shell/...
go test ./pkg/shell/...
```

Expected: PASS (まだ未使用)

- [ ] **Step 4: Commit**

```bash
git add pkg/shell/taint.go
git commit -m "feat(taint): #448 buildArgBinding ヘルパを追加

CallExpr の args から tainted shell var 参照を抽出し、関数本体内の
\$1/\$2/.../\$@/\$* に対応する binding map を返す。Offset=-1 で env-like 扱い。
\$@ は引数のいずれかが tainted なら tainted の保守的 union。
"
```

---

## Task 5: `recordVisibleAt` ヘルパ追加 (まだ呼び出さない)

**Files:**
- Modify: `pkg/shell/taint.go`

**Goal:** 複数 call-site から同じ body Stmt を walk した時の visibleAt union ヘルパを追加。仕様書 §4.5。

- [ ] **Step 1: ヘルパ関数を追加**

`pkg/shell/taint.go` 末尾 (`buildArgBinding` の後) に追加:

```go
// recordVisibleAt は currentFrame.visible() を visibleAt[stmt] に書き込む。
// 同じ stmt に対する再記録 (= 別 call-site から同じ関数 body を再 walk) は
// 既存値と Sources を保守的に union してマージする (#448 複数 call-site 対応)。
//
// Offset は早い (小さい) 値を保持。-1 (env-like) は常に勝つ。
func recordVisibleAt(result *ScopedTaint, stmt *syntax.Stmt, visible map[string]Entry) {
	if result == nil || stmt == nil {
		return
	}
	existing, ok := result.visibleAt[stmt]
	if !ok {
		result.visibleAt[stmt] = maps.Clone(visible)
		return
	}
	for name, entry := range visible {
		cur, has := existing[name]
		if !has {
			existing[name] = entry
			continue
		}
		cur.Sources = mergeSources(cur.Sources, entry.Sources)
		// 早い (小さい) offset を保持。-1 は env-like で常勝
		if entry.Offset < 0 || (cur.Offset >= 0 && entry.Offset < cur.Offset) {
			cur.Offset = entry.Offset
		}
		existing[name] = cur
	}
}
```

- [ ] **Step 2: ビルドが通ることを確認**

```bash
go build ./pkg/shell/...
go test ./pkg/shell/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/shell/taint.go
git commit -m "feat(taint): #448 recordVisibleAt ヘルパを追加

複数 call-site から同じ body Stmt を walk した時に visibleAt[stmt] を保守的
union するヘルパ。Sources は mergeSources で重複なしマージ、Offset は早い方
(env-like -1 が常勝) を保持。
"
```

---

## Task 6: 単一 call-site の lazy walk を有効化 (TDD)

**Files:**
- Modify: `pkg/shell/taint_test.go` (テスト追加)
- Modify: `pkg/shell/taint.go` (FuncDecl / CallExpr ケース変更)

**Goal:** `foo() { echo "$1"; }; foo "$T"` で body の echo stmt の visibleAt に `tainted["1"] = shellvar:T` が入ることを確認。仕様書 §7.1 ケース #1。

- [ ] **Step 1: 失敗するテストを追加**

`pkg/shell/taint_test.go` の末尾 (`TestPropagateTaint_Scoped` の後) に追加:

```go
// TestPropagateTaint_FunctionArgs は #448 関数引数経由 taint 伝播の挙動を検証する。
// lazy walk: FuncDecl 出現時には body を walk せず、CallExpr 検出時に call-site
// の args の taint state を tainted["1"]/.../[ "@"]/["*"] として inject する。
func TestPropagateTaint_FunctionArgs(t *testing.T) {
	t.Parallel()

	type want struct {
		// finalHas は Final に含まれるべき変数名 → Sources の最初の値
		finalHas map[string]string
		// finalAbsent は Final に含まれてはいけない変数名
		finalAbsent []string
		// stmtVisibleHas は body 内 sink stmt 位置で visible に含まれるべき
		// 変数名と origin を script から正規表現で探して検証する
		// {scriptPattern}: stmt の本文 (e.g., `echo "$1"`)、{var}: visible 内変数名、{origin}: First()
		stmtVisibleHas []stmtVisibleAssertion
	}

	cases := []struct {
		name    string
		script  string
		initial map[string]Entry
		want    want
	}{
		{
			name:    "single_call_simple",
			script:  `foo() { echo "$1"; }; foo "$T"`,
			initial: map[string]Entry{"T": {Sources: []string{"github.event.issue.body"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "github.event.issue.body"},
				stmtVisibleHas: []stmtVisibleAssertion{
					{stmtSubstr: `echo "$1"`, varName: "1", originFirst: "shellvar:T"},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := parseScript(t, tc.script)
			result := PropagateTaint(file, tc.initial)
			assertFunctionArgsResult(t, file, tc.script, result, tc.want)
		})
	}
}

// stmtVisibleAssertion は body 内 stmt の visible map に対する assertion 1 件分。
type stmtVisibleAssertion struct {
	stmtSubstr  string // stmt のテキスト中に含まれるべき部分文字列 (e.g., `echo "$1"`)
	varName     string // visible に含まれるべき変数名 (e.g., "1")
	originFirst string // visible[varName].First() の期待値 (e.g., "shellvar:T")
}

// assertFunctionArgsResult は want に従って Final と stmt-level visibleAt を検証する。
func assertFunctionArgsResult(t *testing.T, file *syntax.File, script string, result *ScopedTaint, w struct {
	finalHas       map[string]string
	finalAbsent    []string
	stmtVisibleHas []stmtVisibleAssertion
}) {
	t.Helper()
	for name, wantOrigin := range w.finalHas {
		entry, ok := result.Final[name]
		if !ok {
			t.Errorf("Final[%q] missing; want origin %q", name, wantOrigin)
			continue
		}
		if entry.First() != wantOrigin {
			t.Errorf("Final[%q].First() = %q; want %q", name, entry.First(), wantOrigin)
		}
	}
	for _, name := range w.finalAbsent {
		if _, ok := result.Final[name]; ok {
			t.Errorf("Final[%q] should be absent", name)
		}
	}
	for _, assertion := range w.stmtVisibleHas {
		stmt := findStmtBySubstr(t, file, script, assertion.stmtSubstr)
		if stmt == nil {
			t.Errorf("stmt with substr %q not found in script", assertion.stmtSubstr)
			continue
		}
		visible := result.At(stmt)
		entry, ok := visible[assertion.varName]
		if !ok {
			t.Errorf("visibleAt(stmt=%q)[%q] missing; want origin %q", assertion.stmtSubstr, assertion.varName, assertion.originFirst)
			continue
		}
		if entry.First() != assertion.originFirst {
			t.Errorf("visibleAt(stmt=%q)[%q].First() = %q; want %q", assertion.stmtSubstr, assertion.varName, entry.First(), assertion.originFirst)
		}
	}
}

// findStmtBySubstr は file 内で「script[stmt.Pos():stmt.End()] が substr を含む」最初の Stmt を返す。
// 見つからなければ nil。
func findStmtBySubstr(t *testing.T, file *syntax.File, script, substr string) *syntax.Stmt {
	t.Helper()
	var found *syntax.Stmt
	syntax.Walk(file, func(node syntax.Node) bool {
		if found != nil {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		start := int(stmt.Pos().Offset())
		end := int(stmt.End().Offset())
		if start < 0 || end > len(script) || start >= end {
			return true
		}
		if strings.Contains(script[start:end], substr) {
			found = stmt
			return false
		}
		return true
	})
	return found
}
```

修正: `stmtVisibleHas []stmtVisibleAssertion` のフィールドを参照する `assertFunctionArgsResult` の引数型は test 内 `want` struct と整合させるため、テスト内で構造体を共有する形に整理すること。簡易的には `assertFunctionArgsResult` を消して各 t.Run 内で直接 assertion を書く形でも可。

代替案 (簡素): 上記の `assertFunctionArgsResult` ヘルパは外し、t.Run 内に inline で書く。今回は ヘルパありで進めるが、実装中に煩雑なら inline 化してよい。

- [ ] **Step 2: テストを実行して失敗することを確認**

```bash
go test -v ./pkg/shell -run TestPropagateTaint_FunctionArgs/single_call_simple
```

Expected: FAIL — body 内 echo stmt の visibleAt に `tainted["1"]` が無いはず (現状は FuncDecl 出現時に空 frame で body walk するので `$1` は untracked)。

- [ ] **Step 3: FuncDecl ケースを「テーブル登録のみ」に変更**

`pkg/shell/taint.go::makeWalkFn` の `*syntax.FuncDecl` ケースを以下に置換:

```go
		case *syntax.FuncDecl:
			if n.Body == nil || n.Name == nil {
				return false
			}
			// body は walk しない。テーブル登録のみ (#448 lazy walk)。
			// 後勝ち = bash 仕様 (関数の再定義は最後の定義が有効)。
			funcTable[n.Name.Value] = n
			return false
```

- [ ] **Step 4: CallExpr ケースを追加**

`pkg/shell/taint.go::makeWalkFn` の switch ブロックに以下のケースを追加 (`*syntax.Assign` の前あたり):

```go
		case *syntax.CallExpr:
			name := callCommandName(n)
			if name == "" {
				return true // 動的 dispatch / 引数なし → 子ノード walk のみ
			}
			decl, ok := funcTable[name]
			if !ok {
				return true // funcTable 未登録 (forward ref or 外部コマンド) → 通常 walk
			}
			if visited[name] >= 1 {
				return true // 再帰展開 depth=1 で打ち切り (#448)
			}
			binding := buildArgBinding(n, (*current).visible())
			child := &scopeFrame{kind: scopeFunc, parent: *current, local: binding}
			prev := *current
			*current = child
			visited[name]++
			syntax.Walk(decl.Body, makeWalkFn(current, result, funcTable, visited))
			visited[name]--
			*current = prev
			return true
```

- [ ] **Step 5: テストを実行して passing を確認**

```bash
go test -v ./pkg/shell -run TestPropagateTaint_FunctionArgs/single_call_simple
```

Expected: PASS

- [ ] **Step 6: 既存テスト (regression) も pass することを確認**

```bash
go test ./pkg/shell/...
```

Expected: PASS (TestPropagateTaint_Scoped 含む既存全件)

- [ ] **Step 7: Commit**

```bash
git add pkg/shell/taint.go pkg/shell/taint_test.go
git commit -m "feat(taint): #448 単一 call-site の lazy walk を実装

FuncDecl 出現時は funcTable 登録のみ、CallExpr 出現時に call-site の args
binding を inject して body を walk する lazy walk semantics を導入。
TestPropagateTaint_FunctionArgs/single_call_simple で動作確認。
"
```

---

## Task 7: 複数 call-site の visibleAt union (TDD)

**Files:**
- Modify: `pkg/shell/taint_test.go` (ケース追加)
- Modify: `pkg/shell/taint.go` (Stmt ケースで `recordVisibleAt` を使う)

**Goal:** `foo "$T"; foo "safe"` のように複数 call-site から同じ body stmt が walk された時、visibleAt[stmt] が両方の binding を保守的 union することを確認。仕様書 §7.1 ケース #2。

- [ ] **Step 1: ケースを追加**

`pkg/shell/taint_test.go::TestPropagateTaint_FunctionArgs` の cases スライスに追加:

```go
		{
			name:    "multi_call_union",
			script:  `foo() { echo "$1"; }; foo "$T"; foo "safe"`,
			initial: map[string]Entry{"T": {Sources: []string{"github.event.issue.body"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "github.event.issue.body"},
				stmtVisibleHas: []stmtVisibleAssertion{
					// 第二の call (foo "safe") では本来 untainted だが、保守的 union で
					// 第一の call (foo "$T") の binding が visible に残る。
					{stmtSubstr: `echo "$1"`, varName: "1", originFirst: "shellvar:T"},
				},
			},
		},
```

- [ ] **Step 2: テストを実行して失敗することを確認**

```bash
go test -v ./pkg/shell -run TestPropagateTaint_FunctionArgs/multi_call_union
```

Expected: FAIL — 現状は最後の call (`foo "safe"`) の walk で visibleAt が上書きされ、`tainted["1"]` が無くなっている (binding が空のため)。

- [ ] **Step 3: `*syntax.Stmt` ケースを `recordVisibleAt` 経由に変更**

`pkg/shell/taint.go::makeWalkFn` の `*syntax.Stmt` ケースを以下に変更:

```go
		case *syntax.Stmt:
			// 各 Stmt 入口で visibleAt を記録 (複数 call-site から walk された場合は
			// 保守的 union — recordVisibleAt が既存と merge する)。
			recordVisibleAt(result, n, (*current).visible())
			return true
```

- [ ] **Step 4: テストを実行して passing を確認**

```bash
go test -v ./pkg/shell -run TestPropagateTaint_FunctionArgs/multi_call_union
```

Expected: PASS

- [ ] **Step 5: 既存テスト全体を確認**

```bash
go test ./pkg/shell/...
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/shell/taint.go pkg/shell/taint_test.go
git commit -m "feat(taint): #448 複数 call-site の visibleAt 保守的 union

*syntax.Stmt ケースで recordVisibleAt を使うことで、同じ body stmt が
複数の call-site から walk された場合に visibleAt[stmt] が両 binding を
mergeSources で union するようになる (FP 寄り、issue 案明記)。
"
```

---

## Task 8: `$@` / `$*` および mixed-args ケースの検証 (TDD)

**Files:**
- Modify: `pkg/shell/taint_test.go` (3 ケース追加)

**Goal:** 仕様書 §7.1 ケース #3, #4, #5 を緑にする。実装は Task 4 で既に完了しているはず (`buildArgBinding` が `$@` / `$*` を組み立てる) なので、テスト追加のみで pass するか確認。

- [ ] **Step 1: ケースを追加**

`pkg/shell/taint_test.go::TestPropagateTaint_FunctionArgs` の cases スライスに追加:

```go
		{
			name:    "mixed_args_partial_taint",
			script:  `foo() { cmd "$1" "$2"; }; foo "$T" "safe"`,
			initial: map[string]Entry{"T": {Sources: []string{"github.event.issue.body"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "github.event.issue.body"},
				stmtVisibleHas: []stmtVisibleAssertion{
					{stmtSubstr: `cmd "$1" "$2"`, varName: "1", originFirst: "shellvar:T"},
					{stmtSubstr: `cmd "$1" "$2"`, varName: "@", originFirst: "github.event.issue.body"},
				},
			},
		},
		{
			name:    "at_arg_either_tainted",
			script:  `foo() { cmd "$@"; }; foo "$T1" "$T2"`,
			initial: map[string]Entry{
				"T1": {Sources: []string{"github.event.issue.title"}, Offset: -1},
				"T2": {Sources: []string{"github.event.issue.body"}, Offset: -1},
			},
			want: want{
				finalHas: map[string]string{
					"T1": "github.event.issue.title",
					"T2": "github.event.issue.body",
				},
				stmtVisibleHas: []stmtVisibleAssertion{
					// "@" の Sources は両 args の Sources を union (順序保持)
					{stmtSubstr: `cmd "$@"`, varName: "@", originFirst: "github.event.issue.title"},
				},
			},
		},
		{
			name:    "star_alias_of_at",
			script:  `foo() { cmd "$*"; }; foo "$T"`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "secrets.GH"},
				stmtVisibleHas: []stmtVisibleAssertion{
					{stmtSubstr: `cmd "$*"`, varName: "*", originFirst: "secrets.GH"},
				},
			},
		},
```

- [ ] **Step 2: テストを実行**

```bash
go test -v ./pkg/shell -run "TestPropagateTaint_FunctionArgs/(mixed_args_partial_taint|at_arg_either_tainted|star_alias_of_at)"
```

Expected: PASS (`buildArgBinding` で既に組まれているはず)。

- [ ] **Step 3: Commit**

```bash
git add pkg/shell/taint_test.go
git commit -m "test(taint): #448 \$@ / \$* および mixed-args の binding を検証

仕様書 §7.1 ケース #3 (mixed_args_partial_taint), #4 (at_arg_either_tainted),
#5 (star_alias_of_at) のテーブルケースを追加。buildArgBinding で組まれた
binding が正しく visibleAt に反映されることを確認。
"
```

---

## Task 9: forward reference / 直接再帰 / 相互再帰 の検証 (TDD)

**Files:**
- Modify: `pkg/shell/taint_test.go`

**Goal:** 仕様書 §7.1 ケース #6, #7, #8 と `RecursionGuardDecrement` を緑にする。実装は Task 6 で既に完了 (`visited[name]` increment/decrement) しているはず。

- [ ] **Step 1: ケースを追加**

`pkg/shell/taint_test.go::TestPropagateTaint_FunctionArgs` の cases スライスに追加:

```go
		{
			// forward ref: 1番目の foo 呼び出しは funcTable 未登録のためスキップ。
			// 2番目の foo() 定義は登録のみ。Final に外乱なし。
			name:    "forward_reference_unresolved",
			script:  `foo "$T"; foo() { echo "$1"; }`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "secrets.GH"},
			},
		},
		{
			// 直接再帰: 外側 foo "$T" で body walk、内側 foo "$1" は visited[foo]=1 で skip。
			// echo "$1" stmt の visibleAt には binding["1"] = shellvar:T が残る。
			name:    "direct_recursion_depth1",
			script:  `foo() { foo "$1"; echo "$1"; }; foo "$T"`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "secrets.GH"},
				stmtVisibleHas: []stmtVisibleAssertion{
					{stmtSubstr: `echo "$1"`, varName: "1", originFirst: "shellvar:T"},
				},
			},
		},
		{
			// 相互再帰: foo→bar→foo (2回目は skip)。各関数 1 回 walk。
			// (assertion は外乱なしのみ確認、深い stmt 検証は省略)
			name:    "mutual_recursion",
			script:  `foo() { bar; }; bar() { foo; }; foo "$T"`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "secrets.GH"},
			},
		},
```

- [ ] **Step 2: テストを実行**

```bash
go test -v ./pkg/shell -run "TestPropagateTaint_FunctionArgs/(forward_reference_unresolved|direct_recursion_depth1|mutual_recursion)"
```

Expected: PASS

- [ ] **Step 3: `RecursionGuardDecrement` テストを追加**

`pkg/shell/taint_test.go::TestPropagateTaint_FunctionArgs` の後に独立テスト関数として追加:

```go
// TestPropagateTaint_FunctionArgs_RecursionGuardDecrement は visited[name] が body walk
// 完了で正しく decrement され、連続する兄弟 call-site それぞれで body が walk されることを確認する。
// (もし visited が decrement されないと 2 回目の foo "$U" が skip される)
func TestPropagateTaint_FunctionArgs_RecursionGuardDecrement(t *testing.T) {
	t.Parallel()
	script := `foo() { echo "$1"; }; foo "$T"; foo "$U"`
	initial := map[string]Entry{
		"T": {Sources: []string{"github.event.issue.title"}, Offset: -1},
		"U": {Sources: []string{"github.event.issue.body"}, Offset: -1},
	}
	file := parseScript(t, script)
	result := PropagateTaint(file, initial)

	stmt := findStmtBySubstr(t, file, script, `echo "$1"`)
	if stmt == nil {
		t.Fatal("echo stmt not found")
	}
	visible := result.At(stmt)
	entry, ok := visible["1"]
	if !ok {
		t.Fatalf("visibleAt[echo][1] missing")
	}
	// Sources は T と U の両 origin を union (順序保持)
	wantSources := []string{"shellvar:T", "shellvar:U"}
	if !slices.Equal(entry.Sources, wantSources) {
		t.Errorf("visibleAt[echo][1].Sources = %v; want %v", entry.Sources, wantSources)
	}
}
```

`pkg/shell/taint_test.go` の import に `"slices"` を追加 (まだ無ければ)。

- [ ] **Step 4: テストを実行**

```bash
go test -v ./pkg/shell -run TestPropagateTaint_FunctionArgs_RecursionGuardDecrement
```

Expected: PASS

- [ ] **Step 5: 既存全件確認**

```bash
go test ./pkg/shell/...
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/shell/taint_test.go
git commit -m "test(taint): #448 forward ref / 再帰 / 相互再帰 のセマンティクスを検証

仕様書 §7.1 ケース #6, #7, #8 および RecursionGuardDecrement を追加。
visited[name] increment/decrement が連続兄弟 call-site で正しく動作することを
明示的に検証する discriminating ケースを含む。
"
```

---

## Task 10: 残りの edge ケース (TDD)

**Files:**
- Modify: `pkg/shell/taint_test.go`

**Goal:** 仕様書 §7.1 ケース #9〜#17 (unused / empty args / local 経由 / nested calls / composite word / non-function call / redefined / regression sanity / dynamic dispatch) を緑にする。

- [ ] **Step 1: ケースを追加**

`pkg/shell/taint_test.go::TestPropagateTaint_FunctionArgs` の cases スライスに追加:

```go
		{
			name:    "unused_function_definition",
			script:  `foo() { echo "$T"; }`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "secrets.GH"},
			},
		},
		{
			name:    "empty_args_call",
			script:  `foo() { echo "$1"; }; foo`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "secrets.GH"},
				// $1 は binding 未登録 (引数なし call) → visibleAt の "1" は無いはず
				// (assertion 省略: 「無いことの assertion」は他テストでカバー済み)
			},
		},
		{
			name:    "local_assigns_from_arg",
			script:  `foo() { local X="$1"; echo "$X"; }; foo "$T"`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "secrets.GH"},
				stmtVisibleHas: []stmtVisibleAssertion{
					{stmtSubstr: `echo "$X"`, varName: "X", originFirst: "shellvar:1"},
					// 親 chain で "1" も見えるはず
					{stmtSubstr: `echo "$X"`, varName: "1", originFirst: "shellvar:T"},
				},
			},
		},
		{
			name:    "nested_function_calls",
			script:  `outer() { inner "$1"; }; inner() { echo "$1"; }; outer "$T"`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "secrets.GH"},
				stmtVisibleHas: []stmtVisibleAssertion{
					// inner の echo body 内で "1" は outer's $1 を参照する chain
					// → binding["1"] = shellvar:1 (outer's $1 を chain) → 親 chain で T へ
					{stmtSubstr: `echo "$1"`, varName: "1", originFirst: "shellvar:1"},
				},
			},
		},
		{
			name:    "composite_word_arg",
			script:  `foo() { echo "$1"; }; foo "prefix-$T-suffix"`,
			initial: map[string]Entry{"T": {Sources: []string{"github.event.issue.body"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "github.event.issue.body"},
				stmtVisibleHas: []stmtVisibleAssertion{
					{stmtSubstr: `echo "$1"`, varName: "1", originFirst: "shellvar:T"},
				},
			},
		},
		{
			name:    "non_function_callexpr_unaffected",
			script:  `echo "$T"`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "secrets.GH"},
			},
		},
		{
			name:    "redefined_function_winner_takes",
			script:  `foo() { echo "first"; }; foo() { echo "$1"; }; foo "$T"`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{"T": "secrets.GH"},
				stmtVisibleHas: []stmtVisibleAssertion{
					// 後勝ち: 2 番目の body の echo "$1" stmt の visibleAt に "1" がある
					{stmtSubstr: `echo "$1"`, varName: "1", originFirst: "shellvar:T"},
				},
			},
		},
		{
			name:    "dynamic_dispatch_unresolved",
			script:  `cmd="$T"; $cmd "arg"`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{
					"T":   "secrets.GH",
					"cmd": "shellvar:T",
				},
				// $cmd は wordLitPrefix が空 → funcTable 未登録扱い → 静的解決スキップ
				// (assertion 省略: 「foo body walk が走らない」は外乱なしで担保)
			},
		},
```

- [ ] **Step 2: テストを実行**

```bash
go test -v ./pkg/shell -run TestPropagateTaint_FunctionArgs
```

Expected: PASS (全ケース)

- [ ] **Step 3: NilFile テストを追加**

`pkg/shell/taint_test.go` の末尾に追加:

```go
// TestPropagateTaint_FunctionArgs_NilFile は file=nil 入力に対する defensive 動作を検証する。
func TestPropagateTaint_FunctionArgs_NilFile(t *testing.T) {
	t.Parallel()
	initial := map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}}
	result := PropagateTaint(nil, initial)
	if result == nil {
		t.Fatal("PropagateTaint(nil, ...) returned nil; want non-nil ScopedTaint")
	}
	entry, ok := result.Final["T"]
	if !ok {
		t.Errorf("Final[T] missing")
	} else if entry.First() != "secrets.GH" {
		t.Errorf("Final[T].First() = %q; want %q", entry.First(), "secrets.GH")
	}
}
```

- [ ] **Step 4: テスト実行**

```bash
go test -v ./pkg/shell -run TestPropagateTaint_FunctionArgs_NilFile
go test ./pkg/shell/... ./pkg/core/...
```

Expected: PASS (全件)

- [ ] **Step 5: Commit**

```bash
git add pkg/shell/taint_test.go
git commit -m "test(taint): #448 残りの edge ケース (#9〜#17 + NilFile) を緑化

unused_function_definition, empty_args_call, local_assigns_from_arg,
nested_function_calls, composite_word_arg, non_function_callexpr_unaffected,
redefined_function_winner_takes, dynamic_dispatch_unresolved を追加。
NilFile defensive ケースも追加。既存 #447 ケースに regression なし。
"
```

---

## Task 11: TaintTracker integration: function 内 GITHUB_OUTPUT 書き込み (TDD)

**Files:**
- Modify: `pkg/core/taint_test.go`

**Goal:** 関数内の `>> $GITHUB_OUTPUT` 書き込みが call-site 引数 taint を反映して `taintedOutputs` に記録されることを確認。仕様書 §7.2 の 1 ケース目。`pkg/core/taint.go` 自体は変更しない (透過対応)。

- [ ] **Step 1: 既存テスト構造を確認**

```bash
grep -n "func TestTaintTracker" pkg/core/taint_test.go | head -10
```

参考: 既存テストのスタイルを踏襲して書く。

- [ ] **Step 2: テストを追加**

`pkg/core/taint_test.go` の末尾に追加:

```go
// TestTaintTracker_RedirWriteInFunctionBody は #448 関数引数経由 taint が
// $GITHUB_OUTPUT 書き込み経路に正しく流れることを検証する。
//
// 関数本体内の `echo "x=$1" >> $GITHUB_OUTPUT` は、call-site の untrusted
// 引数 taint を通じて taintedOutputs に記録されるべき。
func TestTaintTracker_RedirWriteInFunctionBody(t *testing.T) {
	t.Parallel()
	tracker := NewTaintTracker()

	step := makeRunStepWithID(t, "step1", `
foo() { echo "x=$1" >> $GITHUB_OUTPUT; }
foo "${{ github.event.issue.title }}"
`)
	tracker.AnalyzeStep(step)

	outputs := tracker.GetTaintedOutputs()
	step1Out, ok := outputs["step1"]
	if !ok {
		t.Fatalf("taintedOutputs[step1] missing; got: %v", outputs)
	}
	xSources, ok := step1Out["x"]
	if !ok {
		t.Fatalf("taintedOutputs[step1][x] missing; got: %v", step1Out)
	}
	if !slices.Contains(xSources, "github.event.issue.title") {
		t.Errorf("taintedOutputs[step1][x] = %v; want to contain %q", xSources, "github.event.issue.title")
	}
}

// makeRunStepWithID は runStr で指定した body を持つ run step を構築する test helper。
// 既存の test helper があればそちらを使う形に書き換えること。
func makeRunStepWithID(t *testing.T, stepID, runBody string) *ast.Step {
	t.Helper()
	return &ast.Step{
		ID: &ast.String{Value: stepID, Pos: &ast.Position{Line: 1, Col: 1}},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: runBody, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
}
```

`pkg/core/taint_test.go` の import に必要なもの (`slices`, `github.com/sisaku-security/sisakulint/pkg/ast`) を追加。既に existing helper があれば使う (`makeRunStepWithID` 重複 avoid)。

- [ ] **Step 3: テストを実行**

```bash
go test -v ./pkg/core -run TestTaintTracker_RedirWriteInFunctionBody
```

Expected: PASS (taint.go は変更不要、既存の per-stmt visible 経由で動くはず)

- [ ] **Step 4: 失敗した場合のデバッグ手順** — もし FAIL なら以下を確認:
  - `scoped.At(w.Stmt)` が body 内 stmt に対して `tainted["1"]` を含むか (debug print で `pkg/shell/taint.go::PropagateTaint` の result.visibleAt の中身を出す)
  - `expandShellvarMarkers` が `shellvar:1` を chain 展開しているか (`pkg/core/taint.go::expandShellvarMarkers` の loop に debug print)
  - 失敗の根本が `shell.PropagateTaint` の binding 不在なら Task 6-10 の実装漏れ。`pkg/core/taint.go` ではなく `pkg/shell/taint.go` を見直す

- [ ] **Step 5: Commit**

```bash
git add pkg/core/taint_test.go
git commit -m "test(taint): #448 関数本体内 GITHUB_OUTPUT 書き込みの taint 伝播を検証

call-site の untrusted 引数 taint が body 内 \$GITHUB_OUTPUT 書き込みを
通じて taintedOutputs に記録されることを確認。pkg/core/taint.go 自体は
変更不要 (scoped.At(stmt) 経由で透過対応)。
"
```

---

## Task 12: TaintTracker integration: chain 展開 (TDD)

**Files:**
- Modify: `pkg/core/taint_test.go`

**Goal:** 仕様書 §7.2 の 2 ケース目。shellvar 経由の chain (TITLE → "$1" → echo) が origin まで遡って展開されることを確認。

- [ ] **Step 1: テストを追加**

`pkg/core/taint_test.go::TestTaintTracker_RedirWriteInFunctionBody` の後に追加:

```go
// TestTaintTracker_FunctionArg_ChainExpansion は #448 で関数引数経由 taint が
// shellvar chain を経て origin まで遡って展開されることを検証する。
func TestTaintTracker_FunctionArg_ChainExpansion(t *testing.T) {
	t.Parallel()
	tracker := NewTaintTracker()

	step := makeRunStepWithID(t, "step1", `
TITLE="${{ github.event.issue.title }}"
foo() { echo "y=$1" >> $GITHUB_OUTPUT; }
foo "$TITLE"
`)
	tracker.AnalyzeStep(step)

	outputs := tracker.GetTaintedOutputs()
	step1Out, ok := outputs["step1"]
	if !ok {
		t.Fatalf("taintedOutputs[step1] missing; got: %v", outputs)
	}
	ySources, ok := step1Out["y"]
	if !ok {
		t.Fatalf("taintedOutputs[step1][y] missing; got: %v", step1Out)
	}
	// chain: shellvar:1 → shellvar:TITLE → github.event.issue.title
	if !slices.Contains(ySources, "github.event.issue.title") {
		t.Errorf("taintedOutputs[step1][y] = %v; want to contain %q (chain: shellvar:1 → shellvar:TITLE → ...)", ySources, "github.event.issue.title")
	}
}
```

- [ ] **Step 2: テストを実行**

```bash
go test -v ./pkg/core -run TestTaintTracker_FunctionArg_ChainExpansion
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/core/taint_test.go
git commit -m "test(taint): #448 関数引数経由 taint の shellvar chain 展開を検証

shellvar:1 → shellvar:TITLE → github.event.issue.title の chain が
expandShellvarMarkers で正しく展開され、taintedOutputs に origin まで
遡った Sources が記録される。
"
```

---

## Task 13: secret-in-log autofix を positional 解決に対応 (TDD)

**Files:**
- Modify: `pkg/core/secretinlog_test.go` (テスト追加)
- Modify: `pkg/core/secretinlog.go` (`resolveMaskTarget` ヘルパ + `FixStep` の autofix 経路修正)

**Goal:** 仕様書 §6.2.2 と §7.3 の `TestSecretInLog_PositionalArgFromShellVar_DetectsLeak` / `_AutofixMasksUpstream` を緑にする。

- [ ] **Step 1: 失敗するテスト (検出系) を追加**

`pkg/core/secretinlog_test.go` の末尾に追加:

```go
// TestSecretInLog_PositionalArgFromShellVar_DetectsLeak は #448 で関数引数経由
// の secret 漏洩 (echo "$1") が検出されることを確認する。
func TestSecretInLog_PositionalArgFromShellVar_DetectsLeak(t *testing.T) {
	t.Parallel()
	rule := NewSecretInLogRule()

	workflow := parseWorkflowYAML(t, `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          KEY: ${{ secrets.GH_TOKEN }}
        run: |
          TOKEN=$(echo "$KEY" | jq -r '.token')
          leak() { echo "$1"; }
          leak "$TOKEN"
`)
	visitWorkflowWith(t, rule, workflow)

	errs := rule.Errors()
	if len(errs) != 1 {
		t.Fatalf("got %d errors; want 1; errors: %v", len(errs), errs)
	}
	msg := errs[0].Message
	if !strings.Contains(msg, "$1") {
		t.Errorf("error message %q should mention positional arg $1", msg)
	}
	if !strings.Contains(msg, "shellvar:TOKEN") {
		t.Errorf("error message %q should mention origin shellvar:TOKEN", msg)
	}
}
```

`parseWorkflowYAML` および `visitWorkflowWith` は既存 helper を使う。なければ既存 secret-in-log テスト (`secretinlog_test.go` 内) のスタイルを踏襲して inline で書く。

- [ ] **Step 2: テストを実行して失敗を確認**

```bash
go test -v ./pkg/core -run TestSecretInLog_PositionalArgFromShellVar_DetectsLeak
```

Expected: 検出系自体は Task 6 で `pkg/shell/taint.go` の lazy walk が動いていれば PASS する可能性が高い。FAIL なら検出ロジックがまだ整っていない。

- [ ] **Step 3: 失敗するテスト (autofix 系) を追加**

`pkg/core/secretinlog_test.go` の `TestSecretInLog_PositionalArgFromShellVar_DetectsLeak` の後に追加:

```go
// TestSecretInLog_PositionalArgFromShellVar_AutofixMasksUpstream は
// positional 引数 ($1) のリークに対して autofix が **upstream 変数 (TOKEN) を
// マスクする** ことを検証する (positional の "$1" を直接マスクしない)。
func TestSecretInLog_PositionalArgFromShellVar_AutofixMasksUpstream(t *testing.T) {
	t.Parallel()
	rule := NewSecretInLogRule()

	workflow := parseWorkflowYAML(t, `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          KEY: ${{ secrets.GH_TOKEN }}
        run: |
          TOKEN=$(echo "$KEY" | jq -r '.token')
          leak() { echo "$1"; }
          leak "$TOKEN"
`)
	visitWorkflowWith(t, rule, workflow)
	applyAllAutoFixers(t, rule)

	step := workflow.Jobs["build"].Steps[0]
	exec, ok := step.Exec.(*ast.ExecRun)
	if !ok || exec.Run == nil {
		t.Fatal("step.Exec is not ExecRun")
	}
	got := exec.Run.Value
	wantInsert := `echo "::add-mask::$TOKEN"`
	if !strings.Contains(got, wantInsert) {
		t.Errorf("script after autofix does not contain %q; got:\n%s", wantInsert, got)
	}
	// TOKEN= 行の直後に挿入されているか確認 (insertAfterAssignment による)
	tokenLineIdx := strings.Index(got, "TOKEN=$(")
	maskLineIdx := strings.Index(got, wantInsert)
	if tokenLineIdx < 0 || maskLineIdx < 0 || maskLineIdx <= tokenLineIdx {
		t.Errorf("expected mask to be inserted after TOKEN= line; got:\n%s", got)
	}
	// positional "$1" を直接マスクする誤った insert がないこと
	if strings.Contains(got, `echo "::add-mask::$1"`) {
		t.Errorf("script should NOT contain '::add-mask::$1' (positional); got:\n%s", got)
	}
}
```

`applyAllAutoFixers` は既存 helper を使う (なければ rule.AutoFixers() を取り出して順次適用)。

- [ ] **Step 4: テストを実行して失敗を確認**

```bash
go test -v ./pkg/core -run TestSecretInLog_PositionalArgFromShellVar_AutofixMasksUpstream
```

Expected: FAIL — 現状 autofix は `f.varName="1"` を使うため `::add-mask::$1` を挿入し、`insertAfterAssignment(script, "1", ...)` も空振り。

- [ ] **Step 5: `resolveMaskTarget` および `isPositional` ヘルパを追加**

`pkg/core/secretinlog.go` の末尾に追加:

```go
// resolveMaskTarget は autofix のマスク対象変数名を決定する。
//
// セマンティクス (#448):
//   - varName が positional ($1, $2, ...): origin が "shellvar:UPSTREAM" の場合は
//     UPSTREAM を返す (immediate upstream var をマスク対象にする)。
//     origin が shellvar:* でない (env var 由来 secrets.X 等) なら ("", false) を返す
//     → autofix no-op
//   - varName が "@" / "*": 確実な single-var ターゲットが取れないので ("", false) → autofix no-op
//   - 通常 var: そのまま返す (現状互換)
func resolveMaskTarget(varName, origin string) (string, bool) {
	if varName == "@" || varName == "*" {
		return "", false
	}
	if !isPositional(varName) {
		return varName, true
	}
	if upstream, ok := strings.CutPrefix(origin, "shellvar:"); ok && upstream != "" {
		return upstream, true
	}
	return "", false
}

// isPositional は s が positional parameter ($1, $2, ...) を表す数値文字列か判定する。
func isPositional(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
```

- [ ] **Step 6: `secretInLogFixer.FixStep` を `resolveMaskTarget` 経由に変更**

`pkg/core/secretinlog.go::FixStep` (現状 L457-512) を以下に置換:

```go
func (f *secretInLogFixer) FixStep(node *ast.Step) error {
	if node == nil || node.Exec == nil {
		return nil
	}
	execRun, ok := node.Exec.(*ast.ExecRun)
	if !ok || execRun.Run == nil {
		return nil
	}
	script := execRun.Run.Value

	maskTarget, ok := resolveMaskTarget(f.varName, f.origin)
	if !ok {
		// $@ / $* のリーク、または origin が shellvar:* でない positional →
		// 確実な single-var ターゲットが取れないため autofix は no-op。
		// lint diag 自体は既に出ているので、手動修正に委ねる。
		return nil
	}

	// sink 位置より前に有効な add-mask が既に存在していれば、追加挿入は不要。
	if hasAddMaskBefore(script, maskTarget, f.leakOffset) {
		return nil
	}

	addMask := `echo "::add-mask::$` + maskTarget + `"`

	// origin が "shellvar:*" の場合、変数のアサイン直後に add-mask を挿入する。
	// env var 由来（"secrets.*"）の場合はスクリプト冒頭に挿入する。
	if strings.HasPrefix(f.origin, "shellvar:") {
		updated, ok := insertAfterAssignment(script, maskTarget, addMask)
		if ok {
			execRun.Run.Value = updated
			if execRun.Run.BaseNode != nil {
				execRun.Run.BaseNode.Value = updated
			}
			return nil
		}
		// アサインが見つからない／同一行に sink がある等、安全に挿入できない場合は
		// 冒頭挿入にフォールスルーしない（既存仕様維持）。手動修正に委ねる。
		return nil
	}

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

注意: 既存 FixStep の comment block (`// origin が "shellvar:*" の場合、変数のアサイン直後...` 等) は引き続き有効。

- [ ] **Step 7: テスト再実行**

```bash
go test -v ./pkg/core -run "TestSecretInLog_PositionalArgFromShellVar_(DetectsLeak|AutofixMasksUpstream)"
```

Expected: PASS

- [ ] **Step 8: 既存 secret-in-log テストの回帰確認**

```bash
go test ./pkg/core -run TestSecretInLog
```

Expected: PASS (全件)

- [ ] **Step 9: Commit**

```bash
git add pkg/core/secretinlog.go pkg/core/secretinlog_test.go
git commit -m "feat(taint): #448 SecretInLog autofix を positional 名解決に対応

resolveMaskTarget ヘルパを追加し、leak.VarName が positional (\$1) の場合に
origin (shellvar:UPSTREAM) から UPSTREAM 名を抽出してマスク対象にする。
\$@ / \$* は best-effort 不能のため no-op。
"
```

---

## Task 14: secret-in-log の `$@` no-autofix と chain ケース (TDD)

**Files:**
- Modify: `pkg/core/secretinlog_test.go`

**Goal:** 仕様書 §7.3 の `TestSecretInLog_AtArg_DetectsLeakNoAutofix` と `TestSecretInLog_FunctionLocalChainsThroughArg` を緑にする。

- [ ] **Step 1: テストを追加**

`pkg/core/secretinlog_test.go` の `TestSecretInLog_PositionalArgFromShellVar_AutofixMasksUpstream` の後に追加:

```go
// TestSecretInLog_AtArg_DetectsLeakNoAutofix は echo "$@" の漏洩が検出され、
// かつ autofix は no-op (script 不変) であることを確認する。
func TestSecretInLog_AtArg_DetectsLeakNoAutofix(t *testing.T) {
	t.Parallel()
	rule := NewSecretInLogRule()

	workflow := parseWorkflowYAML(t, `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          T1: ${{ secrets.GH_TOKEN }}
          T2: ${{ secrets.AWS_KEY }}
        run: |
          leak() { echo "$@"; }
          leak "$T1" "$T2"
`)
	visitWorkflowWith(t, rule, workflow)

	errs := rule.Errors()
	if len(errs) == 0 {
		t.Fatal("expected at least 1 leak error for echo \"$@\"; got 0")
	}

	step := workflow.Jobs["build"].Steps[0]
	exec, _ := step.Exec.(*ast.ExecRun)
	scriptBefore := exec.Run.Value
	applyAllAutoFixers(t, rule)
	scriptAfter := exec.Run.Value
	if scriptBefore != scriptAfter {
		t.Errorf("autofix should be no-op for $@ leak; before:\n%s\nafter:\n%s", scriptBefore, scriptAfter)
	}
}

// TestSecretInLog_FunctionLocalChainsThroughArg は関数本体内で local X="$1" 経由の
// 派生変数の echo が leak 検出され、origin chain が upstream まで遡ることを確認する。
func TestSecretInLog_FunctionLocalChainsThroughArg(t *testing.T) {
	t.Parallel()
	rule := NewSecretInLogRule()

	workflow := parseWorkflowYAML(t, `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          KEY: ${{ secrets.GH_TOKEN }}
        run: |
          TOKEN=$(echo "$KEY" | jq -r '.token')
          leak() { local X="$1"; echo "$X"; }
          leak "$TOKEN"
`)
	visitWorkflowWith(t, rule, workflow)

	errs := rule.Errors()
	if len(errs) == 0 {
		t.Fatal("expected leak detection for echo \"$X\" inside function body; got 0")
	}
	msg := errs[0].Message
	if !strings.Contains(msg, "$X") {
		t.Errorf("error message %q should mention $X", msg)
	}
}
```

- [ ] **Step 2: テスト実行**

```bash
go test -v ./pkg/core -run "TestSecretInLog_(AtArg_DetectsLeakNoAutofix|FunctionLocalChainsThroughArg)"
```

Expected: PASS

- [ ] **Step 3: 既存全件確認**

```bash
go test ./...
```

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/core/secretinlog_test.go
git commit -m "test(taint): #448 \$@ no-autofix と function-local chain を検証

echo \"\$@\" の漏洩が検出されつつ autofix は no-op であること、および
local X=\"\$1\"; echo \"\$X\" の chain が upstream (TOKEN) まで遡って
検出されることを確認。
"
```

---

## Task 15: workflow fixture 追加

**Files:**
- Create: `script/actions/taint-args-vulnerable.yaml`
- Create: `script/actions/taint-args-safe.yaml`
- Modify: `script/README.md`

**Goal:** 仕様書 §7.4。`sisakulint` バイナリ経由で実際にリーク検出と autofix が動くことを fixture で確認できるようにする。

- [ ] **Step 1: vulnerable fixture を作成**

`script/actions/taint-args-vulnerable.yaml` を作成:

```yaml
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    timeout-minutes: 5
    steps:
      - env:
          GH_TOKEN: ${{ secrets.GH_TOKEN }}
        run: |
          TOKEN=$(echo "$GH_TOKEN" | jq -r '.token')
          leak() {
            echo "received: $1"
          }
          leak "$TOKEN"
```

- [ ] **Step 2: safe fixture を作成**

`script/actions/taint-args-safe.yaml` を作成:

```yaml
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    timeout-minutes: 5
    steps:
      - env:
          GH_TOKEN: ${{ secrets.GH_TOKEN }}
        run: |
          TOKEN=$(echo "$GH_TOKEN" | jq -r '.token')
          echo "::add-mask::$TOKEN"
          leak() {
            echo "received: $1"
          }
          leak "$TOKEN"
```

- [ ] **Step 3: ビルドして fixture で検証**

```bash
go build -o /tmp/sisakulint ./cmd/sisakulint
/tmp/sisakulint script/actions/taint-args-vulnerable.yaml
```

Expected: `secret-in-log` の警告が 1 件出ること (echo "received: $1" に対して)。

```bash
/tmp/sisakulint script/actions/taint-args-safe.yaml
```

Expected: 警告 0 件 (mask が先に出ているため)。

```bash
/tmp/sisakulint -fix dry-run script/actions/taint-args-vulnerable.yaml
```

Expected: dry-run 出力で TOKEN= 直後に `echo "::add-mask::$TOKEN"` の挿入が表示されること。

- [ ] **Step 4: `script/README.md` に説明を追加**

`script/README.md` の Example Files テーブル (現状 23-46 行目あたり) に以下の行を追加:

```markdown
| `taint-args-vulnerable.yaml` | 関数引数経由の secret 漏洩 (`leak() { echo "$1"; }; leak "$TOKEN"`) — `secret-in-log` が検出 |
| `taint-args-safe.yaml` | autofix 後の安全パターン (TOKEN= の直後に `::add-mask::$TOKEN` を挿入) |
```

- [ ] **Step 5: Commit**

```bash
git add script/actions/taint-args-vulnerable.yaml script/actions/taint-args-safe.yaml script/README.md
git commit -m "test(taint): #448 関数引数 taint の workflow fixture 2 ファイル

taint-args-vulnerable.yaml: leak() { echo \"\$1\"; }; leak \"\$TOKEN\" で
secret-in-log が検出されることを示す。
taint-args-safe.yaml: TOKEN= 直後に ::add-mask::\$TOKEN が挿入された安全形。
script/README.md に説明を追加。
"
```

---

## Task 16: docstring と CLAUDE.md の更新 + 最終回帰

**Files:**
- Modify: `pkg/shell/taint.go` (`PropagateTaint` の docstring)
- Modify: `CLAUDE.md`

**Goal:** 仕様書 §9 受け入れ基準のうち、docstring 更新と CLAUDE.md 追記を完了させる。`(#448 で改善予定)` の TODO を削除し、関数引数 lazy walk のセマンティクスを追記。

- [ ] **Step 1: `pkg/shell/taint.go::PropagateTaint` の docstring を更新**

現状 (taint.go:243-256 周辺) の docstring を以下に置換:

```go
// PropagateTaint は initial を seed として AST を順方向 1 パス walk し、
// scope-aware に taint を伝播する。
//
// セマンティクス:
//   - 既に tainted な変数への再代入は origin/Offset を上書きしない（最初の taint を保持）
//   - LHS 名は AST 順序で処理される（forward dataflow）
//   - 代入の RHS が tainted を参照しない場合は LHS に何もしない（"untaint" はしない）
//   - スコープ:
//     - *syntax.Subshell `( ... )` と *syntax.CmdSubst `$(...)` は entry 時に
//       親 visible を snapshot copy して隔離。内部代入は親に漏れない
//     - *syntax.FuncDecl 本体は parent への lookup chain で bash dynamic scoping を
//       近似。`local` / 装飾なし `declare` は本体ローカル、その他の代入は #447 の
//       簡略案 A により親に漏らさない
//   - 関数引数経由 taint 伝播 (#448):
//     - FuncDecl 出現時には body を walk せず関数テーブル (funcTable) に登録のみ
//     - CallExpr 検出時に call-site の args の taint state を tainted["1"]/[ "2"]/.../["@"]/["*"]
//       として inject した上で body を walk (lazy walk)
//     - 複数 call-site から同じ body stmt が walk された場合、visibleAt[stmt] は
//       Sources を保守的 union (FP 寄り)
//     - 再帰呼び出しは visited[name] で depth=1 制限 (固定点反復はしない)
//     - forward reference (定義前 call) は 1-pass walk で自然に未登録扱い → bash 一致
//
// 戻り値は initial を変更せず新しい *ScopedTaint を返す。
```

ポイント: `(#448 で改善予定)` のフレーズを削除し、関数引数 semantics を新規箇条書きで追記。

- [ ] **Step 2: `CLAUDE.md` の TaintTracker 説明を更新**

`CLAUDE.md` の "Scope-aware propagation (#447)" セクション (現状 100 行目周辺、「**Known limitation**: ...」の前) に以下の段落を追加:

```markdown
- **Function argument taint propagation (#448)**: `pkg/shell/taint.go::PropagateTaint` は **lazy walk** で関数本体内の `$1` / `$2` / `$@` / `$*` を解決する。FuncDecl 出現時には body を walk せず関数テーブルに登録のみ、CallExpr 検出時に call-site の args の taint state (`shellvar:UPSTREAM` 形式) を `tainted["1"]/.../[ "@"]` として inject した上で body を walk する。複数 call-site は visibleAt[stmt] を保守的 union (FP 寄り)、再帰呼び出しは visited[name] で depth=1 制限、forward reference (定義前 call) は bash 一致で untracked。`$@` / `$*` は引数のいずれかが tainted なら tainted。`secretinlog.go` の autofix は positional ($1) のリークに対し `resolveMaskTarget` で origin (`shellvar:TOKEN`) から upstream 変数名 (TOKEN) を抽出してマスク対象にする。`$@` / `$*` のリークは best-effort 不能で autofix off (lint 警告は出る)。
- **Function side-effect**: 関数本体内の non-local 代入 (`X="$T"`) は #447 / #448 とも簡略案 A により親フレームには漏らさない。完全対応は別 issue。
```

- [ ] **Step 3: 既存テスト回帰**

```bash
go test ./...
```

Expected: PASS (全件)

- [ ] **Step 4: vet / lint 確認**

```bash
go vet ./...
```

Expected: clean

- [ ] **Step 5: 受け入れ基準を逐次確認**

仕様書 §9 のチェックリストを 1 つずつ確認:

```bash
# pkg/shell/taint_test.go::TestPropagateTaint_FunctionArgs の新規 17+ ケース緑
go test -v ./pkg/shell -run TestPropagateTaint_FunctionArgs

# 既存 #447 ケース regression なし
go test -v ./pkg/shell -run TestPropagateTaint_Scoped

# pkg/core/taint_test.go の新規 2 ケース緑
go test -v ./pkg/core -run "TestTaintTracker_(RedirWriteInFunctionBody|FunctionArg_ChainExpansion)"

# pkg/core/secretinlog_test.go の新規 4 ケース緑
go test -v ./pkg/core -run "TestSecretInLog_(PositionalArgFromShellVar_DetectsLeak|PositionalArgFromShellVar_AutofixMasksUpstream|AtArg_DetectsLeakNoAutofix|FunctionLocalChainsThroughArg)"

# 既存全件
go test ./...

# fixture 動作確認
go build -o /tmp/sisakulint ./cmd/sisakulint
/tmp/sisakulint script/actions/taint-args-vulnerable.yaml
/tmp/sisakulint script/actions/taint-args-safe.yaml
/tmp/sisakulint -fix dry-run script/actions/taint-args-vulnerable.yaml
```

すべて期待通りに動作することを確認。

- [ ] **Step 6: docstring の `(#448 で改善予定)` が削除されたことを確認**

```bash
grep -n "#448 で改善予定" pkg/shell/taint.go
```

Expected: 出力なし (削除済み)

- [ ] **Step 7: Commit**

```bash
git add pkg/shell/taint.go CLAUDE.md
git commit -m "docs(taint): #448 docstring と CLAUDE.md に関数引数 lazy walk を反映

PropagateTaint docstring から (#448 で改善予定) の TODO を削除し、関数引数
経由 taint 伝播 (lazy walk, 複数 call-site 保守的 union, 再帰 depth=1, forward
ref bash 一致, \$@/\$* は引数いずれかで tainted) のセマンティクスを追記。
CLAUDE.md の TaintTracker 説明にも対応点を追加。
"
```

---

## Task 17: PR 作成準備 (任意 — ユーザの判断)

**Goal:** 全タスクが緑で受け入れ基準を満たしたら、PR を作成する。

- [ ] **Step 1: ブランチ状態の確認**

```bash
git log --oneline main..HEAD
git diff --stat main..HEAD
```

Expected: 16 個前後の commit、変更ファイルが File Structure テーブルに列挙したものと一致。

- [ ] **Step 2: ユーザに PR 作成可否を確認**

ユーザに「全タスク完了。`gh pr create` で PR を作成しますか?」と確認。承認が得られた場合のみ次へ。

- [ ] **Step 3: PR 作成**

```bash
gh pr create --title "feat(taint): #448 TaintTracker の関数引数 taint 伝播" --body "$(cat <<'EOF'
## Summary

- `pkg/shell/taint.go::PropagateTaint` を **lazy walk** に切り替え、関数本体内の `$1` / `$2` / `$@` / `$*` を call-site 引数 taint で解決
- `pkg/core/secretinlog.go` の autofix を positional 名 → upstream 名解決 (`resolveMaskTarget`) に対応
- 公開 API (`*ScopedTaint`, `At(stmt)`) は不変、`pkg/core/taint.go` は変更なし

## Spec / Plan

- 設計: `docs/superpowers/specs/2026-04-27-448-tainttracker-function-args-design.md`
- プラン: `docs/superpowers/plans/2026-04-27-448-tainttracker-function-args.md`

Closes #448.

## Test plan

- [ ] `go test ./pkg/shell/... ./pkg/core/...` 緑
- [ ] `go test ./...` 全体緑
- [ ] `sisakulint script/actions/taint-args-vulnerable.yaml` で 1 件、`taint-args-safe.yaml` で 0 件
- [ ] `sisakulint -fix dry-run script/actions/taint-args-vulnerable.yaml` で TOKEN= 行直後に `echo "::add-mask::$TOKEN"` 挿入

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review

### Spec coverage チェック

| 仕様書 | 対応タスク |
|---|---|
| §1 背景 | (記述のみ — タスク不要) |
| §2 ゴール / 非ゴール | Task 6-10 (lazy walk semantics)、Task 13 (autofix) |
| §3 アプローチ選択 | Task 6 (Lazy walk採用)、Task 4 (Approach 1: shellvar のみ) |
| §4.1 公開 API 不変 | Task 6 (シグネチャ不変を維持)、Task 11-12 で確認 |
| §4.2 walker state 拡張 | Task 1 (refactor)、Task 6 (利用) |
| §4.3 walker 拡張 | Task 6 (FuncDecl/CallExpr ケース) |
| §4.4 buildArgBinding | Task 4 |
| §4.5 recordVisibleAt | Task 5、Task 7 (利用) |
| §4.6 mergeSources | Task 2 |
| §4.7 callCommandName | Task 3 |
| §5.1 関数 resolution table | Task 6 (登録ロジック)、Task 10 (redefined ケース) |
| §5.2 CallExpr 解決判定 | Task 6 (基本)、Task 9 (forward ref / 再帰)、Task 10 (dynamic dispatch) |
| §5.3 再帰展開ポリシー | Task 9 (3 ケース)、`RecursionGuardDecrement` |
| §5.4 `$@` / `$*` semantics | Task 8 |
| §5.5 processAssign / WordReferencesEntry 影響 | Task 10 (`local_assigns_from_arg`) で検証 |
| §5.6 関数副作用 (簡略案 A 維持) | (#447 既存ロジック維持、テスト回帰で担保) |
| §5.7 エッジケース | Task 10 |
| §6.1 taint.go 変更不要 | Task 11-12 で確認 |
| §6.2.2 secretinlog autofix | Task 13 |
| §7.1 unit | Task 6-10 |
| §7.2 integration | Task 11-12 |
| §7.3 secret-in-log integration | Task 13-14 |
| §7.4 fixture | Task 15 |
| §8 実装順序 | Task 1-16 (順序対応) |
| §9 受け入れ基準 | Task 16 Step 5 |
| §10 リスク (known limitation) | Task 16 (CLAUDE.md 反映) |
| §11 後続作業 | (本 issue 範囲外) |

### Placeholder スキャン: なし (TBD/TODO/FIXME 含む箇所は受け入れ基準のテキスト内のみ、これは仕様書からの引用)

### Type / signature 整合性

- `mergeSources(dst, src []string) []string` — Task 2 で定義、Task 4・5 で使用、シグネチャ一致
- `recordVisibleAt(result *ScopedTaint, stmt *syntax.Stmt, visible map[string]Entry)` — Task 5 で定義、Task 7 で `*syntax.Stmt` ケースから呼び出し、シグネチャ一致
- `buildArgBinding(call *syntax.CallExpr, visible map[string]Entry) map[string]Entry` — Task 4 で定義、Task 6 の CallExpr ケースで使用、シグネチャ一致
- `callCommandName(call *syntax.CallExpr) string` — Task 3 で定義、Task 6 で使用、シグネチャ一致
- `resolveMaskTarget(varName, origin string) (string, bool)` — Task 13 Step 5 で定義、同 Step 6 で使用、シグネチャ一致
- `isPositional(s string) bool` — Task 13 Step 5 で定義、`resolveMaskTarget` 内のみで使用

整合性問題なし。
