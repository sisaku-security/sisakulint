# #447 TaintTracker シェルスコープ対応 — 実装プラン

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `pkg/shell/taint.go::PropagateTaint` を scope-aware に拡張し、subshell / `$(...)` / function 本体の bash スコープ意味論を導入する。両 caller (`pkg/core/taint.go`, `pkg/core/secretinlog.go`) を per-stmt visible lookup に切り替え、FP 抑制と FN 修正を両立させる。

**Architecture:** `PropagateTaint` の戻り値を `*ScopedTaint` (`Final` map + `visibleAt` per-Stmt snapshot) に変更。内部に `scopeFrame` のスタックを持ち、`syntax.Walk` で `*syntax.Subshell` / `*syntax.CmdSubst` / `*syntax.FuncDecl` の入退場で push/pop。Subshell/CmdSubst は親 visible を snapshot copy して隔離、FuncDecl は parent への lookup chain で bash dynamic scoping を近似。

**Tech Stack:** Go 1.22+, `mvdan.cc/sh/v3/syntax` (bash AST)、`maps` 標準ライブラリ、既存 `pkg/shell` プリミティブ (`WalkAssignments`, `WordReferencesEntry` 等)。

**Spec:** [docs/superpowers/specs/2026-04-27-447-tainttracker-shell-scope-design.md](../specs/2026-04-27-447-tainttracker-shell-scope-design.md)

---

## File Structure

| Path | Action | Responsibility |
|---|---|---|
| `pkg/shell/taint.go` | Modify | `ScopedTaint` 型追加、`PropagateTaint` をスコープ対応 walker に書き換え、`scopeFrame` 内部構造 |
| `pkg/shell/taint_test.go` | Modify | 新規 13 ケース + API 検証 (NilFile, At fallback) |
| `pkg/core/taint.go` | Modify | `recordRedirWrite` のシグネチャ更新、`AnalyzeStep` での per-stmt 展開 |
| `pkg/core/taint_test.go` | Modify | `TestTaintTracker_RedirWriteInSubshell` 追加 |
| `pkg/core/secretinlog.go` | Modify | `findEchoLeaks` と `collectGitHubEnvTaintWrites` を `*shell.ScopedTaint` 受け取りに変更 (per-stmt lookup) |
| `pkg/core/secretinlog_test.go` | Modify | `TestSecretInLog_FunctionLocalScope_DetectsLeak`, `TestSecretInLog_SubshellLocalAssignment_NotLeakedInParent` 追加 |
| `script/actions/taint-scope-fp-safe.yaml` | Create | FP 抑制を示す fixture |
| `script/actions/taint-scope-fn-vulnerable.yaml` | Create | 関数本体内 sink の正検出を示す fixture |
| `script/README.md` | Modify | 新 fixture 追記 |
| `CLAUDE.md` | Modify | TaintTracker 説明にスコープ対応の旨を追記、TODO コメント削除予定箇所メモ |

---

## Task 1: `ScopedTaint` 型と signature 変更 (scope 動作なし、互換のみ)

**Files:**
- Modify: `pkg/shell/taint.go:30-206`
- Modify: `pkg/shell/taint_test.go` (全テスト)
- Modify: `pkg/core/taint.go:226-240`
- Modify: `pkg/core/secretinlog.go:398-409`

### Step 1: 既存テスト名・呼び出し箇所を確認

- [ ] Run: `grep -n 'PropagateTaint(' pkg/shell/taint_test.go pkg/core/taint.go pkg/core/secretinlog.go`
- [ ] Expected: 4 箇所程度 (`taint.go:229`, `secretinlog.go:398`, `taint_test.go` 内のいくつか)

### Step 2: `pkg/shell/taint.go` に `ScopedTaint` 型と新シグネチャを追加

`PropagateTaint` 関数 (現 L182-206) を以下に置き換える。**スコープ動作はまだ実装しない** — 戻り値の `Final` は旧実装と同じ、`visibleAt` は空 map で互換性確保のみ目的。

- [ ] Edit `pkg/shell/taint.go` — `Entry` 型の直後 (L42 あたり) に追加:

```go
// ScopedTaint は scope-aware な taint propagation の結果。
//
// Final はスクリプト末尾時点で親スコープから見える tainted vars。
// 旧 PropagateTaint の戻り値と同じ形。cross-step 伝播 (taint.go の
// $GITHUB_OUTPUT 記録、secretinlog.go の crossStepEnv 構築) で使う。
//
// visibleAt は AST 内の各 *syntax.Stmt 入口時点で「そのスコープから
// 見える tainted vars の union」を保持。sink 検出で「この位置でこの
// 変数は tainted か?」のクエリに使う。直接アクセスせず At() を経由する。
type ScopedTaint struct {
	Final     map[string]Entry
	visibleAt map[*syntax.Stmt]map[string]Entry
}

// At は stmt の入口時点で見えている tainted set を返す。
// stmt が nil または visibleAt に未登録の場合は Final を返す
// (root scope sink のフォールバック)。
func (s *ScopedTaint) At(stmt *syntax.Stmt) map[string]Entry {
	if s == nil {
		return nil
	}
	if stmt == nil {
		return s.Final
	}
	if v, ok := s.visibleAt[stmt]; ok {
		return v
	}
	return s.Final
}
```

- [ ] Edit `pkg/shell/taint.go` — `PropagateTaint` 関数 (L172-206) を以下に書き換え:

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
//       近似。`local` / 装飾なし `declare` は本体ローカル、その他の代入は本 issue の
//       簡略案 A により親に漏らさない (#448 で改善予定)
//
// 戻り値は initial を変更せず新しい *ScopedTaint を返す。
func PropagateTaint(file *syntax.File, initial map[string]Entry) *ScopedTaint {
	result := &ScopedTaint{
		Final:     make(map[string]Entry, len(initial)),
		visibleAt: make(map[*syntax.Stmt]map[string]Entry),
	}
	maps.Copy(result.Final, initial)
	if file == nil {
		return result
	}

	// 暫定実装: 旧フラット動作で Final を埋める。
	// Task 2 以降でスコープ対応に置き換える。
	for _, a := range WalkAssignments(file) {
		if _, already := result.Final[a.Name]; already {
			continue
		}
		if a.Value == nil {
			continue
		}
		refName, found := WordReferencesEntry(a.Value, result.Final)
		if !found {
			continue
		}
		result.Final[a.Name] = Entry{
			Sources: []string{"shellvar:" + refName},
			Offset:  a.Offset,
		}
	}
	return result
}
```

### Step 3: `pkg/core/taint.go` の caller を最小修正

- [ ] Edit `pkg/core/taint.go:228-241` — `t.taintedVars = shell.PropagateTaint(...)` を以下に変更:

```go
	scoped := shell.PropagateTaint(file, t.taintedVars)
	t.taintedVars = scoped.Final
	expandShellvarMarkers(t.taintedVars)

	// shell.PropagateTaint marks derived variables with "shellvar:X" chain
	// markers; taint.go callers expect transitive source lists for richer
	// reporting (e.g. trace back to "github.event.issue.title"). Expand the
	// markers in place. Bounded passes guard against pathological chains.
	// (NOTE: scope-aware per-stmt expansion is added in Task 10)

	// GITHUB_OUTPUT writes
	for _, w := range shell.WalkRedirectWrites(file, "GITHUB_OUTPUT") {
		t.recordRedirWrite(stepID, w, exprMap)
	}
```

### Step 4: `pkg/core/secretinlog.go` の caller を最小修正

- [ ] Edit `pkg/core/secretinlog.go:398-408` — `tainted := shell.PropagateTaint(...)` を以下に変更:

```go
	scoped := shell.PropagateTaint(file, initialTainted)
	tainted := scoped.Final
	leaks := rule.findEchoLeaks(file, tainted, script, execRun.Run)
	for _, leak := range leaks {
		rule.reportLeak(leak)
		rule.addAutoFixerForLeak(step, leak)
	}
	// 後続 step の crossStepEnv に伝播させる。
	for name, origin := range rule.collectGitHubEnvTaintWrites(file, tainted, script) {
		rule.crossStepEnv[name] = origin
	}
```

### Step 5: `pkg/shell/taint_test.go` の既存 `PropagateTaint` テストを更新

- [ ] Run: `grep -n 'PropagateTaint(' pkg/shell/taint_test.go`
- [ ] 各箇所で `result := PropagateTaint(...)` を `result := PropagateTaint(...).Final` に変更 (assertion 対象は同じく `map[string]Entry`)

### Step 6: ビルド & 全テスト確認

- [ ] Run: `go build ./...`
- [ ] Expected: 成功 (compile error なし)
- [ ] Run: `go test ./pkg/shell/... ./pkg/core/...`
- [ ] Expected: 全テスト pass (旧挙動維持)

### Step 7: Commit

- [ ] Run:
```bash
git add pkg/shell/taint.go pkg/shell/taint_test.go pkg/core/taint.go pkg/core/secretinlog.go
git commit -m "$(cat <<'EOF'
refactor(taint): #447 PropagateTaint の戻り値を *ScopedTaint に変更

スコープ動作の追加に向けた API 変更のみ。挙動は旧実装と同じ
(Final は旧戻り値と同形、visibleAt は空)。callers (taint.go,
secretinlog.go) を最小修正で追従。

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Subshell スコープ隔離

**Files:**
- Modify: `pkg/shell/taint.go` — `PropagateTaint` 内部実装を walker ベースに置換
- Modify: `pkg/shell/taint_test.go` — 新規 `TestPropagateTaint_Scoped` 追加

### Step 1: 失敗するテストを追加

- [ ] Edit `pkg/shell/taint_test.go` — ファイル末尾に追加:

```go
// TestPropagateTaint_Scoped は scope-aware な PropagateTaint の挙動を検証する。
func TestPropagateTaint_Scoped(t *testing.T) {
	t.Parallel()

	type want struct {
		// finalHas は Final に含まれるべき変数名 → Sources の最初の値
		finalHas map[string]string
		// finalAbsent は Final に含まれてはいけない変数名
		finalAbsent []string
	}

	cases := []struct {
		name    string
		script  string
		initial map[string]Entry
		want    want
	}{
		{
			name:    "subshell_isolation_fp_suppressed",
			script:  `X="$T"; ( X="safe"; cmd "$X" )`,
			initial: map[string]Entry{"T": {Sources: []string{"github.event.issue.body"}, Offset: -1}},
			want: want{
				// 親 X は T 経由で tainted (subshell 内の X="safe" は親に漏れない)
				finalHas: map[string]string{
					"T": "github.event.issue.body",
					"X": "shellvar:T",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := parseScript(t, tc.script)
			result := PropagateTaint(file, tc.initial)
			for name, wantOrigin := range tc.want.finalHas {
				entry, ok := result.Final[name]
				if !ok {
					t.Errorf("Final[%q] missing; want origin %q", name, wantOrigin)
					continue
				}
				if entry.First() != wantOrigin {
					t.Errorf("Final[%q].First() = %q; want %q", name, entry.First(), wantOrigin)
				}
			}
			for _, name := range tc.want.finalAbsent {
				if _, ok := result.Final[name]; ok {
					t.Errorf("Final[%q] should be absent", name)
				}
			}
		})
	}
}
```

### Step 2: テストが失敗することを確認

- [ ] Run: `go test ./pkg/shell/ -run TestPropagateTaint_Scoped/subshell_isolation_fp_suppressed -v`
- [ ] Expected: FAIL — `Final[X].First()` が `shellvar:T` ではなく `shellvar:X` (subshell 内の X="safe" を親も拾っている可能性) または別値になる

### Step 3: `PropagateTaint` を walker ベースに書き換え

- [ ] Edit `pkg/shell/taint.go` — `PropagateTaint` 関数全体 (現 L172 以降) を以下に置き換え:

```go
// scopeKind は scope frame の種別。
type scopeKind int

const (
	scopeRoot     scopeKind = iota // スクリプトルート
	scopeFunc                      // FuncDecl 本体
	scopeSubshell                  // ( ... )
	scopeCmdSubst                  // $(...)
)

// scopeFrame は scope-aware walker のスタック要素。
//
// local はこの frame で局所宣言された tainted vars。
// parent は lookup chain (function 用) または nil (root)。
// subshell/cmdsubst frame は entry 時に親の visible を local に snapshot copy
// しているため、parent chain は使わない (kind の判定で分岐する)。
type scopeFrame struct {
	parent *scopeFrame
	local  map[string]Entry
	kind   scopeKind
}

// visible はこの frame から見える tainted vars の union を返す。
// FuncDecl 本体: 自 frame.local + parent.visible() (再帰 chain)
// Subshell/CmdSubst: 自 frame.local のみ (entry 時 snapshot 済み)
// Root: 自 frame.local のみ
func (f *scopeFrame) visible() map[string]Entry {
	out := maps.Clone(f.local)
	if out == nil {
		out = make(map[string]Entry)
	}
	if f.kind == scopeFunc && f.parent != nil {
		for k, v := range f.parent.visible() {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
	}
	return out
}

// PropagateTaint は initial を seed として AST を順方向 1 パス walk し、
// scope-aware に taint を伝播する。
//
// セマンティクス:
//   - 既に tainted な変数への再代入は origin/Offset を上書きしない
//   - LHS 名は AST 順序で処理される（forward dataflow）
//   - 代入の RHS が tainted を参照しない場合は LHS に何もしない（untaint しない）
//   - スコープ:
//     - *syntax.Subshell と *syntax.CmdSubst は entry 時に親 visible を
//       snapshot copy して隔離。内部代入は親に漏れない
//     - *syntax.FuncDecl 本体は parent への lookup chain で dynamic scoping を近似。
//       `local` / 装飾なし `declare` は本体ローカル、その他の代入は簡略案 A により
//       親に漏らさない (#448 で改善予定)
//
// 戻り値は initial を変更せず新しい *ScopedTaint を返す。
func PropagateTaint(file *syntax.File, initial map[string]Entry) *ScopedTaint {
	result := &ScopedTaint{
		Final:     make(map[string]Entry, len(initial)),
		visibleAt: make(map[*syntax.Stmt]map[string]Entry),
	}
	maps.Copy(result.Final, initial)
	if file == nil {
		return result
	}

	root := &scopeFrame{kind: scopeRoot, local: maps.Clone(initial)}
	if root.local == nil {
		root.local = make(map[string]Entry)
	}
	current := root
	syntax.Walk(file, makeWalkFn(&current, result))

	// Final は root frame の最終状態 (subshell/funcdecl frame は pop 済み)
	maps.Copy(result.Final, root.local)
	return result
}

// makeWalkFn は scope frame stack を維持しつつ walk するクロージャを返す。
// `current` は現在の frame を指す pointer-to-pointer で、subshell/funcdecl 入退場時に
// 書き換える。
func makeWalkFn(current **scopeFrame, result *ScopedTaint) func(syntax.Node) bool {
	return func(node syntax.Node) bool {
		if node == nil {
			return false
		}
		switch n := node.(type) {
		case *syntax.Subshell:
			child := &scopeFrame{kind: scopeSubshell, parent: *current, local: maps.Clone((*current).visible())}
			*current = child
			for _, stmt := range n.Stmts {
				syntax.Walk(stmt, makeWalkFn(current, result))
			}
			*current = (*current).parent
			return false
		case *syntax.CmdSubst:
			child := &scopeFrame{kind: scopeCmdSubst, parent: *current, local: maps.Clone((*current).visible())}
			*current = child
			for _, stmt := range n.Stmts {
				syntax.Walk(stmt, makeWalkFn(current, result))
			}
			*current = (*current).parent
			return false
		case *syntax.FuncDecl:
			// 関数本体の処理は Task 4 で実装
			return false
		case *syntax.Stmt:
			// 各 Stmt 入口で visibleAt を記録
			result.visibleAt[n] = (*current).visible()
			return true
		case *syntax.DeclClause:
			processDeclClause(*current, n)
			return false // children は処理済み (二重カウント防止)
		case *syntax.Assign:
			processAssign(*current, n, AssignNone)
			return true
		}
		return true
	}
}

// processAssign は単純代入 X=Y を current frame に書き込む。
// 既に tainted な変数の上書きはしない (最初の taint を保持)。
func processAssign(current *scopeFrame, a *syntax.Assign, kw AssignKeyword) {
	if a == nil || a.Name == nil {
		return
	}
	name := a.Name.Value
	if _, already := current.local[name]; already {
		return
	}
	if a.Value == nil {
		return
	}
	visible := current.visible()
	refName, found := WordReferencesEntry(a.Value, visible)
	if !found {
		return
	}
	current.local[name] = Entry{
		Sources: []string{"shellvar:" + refName},
		Offset:  int(a.Pos().Offset()), //nolint:gosec // file offsets fit in int
	}
}

// processDeclClause は DeclClause (export X=Y / local X=Y / readonly X=Y / declare X=Y) を処理する。
// keyword に応じた scope target は Task 6/7 で実装。本 Task では全部 current frame に書く
// (Subshell/CmdSubst では結果同じ、FuncDecl 内は Task 5/6/7 で再分岐する)。
func processDeclClause(current *scopeFrame, decl *syntax.DeclClause) {
	if decl == nil {
		return
	}
	kw := keywordFor(decl.Variant.Value)
	for _, a := range decl.Args {
		processAssign(current, a, kw)
	}
}
```

注意: `processAssign` の第 3 引数 `kw` は本 Task では使わないが、Task 5/6/7 で参照するため引数に残す。

### Step 4: テストが pass することを確認

- [ ] Run: `go test ./pkg/shell/ -run TestPropagateTaint_Scoped/subshell_isolation_fp_suppressed -v`
- [ ] Expected: PASS

### Step 5: 既存テスト群の回帰確認

- [ ] Run: `go test ./pkg/shell/...`
- [ ] Expected: 全 pass。失敗するなら walker のフォールスルー漏れ (Stmt の handler が return true を返さず children に降りていない等) を疑う

### Step 6: Commit

- [ ] Run:
```bash
git add pkg/shell/taint.go pkg/shell/taint_test.go
git commit -m "$(cat <<'EOF'
feat(taint): #447 Subshell スコープ隔離を実装

PropagateTaint を scope frame stack ベースの walker に書き換え。
*syntax.Subshell `( ... )` の内部代入が親に漏れないことを検証する
ユニットテスト 1 件追加。CmdSubst / FuncDecl は後続タスクで実装。

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: CmdSubst スコープ隔離 + visibleAt スナップショット検証

**Files:**
- Modify: `pkg/shell/taint_test.go`

### Step 1: CmdSubst 隔離と visibleAt の失敗テストを追加

- [ ] Edit `pkg/shell/taint_test.go` — `TestPropagateTaint_Scoped` の `cases` に追加:

```go
		{
			name:   "subshell_inner_sees_parent_tainted",
			script: `X="$T"; ( cmd "$X" )`,
			initial: map[string]Entry{"T": {Sources: []string{"github.event.issue.body"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{
					"T": "github.event.issue.body",
					"X": "shellvar:T",
				},
			},
		},
		{
			name:   "cmdsubst_isolation",
			script: `R=$(X="leaked"; echo "$X"); cmd "$X"`,
			initial: map[string]Entry{"T": {Sources: []string{"github.event.issue.body"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{
					"T": "github.event.issue.body",
				},
				finalAbsent: []string{"X"}, // cmdsubst 内の X="leaked" は親に漏れない
			},
		},
		{
			name:   "nested_subshell",
			script: `( X="$T"; ( cmd "$X" ) )`,
			initial: map[string]Entry{"T": {Sources: []string{"github.event.issue.body"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{
					"T": "github.event.issue.body",
				},
				finalAbsent: []string{"X"}, // 内側の X は外側 subshell に閉じる
			},
		},
```

加えて `visibleAt` を直接検証する新規テスト関数を追加:

```go
// TestScopedTaint_At は visibleAt の per-Stmt snapshot を検証する。
func TestScopedTaint_At(t *testing.T) {
	t.Parallel()

	t.Run("subshell_inner_stmt_sees_parent_tainted", func(t *testing.T) {
		t.Parallel()
		// X="$T" は親、( cmd "$X" ) の cmd は subshell 内
		file := parseScript(t, `X="$T"; ( cmd "$X" )`)
		initial := map[string]Entry{"T": {Sources: []string{"github.event.issue.body"}, Offset: -1}}
		result := PropagateTaint(file, initial)

		// AST から内側 cmd の Stmt を取り出して At を検証
		var innerStmt *syntax.Stmt
		syntax.Walk(file, func(n syntax.Node) bool {
			if sub, ok := n.(*syntax.Subshell); ok {
				if len(sub.Stmts) > 0 {
					innerStmt = sub.Stmts[0]
				}
				return false
			}
			return true
		})
		if innerStmt == nil {
			t.Fatal("inner subshell stmt not found")
		}
		visible := result.At(innerStmt)
		if _, ok := visible["T"]; !ok {
			t.Errorf("inner subshell visible should contain T, got %v", keysOf(visible))
		}
		if _, ok := visible["X"]; !ok {
			t.Errorf("inner subshell visible should contain X (snapshotted from parent), got %v", keysOf(visible))
		}
	})

	t.Run("at_nil_returns_final", func(t *testing.T) {
		t.Parallel()
		file := parseScript(t, `X=v`)
		initial := map[string]Entry{"T": {Sources: []string{"x"}, Offset: -1}}
		result := PropagateTaint(file, initial)
		got := result.At(nil)
		if _, ok := got["T"]; !ok {
			t.Errorf("At(nil) should fall back to Final, got %v", keysOf(got))
		}
	})

	t.Run("at_unknown_stmt_returns_final", func(t *testing.T) {
		t.Parallel()
		// 別ファイルの Stmt を渡してフォールバック確認
		file := parseScript(t, `X=v`)
		other := parseScript(t, `Y=z`)
		initial := map[string]Entry{"T": {Sources: []string{"x"}, Offset: -1}}
		result := PropagateTaint(file, initial)
		var otherStmt *syntax.Stmt
		if len(other.Stmts) > 0 {
			otherStmt = other.Stmts[0]
		}
		got := result.At(otherStmt)
		if _, ok := got["T"]; !ok {
			t.Errorf("At(unknown stmt) should fall back to Final, got %v", keysOf(got))
		}
	})

	t.Run("nil_scoped_returns_nil", func(t *testing.T) {
		t.Parallel()
		var s *ScopedTaint
		if got := s.At(nil); got != nil {
			t.Errorf("nil ScopedTaint.At should return nil, got %v", got)
		}
	})
}

// keysOf is a test helper that returns sorted keys of a map for debug output.
func keysOf(m map[string]Entry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
```

### Step 2: 失敗確認

- [ ] Run: `go test ./pkg/shell/ -run TestPropagateTaint_Scoped -v`
- [ ] Expected: `cmdsubst_isolation` などが既に PASS している可能性が高い (Task 2 の walker が Subshell と CmdSubst の両 case を処理しているため)。FAIL したものだけ次 step で対処
- [ ] Run: `go test ./pkg/shell/ -run TestScopedTaint_At -v`
- [ ] Expected: 4 ケースとも PASS (Task 2 で visibleAt 自体は実装済み)

### Step 3: もし失敗があれば原因調査・修正

- [ ] FAIL があれば walker の `*syntax.CmdSubst` ハンドラまたは `*syntax.Stmt` の visibleAt 記録漏れを修正
- [ ] 修正後 Step 2 を再実行

### Step 4: Commit

- [ ] Run:
```bash
git add pkg/shell/taint_test.go
git commit -m "$(cat <<'EOF'
test(taint): #447 CmdSubst 隔離と visibleAt スナップショット検証を追加

cmdsubst_isolation / nested_subshell / subshell_inner_sees_parent ケース
と TestScopedTaint_At (At(nil) / At(unknown) フォールバック含む) を追加。
walker は Task 2 で実装済みのため挙動修正は不要。

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: FuncDecl 本体スコープ + `local` ハンドリング

**Files:**
- Modify: `pkg/shell/taint.go` — walker に FuncDecl ハンドラ追加、`processDeclClause` で `local` を分岐
- Modify: `pkg/shell/taint_test.go` — case 4, 12 追加

### Step 1: 失敗テストを追加

- [ ] Edit `pkg/shell/taint_test.go` — `TestPropagateTaint_Scoped` の `cases` に追加:

```go
		{
			name:    "function_local_isolated",
			script:  `foo() { local X="$T"; }; foo`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas:    map[string]string{"T": "secrets.GH"},
				finalAbsent: []string{"X"}, // 関数内の local X は親に漏れない
			},
		},
		{
			name:    "root_local_treated_as_root_assign",
			script:  `local X="$T"`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				// root scope の local は bash 実行時エラーだが、解析では root に書く (FN 抑制)
				finalHas: map[string]string{
					"T": "secrets.GH",
					"X": "shellvar:T",
				},
			},
		},
```

加えて `visibleAt` で関数内 sink を検証:

```go
	t.Run("function_body_inner_sees_local", func(t *testing.T) {
		t.Parallel()
		file := parseScript(t, `foo() { local X="$T"; cmd "$X"; }; foo`)
		initial := map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}}
		result := PropagateTaint(file, initial)

		// 関数本体内の `cmd "$X"` Stmt を取り出す
		var cmdStmt *syntax.Stmt
		syntax.Walk(file, func(n syntax.Node) bool {
			fd, ok := n.(*syntax.FuncDecl)
			if !ok || fd.Body == nil {
				return true
			}
			body, ok := fd.Body.Cmd.(*syntax.Block)
			if !ok {
				return true
			}
			// body.Stmts: [0]=local X=, [1]=cmd "$X"
			if len(body.Stmts) >= 2 {
				cmdStmt = body.Stmts[1]
			}
			return false
		})
		if cmdStmt == nil {
			t.Fatal("function body cmd stmt not found")
		}
		visible := result.At(cmdStmt)
		if _, ok := visible["X"]; !ok {
			t.Errorf("function body cmd visible should contain X (local), got %v", keysOf(visible))
		}
	})
```

→ この test は `TestScopedTaint_At` 関数内に追加する。

### Step 2: 失敗確認

- [ ] Run: `go test ./pkg/shell/ -run 'TestPropagateTaint_Scoped/function_local_isolated|TestPropagateTaint_Scoped/root_local_treated_as_root_assign|TestScopedTaint_At/function_body_inner_sees_local' -v`
- [ ] Expected: 全部 FAIL (FuncDecl が walker でスキップされているため)

### Step 3: walker に FuncDecl ハンドラを追加

- [ ] Edit `pkg/shell/taint.go` — `makeWalkFn` 内 `case *syntax.FuncDecl:` を以下に置き換え:

```go
		case *syntax.FuncDecl:
			if n.Body == nil {
				return false
			}
			child := &scopeFrame{kind: scopeFunc, parent: *current, local: make(map[string]Entry)}
			prev := *current
			*current = child
			syntax.Walk(n.Body, makeWalkFn(current, result))
			*current = prev
			return false
```

(Task 2 で walker は makeWalkFn 1 つに統一済み。修正箇所は 1 箇所のみ)

### Step 4: `processDeclClause` で `local` を分岐

- [ ] Edit `pkg/shell/taint.go` — `processDeclClause` を以下に置き換え:

```go
// processDeclClause は DeclClause を処理する。
// セマンティクス (#447):
//   - local: 常に current frame に書く (FuncDecl 内なら本体ローカル、root なら root ※bash エラーだが解析許容)
//   - declare (装飾なし): FuncDecl 内なら current frame、それ以外なら current frame に書く (Task 6 で declare -g 対応)
//   - export / readonly: FuncDecl 内では簡略案 A により無視 (親に漏らさない)、それ以外なら current frame に書く
func processDeclClause(current *scopeFrame, decl *syntax.DeclClause) {
	if decl == nil {
		return
	}
	kw := keywordFor(decl.Variant.Value)

	// FuncDecl 内で export / readonly は簡略案 A により無視 (親に漏らさない)
	if current.kind == scopeFunc && (kw == AssignExport || kw == AssignReadonly) {
		return
	}
	// declare -g の判定は Task 6 で追加。本 Task では declare は current frame に書く

	for _, a := range decl.Args {
		processAssign(current, a, kw)
	}
}
```

加えて、`AssignNone` (装飾なし `X=Y`) も FuncDecl 内では簡略案 A により親に漏らさない。`processAssign` 自体は current frame に書くので、FuncDecl 本体 walk の中なら自然と本体ローカルに閉じる (簡略案 A の「無視」は実質「FuncDecl 本体の local に書いて、関数を抜ける際に discard」と等価)。

つまり Walker 上の FuncDecl pop で frame ごと捨てるため、FuncDecl 内の `X=Y` (AssignNone) は親に漏れない ← これで簡略案 A が成立する。**追加の特別処理は不要**。

ただし `processAssign` 内で `current.visible()` を見ているので、関数本体の親 lookup chain が効く (関数内で親の T を参照できる)。

### Step 5: テスト pass 確認

- [ ] Run: `go test ./pkg/shell/ -run 'TestPropagateTaint_Scoped|TestScopedTaint_At' -v`
- [ ] Expected: 全 pass
- [ ] Run: `go test ./pkg/shell/...`
- [ ] Expected: 全 pass (回帰なし)

### Step 6: Commit

- [ ] Run:
```bash
git add pkg/shell/taint.go pkg/shell/taint_test.go
git commit -m "$(cat <<'EOF'
feat(taint): #447 FuncDecl スコープと local キーワードを実装

walker に FuncDecl ハンドラを追加。本体は scopeFunc frame で push し、
parent への lookup chain で bash dynamic scoping を近似。local 宣言は
本体ローカルに閉じる。関数内 export/readonly は簡略案 A により親に
漏らさない。

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `declare` / `declare -g` セマンティクス

**Files:**
- Modify: `pkg/shell/taint.go` — `processDeclClause` で `-g` フラグ判定
- Modify: `pkg/shell/taint_test.go` — case 5, 6, 7, 8 追加

### Step 1: 失敗テストを追加

- [ ] Edit `pkg/shell/taint_test.go` — `TestPropagateTaint_Scoped` の `cases` に追加:

```go
		{
			name:    "function_declare_local_by_default",
			script:  `foo() { declare X="$T"; }; foo`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas:    map[string]string{"T": "secrets.GH"},
				finalAbsent: []string{"X"}, // 関数内 declare はデフォルト local
			},
		},
		{
			name:    "function_declare_g_simplified_A_ignored",
			script:  `foo() { declare -g X="$T"; }; foo`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				// 簡略案 A: 関数内の non-local 代入 (declare -g 含む) は親に漏らさない
				finalHas:    map[string]string{"T": "secrets.GH"},
				finalAbsent: []string{"X"},
			},
		},
		{
			name:    "function_export_simplified_A_ignored",
			script:  `foo() { export X="$T"; }; foo`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas:    map[string]string{"T": "secrets.GH"},
				finalAbsent: []string{"X"},
			},
		},
		{
			name:    "function_readonly_simplified_A_ignored",
			script:  `foo() { readonly X="$T"; }; foo`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas:    map[string]string{"T": "secrets.GH"},
				finalAbsent: []string{"X"},
			},
		},
```

### Step 2: 失敗確認

- [ ] Run: `go test ./pkg/shell/ -run 'TestPropagateTaint_Scoped/function_declare_local_by_default|TestPropagateTaint_Scoped/function_declare_g_simplified_A_ignored|TestPropagateTaint_Scoped/function_export_simplified_A_ignored|TestPropagateTaint_Scoped/function_readonly_simplified_A_ignored' -v`
- [ ] Expected: `function_declare_local_by_default` は既に PASS している可能性あり。`function_declare_g_simplified_A_ignored` は FAIL する可能性あり (`declare -g` を「親に漏らす」と誤実装している場合)

### Step 3: `processDeclClause` で `declare -g` を判定

- [ ] Edit `pkg/shell/taint.go` — `processDeclClause` を以下に置き換え:

```go
// processDeclClause は DeclClause を処理する。
// セマンティクス (#447):
//   - local: 常に current frame に書く
//   - declare / typeset (装飾なし): current frame に書く (FuncDecl 内なら本体ローカル)
//   - declare -g (グローバル指定): FuncDecl 内では簡略案 A により無視
//   - export / readonly: FuncDecl 内では簡略案 A により無視、それ以外なら current frame に書く
func processDeclClause(current *scopeFrame, decl *syntax.DeclClause) {
	if decl == nil {
		return
	}
	kw := keywordFor(decl.Variant.Value)

	if current.kind == scopeFunc {
		// FuncDecl 内で export / readonly は簡略案 A により無視
		if kw == AssignExport || kw == AssignReadonly {
			return
		}
		// declare -g も簡略案 A により無視
		if kw == AssignDeclare && declHasGlobalFlag(decl) {
			return
		}
	}

	for _, a := range decl.Args {
		processAssign(current, a, kw)
	}
}

// declHasGlobalFlag は DeclClause に -g (global) フラグが付いているか判定する。
// `declare -g X=v` の場合 Args[0] が `-g` または `-Ag` 等のフラグ Word になる
// ことがあるが、mvdan/sh では -g のような short option も Args の Lit として扱われる。
// そのため Args の先頭から Lit を見て、`-` で始まり 'g' を含む文字列があれば true。
func declHasGlobalFlag(decl *syntax.DeclClause) bool {
	for _, a := range decl.Args {
		if a == nil || a.Name == nil {
			continue
		}
		// flag は Name.Value が `-` で始まる純粋な文字列
		if strings.HasPrefix(a.Name.Value, "-") && strings.Contains(a.Name.Value, "g") && a.Value == nil {
			return true
		}
	}
	return false
}
```

### Step 4: テスト pass 確認

- [ ] Run: `go test ./pkg/shell/ -run TestPropagateTaint_Scoped -v`
- [ ] Expected: 全 case pass
- [ ] Run: `go test ./pkg/shell/...`
- [ ] Expected: 回帰なし

### Step 5: Commit

- [ ] Run:
```bash
git add pkg/shell/taint.go pkg/shell/taint_test.go
git commit -m "$(cat <<'EOF'
feat(taint): #447 declare / declare -g / export / readonly のスコープ semantics

関数内 declare はデフォルト local。declare -g / export / readonly は
簡略案 A により親に漏らさない (#448 で改善)。テスト 4 ケース追加。

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: ネストスコープと API edge ケース

**Files:**
- Modify: `pkg/shell/taint_test.go` — case 9-11, 13, NilFile

### Step 1: テスト追加

- [ ] Edit `pkg/shell/taint_test.go` — `TestPropagateTaint_Scoped` の `cases` に追加:

```go
		{
			name:    "subshell_with_funcdecl_inside",
			script:  `( foo() { local X="$T"; }; foo )`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas:    map[string]string{"T": "secrets.GH"},
				finalAbsent: []string{"X"},
			},
		},
		{
			name:    "function_with_subshell_inside",
			script:  `foo() { local X="$T"; ( cmd "$X" ); }; foo`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas:    map[string]string{"T": "secrets.GH"},
				finalAbsent: []string{"X"},
			},
		},
		{
			name:    "regression_no_scope_constructs",
			script:  `X="$T"; Y="$X"; cmd "$Y"`,
			initial: map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}},
			want: want{
				finalHas: map[string]string{
					"T": "secrets.GH",
					"X": "shellvar:T",
					"Y": "shellvar:X",
				},
			},
		},
```

加えて NilFile テストを `TestScopedTaint_At` に追加:

```go
	t.Run("nil_file", func(t *testing.T) {
		t.Parallel()
		initial := map[string]Entry{"T": {Sources: []string{"secrets.GH"}, Offset: -1}}
		result := PropagateTaint(nil, initial)
		if result == nil {
			t.Fatal("PropagateTaint(nil, ...) should return non-nil ScopedTaint")
		}
		if _, ok := result.Final["T"]; !ok {
			t.Errorf("Final should contain initial T, got %v", keysOf(result.Final))
		}
	})
```

### Step 2: テスト pass 確認

- [ ] Run: `go test ./pkg/shell/ -run 'TestPropagateTaint_Scoped|TestScopedTaint_At' -v`
- [ ] Expected: 全 pass (Task 4 の FuncDecl 実装と Task 2 の Subshell 実装で composition は自然動作するはず)
- [ ] FAIL があれば walker の入れ子処理を確認

### Step 3: Commit

- [ ] Run:
```bash
git add pkg/shell/taint_test.go
git commit -m "$(cat <<'EOF'
test(taint): #447 ネストスコープと NilFile / 回帰ケースを追加

subshell_with_funcdecl_inside / function_with_subshell_inside /
regression_no_scope_constructs / nil_file の 4 ケース。Task 4-5 の
walker composition で動作することを確認。

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `pkg/core/taint.go` を scope-aware に統合

**Files:**
- Modify: `pkg/core/taint.go:226-241` — `recordRedirWrite` のシグネチャ更新と `AnalyzeStep` での per-stmt 展開
- Modify: `pkg/core/taint.go:459-487` — `recordRedirWrite` 本体
- Modify: `pkg/core/taint_test.go` — `TestTaintTracker_RedirWriteInSubshell` 追加

### Step 1: 失敗テストを追加

- [ ] Edit `pkg/core/taint_test.go` — ファイル末尾に追加 (`makeBPatternRunStep` ヘルパは L878 で既存):

```go
// TestTaintTracker_RedirWriteInSubshell は subshell 内の `>> $GITHUB_OUTPUT`
// 書き込みでも親スコープの tainted vars が正しく検出されることを検証する (#447)。
func TestTaintTracker_RedirWriteInSubshell(t *testing.T) {
	t.Parallel()

	step := makeBPatternRunStep("leak", `T="${{ github.event.issue.body }}"
( echo "out=$T" >> $GITHUB_OUTPUT )`)

	tracker := NewTaintTracker()
	tracker.AnalyzeStep(step)

	outputs := tracker.GetTaintedOutputs()
	stepOutputs, ok := outputs["leak"]
	if !ok {
		t.Fatalf("step %q should have tainted outputs, got %v", "leak", outputs)
	}
	srcs, ok := stepOutputs["out"]
	if !ok {
		keys := make([]string, 0, len(stepOutputs))
		for k := range stepOutputs {
			keys = append(keys, k)
		}
		t.Fatalf("output %q should be tainted, got keys %v", "out", keys)
	}
	if len(srcs) == 0 || !strings.Contains(srcs[0], "github.event.issue.body") {
		t.Errorf("output sources should reference github.event.issue.body, got %v", srcs)
	}
}
```

`strings` import が無ければ:

- [ ] Run: `grep -n '"strings"' pkg/core/taint_test.go`
- [ ] If absent, add to import block

### Step 2: 失敗確認

- [ ] Run: `go test ./pkg/core/ -run TestTaintTracker_RedirWriteInSubshell -v`
- [ ] Expected: FAIL — subshell 内の T 参照が検出されない (現行 `recordRedirWrite` は global `t.taintedVars` 参照、subshell scope を意識していない)

### Step 3: `pkg/core/taint.go` の `AnalyzeStep` を per-stmt 展開に変更

- [ ] Edit `pkg/core/taint.go` — `AnalyzeStep` 内 (現 L228-241) を以下に置き換え:

```go
	scoped := shell.PropagateTaint(file, t.taintedVars)
	t.taintedVars = scoped.Final
	expandShellvarMarkers(t.taintedVars)

	// GITHUB_OUTPUT writes
	for _, w := range shell.WalkRedirectWrites(file, "GITHUB_OUTPUT") {
		visible := scoped.At(w.Stmt)
		// shellvar:X markers must be expanded before recording into taintedOutputs
		// (cross-step propagation). expand a per-stmt copy to keep the scoped
		// snapshot intact for any later use.
		expanded := maps.Clone(visible)
		if expanded == nil {
			expanded = make(map[string]shell.Entry)
		}
		expandShellvarMarkers(expanded)
		t.recordRedirWrite(stepID, w, exprMap, expanded)
	}
```

`maps` パッケージの import を上に追加:

- [ ] Run: `grep -n '"maps"' pkg/core/taint.go`
- [ ] If absent, add to import block

### Step 4: `recordRedirWrite` のシグネチャと本体を更新

- [ ] Edit `pkg/core/taint.go` — `recordRedirWrite` (現 L459-487) を以下に置き換え:

```go
// recordRedirWrite は WalkRedirectWrites の結果をもとに taintedOutputs に記録する。
// VALUE 内に直接 untrusted 式（プレースホルダ経由を含む）があるか、または
// visible 内の tainted 変数を参照していれば、その output を tainted として登録する。
//
// visible は scope-aware な per-stmt visible map (caller で展開済み)。
func (t *TaintTracker) recordRedirWrite(stepID string, w shell.RedirWrite, exprMap map[string]string, visible map[string]shell.Entry) {
	sources := t.collectExpressionSources(w.Value, exprMap)

	// VALUE 内の $VAR 参照を visible と照合
	if w.ValueWord != nil {
		if name, ok := shell.WordReferencesEntry(w.ValueWord, visible); ok {
			sources = mergeUnique(sources, visible[name].Sources)
		}
	} else {
		// heredoc 等で ValueWord が無い場合は文字列ベースで $VAR を検出
		varRefPattern := regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
		for _, m := range varRefPattern.FindAllStringSubmatch(w.Value, -1) {
			if len(m) < 2 {
				continue
			}
			if entry, ok := visible[m[1]]; ok {
				sources = mergeUnique(sources, entry.Sources)
			}
		}
	}

	if len(sources) == 0 {
		return
	}
	if t.taintedOutputs[stepID] == nil {
		t.taintedOutputs[stepID] = make(map[string][]string)
	}
	t.taintedOutputs[stepID][w.Name] = sources
}
```

### Step 5: テスト pass 確認

- [ ] Run: `go test ./pkg/core/ -run TestTaintTracker_RedirWriteInSubshell -v`
- [ ] Expected: PASS
- [ ] Run: `go test ./pkg/core/...`
- [ ] Expected: 全 pass (回帰なし)

### Step 6: Commit

- [ ] Run:
```bash
git add pkg/core/taint.go pkg/core/taint_test.go
git commit -m "$(cat <<'EOF'
feat(taint): #447 TaintTracker を scope-aware lookup に統合

recordRedirWrite に visible map を引数追加し、AnalyzeStep で per-stmt の
scoped.At() を expandShellvarMarkers してから渡すように変更。これで
subshell 内の `>> $GITHUB_OUTPUT` でも親スコープの tainted vars が
正しく検出される。

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `pkg/core/secretinlog.go` を scope-aware に統合

**Files:**
- Modify: `pkg/core/secretinlog.go:71-110` — `findEchoLeaks`
- Modify: `pkg/core/secretinlog.go:128-166` — `collectRedirectSinkLeaks` (シグネチャは変えず、呼び出し元で per-stmt visible を渡す)
- Modify: `pkg/core/secretinlog.go:225-266` — `collectLeakedVars` (シグネチャ不変、呼び出し元で per-stmt visible を渡す)
- Modify: `pkg/core/secretinlog.go:669-704` — `collectGitHubEnvTaintWrites`
- Modify: `pkg/core/secretinlog.go:398-409` — caller (今回ここで scoped を直接使う)
- Modify: `pkg/core/secretinlog_test.go` — 2 ケース追加

### Step 1: 失敗テストを追加

`secretinlog_test.go` には専用ヘルパが無く、`*ast.Step` / `*ast.Job` を inline で組む既存パターン (`TestSecretInLog_VisitJob_Integration` L131-236 参照) を踏襲する。

- [ ] Edit `pkg/core/secretinlog_test.go` — ファイル末尾に追加:

```go
// TestSecretInLog_FunctionLocalScope_DetectsLeak は関数本体内で local 宣言された
// 変数を echo すると leak として検出されることを検証する (#447 FN 修正)。
func TestSecretInLog_FunctionLocalScope_DetectsLeak(t *testing.T) {
	t.Parallel()

	rule := NewSecretInLogRule()

	envVars := map[string]*ast.EnvVar{
		"secret": {
			Name:  &ast.String{Value: "SECRET"},
			Value: &ast.String{Value: "${{ secrets.GH_TOKEN }}"},
		},
	}
	step := &ast.Step{
		Env: &ast.Env{Vars: envVars},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `leak() {
  local SECRET_LOCAL="$SECRET"
  echo "$SECRET_LOCAL"
}
leak`, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}

	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got == 0 {
		t.Fatalf("expected leak detection for SECRET_LOCAL inside function body, got 0 errors")
	}
}

// TestSecretInLog_SubshellLocalAssignment_NotLeakedInParent は subshell 内の
// 上書きが親スコープの sink 検出に影響しないことを検証する (#447 FP/FN 防止)。
func TestSecretInLog_SubshellLocalAssignment_NotLeakedInParent(t *testing.T) {
	t.Parallel()

	rule := NewSecretInLogRule()

	envVars := map[string]*ast.EnvVar{
		"secret": {
			Name:  &ast.String{Value: "SECRET"},
			Value: &ast.String{Value: "${{ secrets.GH_TOKEN }}"},
		},
	}
	step := &ast.Step{
		Env: &ast.Env{Vars: envVars},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `( SECRET="dummy" )
echo "$SECRET"`, Pos: &ast.Position{Line: 1, Col: 1}},
		},
	}
	job := &ast.Job{Steps: []*ast.Step{step}}

	if err := rule.VisitJobPre(job); err != nil {
		t.Fatalf("VisitJobPre: %v", err)
	}
	if got := len(rule.Errors()); got == 0 {
		t.Fatalf("expected leak detection for parent SECRET (subshell override should not affect parent)")
	}
}
```

### Step 2: 失敗確認

- [ ] Run: `go test ./pkg/core/ -run 'TestSecretInLog_FunctionLocalScope_DetectsLeak|TestSecretInLog_SubshellLocalAssignment_NotLeakedInParent' -v`
- [ ] Expected: 1 つ目は FAIL (関数内 local の sink を `findEchoLeaks` が検出しない)、2 つ目は **既に PASS する可能性**あり (subshell 内の代入が親に漏れる現状でも、scoped でないので親の SECRET は env 由来 tainted のまま) — 実際の挙動を確認

### Step 3: `findEchoLeaks` のシグネチャを `*shell.ScopedTaint` に変更

- [ ] Edit `pkg/core/secretinlog.go:71-110` — `findEchoLeaks` を以下に置き換え:

```go
func (rule *SecretInLogRule) findEchoLeaks(file *syntax.File, scoped *shell.ScopedTaint, script string, runStr *ast.String) []echoLeakOccurrence {
	if file == nil {
		return nil
	}
	var leaks []echoLeakOccurrence
	// currentVisible は最後に visit した *syntax.Stmt の visible map。
	// 内側の CallExpr などは同じ stmt スコープにいるため、これを使って lookup する。
	var currentVisible map[string]shell.Entry

	syntax.Walk(file, func(node syntax.Node) bool {
		// コマンド置換の内部は stdout がパイプに接続されるため、
		// echo/printf の出力はビルドログには現れない。子ノードの探索をスキップする。
		if _, isCmdSubst := node.(*syntax.CmdSubst); isCmdSubst {
			return false
		}
		if stmt, isStmt := node.(*syntax.Stmt); isStmt {
			// stdout を「ログに出ない先」へリダイレクトしている Stmt は子ノードごとスキップ。
			if stmtRedirectsStdoutAwayFromLog(stmt) {
				return false
			}
			currentVisible = scoped.At(stmt)
			// cat / tee / dd の here-string (<<<) や heredoc (<<) を経由した
			// 漏洩は Stmt の Redirs 側に taint があるため、ここで検査する。
			rule.collectRedirectSinkLeaks(stmt, currentVisible, script, runStr, &leaks)
			return true
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		cmdName := firstWordLiteral(call.Args[0])
		if cmdName != "echo" && cmdName != "printf" {
			return true
		}
		if cmdName == "printf" && len(call.Args) >= 2 && firstWordLiteral(call.Args[1]) == "-v" {
			return true
		}
		for _, arg := range call.Args[1:] {
			rule.collectLeakedVars(arg, currentVisible, script, runStr, cmdName, &leaks)
		}
		return true
	})
	return leaks
}
```

### Step 4: `collectGitHubEnvTaintWrites` も scoped 化

- [ ] Edit `pkg/core/secretinlog.go:669-704` — `collectGitHubEnvTaintWrites` を以下に置き換え:

```go
func (rule *SecretInLogRule) collectGitHubEnvTaintWrites(
	file *syntax.File,
	scoped *shell.ScopedTaint,
	script string,
) map[string]string {
	result := make(map[string]string)
	if file == nil {
		return result
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		if !stmtRedirectsToGitHubEnv(stmt) {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		visible := scoped.At(stmt)
		cmdName := firstWordLiteral(call.Args[0])
		switch cmdName {
		case "echo", "printf":
			rule.collectEchoEnvWrites(call, visible, result)
		case "cat", "tee", "dd":
			rule.collectHeredocEnvWrites(stmt, visible, script, result)
		}
		return true
	})
	return result
}
```

### Step 5: caller (`AnalyzeStep` 相当部分 L398-409) を更新

- [ ] Edit `pkg/core/secretinlog.go:398-409` — Task 1 で書いた:

```go
	scoped := shell.PropagateTaint(file, initialTainted)
	tainted := scoped.Final
	leaks := rule.findEchoLeaks(file, tainted, script, execRun.Run)
	for _, leak := range leaks {
		rule.reportLeak(leak)
		rule.addAutoFixerForLeak(step, leak)
	}
	for name, origin := range rule.collectGitHubEnvTaintWrites(file, tainted, script) {
		rule.crossStepEnv[name] = origin
	}
```

を以下に置き換え:

```go
	scoped := shell.PropagateTaint(file, initialTainted)
	leaks := rule.findEchoLeaks(file, scoped, script, execRun.Run)
	for _, leak := range leaks {
		rule.reportLeak(leak)
		rule.addAutoFixerForLeak(step, leak)
	}
	// 後続 step の crossStepEnv に伝播させる。
	for name, origin := range rule.collectGitHubEnvTaintWrites(file, scoped, script) {
		rule.crossStepEnv[name] = origin
	}
```

注: secretinlog.go は `expandShellvarMarkers` を呼ばない (autofix が `shellvar:X` 形式を必要とするため、§5.2 spec 参照)。`scoped.At()` の戻り値はそのまま渡す。

### Step 6: テスト pass 確認

- [ ] Run: `go test ./pkg/core/ -run 'TestSecretInLog' -v`
- [ ] Expected: 全 pass (新規 2 ケース含む、既存 secretinlog テストの回帰なし)
- [ ] Run: `go test ./pkg/core/...`
- [ ] Expected: 全 pass

### Step 7: Commit

- [ ] Run:
```bash
git add pkg/core/secretinlog.go pkg/core/secretinlog_test.go
git commit -m "$(cat <<'EOF'
feat(taint): #447 SecretInLog を scope-aware lookup に統合

findEchoLeaks と collectGitHubEnvTaintWrites を *shell.ScopedTaint
受け取りに変更し、各 *syntax.Stmt の入口で scoped.At() を取って per-stmt
visible map で sink 判定する。関数本体内 local 変数の echo / subshell 内
書き込みの取扱いを正しくし、FN 修正と FP 抑制を両立。

shellvar:X マーカーは autofix が変数アサイン直後への ::add-mask:: 挿入
判定に使うため、secretinlog 側では展開せずそのまま流す (taint.go 側の
per-stmt 展開とは独立のポリシー、spec §5 参照)。

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Workflow fixture 追加 + 手動動作確認

**Files:**
- Create: `script/actions/taint-scope-fp-safe.yaml`
- Create: `script/actions/taint-scope-fn-vulnerable.yaml`
- Modify: `script/README.md`

### Step 1: FP 抑制 fixture を作成

- [ ] Create `script/actions/taint-scope-fp-safe.yaml`:

```yaml
# このワークフローは sisakulint の TaintTracker シェルスコープ対応 (#447) の
# False Positive 抑制を示すデモ。
#
# ( ... ) サブシェル内での変数上書きは親スコープに漏れない (bash 仕様)。
# scoped TaintTracker はこれを正しく区別し、subshell 内の curl は "sanitized"
# のみを参照、親の curl は依然として tainted な BODY を参照していると判定する。
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          BODY="${{ github.event.pull_request.body }}"
          ( BODY="sanitized"; curl "https://api.example.com?q=$BODY" )
          curl "https://api.example.com?q=$BODY"
```

### Step 2: FN 修正 fixture を作成

- [ ] Create `script/actions/taint-scope-fn-vulnerable.yaml`:

```yaml
# このワークフローは sisakulint の TaintTracker シェルスコープ対応 (#447) の
# False Negative 修正を示すデモ。
#
# 関数本体内で local 宣言された SECRET_LOCAL を echo するパターンは、scope-aware
# な secret-in-log ルールが leak として検出する。
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          SECRET: ${{ secrets.GH_TOKEN }}
        run: |
          leak() {
            local SECRET_LOCAL="$SECRET"
            echo "$SECRET_LOCAL"
          }
          leak
```

### Step 3: `script/README.md` に追記

- [ ] Run: `head -50 script/README.md` でフォーマット確認
- [ ] Edit `script/README.md` — 該当セクション (例: "Examples by rule") に以下を追加:

```markdown
- `taint-scope-fp-safe.yaml` — TaintTracker scope-aware (#447): subshell 内の変数上書きが親スコープに漏れないことを示す
- `taint-scope-fn-vulnerable.yaml` — TaintTracker scope-aware (#447): 関数本体内 local 変数の secret-in-log 検出を示す
```

### Step 4: 手動動作確認

- [ ] Run: `go build -o /tmp/sisakulint ./cmd/sisakulint`
- [ ] Run: `/tmp/sisakulint script/actions/taint-scope-fp-safe.yaml`
- [ ] Expected: 親 curl の `$BODY` についての code-injection (medium または critical) 警告が出る。subshell 内 curl については適切に判定される
- [ ] Run: `/tmp/sisakulint script/actions/taint-scope-fn-vulnerable.yaml`
- [ ] Expected: 関数本体内 echo の SECRET_LOCAL について secret-in-log 警告が出る

### Step 5: Commit

- [ ] Run:
```bash
git add script/actions/taint-scope-fp-safe.yaml script/actions/taint-scope-fn-vulnerable.yaml script/README.md
git commit -m "$(cat <<'EOF'
test(taint): #447 scope-aware fixture 2 ファイルを追加

taint-scope-fp-safe.yaml: subshell 内変数上書きの隔離を示す。
taint-scope-fn-vulnerable.yaml: 関数本体内 local 変数の secret-in-log
正検出を示す。script/README.md に追記。

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: ドキュメント更新と TODO コメント削除

**Files:**
- Modify: `pkg/shell/taint.go` — `PropagateTaint` の docstring から旧 TODO 文言を削除
- Modify: `CLAUDE.md` — TaintTracker の説明にスコープ対応の旨を追記

### Step 1: 旧 TODO コメントを削除

- [ ] Edit `pkg/shell/taint.go` — Task 4 で `PropagateTaint` の docstring を書き換え済み。念のため `grep -n '#447 で対応' pkg/shell/taint.go` で残存していないか確認
- [ ] Run: `grep -n '#447 で対応\|スコープは無視' pkg/shell/taint.go`
- [ ] Expected: 0 件 (Task 4 の置換でクリーンアップ済みのはず)

### Step 2: `CLAUDE.md` の TaintTracker 説明を更新

- [ ] Run: `grep -n 'taint analysis\|TaintTracker\|#446' CLAUDE.md | head`
- [ ] Edit `CLAUDE.md` — `pkg/shell/taint.go` を扱うセクションを更新。具体的には #446 の項目に続けて以下を追加 (既存 `Taint analysis (#446)` の節の末尾あたり):

```markdown
- **Scope-aware propagation (#447)**: `shell.PropagateTaint` は scope frame stack ベースで walk し、`*syntax.Subshell` / `*syntax.CmdSubst` は entry 時に親 visible を snapshot copy して隔離、`*syntax.FuncDecl` 本体は parent への lookup chain で bash dynamic scoping を近似 (`local` / 装飾なし `declare` は本体ローカル、その他は簡略案 A により親に漏らさない)。戻り値は `*shell.ScopedTaint` で、`Final` (script 末尾の親スコープ) と `At(stmt)` (per-stmt visible) を持つ。`taint.go` は per-stmt 展開で `recordRedirWrite` に渡す。`secretinlog.go` は `shellvar:X` マーカーを autofix のため raw 保持する (展開しない)
```

### Step 3: 全テスト最終確認

- [ ] Run: `go test ./...`
- [ ] Expected: 全 pass

### Step 4: lint / vet

- [ ] Run: `go vet ./...`
- [ ] Expected: 警告なし

### Step 5: Commit

- [ ] Run:
```bash
git add CLAUDE.md pkg/shell/taint.go
git commit -m "$(cat <<'EOF'
docs(taint): #447 CLAUDE.md と taint.go docstring を更新

scope-aware な PropagateTaint の挙動と caller ごとの shellvar 展開
ポリシー (taint.go: 展開、secretinlog.go: 保持) を CLAUDE.md に追記。
旧 TODO コメントは Task 4 の docstring 書き換えで削除済み。

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## 完了チェック

- [ ] `pkg/shell/taint_test.go` — `TestPropagateTaint_Scoped` 13 ケース、`TestScopedTaint_At` 5 ケース、全 pass
- [ ] `pkg/core/taint_test.go` — `TestTaintTracker_RedirWriteInSubshell` pass
- [ ] `pkg/core/secretinlog_test.go` — `TestSecretInLog_FunctionLocalScope_DetectsLeak`, `TestSecretInLog_SubshellLocalAssignment_NotLeakedInParent` pass
- [ ] 既存テスト全 pass (回帰なし)
- [ ] `script/actions/taint-scope-fp-safe.yaml` で親 curl の検出が観測できる
- [ ] `script/actions/taint-scope-fn-vulnerable.yaml` で関数内 echo の secret-in-log 警告が出る
- [ ] `pkg/shell/taint.go` の旧 TODO コメント (`#447 で対応`) が削除済み
- [ ] `CLAUDE.md` に scope 対応の説明が追加済み
- [ ] commit 履歴: 10 commits (Task 1-10)

---

## 後続作業 (本プラン外)

- #448 (関数引数の taint 伝播) — 本 plan 完了後に着手可能
- Pipeline / バックグラウンド `&` の subshell 化 — 必要であれば新規 issue 化
- `shell.ScopedTaint.AtExpanded(stmt)` ヘルパ — caller 側展開の DRY 化候補
