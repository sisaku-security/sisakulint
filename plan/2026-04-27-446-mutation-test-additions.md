# #446 Mutation Survived テスト追加 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** PR #450 レビューで指摘された survived mutations を kill するユニットテストを 6 件追加し、issue #446 をクローズする。

**Architecture:** 純粋なテスト追加のみ。3 ファイル（`pkg/core/taint_test.go` / `pkg/shell/taint_test.go` / `pkg/core/secretinlog_test.go`）に同パッケージから非公開関数を直接呼ぶユニットテストを 1 件ずつ／2 件ずつ／1 件追加する。実装ロジックには触らない。

**Tech Stack:** Go / `mvdan.cc/sh/v3/syntax` / 既存 `go test -race` 基盤

**Spec:** `docs/superpowers/specs/2026-04-27-446-mutation-test-additions-design.md`

---

## File Structure

### Modify
- `pkg/core/taint_test.go` — テスト 3 件追加（mutation 1, 2, 3）。import に `strings` と `mvdan.cc/sh/v3/syntax` を追加
- `pkg/shell/taint_test.go` — テスト 2 件追加（mutation 4, 5）。import 既存
- `pkg/core/secretinlog_test.go` — テスト 1 件追加（mutation 6）。import 既存

### 触らない
- `pkg/core/taint.go`
- `pkg/shell/taint.go`
- `pkg/core/secretinlog.go`
- 全ての rule ファイル

---

## Cycle 0: Baseline 確認

### Task 0: 既存テスト全件 PASS を確認

**Files:** なし（実行のみ）

- [ ] **Step 1: 全テスト実行**

```bash
go test -race -count=1 ./pkg/shell/... ./pkg/core/...
```

Expected: PASS（全件成功）

- [ ] **Step 2: 失敗があれば原因を確認して停止**

Mutation テスト追加前から失敗しているテストがあれば本計画と無関係なので、その時点でユーザーに報告して中断。

---

## Cycle 1: pkg/core/taint.go 関連テスト 3 件

### Task 1: `TestAssignmentValueText_SglQuoted` を追加

**Files:**
- Modify: `pkg/core/taint_test.go`

**Why:** `assignmentValueText` の `*syntax.SglQuoted` 分岐（commit `ecc9501` の fix）に対するユニット直接 assert が無いため survived。

- [ ] **Step 1: import に `strings` と `mvdan.cc/sh/v3/syntax` を追加**

`pkg/core/taint_test.go` の先頭を以下のように変更:

```go
package core

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)
```

- [ ] **Step 2: テストヘルパとケースをファイル末尾に追記**

```go
// parseAssignWord は `X=...` 形式のスクリプトを bash として parse し、
// X の代入の右辺 *syntax.Word を返す。assignmentValueText / expandShellvarMarkers
// 等の非公開ヘルパへの直接ユニットテストで使う。
func parseAssignWord(t *testing.T, src string) *syntax.Word {
	t.Helper()
	p := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	f, err := p.Parse(strings.NewReader(src), "")
	if err != nil {
		t.Fatalf("parse %q failed: %v", src, err)
	}
	if len(f.Stmts) == 0 {
		t.Fatalf("no statements parsed for %q", src)
	}
	ce, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(ce.Assigns) == 0 {
		t.Fatalf("no assignment parsed for %q", src)
	}
	return ce.Assigns[0].Value
}

// TestAssignmentValueText_SglQuoted は assignmentValueText が
// *syntax.SglQuoted の Value も連結することを直接 assert する。
// SglQuoted ケースが脱落すると `X='${{ ... }}'` の placeholder が
// 拾えなくなり、以後の taint 検出が落ちる。
func TestAssignmentValueText_SglQuoted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		script string
		want   string
	}{
		{
			name:   "lit_only",
			script: `X=hello`,
			want:   "hello",
		},
		{
			name:   "single_quoted_with_placeholder",
			// SglQuoted.Value がそのまま戻り値に含まれること。
			// SglQuoted ケースが無いと "" になる。
			script: `X='${{ github.event.issue.title }}'`,
			want:   `${{ github.event.issue.title }}`,
		},
		{
			name:   "double_quoted_lit_inside",
			script: `X="abc"`,
			want:   "abc",
		},
		{
			name:   "mixed_lit_and_sglquoted",
			script: `X=pre'inner'post`,
			want:   "preinnerpost",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := parseAssignWord(t, tc.script)
			got := assignmentValueText(w)
			if got != tc.want {
				t.Errorf("assignmentValueText(%q) = %q, want %q", tc.script, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 3: 追加テストのみ実行して PASS を確認**

```bash
go test -race -count=1 -run TestAssignmentValueText_SglQuoted ./pkg/core/...
```

Expected: PASS

---

### Task 2: `TestTaintTracker_ExpandShellvarMarkers_DepthThree` を追加

**Files:**
- Modify: `pkg/core/taint_test.go`

**Why:** `expandShellvarMarkers` の transitive 展開について、現状テストは深さ 2 (`A → B`) までしかカバーしていない。深さ 3 以上の chain が正しく解決されることを assert する。

- [ ] **Step 1: テスト関数をファイル末尾に追記**

```go
// TestTaintTracker_ExpandShellvarMarkers_DepthThree は
// A → B → C → D の 3 段以上 chain でも transitive に taint source が
// 解決され、`shellvar:` マーカーが Sources に残らないことを assert する。
func TestTaintTracker_ExpandShellvarMarkers_DepthThree(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()
	step := &ast.Step{
		ID: &ast.String{Value: "depth3"},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `A="${{ github.event.issue.title }}"
B="$A"
C="$B"
D="$C"
echo "out=$D" >> $GITHUB_OUTPUT`},
		},
	}
	tracker.AnalyzeStep(step)

	outputs, ok := tracker.taintedOutputs["depth3"]
	if !ok {
		t.Fatal("step depth3 should produce tainted outputs")
	}
	sources, ok := outputs["out"]
	if !ok {
		t.Fatalf("output 'out' should be tainted via depth-3 chain, got outputs=%+v", outputs)
	}
	foundOrigin := false
	for _, s := range sources {
		if s == "github.event.issue.title" {
			foundOrigin = true
		}
		if strings.HasPrefix(s, "shellvar:") {
			t.Errorf("unresolved shellvar marker survived expansion: %q (sources=%v)", s, sources)
		}
	}
	if !foundOrigin {
		t.Errorf("taint should trace back to github.event.issue.title via A->B->C->D, got: %v", sources)
	}
}
```

- [ ] **Step 2: 追加テストのみ実行して PASS を確認**

```bash
go test -race -count=1 -run TestTaintTracker_ExpandShellvarMarkers_DepthThree ./pkg/core/...
```

Expected: PASS

---

### Task 3: `TestTaintTracker_ExpandShellvarMarkers_SelfReference` を追加

**Files:**
- Modify: `pkg/core/taint_test.go`

**Why:** `expandShellvarMarkers` の self-reference 短絡（`ref != name`）を assert するテストが無い。`X=$X` のようなパターンで `shellvar:X` が Sources に残ったり、無限ループにならないことを保証する。

- [ ] **Step 1: テスト関数をファイル末尾に追記**

```go
// TestTaintTracker_ExpandShellvarMarkers_SelfReference は
// `X=$X` 形式の自己参照で `shellvar:X` マーカーが Sources に
// 残らず、かつ maxPasses 内で安定停止することを保証する。
func TestTaintTracker_ExpandShellvarMarkers_SelfReference(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()
	step := &ast.Step{
		ID: &ast.String{Value: "self-ref"},
		Exec: &ast.ExecRun{
			Run: &ast.String{Value: `X="${{ github.event.issue.title }}"
X="$X"
echo "out=$X" >> $GITHUB_OUTPUT`},
		},
	}
	tracker.AnalyzeStep(step)

	outputs, ok := tracker.taintedOutputs["self-ref"]
	if !ok {
		t.Fatal("step self-ref should produce tainted outputs")
	}
	sources, ok := outputs["out"]
	if !ok {
		t.Fatalf("output 'out' should remain tainted across self-assign, got outputs=%+v", outputs)
	}
	for _, s := range sources {
		if s == "shellvar:X" {
			t.Errorf("self-reference shellvar:X must not survive expansion, got: %v", sources)
		}
	}
	foundOrigin := false
	for _, s := range sources {
		if s == "github.event.issue.title" {
			foundOrigin = true
		}
	}
	if !foundOrigin {
		t.Errorf("taint should still trace to github.event.issue.title, got: %v", sources)
	}
}
```

- [ ] **Step 2: 追加テストのみ実行して PASS を確認**

```bash
go test -race -count=1 -run TestTaintTracker_ExpandShellvarMarkers_SelfReference ./pkg/core/...
```

Expected: PASS

---

## Cycle 2: pkg/shell/taint.go 関連テスト 2 件

### Task 4: `TestDblQuotedTargetMatches_Compound` を追加

**Files:**
- Modify: `pkg/shell/taint_test.go`

**Why:** `dblQuotedTargetMatches` 内の `len(dq.Parts) != 1` ガードを kill するため、内側 Parts が複合のとき `false` を返すケースを直接 assert する。Mutation `!=` → `==` を入れた場合に Parts[0] が target ParamExp であるテストでないと検出できないため、`"$GITHUB_OUTPUT/$X"` のように先頭が target ParamExp である compound を使う。

- [ ] **Step 1: テスト関数を `TestDblQuotedTargetMatches_NonParam` の直後に追記**

```go
// TestDblQuotedTargetMatches_Compound は内側 Parts が複合の場合
// （`"$GITHUB_OUTPUT/$X"` のように target ParamExp が先頭にあっても）
// false が返ることを assert する。`len(dq.Parts) != 1` ガードを
// 取り除く mutation を kill するため、先頭が target ParamExp である
// compound を必ず含める。
func TestDblQuotedTargetMatches_Compound(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		script string
	}{
		{
			name: "param_lit_param",
			// DblQuoted Parts = [ParamExp(GITHUB_OUTPUT), Lit(/), ParamExp(X)]
			script: `echo x >> "$GITHUB_OUTPUT/$X"`,
		},
		{
			name: "param_then_lit_suffix",
			// DblQuoted Parts = [ParamExp(GITHUB_OUTPUT), Lit(suffix)]
			script: `echo x >> "${GITHUB_OUTPUT}suffix"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := parseScript(t, tc.script)
			w := file.Stmts[0].Redirs[0].Word
			if len(w.Parts) != 1 {
				t.Fatalf("expected single-part outer Word, got %d parts", len(w.Parts))
			}
			dq, ok := w.Parts[0].(*syntax.DblQuoted)
			if !ok {
				t.Fatalf("expected DblQuoted, got %T", w.Parts[0])
			}
			if len(dq.Parts) <= 1 {
				t.Fatalf("setup error: DblQuoted should be compound (>=2 parts), got %d", len(dq.Parts))
			}
			if dblQuotedTargetMatches(dq, "GITHUB_OUTPUT") {
				t.Errorf("compound DblQuoted (parts=%d) must not match target", len(dq.Parts))
			}
		})
	}
}
```

- [ ] **Step 2: 追加テストのみ実行して PASS を確認**

```bash
go test -race -count=1 -run TestDblQuotedTargetMatches_Compound ./pkg/shell/...
```

Expected: PASS

---

### Task 5: `TestExtractHeredocAssignments_CommentLine` を追加

**Files:**
- Modify: `pkg/shell/taint_test.go`

**Why:** `extractHeredocAssignments` の `strings.HasPrefix(line, "#")` ガードを kill するため、heredoc body に `# K=V` 形式コメント行を含めて assignment として誤抽出されないことを assert する。既存 `TestExtractHeredocAssignments_NilAndEdge` には `# comment` 行があるが、`#` 直後に `KEY=VALUE` の形をしていないため、`#` ガード除去後も既存テストが PASS してしまう。

- [ ] **Step 1: テスト関数を `TestExtractHeredocAssignments_NilAndEdge` の直後に追記**

```go
// TestExtractHeredocAssignments_CommentLine は heredoc 本文の
// `# K=V` 形式コメント行を assignment として誤抽出しないことを assert する。
// 既存 NilAndEdge テストは `# comment`（=を含まない）形式のため、
// `#` ガードを取り除いても通ってしまい mutation が survive する。
func TestExtractHeredocAssignments_CommentLine(t *testing.T) {
	t.Parallel()
	src := "cat <<EOF >> $GITHUB_OUTPUT\n# K=ignored\n  # leading_ws=ignored\nNAME=value\nEOF"
	file := parseScript(t, src)
	stmt := file.Stmts[0]
	var hdoc *syntax.Word
	for _, r := range stmt.Redirs {
		if r.Hdoc != nil {
			hdoc = r.Hdoc
			break
		}
	}
	if hdoc == nil {
		t.Fatal("heredoc body not found")
	}
	got := extractHeredocAssignments(hdoc)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry (NAME=value only), got %d: %+v", len(got), got)
	}
	if got[0].name != "NAME" || got[0].value != "value" {
		t.Errorf("got %+v, want {name:NAME, value:value}", got[0])
	}
}
```

- [ ] **Step 2: 追加テストのみ実行して PASS を確認**

```bash
go test -race -count=1 -run TestExtractHeredocAssignments_CommentLine ./pkg/shell/...
```

Expected: PASS

---

## Cycle 3: pkg/core/secretinlog.go 関連テスト 1 件

### Task 6: `TestOffsetToPosition_ColumnValue` を追加

**Files:**
- Modify: `pkg/core/secretinlog_test.go`

**Why:** `offsetToPosition` の Col 計算と Literal=true 補正パスに対する直接 assert が無く、ROW のみの暗黙的 assert になっている。Col 値・Literal 補正・out-of-range フォールバックを table-driven で網羅する。

- [ ] **Step 1: テスト関数をファイル末尾に追記**

```go
// TestOffsetToPosition_ColumnValue は offsetToPosition の Line/Col 計算と
// Literal block 補正、out-of-range フォールバックを直接 assert する。
//
// script のオフセット境界:
//   "echo $TOKEN\n  echo $SECRET\n"
//        ^5             ^19
//   - line 1: `echo $TOKEN` (offset 0..10), '\n' at 11
//   - line 2: `  echo $SECRET` (offset 12..25), '\n' at 26
func TestOffsetToPosition_ColumnValue(t *testing.T) {
	t.Parallel()

	const script = "echo $TOKEN\n  echo $SECRET\n"
	tokenDollar := strings.Index(script, "$TOKEN")   // expect 5
	secretDollar := strings.Index(script, "$SECRET") // expect 19
	if tokenDollar != 5 || secretDollar != 19 {
		t.Fatalf("setup error: tokenDollar=%d, secretDollar=%d", tokenDollar, secretDollar)
	}

	type want struct {
		Line int
		Col  int
	}
	cases := []struct {
		name   string
		runStr *ast.String
		offset int
		want   want
	}{
		{
			name:   "first_line_no_literal",
			runStr: &ast.String{Pos: &ast.Position{Line: 10, Col: 0}, Literal: false},
			offset: tokenDollar,
			want:   want{Line: 10, Col: 6}, // col = 5 + 1
		},
		{
			name:   "second_line_no_literal",
			runStr: &ast.String{Pos: &ast.Position{Line: 10, Col: 0}, Literal: false},
			offset: secretDollar,
			want:   want{Line: 11, Col: 8}, // 19 - 11 - 1 = 7, +1 = 8
		},
		{
			name:   "second_line_literal_block",
			runStr: &ast.String{Pos: &ast.Position{Line: 10, Col: 0}, Literal: true},
			offset: secretDollar,
			want:   want{Line: 12, Col: 8}, // Literal => Line += 1
		},
		{
			name:   "negative_offset_clamped_to_zero",
			runStr: &ast.String{Pos: &ast.Position{Line: 10, Col: 0}, Literal: false},
			offset: -1,
			want:   want{Line: 10, Col: 1}, // forced to 0, col = 0 + 1
		},
		{
			name:   "out_of_range_offset_clamped_to_zero",
			runStr: &ast.String{Pos: &ast.Position{Line: 10, Col: 0}, Literal: false},
			offset: len(script) + 5,
			want:   want{Line: 10, Col: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := offsetToPosition(tc.runStr, script, tc.offset)
			if got.Line != tc.want.Line || got.Col != tc.want.Col {
				t.Errorf("got Line=%d Col=%d, want Line=%d Col=%d",
					got.Line, got.Col, tc.want.Line, tc.want.Col)
			}
		})
	}
}
```

- [ ] **Step 2: 追加テストのみ実行して PASS を確認**

```bash
go test -race -count=1 -run TestOffsetToPosition_ColumnValue ./pkg/core/...
```

Expected: PASS

---

## Cycle 4: 全件再実行・コミット・issue クローズ

### Task 7: 全テスト PASS の最終確認・main 直接コミット・issue close

**Files:** なし（実行・コミット・gh CLI のみ）

- [ ] **Step 1: 全テスト再実行**

```bash
go test -race -count=1 ./pkg/shell/... ./pkg/core/...
```

Expected: PASS（既存テスト + 追加 6 件すべて）

- [ ] **Step 2: vet も通すことを確認**

```bash
go vet ./pkg/shell/... ./pkg/core/...
```

Expected: 出力なし

- [ ] **Step 3: ステージして main に直接コミット**

```bash
git add pkg/core/taint_test.go pkg/shell/taint_test.go pkg/core/secretinlog_test.go \
        plan/2026-04-27-446-mutation-test-additions.md \
        docs/superpowers/specs/2026-04-27-446-mutation-test-additions-design.md

git commit -m "$(cat <<'EOF'
test(taint): #446 mutation survived テスト6件を追加

HikaruEgashira レビュー (PR #450) で指摘された survived mutations を
kill するユニットテストを追加。ロジック変更なし。

- pkg/core/taint_test.go: assignmentValueText SglQuoted /
  expandShellvarMarkers depth>=3 chain / self-reference
- pkg/shell/taint_test.go: dblQuotedTargetMatches compound /
  extractHeredocAssignments comment line
- pkg/core/secretinlog_test.go: offsetToPosition Line/Col/Literal/
  out-of-range fallback

Refs: #446
EOF
)"
```

- [ ] **Step 4: コミット成功を確認**

```bash
git log -1 --oneline
git status
```

Expected: HEAD が新しいコミットで status は clean

- [ ] **Step 5: main に push（ユーザー承認後）**

⚠️ **push は破壊的操作の対極ではないが共有状態を変える。実行前にユーザーに確認すること。**

```bash
git push origin main
```

- [ ] **Step 6: issue #446 をクローズ**

```bash
gh issue close 446 --repo sisaku-security/sisakulint --comment "$(cat <<'EOF'
PR #450 で実装、本コミット (test(taint): #446 mutation survived テスト6件を追加) で
HikaruEgashira レビュー指摘の mutation survived 6 件のユニットテストを追加。

epic #445 の子 issue として完了。後続子 issue は #447 (シェルスコープ対応) /
#448 (関数引数の taint 伝播)。
EOF
)"
```

- [ ] **Step 7: issue がクローズされたことを確認**

```bash
gh issue view 446 --repo sisaku-security/sisakulint --json state,closedAt
```

Expected: `state: "CLOSED"` と `closedAt` がセットされている

---

## Risk / Rollback

- 追加テストが PASS しない場合 → 該当テストの assertion を実装の実挙動に合わせて修正（mutation 元の意図と乖離していないか spec 章を再確認）。実装側を変えてはいけない（本計画はテストのみのスコープ）
- `go test -race` が他のテストで落ちる場合 → 本計画の追加テストとは無関係なので、コミット前にユーザーに報告して中断
- push 後に CI で問題発生 → revert は `git revert <SHA>` で 1 コミット戻す（コミットを 1 つにまとめている理由）
