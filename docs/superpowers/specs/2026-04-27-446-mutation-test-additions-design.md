# #446 Mutation Survived テスト追加 設計仕様

## 背景

Issue #446（TaintTracker AST ベース移行）の本体は PR #450 でマージ済み（regression 0、function カバレッジ 90%+）。レビュアー HikaruEgashira による mutation testing で 6 件の survived mutations が報告された。これらはいずれも実バグではなく **テストの assert 不足** に起因するもので、follow-up としてユニットテストを追加することで mutation を kill する。

PR #450 のレビュー本文より該当箇所を引用:

> Survived 6 件はいずれも実バグではなくテストの assert 不足。Approve は妨げないが、follow-up で補強推奨

本仕様書はその follow-up を扱う。

## 目標

- 報告された 6 件の survived mutations を kill するユニットテストを追加する
- ロジック変更は **行わない**（テストの追加のみ）
- 完了後 issue #446 をクローズする

## 非目標

- Mutation testing ツールの導入・自動化（手動レビューでの確認に留める）
- Survived mutations 以外のカバレッジ拡張
- 後続子チケット #447 / #448 への着手

## 対象 mutation と テスト設計

### Mutation 1: `assignmentValueText` SglQuoted ケース

**実装**: `pkg/core/taint.go:272-287`

`X='${{ github.event.issue.title }}'` のように single-quoted で囲まれた `${{ ... }}` プレースホルダは、AST 上では `*syntax.Lit` ではなく `*syntax.SglQuoted.Value` に格納される。fix commit `ecc9501` で `*syntax.SglQuoted` ケースを追加し、placeholder 検出に貢献するようにした。

レビュー指摘:「end-to-end では検出可だがユニットでは弱い」。よって **直接ユニットテスト** を追加する。

**追加テスト**: `pkg/core/taint_test.go::TestAssignmentValueText_SglQuoted`

```go
// X='content with ${{ expr }}' を bash パーサで Word にし、assignmentValueText を直接呼ぶ
// → 戻り値が SglQuoted.Value 部分を含むことを assert
// 比較: SglQuoted ケースが無ければ空文字列が返る
```

同パッケージの非公開関数として直接呼び出し可能（`pkg/core/taint_test.go` は `package core`）。テストは Lit のみ / SglQuoted のみ / 混在の 3 ケースで table-driven。

### Mutation 2: `expandShellvarMarkers` 深さ ≥3 chain

**実装**: `pkg/core/taint.go:406-437`

`A → B → C → D` のような 3 段以上の shellvar chain で transitive 展開が正しく行われることを確認するテストが現状は深さ 2 までしかない。

**追加テスト**: `pkg/core/taint_test.go::TestTaintTracker_ExpandShellvarMarkers_DepthThree`

```bash
A="${{ github.event.issue.title }}"
B="$A"
C="$B"
D="$C"
echo "$D" >> "$GITHUB_OUTPUT"
```

期待: `D` の最終 Sources に `github.event.issue.title` が含まれる（`shellvar:C` のような未解決マーカーは残らない）。

### Mutation 3: `expandShellvarMarkers` self-reference ガード

**実装**: `pkg/core/taint.go:414`（`ref != name` 短絡）

`X=$X` のような自己参照で無限ループせず、`shellvar:X` マーカーが Sources に残らないことを assert。

**追加テスト**: `pkg/core/taint_test.go::TestTaintTracker_ExpandShellvarMarkers_SelfReference`

```bash
X="${{ github.event.issue.title }}"
X="$X"
echo "$X" >> "$GITHUB_OUTPUT"
```

期待: `X` の Sources に `github.event.issue.title` を含み、`shellvar:X` を含まない。実行が `maxPasses` (16) 内で終わる。

### Mutation 4: `dblQuotedTargetMatches` compound 不一致

**実装**: `pkg/shell/taint.go:328-337`

`"$GITHUB_OUTPUT/$X"` のような複合 DblQuoted は単一 ParamExp ではないため `len(dq.Parts) != 1` で `false` を返す。この **negative ケース** を assert するテストが無い。

**追加テスト**: `pkg/shell/taint_test.go::TestDblQuotedTargetMatches_Compound`

`pkg/shell/taint_test.go` は同パッケージのため `dblQuotedTargetMatches` を直接呼び出せる。既存 `TestDblQuotedTargetMatches_NonParam` の隣に同形で追加する。

```go
// `"$GITHUB_OUTPUT/$X"` を parse して dq を取り出し、
// dblQuotedTargetMatches(dq, "GITHUB_OUTPUT") == false を assert
// 併せて `"${GITHUB_OUTPUT}suffix"` のように Lit が混じる compound も false を assert
```

### Mutation 5: heredoc 内 `# K=V` コメント除外

**実装**: `pkg/shell/taint.go:368`（`strings.HasPrefix(line, "#")` 除外）

heredoc 本文に `# K=V` 形式のコメント行が含まれる場合に assignment として誤抽出しないことを assert。

**追加テスト**: `pkg/shell/taint_test.go::TestExtractHeredocAssignments_CommentLine`

`extractHeredocAssignments` を直接呼び出すユニットテスト。同パッケージなのでアクセス可能。

```go
// heredoc body Word を `# K=ignored\nNAME=value\n  # leading_ws_K=ignored\n` 相当で構築
// extractHeredocAssignments(hdoc) を呼ぶ
// 戻り値が name="NAME", value="value" のみ 1 件であることを assert
// （leading whitespace のあるコメント行も TrimSpace 後に `#` で始まれば除外される点も assert）
```

### Mutation 6: `offsetToPosition` の Col 値

**実装**: `pkg/core/secretinlog.go:319-337`

複数行 script で sink offset を Position に変換する際、`Line` だけでなく `Col` も正しく計算されることを assert する直接テストが無い。

**追加テスト**: `pkg/core/secretinlog_test.go::TestOffsetToPosition_ColumnValue`

`offsetToPosition` を直接呼び出すユニットテスト。table-driven で複数ケースを並べる。

```go
// script:  "echo $TOKEN\n  echo $SECRET\n"
//
// ケース 1: offset = 5 (= "$TOKEN" の "$" 位置, line 1)
//   期待: Line == runStr.Pos.Line, Col == 6
// ケース 2: offset = 19 (= "$SECRET" の "$" 位置, line 2 内, 行頭 from "  echo ")
//   期待: Line == runStr.Pos.Line + 1, Col == 8 ("$SECRET" の前に 2 spaces + "echo " + 1 space = 7 文字, +1 で col=8)
// ケース 3: runStr.Literal == true でのケース 2 → Line++ 補正で Line == runStr.Pos.Line + 2
// ケース 4: offset < 0 / offset > len(script) のフォールバック (offset = 0 として計算)
```

各ケースで `Line` と `Col` の両方を assert することが mutation 6 を kill する条件。

## ファイル変更一覧

### Modify
- `pkg/core/taint_test.go` — 3 テスト追加
- `pkg/shell/taint_test.go` — 2 テスト追加
- `pkg/core/secretinlog_test.go` — 1 テスト追加

### 触らない
- `pkg/core/taint.go`
- `pkg/shell/taint.go`
- `pkg/core/secretinlog.go`
- `pkg/core/workflow_taint.go`
- 全ての rule ファイル

## テスト実行

```bash
go test -race -count=1 ./pkg/shell/... ./pkg/core/...
```

期待: 全件 PASS（既存テストとの相互作用なし）。

## コミット運用

- ブランチ: **main 直接コミット**（ユーザー承認済み）
- コミット数: **1**（ロジック変更ゼロのテスト追加なので分割不要）

コミットメッセージ:

```
test(taint): #446 mutation survived テスト6件を追加

HikaruEgashira レビュー (PR #450) で指摘された survived mutations を
kill するユニットテストを追加。ロジック変更なし。

- pkg/core/taint_test.go: SglQuoted / depth>=3 chain / self-ref
- pkg/shell/taint_test.go: compound DblQuoted target / heredoc コメント
- pkg/core/secretinlog_test.go: offsetToPosition Col 値
```

## クローズ手順

1. テスト追加コミットを main に push
2. CI pass を確認
3. `gh issue close 446 --comment "PR #450 で実装、本コミットで mutation survived テスト 6 件追加。epic #445 の子 issue として完了。"` を実行

## 親 epic

#445（後続子 issue: #447 シェルスコープ対応 / #448 関数引数の taint 伝播）
