# TaintTracker AST 化と secret-in-log の taint 機構共通基盤化 — 設計書

**Issue**: [#446](https://github.com/sisaku-security/sisakulint/issues/446) (epic [#445](https://github.com/sisaku-security/sisakulint/issues/445))
**作成日**: 2026-04-25
**ステータス**: ドラフト（設計承認待ち）
**スコープ選択**: B（Refactor + AST 化で自然に拾えるギャップ修正）+ b（共通 Propagator まで抜き出す中程度の統合）+ A（`pkg/shell/taint.go` に純関数として配置）+ A（1 PR big-bang）

---

## 1. 目的とゴール

`pkg/core/taint.go` の `TaintTracker`（`code-injection` / `request-forgery` / `env-var-injection` ルールが利用）と、`pkg/core/secretinlog.go` 内の独立した taint 機構を **AST ベース**で統合する。

### 1.1 期待される成果

1. **二重実装の解消**: `taint.go`（regex）と `secretinlog.go`（AST）に散在する taint 伝播ロジックを `pkg/shell/taint.go` の純関数群に集約
2. **AST 化による自然な FP/FN 修正**: regex の限界で誤検出/見逃ししていたパターン（コメント内 `# X=$Y`、ヒアドキュメント内 `=`、行継続を跨ぐ代入、一行複数代入）を AST により自動的に正しく扱う
3. **将来の scope 対応 (#447) と関数引数 (#448) の地ならし**: 共通基盤が整うことで後続 issue の実装範囲が明確になる

### 1.2 非ゴール（明示的に「やらない」）

| 項目 | 理由 | 対応先 |
|---|---|---|
| シェルスコープ意味論（subshell / function / `local`） | 意味論変更で挙動広範影響 | #447 |
| 関数引数 (`$1`, `$@`) の taint 伝播 | 設計が非自明 | #448 |
| コマンド置換 `X=$(cmd)` の cmd 出力を tainted 扱い | 過剰 FP の懸念 | 必要時に別途起票 |
| 配列要素 `arr[0]=$X` の追跡 | 利用頻度低 | 必要時に別途起票 |
| `${VAR:-default}` のデフォルト値展開を考慮した非伝播判定 | 利用パターンが読めない | 既存の保守的伝播を維持 |
| `WorkflowTaintMap` / `WorkflowSecretTaintMap` の統合 | 別レイヤー | #392 / #432 / #433 |
| `pkg/core/secretexfiltration.go` の AST 化 | 別ルール | #449 |
| `pkg/shell/parser.go` 既存メソッドの置換 | 既存 caller への影響大 | 必要時に別途起票 |

### 1.3 設計フィロソフィー

- **AST 化で自然に消える FP は受け入れる**: regex 由来の誤検出はテスト期待値修正を伴ってでも消す
- **意味論を変える FP/FN 改善はしない**: subshell scope などの semantic な改善は別 issue（#447）で
- **新規 FP を持ち込みうる機能は実装しない**: コマンド置換・配列・デフォルト値展開などは慎重に避ける
- **公開 API は維持**: caller (`codeinjection.go` 等) の import や呼び出し変更ゼロ

---

## 2. アーキテクチャ全体像

```
┌─────────────────────────────────────────────────────────────┐
│ pkg/shell/taint.go (新設) - 純関数 / state を持たない        │
├─────────────────────────────────────────────────────────────┤
│ Entry / AssignmentInfo / RedirWrite 型                       │
│ WalkAssignments / WordReferencesEntry                        │
│ PropagateTaint (forward dataflow, order-aware, 1 パス)       │
│ WalkRedirectWrites (target = GITHUB_OUTPUT / GITHUB_ENV ...) │
└─────────────────────────────────────────────────────────────┘
              ▲                                  ▲
              │                                  │
   ┌──────────┴─────────┐             ┌──────────┴────────┐
   │ pkg/core/taint.go  │             │ pkg/core/         │
   │ (TaintTracker)     │             │ secretinlog.go    │
   │                    │             │ (SecretInLogRule) │
   │ - regex 削除        │             │                   │
   │ - Propagator 利用   │             │ - propagateTaint  │
   │ - public API 維持   │             │   削除 → 共通へ    │
   │   (caller 影響 0)  │             │ - 既存 order-aware │
   │                    │             │   動作完全維持     │
   └────────────────────┘             └───────────────────┘
              ▲                                  ▲
   ┌──────────┴─────────┐                       │
   │ codeinjection.go   │              既存挙動完全維持
   │ requestforgery.go  │
   │ envvarinjection.go │
   └────────────────────┘
```

### 2.1 主要な設計ポイント

1. **`pkg/shell/taint.go` は純関数**: state を持たず、入力 AST + initial taint を受け取って taint map を返す。テスト容易性が高い
2. **TaintTracker の public API は不変**: `NewTaintTracker()` / `AnalyzeStep()` / `IsTainted()` / `IsTaintedExpr()` / `RegisterJobOutputs()` / `GetTaintedOutputs()` のシグネチャは維持
3. **共通 `Entry` 型**: `Sources []string` と `Offset int` の両方を持つ
   - TaintTracker 既存の「複数 source 対応」を維持
   - secretinlog 既存の「order-aware FP 抑制」を維持
4. **AST 化で自然に拾われるギャップ**:
   - コメント内の `# X=$Y` を誤マッチしなくなる
   - ヒアドキュメント内 `=` を誤マッチしなくなる
   - クォート文字列内の `=` を誤マッチしなくなる
   - 行継続 `\` を跨ぐ代入を正しく拾う
   - 一行複数代入 `X=1; Y=$Z` を両方拾う
   - `export X=Y` / `local X=Y` / `readonly X=Y` (DeclClause) を統一的に扱う
   - heredoc 経由の `>> $GITHUB_OUTPUT` を共通の `WalkRedirectWrites` で扱う

---

## 3. `pkg/shell/taint.go` API 詳細

### 3.1 データ型

```go
// Entry は一つの変数（または step output）が tainted であることを表す。
type Entry struct {
    // Sources は taint の上流（複数あり得る）。
    // 例: ["github.event.issue.title"], ["secrets.GCP_KEY"], ["shellvar:URL"]
    // 表示用の主 origin は Sources[0]（呼び出し側で First() を使う）。
    // 重複は PropagateTaint 側で除去する（既存 taint.go の deduplicateStrings 相当）。
    // 順序保持で重複なし。
    Sources []string

    // Offset は variable が tainted になった時点のスクリプト内バイトオフセット。
    // env 由来（スクリプト開始前から tainted）は -1。
    // sink との比較で order-aware FP 抑制に使う（sink.Offset > Entry.Offset で leak 確定）。
    Offset int
}

func (e Entry) First() string

// AssignmentInfo は walk 中に検出した代入文の情報。
type AssignmentInfo struct {
    Name    string         // LHS 変数名
    Value   *syntax.Word   // RHS（nil のことあり: `local X` のような宣言のみ）
    Offset  int            // assign.Pos().Offset()
    Keyword AssignKeyword  // None / Export / Local / Readonly / Declare
}

type AssignKeyword int
const (
    AssignNone AssignKeyword = iota
    AssignExport
    AssignLocal
    AssignReadonly
    AssignDeclare
)

// RedirWrite は `>> $TARGET` 系リダイレクトに書き込まれた NAME=VALUE ペア。
type RedirWrite struct {
    Name      string         // パース済み NAME
    Value     string         // パース済み VALUE 文字列（変数参照も含む生形）
    ValueWord *syntax.Word   // VALUE 部分の Word（nil の場合あり: heredoc など）
    Stmt      *syntax.Stmt   // 元の Stmt（位置情報やフォローアップ解析用）
    Offset    int            // 書き込み箇所のバイトオフセット
    IsHeredoc bool           // heredoc 由来かどうか
}
```

### 3.2 関数シグネチャ

```go
// WalkAssignments は file 内の全代入文を順序通りに返す。
func WalkAssignments(file *syntax.File) []AssignmentInfo

// WordReferencesEntry は word 内で tainted 集合に含まれる ParamExp が
// 1 つでも参照されていれば（first-match の名前, true）を返す。
// $X, ${X}, "${X}" すべて拾う。$$, $1, $@ などは対象外。
func WordReferencesEntry(word *syntax.Word, tainted map[string]Entry) (string, bool)

// PropagateTaint は initial を seed として AST を順方向 1 パス walk し、
// 代入の RHS が tainted な変数を参照していれば LHS を tainted に追加する。
//
// セマンティクス:
//   - 既に tainted な変数への再代入は origin 上書きしない（最初の taint を保持）
//   - LHS 名は AST 順序で処理される（forward dataflow）
//   - 代入の RHS が tainted を参照しない場合は LHS に何もしない（"untaint" はしない）
//   - スコープは無視（subshell/function 内も親と同じ namespace ← 本 issue では維持、#447 で対応）
//
// 戻り値は initial を変更せず新しい map を返す。
func PropagateTaint(file *syntax.File, initial map[string]Entry) map[string]Entry

// WalkRedirectWrites は `>> $TARGET` または `> $TARGET` リダイレクトを持つ Stmt を探し、
// 書き込まれる NAME=VALUE ペアを抽出する。
//
// target の例: "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_STEP_SUMMARY"
// `${TARGET}` / `"$TARGET"` 等の表記揺れは正規化して比較。
func WalkRedirectWrites(file *syntax.File, target string) []RedirWrite
```

### 3.3 設計上の判断と境界

| 項目 | 採用 | 理由 |
|---|---|---|
| state | 持たない（純関数） | テストしやすい、並行安全 |
| スコープ意味論 | 単一フラット namespace | 本 issue は挙動不変（B）が前提。#447 で対応 |
| 関数引数 `$1`, `$@` | 追跡しない | #448 で対応 |
| コマンド置換 `X=$(cmd)` | RHS 内の ParamExp 参照だけ見る | 既存挙動と同じ |
| 算術代入 `((X=1))` | 対象外 | RHS が untrusted source にならない |
| Heredoc 内の `X=Y` | 対象外（実行されない） | HeredocBody は `*syntax.Assign` ではない |
| `WalkRedirectWrites` の target 比較 | 文字列正規化 | 既存実装の振る舞いを踏襲 |

### 3.4 既存 `pkg/shell/parser.go` との関係

- `ShellParser` は `parser.Parse` の薄いラッパで、変数使用箇所列挙系の API を持つ
- 新 `taint.go` は `*syntax.File` を直接受け取る純関数群（Parser 不要）
- 将来 `ShellParser` のメソッドとして wrap する余地は残すが、本 issue では裸の関数で進める

---

## 4. `pkg/core/taint.go` (TaintTracker) の書き換え

### 4.1 公開 API は完全維持

caller (`codeinjection.go` / `requestforgery.go` / `envvarinjection.go`) からは何も変えない。

### 4.2 内部の置き換えマップ

下記はすべて `taint.go` 内の **internal メソッド/関数** の置換マップ。public API（Section 4.1）は変更なし。

| 既存（regex） | 置き換え後 | 削除 |
|---|---|---|
| `analyzeScript(stepID, script string)` (private) | `analyzeScript(stepID, file *syntax.File)` (private) | – |
| `findTaintedVariableAssignments(script)` | `shell.PropagateTaint(file, initial)` | **削除** |
| `findGitHubOutputWrites(stepID, script)` | `shell.WalkRedirectWrites(file, "GITHUB_OUTPUT")` | **削除** |
| `processHeredocPatterns` | 同上（heredoc は WalkRedirectWrites 内で扱う） | **削除** |
| `checkAndRecordTaint(stepID, name, value)` | 引数型を string→`RedirWrite` に薄く改修 | – |
| `extractUntrustedSources(value)` | 残す（GHA 式は文字列ベースで OK） | – |
| `isUntrustedExpression(exprContent)` | 残す | – |
| `populateTaintedVarsFromEnv(env)` | 残す | – |
| `analyzeActionStep` / `extractActionName` / `initKnownTaintedActions` | 残す（Phase 3 機能） | – |

### 4.3 内部データ型の変更

```go
type TaintTracker struct {
    // [変更] string slice → Entry（Offset を持つ汎用形に）
    taintedVars map[string]shell.Entry  // was: map[string][]string

    // [不変] step output ベースの蓄積
    taintedOutputs map[string]map[string][]string
    knownTaintedActions map[string][]KnownTaintedOutput
}
```

`GetTaintedOutputs()` の戻り値型 `map[string]map[string][]string` は変えない。`Entry.Sources` をそのまま `[]string` として詰める。

### 4.4 B（自然に拾えるギャップ修正）で改善するパターン

| パターン | 旧 regex の挙動 | 新 AST の挙動 |
|---|---|---|
| `# X="${{ ... }}"` （コメント） | 誤検出 | 正しく除外 |
| `cat <<EOF\nX=${{ ... }}\nEOF` | 誤検出 | 正しく除外 |
| `X=1; Y="${{ ... }}"` | 見逃し（行頭アンカー） | 両方拾う |
| `X="${{ ... }}" \\\n   Y` | 見逃し（行ベース分断） | 1 つの assignment として扱う |
| `export X="${{ ... }}"` | 対応済み | 自然に対応（DeclClause） |

---

## 5. `pkg/core/secretinlog.go` の書き換え

### 5.1 何を変えて何を残すか

| 既存 | 処理 | 理由 |
|---|---|---|
| `taintEntry` 型 | **削除** → `shell.Entry` を直接使用 | 二重定義解消 |
| `propagateTaint` | **削除** → `shell.PropagateTaint` | 共通化 |
| `wordReferencesTainted` | **削除** → `shell.WordReferencesEntry` | プリミティブ共通化 |
| `firstTaintedVarIn` | **削除** → `shell.WordReferencesEntry` の戻り値 | 同上 |
| `findEchoLeaks` | **保持** | sink 検出は固有 |
| `collectRedirectSinkLeaks` | **保持** | cat/tee/dd の here-string/heredoc は固有 |
| `collectLeakedVars` | **保持** | sink 引数走査は固有 |
| `stmtRedirectsStdoutAwayFromLog` | **保持** | sink 除外判定 |
| `collectGitHubEnvTaintWrites` | **書き換え** → 内部で `shell.WalkRedirectWrites(file, "GITHUB_ENV")` | $GITHUB_ENV 検出の重複排除 |
| `addAutoFixerForLeak` / `secretInLogFixer` | **保持** | auto-fix は完全に固有 |
| `crossStepEnv` フィールド | **保持** | cross-step 伝播ロジックは本 issue 範囲外で動作不変 |

### 5.2 `taintEntry` → `shell.Entry` 移行の具体例

**before**:
```go
entry, ok := tainted[name]
if !ok || entry.offset >= sinkOffset {
    return
}
leak := echoLeakOccurrence{Origin: entry.origin, ...}
```

**after**:
```go
entry, ok := tainted[name]
if !ok || entry.Offset >= sinkOffset {  // .offset → .Offset
    return
}
leak := echoLeakOccurrence{Origin: entry.First(), ...}  // entry.origin → entry.First()
```

---

## 6. テスト戦略（TDD）

### 6.1 TDD レッドサイクルの順序

t_wada 流に沿って 3 サイクルで進める:

```
Cycle 1: pkg/shell/taint_test.go (新規) RED
  → pkg/shell/taint.go (新規) 最小実装で GREEN
  → refactor

Cycle 2: pkg/core/taint_test.go に B-pattern テスト追加 RED
  → pkg/core/taint.go を shell.* 利用に書き換え GREEN
  → refactor（旧 regex 関数を削除）

Cycle 3: pkg/core/secretinlog_test.go に B-pattern テスト追加 RED
  → pkg/core/secretinlog.go を shell.* 利用に書き換え GREEN
  → refactor（旧 propagateTaint 等を削除）
```

### 6.2 `pkg/shell/taint_test.go` の主要ケース

#### PropagateTaint
- TestPropagateTaint_EmptyInitial
- TestPropagateTaint_DirectAssignment
- TestPropagateTaint_Concatenation（複数 source マージ）
- TestPropagateTaint_OrderAware（assign の Offset 検証）
- TestPropagateTaint_DeclClause_ExportLocalReadonly
- TestPropagateTaint_HeredocBody_NotPropagated
- TestPropagateTaint_Comment_NotPropagated
- TestPropagateTaint_OneLiner_MultipleAssigns
- TestPropagateTaint_Subshell_FlatNamespace（本 issue 維持）
- TestPropagateTaint_FixedPoint_NotNeeded

#### WordReferencesEntry
- TestWordReferencesEntry_PlainParam
- TestWordReferencesEntry_BracedParam
- TestWordReferencesEntry_QuotedString
- TestWordReferencesEntry_NotReferenced
- TestWordReferencesEntry_FirstMatch

#### WalkAssignments
- TestWalkAssignments_Simple
- TestWalkAssignments_OneLinerMultiple
- TestWalkAssignments_DeclClause
- TestWalkAssignments_NoValue（`local X` だけ）

#### WalkRedirectWrites
- TestWalkRedirectWrites_EchoToOutput
- TestWalkRedirectWrites_QuotedTarget
- TestWalkRedirectWrites_BracedTarget
- TestWalkRedirectWrites_PrintfPattern
- TestWalkRedirectWrites_HeredocBody（IsHeredoc=true）
- TestWalkRedirectWrites_HeredocStripTabs（`<<-EOF`）
- TestWalkRedirectWrites_DifferentTarget
- TestWalkRedirectWrites_NoRedirect
- TestWalkRedirectWrites_TargetWithPrefix（`"$X/$GITHUB_OUTPUT"` → 0件）

すべて Table-driven test + `t.Parallel()`（CLAUDE.md 準拠）。

### 6.3 既存テストの扱い

- `pkg/core/taint_test.go` / `taint_integration_test.go` / `secretinlog_test.go` は原則**全件 pass**を維持
- B のスコープで AST 化により挙動が変わるテストがあれば期待値修正、レビューコメントで明示

### 6.4 B 用の新規テスト

`pkg/core/taint_test.go` に追加（regex → AST で挙動が変わるパターン、**ここが本 PR の改善エビデンス**）:
- TestTaintTracker_CommentLineNotMisdetected
- TestTaintTracker_HeredocBodyNotMisdetected
- TestTaintTracker_OneLinerMultipleAssignments
- TestTaintTracker_LineContinuation

`pkg/core/secretinlog_test.go` への追加は **リグレッションテスト目的**（secretinlog は既に AST ベースなので挙動は変わらないはず）。Refactor の安全網として、上記と同等パターンで「secret 漏洩判定」が変化していないことを確認する 4 件を追加する。

### 6.5 カバレッジ目標

- `pkg/shell/taint.go`: **90% 以上**
- `pkg/core/taint.go` / `secretinlog.go`: 現状維持以上（`go test -coverprofile` で測定）

CLAUDE.md の 80% 基準を最低ラインとする。

### 6.6 リグレッションテスト

`script/actions/` 配下の脆弱/安全サンプルワークフローに `sisakulint` を実行し、検出件数差分が「想定された FP 削減」のみであることを確認:

```bash
go build ./cmd/sisakulint
git checkout main && ./sisakulint script/actions/ > /tmp/before.txt
git checkout <feature-branch> && ./sisakulint script/actions/ > /tmp/after.txt
diff /tmp/before.txt /tmp/after.txt
```

---

## 7. PR 戦略

**1 PR（big-bang）** で進める:
- `pkg/shell/taint.go` 新設 + `pkg/core/taint.go` 書き換え + `pkg/core/secretinlog.go` 書き換え
- 想定差分: 700-1000 行
- PR description にこの spec doc へのリンク + Section 4.4 / Section 5 の変更マップを貼る

---

## 8. 工数見積

| サイクル | 内容 | 工数 |
|---|---|---|
| Cycle 1 | `pkg/shell/taint.go` + `taint_test.go` 新設 | 2-3 日 |
| Cycle 2 | `pkg/core/taint.go` 書き換え + B-pattern テスト追加 | 1-2 日 |
| Cycle 3 | `pkg/core/secretinlog.go` 書き換え + B-pattern テスト追加 | 1-2 日 |
| 統合・リグレッション・lint・doc | `script/actions/` 確認 / godoc / CLAUDE.md 更新 | 1 日 |
| **合計** | – | **5-8 日** |

---

## 9. リスクと対策

| リスク | 影響 | 対策 |
|---|---|---|
| `mvdan.cc/sh/v3/syntax` の DeclClause 解析が `export X=Y` と `export X` を均等に扱わない可能性 | `WalkAssignments` の挙動ぶれ | Cycle 1 のテストで両ケース明示確認、必要なら helper で正規化 |
| heredoc 内 `>>` リダイレクトを `WalkRedirectWrites` がどう扱うか曖昧 | 既存 `processHeredocPatterns` 動作が変わる | 既存テスト網羅性確認、不足あれば追加 |
| `taintedVars` を `map[string]shell.Entry` に変える際、`GetTaintedOutputs()` 戻り値型との変換漏れ | 後方互換性破壊 | テストで戻り値の shape を assert |
| `secretinlog.go` の `crossStepEnv` 伝播が書き換え後に動作変化 | cross-step 検出が落ちる | `TestCrossStepTaint*` シリーズで担保、書き換え後重点確認 |
| AST 化で「これまで誤検出していたパターン」が消えることで、ユーザーが慣れていたエラーが出なくなる | UX の予期せぬ変化 | PR description で明記、CHANGELOG に記載 |
| Big-bang PR が 1000 行近くなりレビュー長期化 | マージ遅延 | Section 4.4 / Section 5 の変更マップを PR description にコピー |

---

## 10. 受入条件（Definition of Done）

- [ ] `pkg/shell/taint.go` 新設、godoc 完備
- [ ] `pkg/shell/taint_test.go` 新設、カバレッジ 90% 以上
- [ ] `pkg/core/taint.go` から regex ベースの `findTaintedVariableAssignments` / `findGitHubOutputWrites` / `processHeredocPatterns` を**削除**
- [ ] `pkg/core/secretinlog.go` から `propagateTaint` / `wordReferencesTainted` / `firstTaintedVarIn` / `taintEntry` を**削除**
- [ ] 既存テスト全件 pass（変更を加えたテストはレビューコメントで明示）
- [ ] B-pattern の新規テスト 4件 + secretinlog 同等 が pass
- [ ] `golangci-lint run --fix` でエラーゼロ
- [ ] `script/actions/` リグレッション diff が「想定された FP 削減」のみ
- [ ] この spec doc を repo に commit 済み

---

## 11. 関連 issue

- 親 epic: [#445](https://github.com/sisaku-security/sisakulint/issues/445)
- 後続: [#447](https://github.com/sisaku-security/sisakulint/issues/447)（scope 対応） / [#448](https://github.com/sisaku-security/sisakulint/issues/448)（関数引数）
- 補完関係: [#392](https://github.com/sisaku-security/sisakulint/issues/392) / [#432](https://github.com/sisaku-security/sisakulint/issues/432) / [#433](https://github.com/sisaku-security/sisakulint/issues/433)（cross-workflow taint）
- 別ルール: [#449](https://github.com/sisaku-security/sisakulint/issues/449)（secret-exfiltration AST 化）
