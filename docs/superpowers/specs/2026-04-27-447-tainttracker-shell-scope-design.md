# #447: TaintTracker のシェルスコープ対応 (subshell / function / export / local) — 設計

| 項目 | 内容 |
| --- | --- |
| Issue | [#447](https://github.com/sisaku-security/sisakulint/issues/447) |
| 親 Epic | [#445](https://github.com/sisaku-security/sisakulint/issues/445) (TaintTracker AST 移行・拡張) |
| 関連 / 後続 | #448 (関数引数 taint 伝播 — 本 issue が unblock) |
| 前提 | #446 (TaintTracker AST 化) — マージ済み (commit `d3ab32a`) |
| 工数目安 | 2-3 日 |
| 作成日 | 2026-04-27 |

---

## 1. 背景と目的

`pkg/shell/taint.go::PropagateTaint` は AST ベース化済み (#446) だが、スクリプト全体をフラットな単一名前空間として扱っており、以下のシェルスコープ意味論を区別しない:

- サブシェル `( ... )` 内の代入は親に漏れない
- `$(...)` (CmdSubst) も同様
- `local` / `declare` 宣言は関数本体に閉じる
- 関数本体内の sink (echo/printf/redir) は本体ローカルの変数も参照し得る

結果として以下の FP / FN が発生する:

```bash
# FP: 親スコープの BODY は依然 tainted のはずだが、subshell 内の上書きが伝播してしまう
BODY="${{ github.event.pull_request.body }}"
( BODY="sanitized"; curl "https://example.com?q=$BODY" )
curl "https://example.com?q=$BODY"  # ← 親では tainted のまま正しく検出されるべき

# FN: 関数本体内の local SECRET が echo されているが、本体内 sink が捉えられていない
foo() {
  local SECRET="${{ secrets.GH_TOKEN }}"
  echo "$SECRET"   # secret-in-log が leak と判定すべき
}
foo
```

本 spec は `pkg/shell/taint.go` にスコープスタックを導入し、両 caller (`pkg/core/taint.go`, `pkg/core/secretinlog.go`) を scope-aware に切り替える設計を定義する。

## 2. ゴール / 非ゴール

### ゴール

- `pkg/shell/taint.go::PropagateTaint` をスコープ対応に拡張し、戻り値で per-Stmt の visible tainted set を返す
- bash 準拠のスコープ semantics を実装:
  - `( ... )` Subshell / `$(...)` CmdSubst — entry 時に親 visible を snapshot copy、内部代入は親に漏らさない
  - 関数本体 — `local` / 装飾なし `declare` は本体ローカル、`declare -g` / `export` / `readonly` は親 frame に書く (※ 本 issue では関数の non-local 副作用は親に伝播させない簡略案 A を採用)
- 両 caller (`taint.go`, `secretinlog.go`) を scope-aware lookup に書き換え
- 上記 semantics を unit + integration テストで固定

### 非ゴール (本 issue では扱わない)

- 関数引数経由の taint 伝播 (`foo "$T"; foo() { echo "$1"; }`) — #448
- パイプライン要素の subshell 化 / バックグラウンド `&` の subshell 化 — Q2 で別 issue 化
- `unset X` による untaint
- 関数の副作用 (関数本体内の non-local 代入) を呼び出し位置の親に伝播させること
- workflow / job / file 境界をまたぐ taint — #392 / #432 / #433

## 3. API 設計

### 3.1 新しい型

```go
// pkg/shell/taint.go

// ScopedTaint は scope-aware な taint propagation の結果。
type ScopedTaint struct {
    // Final は親スコープで script 末尾時点での tainted vars。
    // 旧 PropagateTaint の戻り値と同形式。cross-step 伝播 (taint.go の
    // GITHUB_OUTPUT 記録、step→step 連鎖の seed) で使う。
    Final map[string]Entry

    // visibleAt は AST 内の各 *syntax.Stmt 入口時点で「そのスコープから
    // 見える tainted vars の union」を保持。sink 検出 (echo/printf, redir
    // write) で「この位置でこの変数は tainted か?」のクエリに使う。
    visibleAt map[*syntax.Stmt]map[string]Entry
}

// At は stmt の入口時点で見えている tainted set を返す。
// stmt が nil または visibleAt に未登録の場合は Final を返す
// (root scope sink のフォールバック)。
func (s *ScopedTaint) At(stmt *syntax.Stmt) map[string]Entry
```

### 3.2 PropagateTaint シグネチャ変更

```go
// 旧: func PropagateTaint(file *syntax.File, initial map[string]Entry) map[string]Entry
// 新:
func PropagateTaint(file *syntax.File, initial map[string]Entry) *ScopedTaint
```

`file == nil` の場合は `&ScopedTaint{Final: maps.Clone(initial), visibleAt: nil}` を返す。

### 3.3 内部データ構造 (PropagateTaint 内のローカル状態)

```go
type scopeKind int
const (
    scopeRoot scopeKind = iota  // スクリプトルート
    scopeFunc                   // FuncDecl 本体
    scopeSubshell               // ( ... )
    scopeCmdSubst               // $(...)
)

type scopeFrame struct {
    parent *scopeFrame   // bash dynamic scoping の lookup chain (function 用)
    local  map[string]Entry
    kind   scopeKind
}
```

## 4. スコープ Semantics

### 4.1 代入の書き込み先

| 文脈 \ 代入形態 | `X=v` (None) | `local X=v` | `export X=v` | `readonly X=v` | `declare X=v` | `declare -g X=v` |
|---|---|---|---|---|---|---|
| **スクリプトルート** | root | root (※1) | root | root | root | root |
| **`( ... )` Subshell 内** | subshell | subshell (※1) | subshell | subshell | subshell | subshell (※2) |
| **`$(...)` CmdSubst 内** | cmdsubst | cmdsubst (※1) | cmdsubst | cmdsubst | cmdsubst | cmdsubst (※2) |
| **FuncDecl 本体** | (簡略案 A: 無視 ※3) | **func 本体ローカル** | (簡略案 A: 無視 ※3) | (簡略案 A: 無視 ※3) | **func 本体ローカル** | (簡略案 A: 無視 ※3) |

注:
- (※1) ルートでの `local` は bash 実行時エラーだが、AST 解析では root に書く (FN 抑制側に倒す)
- (※2) Subshell/CmdSubst 内の `declare -g` は技術的に subshell 内 global なので、結局 subshell frame 内に書かれるのと同じ。簡略化して subshell frame に書く
- (※3) 簡略案 A: 関数本体内の non-local 代入を呼び出し位置の親 frame に **漏らさない**。関数の副作用伝播は #448 で扱う。本体内 sink の検出は visibleAt 経由で動作する

### 4.2 `local -X` フラグ付き

`local -r X=v`, `local -x X=v` 等のフラグはすべて **local 扱い** (frame ローカルに書く) で簡略化。`declare -g` のみ特別扱い (= 本体内代入なら親 frame ターゲットだが簡略案 A により無視)。

### 4.3 変数参照の lookup chain

| 現在の frame | lookup 順序 |
|---|---|
| **root** | root.local のみ |
| **subshell / cmdsubst** | 自 frame.local のみ (entry 時に親 visible を snapshot コピー済み) |
| **func 本体** | func.local → parent.visible() (再帰的に chain) |

### 4.4 Subshell / CmdSubst の entry 時 snapshot

```go
// 入場時
child := &scopeFrame{kind: scopeSubshell, parent: current}
child.local = maps.Clone(current.visible())  // 浅コピーで親 visible を snapshot
push(child)

// 退場時
pop()  // child を破棄、親の状態は不変
```

### 4.5 `visibleAt` の生成タイミング

- 戦略: **eager snapshot at every `*syntax.Stmt`**
- `syntax.Walk` のコールバック内で `*syntax.Stmt` ノード Pre-visit 時に `visibleAt[stmt] = maps.Clone(currentFrame.visible())`
- 理由: シンプル＆caller 中立。GHA workflow 規模 (数十〜数百 stmt × 十数個 tainted) で性能・メモリとも問題なし

```go
func (f *scopeFrame) visible() map[string]Entry {
    out := maps.Clone(f.local)
    if f.kind == scopeFunc && f.parent != nil {
        // function body は parent への chain lookup
        for k, v := range f.parent.visible() {
            if _, ok := out[k]; !ok {
                out[k] = v
            }
        }
    }
    // subshell/cmdsubst は entry 時に snapshot 済みなので chain 不要
    return out
}
```

## 5. Caller 修正

### 5.1 `pkg/core/taint.go` (`TaintTracker.AnalyzeStep`)

**現状 (L226-241)**:

```go
t.taintedVars = shell.PropagateTaint(file, t.taintedVars)
expandShellvarMarkers(t.taintedVars)
for _, w := range shell.WalkRedirectWrites(file, "GITHUB_OUTPUT") {
    t.recordRedirWrite(stepID, w, exprMap)
}
```

**修正後**:

```go
scoped := shell.PropagateTaint(file, t.taintedVars)
t.taintedVars = scoped.Final
expandShellvarMarkers(t.taintedVars)  // Final 用 (将来の cross-step 直接参照に備え)

for _, w := range shell.WalkRedirectWrites(file, "GITHUB_OUTPUT") {
    visible := scoped.At(w.Stmt)
    expanded := maps.Clone(visible)
    expandShellvarMarkers(expanded)        // ★ per-stmt で展開してから recordRedirWrite に渡す
    t.recordRedirWrite(stepID, w, exprMap, expanded)
}
```

`recordRedirWrite` のシグネチャに `visible map[string]shell.Entry` を追加し、内部の `t.taintedVars` 参照 (L463-477) を `visible` で置き換え。

**`expandShellvarMarkers` を per-stmt で適用する理由**:
`recordRedirWrite` は最終的に `taintedOutputs` (cross-step に伝播する map) に sources を書き込む。`shellvar:X` マーカーはこの map に入ると次 step では解決不能になるため、必ず展開済みである必要がある。`scoped.At(stmt)` の戻り値は walker が生の `shellvar:X` を保持したまま返すので、caller 側で per-stmt にコピー＋展開する。`maps.Clone` の per-loop 呼び出しは GHA workflow 規模では実害なし。

### 5.2 `pkg/core/secretinlog.go`

**現状 (L398-399)**:

```go
tainted := shell.PropagateTaint(file, initialTainted)
leaks := rule.findEchoLeaks(file, tainted, script, execRun.Run)
```

**修正後**:

```go
scoped := shell.PropagateTaint(file, initialTainted)
leaks := rule.findEchoLeaks(file, scoped, script, execRun.Run)
```

`findEchoLeaks` のシグネチャを `(file, scoped *shell.ScopedTaint, ...)` に変更。内部で各 echo/printf stmt の位置から `scoped.At(stmt)` を取り、`WordReferencesEntry(arg, scoped.At(stmt))` で照合する。

**`secretinlog.go` では `expandShellvarMarkers` を呼ばない**:
`secretinlog.go` は origin の `shellvar:X` 形式を **意図的に保持** している (autofix が「変数 X のアサイン直後に `::add-mask::` を挿入」する判定に使うため、L440-475)。よって `scoped.At(stmt)` を直接渡す。`taint.go` 側の per-stmt 展開とは独立した方針。

### 5.3 影響範囲

`shell.PropagateTaint` の caller は以下の 3 箇所に閉じる:

- `pkg/core/taint.go:229`
- `pkg/core/secretinlog.go:398`
- `pkg/shell/taint_test.go` (テスト群)

外部公開はパッケージ内のみ。社外利用者なし。

## 6. テスト設計

### 6.1 `pkg/shell/taint_test.go` — ユニット (セマンティクス固定)

`TestPropagateTaint_Scoped` を新設し、テーブル駆動で以下のケースを検証:

| # | ケース名 | スクリプト (initial: `T` tainted) | Final | visibleAt (sink 位置) |
|---|---|---|---|---|
| 1 | subshell isolation (FP 抑制) | `X="$T"; ( X="safe"; cmd "$X" )` | `X` tainted | subshell 内 cmd: `X` snapshot で tainted (subshell 内代入は subshell frame のみ) |
| 2 | subshell が親の tainted を見る | `X="$T"; ( cmd "$X" )` | `X` tainted | subshell 内 cmd: `X` visible |
| 3 | cmdsubst isolation | `R=$(X="leaked"; echo "$X"); cmd "$X"` | `X` tainted (initial 維持), `R` は X 経由 tainted | cmdsubst 内 echo: `X="leaked"` subshell 限定 |
| 4 | function local 隔離 | `foo() { local X="$T"; cmd "$X"; }; foo; cmd "$X"` | 親 `X` = tainted (initial 維持) | foo body 内 cmd: `X` local tainted; foo 後 cmd: 親 `X` tainted (initial) |
| 5 | function 内 declare (Q4-B) | `foo() { declare X="$T"; cmd "$X"; }; foo` | 親 `X` 不変 | foo body cmd: `X` local |
| 6 | function 内 declare -g | `foo() { declare -g X="$T"; }; foo; cmd "$X"` | 親 `X` 不変 (簡略案 A) | — |
| 7 | function 内 export | `foo() { export X="$T"; }; cmd "$X"` | 親 `X` 不変 (簡略案 A) | — |
| 8 | function 内 readonly | 同上 | 同上 | — |
| 9 | nested subshell | `( X="$T"; ( cmd "$X" ) )` | `X` 不変 | 内側 cmd: `X` visible |
| 10 | subshell 内 function 定義 | `( foo() { local X="$T"; cmd "$X"; }; foo )` | 不変 | foo body cmd: visible |
| 11 | function 内 subshell | `foo() { local X="$T"; ( cmd "$X" ); }; foo` | 不変 | 内側 subshell cmd: `X` visible |
| 12 | root scope の local (実行時エラーだが解析許容) | `local X="$T"; cmd "$X"` | `X` tainted (root 扱い) | cmd: `X` visible |
| 13 | 既存挙動回帰 | `X="$T"; Y="$X"; cmd "$Y"` | `X`, `Y` tainted | cmd: 両方 visible |

加えて以下の API 形状検証を追加:

- `TestPropagateTaint_NilFile` — `file=nil` で `&ScopedTaint{Final: copy(initial), visibleAt: nil}` を返す
- `TestScopedTaint_At_Fallback` — 未登録 stmt で `Final` を返す

### 6.2 `pkg/core/secretinlog_test.go` — 統合 (caller 経由)

最低 2 ケース追加:

- `TestSecretInLog_FunctionLocalScope_DetectsLeak` — 関数本体内の `local SECRET=...; echo "$SECRET"` で leak 検出 (FN 修正)
- `TestSecretInLog_SubshellLocalAssignment_NotLeakedInParent` — `( SECRET="dummy" ); echo "$SECRET"` で「親の SECRET (env 由来 tainted) は subshell 内の上書きに影響されない」→ echo $SECRET は依然 leak 検出 (FP/FN 防止)

### 6.3 `pkg/core/taint_test.go` — 統合

最低 1 ケース追加:

- `TestTaintTracker_RedirWriteInSubshell` — subshell 内の `echo "x=$T" >> $GITHUB_OUTPUT` で `T` tainted のとき output が tainted 記録される

### 6.4 `script/actions/` — workflow fixture (ミニ C)

2 ファイル新設:

**`taint-scope-fp-safe.yaml`** — false positive 抑制を示す:

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          BODY="${{ github.event.pull_request.body }}"
          ( BODY="sanitized"; curl "https://api.example.com?q=$BODY" )
          curl "https://api.example.com?q=$BODY"  # 親スコープでは tainted のまま (検出されるべき)
```

**`taint-scope-fn-vulnerable.yaml`** — function 本体内 sink の正検出を示す:

```yaml
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
            echo "$SECRET_LOCAL"   # secret-in-log: leak 検出されるべき
          }
          leak
```

`script/README.md` に簡単な説明を追加。

## 7. エッジケース

| ケース | 方針 |
|---|---|
| **再帰関数** (`foo() { foo; }`) | 関数本体は walk 1 回のみ。再帰呼び出しは `*syntax.CallExpr` として通常の Stmt 扱い。簡略案 A により副作用は親に伝播しないので無限展開しない |
| **匿名 subshell** in pipeline (`cmd1 \| (X=v; cmd2)`) | `*syntax.Subshell` 単体は検出。pipeline 要素全体の subshell 化は別 issue (Q2 で確認) |
| **ネスト FuncDecl** (`foo() { bar() { local X=v; }; bar; }`) | scope chain で `bar` body の parent = `foo` body。`bar` の `local X` は bar 本体のみ |
| **`function foo { ... }` Bash 構文** | mvdan.cc/sh の `*syntax.FuncDecl` で同じく扱う (Variant 違いだけ) → 透過処理 |
| **`local`/`declare` を root で使う** | bash 実行時エラーだが、static 解析では root frame に書く (FN 抑制側) |
| **`declare X` (値なし)** | `WalkAssignments` が `Value=nil` で返すので taint 伝播対象外 (現行通り) |
| **`local -r X=v`, `local -x X=v` 等のフラグ付き** | すべて local 扱いに簡略化 |
| **`export -f foo`** (関数 export) | 関数定義は変数 namespace に影響しないので無視 |
| **`unset X`** | 簡略化のため無視 (既存 `PropagateTaint` も "untaint" しない方針)。別 issue 化候補 |
| **Subshell 内 function 定義 → subshell 外で呼び出し** | bash 実挙動では subshell 内定義は外に漏れない。AST 上は関数定義あるが簡略案 A により副作用なし → 結果一致 |
| **`PropagateTaint(file=nil, initial)`** | `&ScopedTaint{Final: maps.Clone(initial), visibleAt: nil}` を返す |
| **`At(stmt=nil)`** | `Final` を返す (defensive) |
| **`At(未登録 stmt)`** | `Final` を返す (root scope sink のフォールバック) |

### 7.1 Order-aware Offset との整合

既存の `Entry.Offset` (script 内バイトオフセット) は scope に依らずグローバル。subshell/function 本体内でも `*syntax.Stmt.Pos().Offset()` はファイル全体の絶対オフセット。よって現行の `secretinlog.go` の order-aware FP suppression (`entry.Offset < sinkOffset`) はそのまま有効。

### 7.2 パフォーマンス

- AST walk は O(N)
- `visibleAt` snapshot は per-Stmt の `maps.Clone(visible)` → O(stmt数 × tainted数)
- frame stack 深度は通常 ≤ 5 程度 (subshell ネスト + function 1 段)
- GHA workflow 規模では実害なし

## 8. 実装順序

実装は次の順序で進める。各ステップでテストが通ることを確認 (TDD):

1. **`pkg/shell/taint.go`** — `ScopedTaint` 型と `scopeFrame` 内部構造を追加
2. **`pkg/shell/taint.go`** — `PropagateTaint` を scope-aware walker に書き換え (Subshell + CmdSubst の snapshot copy 動作のみ先に実装)
3. **`pkg/shell/taint_test.go`** — Subshell / CmdSubst ケース (1, 2, 3, 9) のテスト追加・通す
4. **`pkg/shell/taint.go`** — FuncDecl 本体の scope frame push/pop と lookup chain 追加 (簡略案 A)
5. **`pkg/shell/taint_test.go`** — Function ケース (4-8, 10, 11) のテスト追加・通す
6. **`pkg/shell/taint_test.go`** — Edge / API ケース (12, 13, NilFile, At fallback) 追加
7. **`pkg/core/taint.go`** — `recordRedirWrite` のシグネチャ更新と caller 更新
8. **`pkg/core/taint_test.go`** — `TestTaintTracker_RedirWriteInSubshell` 追加・通す
9. **`pkg/core/secretinlog.go`** — `findEchoLeaks` を scope-aware に書き換え
10. **`pkg/core/secretinlog_test.go`** — 統合ケース 2 件追加・通す
11. **`script/actions/taint-scope-fp-safe.yaml`** + **`taint-scope-fn-vulnerable.yaml`** + `script/README.md` 更新
12. 全テスト実行 (`go test ./...`) と `sisakulint script/actions/` で fixture 動作確認
13. mutation test (#446 で導入) を再走させ survived 件数の変化を確認

## 9. 受け入れ基準

- [ ] `pkg/shell/taint_test.go` の新規 13+ ケースが緑
- [ ] `pkg/core/taint_test.go` の新規 1 ケースが緑
- [ ] `pkg/core/secretinlog_test.go` の新規 2 ケースが緑
- [ ] 既存の全テストが緑 (回帰なし)
- [ ] `sisakulint script/actions/taint-scope-fp-safe.yaml` で「subshell 内 curl」と「親 curl」の検出差が観測できる
- [ ] `sisakulint script/actions/taint-scope-fn-vulnerable.yaml` で関数内 echo の leak が検出される
- [ ] `pkg/shell/taint.go::PropagateTaint` の docstring から `// スコープは無視（subshell/function 内も親と同じ namespace ← #447 で対応）` の TODO コメントが削除されている
- [ ] CLAUDE.md の TaintTracker 説明に scope 対応の旨を追記

## 10. リスクと未対応項目

- **関数の副作用伝播 (簡略案 A)**: 関数本体内の non-local 代入を親に漏らさないため、`X="${T}"; foo() { X=safe; }; foo; cmd "$X"` のような「sanitize する関数」が漏れる FP が残る。これは bash 実挙動では `X=safe` が global に書かれるため、本来 untaint すべきだが、`PropagateTaint` は untaint 自体しない設計なので影響は限定的。完全対応は #448 と合わせて検討
- **関数本体は FuncDecl 出現位置で walk される (call-site context は反映されない)**: `foo() { echo "$X"; }; X="${T}"; foo` のように関数定義後に親 X が tainted 化されるケースで、foo body 内の echo の visibleAt は X が tainted **でない**状態で snapshot される (FN)。bash 実挙動では call site で X が visible だが、本 issue では cross-call-site 解析を扱わない。FN 影響は実用上限定的: 関数内で `local` / `declare` 宣言してから sink するケースは正検出される。完全対応は call-site lazy walk が必要で、#448 と合わせて再設計候補
- **Pipeline / バックグラウンド `&` の subshell 化未対応**: Q2 でスコープ外。`cmd | (X=v; cmd2)` のような pipeline 内 subshell は単体検出されるが、`X=v | cmd` のような pipeline LHS の subshell 化は捉えない。FN 影響軽微なため別 issue 候補
- **API シグネチャ変更**: `pkg/shell/taint.go::PropagateTaint` の戻り値変更により、外部利用者がいた場合は影響あり。社内利用のみなので問題なし、ドキュメントには明記
- **`shellvar:X` マーカー展開ポリシーが caller ごとに違う**: `taint.go` は per-stmt で展開、`secretinlog.go` は展開しない (autofix のため raw 保持)。新たな caller を追加する際は §5 の方針を踏襲する必要があり、混乱リスクあり。`pkg/shell` 側で展開ヘルパ (`scoped.AtExpanded(stmt)` など) を将来的に追加する余地あり

## 11. 後続作業

- #448 (関数引数の taint 伝播) — 本 issue 完了後に着手可能
- Pipeline / バックグラウンド subshell 化 — 必要であれば新規 issue 化
- `unset X` による untaint — 別 issue 化検討
