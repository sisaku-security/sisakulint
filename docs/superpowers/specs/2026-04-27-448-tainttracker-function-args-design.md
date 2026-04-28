# #448: TaintTracker の関数引数経由 taint 伝播 — 設計

| 項目 | 内容 |
| --- | --- |
| Issue | [#448](https://github.com/sisaku-security/sisakulint/issues/448) |
| 親 Epic | [#445](https://github.com/sisaku-security/sisakulint/issues/445) (TaintTracker AST 移行・拡張) |
| 関連 / 後続 | #444 D-3 「関数引数 taint 伝播 (オプション)」を解消 |
| 前提 | #446 (TaintTracker AST 化) — マージ済み / #447 (シェルスコープ対応) — マージ済み (commit `bb3ae41`) |
| 工数目安 | 2-3 日 |
| 作成日 | 2026-04-27 |

---

## 1. 背景と目的

`pkg/shell/taint.go::PropagateTaint` は #447 でスコープ対応 (Subshell / CmdSubst / FuncDecl) 済みだが、関数引数 (`$1` / `$2` / `${1}` / `$@`) は **untracked** のままになっている。`WordReferencesEntry` の docstring に「special parameters は対象外」と明記されている通り、現状は以下のパターンが検出できない:

```bash
TOKEN=$(echo "$KEY" | jq -r '.token')   # TOKEN が tainted (shellvar:KEY)
leak() { echo "$1"; }                    # 関数本体: $1 は untracked
leak "$TOKEN"                            # 呼び出しで tainted を渡している
                                          # → echo "$1" の漏洩が未検出 (FN)
```

`secret-in-log` (#444 D-3) で「初版はスキップ」と明記されている関数引数追跡を本 issue で対応する。

本 spec は `pkg/shell/taint.go` の内部 walker を **lazy walk + per-call body 展開** 方式に切り替え、`$1`/`$@` を呼び出しサイトの実引数 taint に基づいて解決する設計を定義する。

## 2. ゴール / 非ゴール

### ゴール

- `pkg/shell/taint.go::PropagateTaint` の内部 walker を拡張し、関数引数経由 taint 伝播を **lazy walk** で実装
- `*ScopedTaint` 型および公開 API (`At(stmt)`) は不変
- bash 準拠の semantics:
  - FuncDecl 出現時には body を walk せず、CallExpr 出現時に call-site の args 情報を `tainted["1"], ["2"], ..., ["@"], ["*"]` として inject した上で body を walk
  - 複数呼び出しサイトでは visibleAt[stmt] を **保守的に union** (issue 案明記)
  - 再帰呼び出しは **1 回展開で打ち切り** (depth=1 制限、固定点反復はしない)
  - `$@` は引数のいずれかが tainted なら tainted (issue 案明記)
  - forward reference (定義前 call) は bash 実挙動と一致 (untracked)
- 両 caller (`pkg/core/taint.go`, `pkg/core/secretinlog.go`) を整合させる:
  - `taint.go` は変更不要 (既存の `scoped.At(stmt)` 経由で透過対応)
  - `secretinlog.go::secretInLogFixer.FixStep` の autofix を positional 名 → upstream 名解決に対応
- 上記 semantics を unit + integration テストで固定

### 非ゴール (本 issue では扱わない)

- `set -- a b c` / `shift` による positional 書き換え
- 関数の non-local 副作用伝播 (#447 の簡略案 A を維持: 関数内 `X="..."` は親に漏らさない)
- `foo "${{ untrusted }}"` 直接 expression を args に書くケース (callback 抽象化による Approach 2 は follow-up issue 候補)
- subshell-内 FuncDecl が外で呼ばれた場合の bash 一致挙動 (= scope-bound funcTable)
- 動的 dispatch (`$cmd "$T"`, `eval`, `bash -c "$cmd"`)
- workflow / job / file 境界をまたぐ関数呼び出し

## 3. アプローチ選択の経緯

### 3.1 関数本体の walk タイミング: Lazy walk を採用

検討した 2 案:

- **A. Lazy walk** (採用) — FuncDecl 出現時には body を walk せず、CallExpr 検出時に call-site の args 情報を `tainted["1"]/["2"]/...` として inject した上で body を walk
- **B. Eager + revisit** — 現状 (eager walk) を温存し `$1` を `paramref:func:1` のような symbolic taint として伝播、CallExpr で実引数の taint で置換

A を採用した理由:
- bash の dynamic dispatch にそのまま対応 (将来 `set --` / `shift` を扱う余地)
- `$1` を既存の `WordReferencesEntry` で同じ map lookup として扱える (special parameter `Param.Value="1","@"` がそのままキーになる)
- call-site context が body 内の per-stmt visible に正しく反映される
- `secret-in-log` の autofix が `shellvar:X` マーカーに依存しているのでスキーマを増やさない方が caller 側のメンテが楽

### 3.2 call-site 引数の taint 抽出範囲: shellvar 参照のみ (Approach 1)

検討した 3 案:

- **Approach 1** (採用) — `shell.PropagateTaint` は shellvar 参照のみで関数引数 binding。CallExpr 検出時、args の Word を `WordReferencesEntry` で照合し、tainted shell var が見つかれば `tainted["1"]/...` として inject
- **Approach 2** — `shell.PropagateTaint` に `WithCallArgTainter(fn)` callback を足し、core 側で `${{ untrusted }}` も含めた tainter を渡す
- **Approach 3** — 関数解決を core 側に外出し (`shell` は table/列挙のみ)

Approach 1 を採用した理由:
- issue の例 (`leak "$TOKEN"`) はすべて shellvar 経由
- 直接 expression を args に書く workflow は実用上ほぼ無い
- `shell` 層の `${{ }}` 中立性を保てる
- 必要なら follow-up issue で Approach 2 のオプトイン拡張に進化できる

## 4. API 設計

### 4.1 公開 API (不変)

```go
// pkg/shell/taint.go
func PropagateTaint(file *syntax.File, initial map[string]Entry) *ScopedTaint
```

`*ScopedTaint` 型 (`Final`, `At(stmt)`) も不変。caller 側 (`pkg/core/taint.go`, `pkg/core/secretinlog.go`) からの呼び出し方は変わらない。

### 4.2 内部データ構造 (PropagateTaint 内のローカル状態)

```go
funcTable := make(map[string]*syntax.FuncDecl)  // 関数登録テーブル
visited   := make(map[string]int)               // 再帰展開ガード (depth count)
```

両者を `makeWalkFn` のクロージャに closure 引数として渡す。

### 4.3 walker 拡張

`makeWalkFn` を 2 箇所変更:

**FuncDecl** — body 即時 walk を廃止、テーブル登録のみ:

```go
case *syntax.FuncDecl:
    if n.Body == nil || n.Name == nil {
        return false
    }
    funcTable[n.Name.Value] = n  // body は ここでは walk しない (#448)
    return false
```

**CallExpr** — 解決可能なら call-site 引数 binding を inject し body を walk:

```go
case *syntax.CallExpr:
    name := callCommandName(n)  // 第1引数の literal command name
    decl, ok := funcTable[name]
    if !ok || visited[name] >= 1 {
        return true  // 未登録 / 再帰深度1超え → 通常 CallExpr として子ノード walk のみ
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

### 4.4 `buildArgBinding` (新規ヘルパ)

```go
// buildArgBinding は CallExpr の args から call-site の taint state を抽出し、
// 関数本体内の $1 / $2 / ... / $@ / $* に対応する binding map を返す。
// untainted な arg は binding に登録しない (lookup miss = untainted の意味)。
//
// $@ / $* は「いずれかの arg が tainted なら tainted」(issue 案)。
// Sources は upstream entry の Sources を union (chain そのまま、後段で expandShellvarMarkers が展開)。
//
// Offset = -1 (env-like): body 内 sink から見て常に "before" 扱い。call-site の物理 offset
// を使うと、関数定義が呼び出し以前にあるケースで sink offset > call-site offset の
// order-aware 判定がおかしくなるため。
func buildArgBinding(call *syntax.CallExpr, visible map[string]Entry) map[string]Entry {
    binding := make(map[string]Entry)
    if len(call.Args) <= 1 {
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

**Source 形式の意図**:
- 個別 positional (`"1"`, `"2"`, ...): `["shellvar:UPSTREAM_NAME"]` 単一マーカー (`processAssign` と同形式)。secret-in-log の autofix が「UPSTREAM の代入直後に `::add-mask::$UPSTREAM` 挿入」の判定に使う
- `"@"` / `"*"`: 全 tainted args の `Sources` を union (raw chain)。autofix は best-effort 不能なので無効化 (§5.2.2)
- `Offset = -1`: body 内のどの sink offset より前として扱う (env 由来と同形式)

### 4.5 `recordVisibleAt` (新規ヘルパ)

複数 call-site から同じ body Stmt を walk した時、`visibleAt[stmt]` を保守的に merge する:

```go
// recordVisibleAt は currentFrame.visible() を visibleAt[stmt] に書き込む。
// 同じ stmt に対する再記録 (= 別 call-site から同じ関数 body を再 walk) は
// 既存値と Sources を union して保守的にマージする。
func recordVisibleAt(result *ScopedTaint, stmt *syntax.Stmt, visible map[string]Entry) {
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

`makeWalkFn` の `*syntax.Stmt` ケースは:

```go
case *syntax.Stmt:
    recordVisibleAt(result, n, (*current).visible())
    return true
```

### 4.6 `mergeSources` (private 新規)

`pkg/core/taint.go::mergeUnique` と同等のロジックを `pkg/shell` 内に private 複製 (cyclic import 回避)。共有化は将来の refactor。

### 4.7 `callCommandName` (新規ヘルパ)

```go
func callCommandName(call *syntax.CallExpr) string {
    if call == nil || len(call.Args) == 0 {
        return ""
    }
    return wordLitPrefix(call.Args[0])  // 既存ヘルパ流用
}
```

`$cmd` のような変数経由呼び出しは `wordLitPrefix` が空文字を返すため、自然に "未登録 → スキップ" となる。

## 5. Semantics 詳細

### 5.1 関数 resolution table

| 状況 | 挙動 |
|---|---|
| FuncDecl 出現 | `funcTable[n.Name.Value] = n` に登録 (上書きあり = bash 仕様: 後勝ち) |
| `function foo { ... }` 構文 | `*syntax.FuncDecl` の Variant 違いだけなので透過処理 |
| Subshell 内 FuncDecl | 同じ `funcTable` に登録 (グローバル共有 — §10 known limitation) |
| 関数名 = 既存コマンド名 (`echo` 等) | `funcTable[echo]` に登録され、以降の `echo` CallExpr は body walk される。bash 実挙動でもユーザ定義が builtin に勝つので一致 |

### 5.2 CallExpr 解決の判定

| 状況 | 挙動 |
|---|---|
| 関数名が funcTable にない | 通常 CallExpr (= 子ノード walk のみ)、関数解決スキップ |
| 関数名が visited[name] >= 1 | 再帰: body 再 walk せず `return true` (CallExpr の子ノードは通常通り walk して visibleAt 記録は残す) |
| `$cmd "$T"` のような変数経由呼び出し | `wordLitPrefix` が空文字 → funcTable 未登録扱い → スキップ (静的解決不能、bash 上は dynamic dispatch) |
| Forward reference (`foo` 呼び出しが `foo()` 定義より前) | 1-pass walk で funcTable 未登録 → スキップ。bash 実挙動 (定義前 call はエラー) と一致 |

### 5.3 再帰展開ポリシー

`visited[name]` は CallExpr 解決時に `++`、body walk 完了で `--` (defer 不可、`syntax.Walk` 同期実行)。

| パターン | 挙動 |
|---|---|
| 直接再帰 `foo() { foo; }; foo "$T"` | 外側 foo "$T" で body walk、内側 foo は visited[foo]=1 で skip |
| 相互再帰 `foo() { bar; }; bar() { foo; }; foo "$T"` | foo→bar→foo (skip)。各関数 1 回ずつ walk |
| ネスト同名呼び出し `foo() { if x; then foo; fi }` | inner foo は skip。展開深度 1 |

### 5.4 `$@` / `$*` semantics

| 参照 | 解釈 |
|---|---|
| `"$1"`, `${1}` | binding["1"] を lookup。tainted なら entry.Sources 経由で taint 伝播 |
| `"$@"`, `"$*"` | binding["@"] を lookup。引数のいずれかが tainted なら全体 tainted (issue 案) |
| `"$0"` | 関数名リテラル → 解析対象外 (`tainted["0"]` を作らない) |
| `"$#"`, `"$?"`, `"$$"`, `"$!"` | 数値・PID 等で tainted 化されない → binding に登録しない |

### 5.5 `processAssign` / `WordReferencesEntry` への影響

**変更不要**。`tainted` map のキーが `"1"`, `"@"` でも既存ロジックは動く:
- `WordReferencesEntry` は `*syntax.ParamExp.Param.Value` をキーに lookup する。bash AST では `$1` の `Param.Value="1"`、`$@` の `Param.Value="@"` なので、binding map の対応キーがあれば自然にマッチ
- `processAssign(local X="$1")` → RHS Word の `WordReferencesEntry` が `("1", true)` を返す → `current.local["X"] = Entry{Sources: ["shellvar:1"], Offset: ...}`

**注意**: `local X="$1"` の結果 `X.Sources = ["shellvar:1"]` となるが、これは body スコープローカルなので問題なし。`expandShellvarMarkers` (taint.go) が走る場合、frame の visible に `tainted["1"]` があるため `shellvar:1` → `shellvar:UPSTREAM` → さらに upstream chain と展開される。secretinlog は expand しないので autofix 時 `f.origin = "shellvar:1"` になる可能性 → §6.2.2 で取り扱い。

### 5.6 関数副作用 (簡略案 A 維持)

#447 の `processDeclClause` ポリシーをそのまま維持:
- 関数本体内の `X="..."` (装飾なし) は `processAssign` で current frame (= func frame) に書く → pop 時に消える
- `local` / `declare` は本体ローカル
- `export` / `readonly` / `declare -g` は簡略案 A により無視

本 issue でこのポリシーは変えない。完全対応は副作用伝播の正しい semantics 設計が必要 (epic #445 配下の follow-up)。

### 5.7 エッジケース

| ケース | 挙動 |
|---|---|
| 引数なし call `foo` | `binding = {}` (空 map)、body 内 `$1` 等は lookup miss で untainted |
| 引数の一部だけ tainted `foo "$T" "safe"` | `binding["1"]` のみ登録、`binding["2"]` は未登録、`binding["@"]` は T 経由 tainted |
| 引数が複合 word `foo "prefix-$T"` | `WordReferencesEntry` が word 内 ParamExp を deep walk するので T を検出 → `binding["1"] = shellvar:T` |
| 引数が cmdsubst `foo "$(cmd)"` | 既存 `WordReferencesEntry` は cmdsubst 内も deep walk するため、cmdsubst 内の tainted 参照を含む arg は tainted 扱い (#447 の lock-in 挙動を継承) |
| 関数を 2 回 redefine | 後勝ち。先の定義の body は funcTable から消える |
| `$1` を `local X="$1"` で受けず直接 sink | `echo "$1"` は `tainted["1"]` で照合され検出 |

## 6. Caller への影響

### 6.1 `pkg/core/taint.go` — **変更不要**

`recordRedirWrite` は既に `scoped.At(w.Stmt)` 経由で per-stmt visible を取得し、`expandShellvarMarkers` でチェーン展開している。body 内 stmt に対する `visibleAt[stmt]` には binding (`tainted["1"]`, `tainted["@"]` 等) が含まれるため、`echo "x=$1" >> $GITHUB_OUTPUT` のような関数内の `$GITHUB_OUTPUT` 書き込みも、shellvar chain が `shellvar:1` → `shellvar:UPSTREAM` → ... と再帰展開され、`taintedOutputs` に正しい origin 列が記録される。

検証は §7.2 の `TestTaintTracker_RedirWriteInFunctionBody` で行う。

### 6.2 `pkg/core/secretinlog.go` — autofix の positional 対応のみ

#### 6.2.1 検出側 (`findEchoLeaks` 等) — **変更不要**

`scoped.At(stmt)` が返す visible に binding が含まれるため、body 内 `echo "$1"` / `echo "$@"` は既存 walker で自然にリーク検出される。エラーメッセージは `variable $1 (origin: shellvar:TOKEN) is printed ...` のように `$1` 参照が出るが許容。

#### 6.2.2 autofix (`secretInLogFixer.FixStep`) — positional 名の解決

現状 `f.varName` を `addMask` の `$NAME` と `insertAfterAssignment` のキーの両方に使っている。`$1`/`$@` で `f.varName == "1"` / `"@"` の時に問題になるので、解決ヘルパを追加する。

```go
func (f *secretInLogFixer) FixStep(node *ast.Step) error {
    // ... 既存の guard ...
    script := execRun.Run.Value

    maskTarget, ok := resolveMaskTarget(f.varName, f.origin)
    if !ok {
        // $@ / $* のリーク、または origin が shellvar:* でない positional →
        // 確実な single-var ターゲットが取れないため autofix は no-op。
        return nil
    }

    if hasAddMaskBefore(script, maskTarget, f.leakOffset) {
        return nil
    }
    addMask := `echo "::add-mask::$` + maskTarget + `"`

    if strings.HasPrefix(f.origin, "shellvar:") {
        updated, ok := insertAfterAssignment(script, maskTarget, addMask)
        if ok {
            execRun.Run.Value = updated
            if execRun.Run.BaseNode != nil {
                execRun.Run.BaseNode.Value = updated
            }
            return nil
        }
        return nil
    }
    // origin が secrets.* (env var 由来): スクリプト冒頭挿入 (既存ロジック維持)
    // ... 既存ロジック ...
}

// resolveMaskTarget は leak.VarName が positional ($1, $2, ...) の場合に
// origin (shellvar:UPSTREAM) から UPSTREAM を取り出して返す。
// $@ / $* は確実な single-var ターゲットが取れないので (false, "") を返す。
// 非 positional はそのまま VarName を返す (現状互換)。
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

`hasAddMaskBefore` は変更不要 (`maskTarget` で正しく一致判定できる)。

### 6.3 影響範囲サマリ

| ファイル | 変更 |
|---|---|
| `pkg/shell/taint.go` | 主要な実装変更 (§4: walker 拡張、`buildArgBinding`、`mergeSources`、`recordVisibleAt`、`callCommandName`) |
| `pkg/core/taint.go` | **変更なし** (recordRedirWrite が既に per-stmt visible 経由) |
| `pkg/core/secretinlog.go` | autofix の `FixStep` のみ (§6.2.2: `resolveMaskTarget` ヘルパ + 呼び出し点 1 箇所) |
| `pkg/shell/taint_test.go` | テストケース追加 (§7.1) |
| `pkg/core/taint_test.go` | テストケース追加 (§7.2) |
| `pkg/core/secretinlog_test.go` | テストケース追加 (§7.3) |
| `script/actions/` | fixture 2 ファイル新設 + `script/README.md` 更新 |

## 7. テスト設計

### 7.1 `pkg/shell/taint_test.go` — semantics unit (新規 `TestPropagateTaint_FunctionArgs`)

テーブル駆動で以下を検証。assertion は (a) `Final` の中身、(b) `At(call-site stmt)` および `At(body sink stmt)` の中身。

| # | ケース名 | スクリプト (initial: `T*` tainted) | 期待 |
|---|---|---|---|
| 1 | single_call_simple | `foo() { echo "$1"; }; foo "$T"` | body echo の visibleAt に `tainted["1"] = shellvar:T` |
| 2 | multi_call_union | `foo() { echo "$1"; }; foo "$T"; foo "safe"` | body echo の visibleAt に `tainted["1"]` (union 保守的、T 経由 tainted) |
| 3 | mixed_args_partial_taint | `foo() { cmd "$1" "$2"; }; foo "$T" "safe"` | `tainted["1"]` あり、`tainted["2"]` 無し、`tainted["@"]` あり |
| 4 | at_arg_either_tainted | `foo() { cmd "$@"; }; foo "$T1" "$T2"` | `tainted["@"].Sources` に T1, T2 由来両方が union |
| 5 | star_alias_of_at | `foo() { cmd "$*"; }; foo "$T"` | `tainted["*"]` も同じ origin (binding["@"] と同形) |
| 6 | forward_reference_unresolved | `foo "$T"; foo() { echo "$1"; }` | 1 番目 CallExpr は funcTable 未登録 → body walk されない。Final に外乱無し |
| 7 | direct_recursion_depth1 | `foo() { foo "$1"; echo "$1"; }; foo "$T"` | 外側 foo body walk → echo "$1" stmt の visibleAt に `tainted["1"]`、内側 foo CallExpr は visited[foo]>=1 で再 walk されない |
| 8 | mutual_recursion | `foo() { bar; }; bar() { foo; }; foo "$T"` | 各関数 1 回ずつ body walk、再入は skip |
| 9 | unused_function_definition | `foo() { echo "$T"; }` (call なし) | foo body は walk されない → visibleAt 空、Final = initial |
| 10 | empty_args_call | `foo() { echo "$1"; }; foo` | binding 空、body の `$1` 参照は visible に "1" 無し → untainted |
| 11 | local_assigns_from_arg | `foo() { local X="$1"; echo "$X"; }; foo "$T"` | body 内 echo の visibleAt に `tainted["X"] = shellvar:1` (frame ローカル)、parent 由来 `tainted["1"] = shellvar:T` も chain で見える |
| 12 | nested_function_calls | `outer() { inner "$1"; }; inner() { echo "$1"; }; outer "$T"` | inner body の echo stmt visibleAt に `tainted["1"] = shellvar:1` (outer's binding chain) |
| 13 | composite_word_arg | `foo() { echo "$1"; }; foo "prefix-$T-suffix"` | arg word 内の T 参照を検出 → `binding["1"] = shellvar:T` |
| 14 | non_function_callexpr_unaffected | `echo "$T"` (関数呼び出しではない通常 CallExpr) | funcTable lookup 空振り、body walk なし、既存挙動に回帰なし |
| 15 | redefined_function_winner_takes | `foo() { echo "first"; }; foo() { echo "$1"; }; foo "$T"` | 後勝ち。2 番目の body が walk され `tainted["1"]` 検出 |
| 16 | regression_447_subshell_isolation | (既存 #447 ケース 1〜13 を現状通り pass) | 関数引数機能の追加で既存 scope semantics に regression なし |
| 17 | dynamic_dispatch_unresolved | `cmd="$T"; $cmd "arg"` | `wordLitPrefix` が空 → funcTable 未登録扱い → 静的解決スキップ |

加えて以下の API/edge ケース:

- `TestPropagateTaint_FunctionArgs_NilFile` — `file=nil` で空 ScopedTaint
- `TestPropagateTaint_FunctionArgs_RecursionGuardDecrement` — visited[name] が body walk 完了で正しく decrement される (連続 2 つの兄弟 call-site で 2 回目も walk される)

### 7.2 `pkg/core/taint_test.go` — integration

最低 2 ケース追加:

- **`TestTaintTracker_RedirWriteInFunctionBody`** — function 内の `>> $GITHUB_OUTPUT` 書き込みが call-site 引数 taint を反映して `taintedOutputs` に記録される

  ```yaml
  - id: step1
    run: |
      foo() { echo "x=$1" >> $GITHUB_OUTPUT; }
      foo "${{ github.event.issue.title }}"
  ```

  期待: `taintedOutputs["step1"]["x"]` に origin chain (展開後) が `["github.event.issue.title"]` で記録

- **`TestTaintTracker_FunctionArg_ChainExpansion`** — shellvar 経由の chain が正しく展開される

  ```bash
  TITLE="${{ github.event.issue.title }}"
  foo() { echo "y=$1" >> $GITHUB_OUTPUT; }
  foo "$TITLE"
  ```

  期待: `taintedOutputs[...]["y"]` に `github.event.issue.title` 含む (shellvar:1 → shellvar:TITLE → github.event.issue.title)

### 7.3 `pkg/core/secretinlog_test.go` — integration

最低 4 ケース追加:

- **`TestSecretInLog_PositionalArgFromShellVar_DetectsLeak`** —

  ```yaml
  env: { KEY: ${{ secrets.GH_TOKEN }} }
  run: |
    TOKEN=$(echo "$KEY" | jq -r '.token')
    leak() { echo "$1"; }
    leak "$TOKEN"
  ```

  期待: 1 件の leak 報告、varName="1"、origin が `shellvar:TOKEN`

- **`TestSecretInLog_PositionalArgFromShellVar_AutofixMasksUpstream`** — 上記と同じスクリプトで autofix 適用後、`echo "::add-mask::$TOKEN"` が `TOKEN=...` 行直後に挿入されている (positional `$1` ではなく upstream `$TOKEN` がマスク対象)

- **`TestSecretInLog_AtArg_DetectsLeakNoAutofix`** —

  ```bash
  leak() { echo "$@"; }
  leak "$T1" "$T2"
  ```

  期待: leak 報告は出る、autofix は no-op (script 不変)

- **`TestSecretInLog_FunctionLocalChainsThroughArg`** —

  ```bash
  leak() { local X="$1"; echo "$X"; }
  leak "$TOKEN"
  ```

  期待: `echo "$X"` が leak 検出され、origin chain が TOKEN まで遡る

### 7.4 `script/actions/` — workflow fixture

2 ファイル新設、`script/README.md` に追記。

**`taint-args-vulnerable.yaml`** — 関数引数経由の secret 漏洩を示す:

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env: { GH_TOKEN: ${{ secrets.GH_TOKEN }} }
        run: |
          TOKEN=$(echo "$GH_TOKEN" | jq -r '.token')
          leak() {
            echo "received: $1"   # secret-in-log: $1 経由で TOKEN 漏洩を検出するべき
          }
          leak "$TOKEN"
```

**`taint-args-safe.yaml`** — 安全な書き換え (sisakulint -fix on で挿入された mask 後の状態):

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env: { GH_TOKEN: ${{ secrets.GH_TOKEN }} }
        run: |
          TOKEN=$(echo "$GH_TOKEN" | jq -r '.token')
          echo "::add-mask::$TOKEN"
          leak() {
            echo "received: $1"
          }
          leak "$TOKEN"
```

検証コマンド:
- `sisakulint script/actions/taint-args-vulnerable.yaml` で 1 件の `secret-in-log` 警告
- `sisakulint script/actions/taint-args-safe.yaml` で警告 0 件
- `sisakulint -fix dry-run script/actions/taint-args-vulnerable.yaml` で正しい挿入が dry-run 表示される

## 8. 実装順序 (TDD)

| # | ステップ | 確認 |
|---|---|---|
| 1 | `pkg/shell/taint.go` に private ヘルパ `mergeSources`, `recordVisibleAt`, `callCommandName`, `buildArgBinding` を追加 (まだ walker 本体は変更しない) | 既存テスト緑 |
| 2 | `makeWalkFn` を funcTable / visited を closure 引数に持つ形に refactor (セマンティクス変更なし、リファクタのみ) | 既存テスト緑 |
| 3 | `*syntax.FuncDecl` ケースを「テーブル登録のみ、body walk しない」に変更。`*syntax.CallExpr` ケースを新設し lazy body walk を実装 (recursion guard, scopeFunc frame push) | §7.1 ケース #1 (single_call_simple) と #14 (regression) を緑 |
| 4 | `recordVisibleAt` を `*syntax.Stmt` ケースの記録に組み込み、複数 call-site の visibleAt union を有効化 | §7.1 ケース #2 (multi_call_union) を緑 |
| 5 | `buildArgBinding` の `$@` / `$*` 対応を確認 | §7.1 ケース #3, #4, #5 を緑 |
| 6 | recursion guard の境界 (forward ref / 直接再帰 / 相互再帰 / 兄弟 call-site) を検証 | §7.1 ケース #6, #7, #8, `RecursionGuardDecrement` を緑 |
| 7 | 残りの edge ケース (#9〜#17) を緑にしつつ既存 `TestPropagateTaint_Scoped` の regression を確認 | §7.1 全件緑 |
| 8 | `pkg/core/taint_test.go` に integration ケースを追加・通す | §7.2 緑 (`taint.go` 自体は変更しない) |
| 9 | `pkg/core/secretinlog.go` の `secretInLogFixer.FixStep` に `resolveMaskTarget` を追加 (positional 解決と `$@`/`$*` no-op) | §7.3 の autofix ケース緑 |
| 10 | `pkg/core/secretinlog_test.go` の検出系・autofix 系 4 ケースを通す | §7.3 全件緑 |
| 11 | `script/actions/taint-args-vulnerable.yaml` / `taint-args-safe.yaml` 新設 + `script/README.md` 更新 | `sisakulint script/actions/taint-args-vulnerable.yaml` で警告 1 件、`safe.yaml` で 0 件 |
| 12 | `go test ./...` 全体緑、`mutation` テスト (#446 で導入) を再走させ survived 件数の変化を確認 | regression 0 件 |
| 13 | `CLAUDE.md` の TaintTracker 説明に「関数引数経由の taint 伝播 (#448)」の旨を追記、§3 の "Known limitation" 表現を更新 | docs 更新済み |

## 9. 受け入れ基準

- [ ] `pkg/shell/taint_test.go::TestPropagateTaint_FunctionArgs` の新規 17+ ケースが緑
- [ ] `pkg/shell/taint_test.go::TestPropagateTaint_Scoped` の既存 13 ケースに regression なし
- [ ] `pkg/core/taint_test.go` の新規 2 ケースが緑
- [ ] `pkg/core/secretinlog_test.go` の新規 4 ケースが緑
- [ ] 既存全テスト緑 (`go test ./...`)
- [ ] `sisakulint script/actions/taint-args-vulnerable.yaml` で `secret-in-log` 警告が 1 件、`taint-args-safe.yaml` で 0 件
- [ ] `sisakulint -fix dry-run script/actions/taint-args-vulnerable.yaml` の挿入位置が `TOKEN=$(...)` 行直後で、`echo "::add-mask::$TOKEN"` (positional `$1` ではなく upstream `TOKEN` をマスク)
- [ ] `pkg/shell/taint.go::PropagateTaint` の docstring から `(#448 で改善予定)` の TODO コメントが削除され、関数引数 lazy walk のセマンティクスが追記されている
- [ ] `CLAUDE.md` のシェルスコープ説明セクションに #448 対応点 (関数引数 binding, 簡略案 A 維持) が追記されている

## 10. リスクと既知の制限

| 項目 | 影響 | 方針 |
|---|---|---|
| **funcTable がスコープ非分離 (グローバル)** | subshell 内で定義された関数を外側から呼び出すケースで bash 実挙動 (subshell 内定義は外で undefined) と乖離。CallExpr が funcTable に hit するため body walk が走り、本来発生しない taint propagation が記録される (FP 寄り) | known limitation。実用上ほぼ発生せず影響軽微。完全対応は scope-bound funcTable の追加が必要 (別 issue 候補) |
| **Uncalled function body の sink 未検出** | `foo() { local X="$T"; echo "$X"; }` (foo が呼ばれない) の内部派生 sink は lazy walk により未検出。pre-#448 (eager walk) では検出されていた | known limitation。bash 実挙動 (uncalled function は実行されない → log にも漏れない) と一致するため defensible。eager walk への巻き戻しはしない方針 |
| **複数 call-site の visibleAt union が保守的 (= FP 寄り)** | `foo "$T"; foo "safe"` で body 内 `echo "$1"` は両 call-site の binding union で tainted 扱いされ、第二の "safe" 呼び出しでは実際は untainted | issue 案明記の保守的方針。FP は「関数の振る舞いが call-site によって taint 状態を変える」設計 (一般にコードスメル) 限定で、実害軽微 |
| **`set -- a b c` / `shift` による positional 書き換え未対応** | 関数本体内で positional を再バインドするコード (`shift; echo "$1"` 等) は本 issue でカバーしない | known limitation。bash の動的 reassignment 解析は別 issue 候補 |
| **関数の non-local 副作用 (簡略案 A 維持)** | `foo() { GLOBAL="$T"; }; foo; echo "$GLOBAL"` で親の GLOBAL が untracked (FN) | #447 の判断を継続。完全対応は副作用伝播の正しい semantics 設計が必要 (epic #445 配下の follow-up) |
| **`foo "${{ untrusted }}"` 直接 expression args 未対応** | call-site で expression を直接渡すケースは shellvar 経由 binding が成立しないため捕捉されない (FN) | known limitation。一旦変数代入してから渡す形 (`X="${{ ... }}"; foo "$X"`) なら自然に追える。完全対応は §3.2 Approach 2 (callback 抽象) を別 issue 化 |
| **動的 dispatch (`$cmd "$T"`, eval, `bash -c "$cmd"`) 未対応** | 静的解析で関数名が決定できない呼び出しは untracked | 設計上の制約。検出は別系統 (code-injection ルール等) で行う |
| **autofix の不完全性: 上流が env-var の positional leak** | upstream 変数 (`TOKEN`) が env-var (e.g., `TOKEN: ${{ secrets.X }}`) の場合、`insertAfterAssignment` が空振りし autofix が no-op | known limitation (既存の env-var autofix 仕様と一貫)。lint 警告は出るので手動対応で塞げる |
| **autofix の不完全性: `$@` / `$*` leak** | best-effort 不能で no-op | 設計上の選択 (§6.2.2)。lint 警告は出る |
| **再帰展開 depth=1 による FN** | 深い再帰呼び出しの内部 sink は検出されない | issue 案明記。固定点反復は計算量爆発のリスクあるため採用せず |

## 11. 後続作業 (epic #445 配下)

- 関数の副作用伝播 (簡略案 A の解除): `foo() { X=...; }; foo; cmd "$X"` の親側 `$X` 解決
- subshell-bound funcTable: bash 実挙動と一致する scope-aware 関数登録
- `set --` / `shift` による positional 再バインド対応
- callback 抽象化による直接 `${{ untrusted }}` args 対応 (§3.2 Approach 2)
- 関数定義からの動的呼び出し (eval / `$cmd`) — 現状は scope 外、検出は code-injection 側で
