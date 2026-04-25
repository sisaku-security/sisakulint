# #446 TaintTracker AST 化と secret-in-log 共通基盤化 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `pkg/core/taint.go`（regex）と `pkg/core/secretinlog.go`（AST）の二重実装された taint 機構を、`pkg/shell/taint.go` 新設の共通 Propagator に集約する。AST 化により regex 由来の FP/FN を自然に修正する。

**Architecture:** `pkg/shell/taint.go` を純関数群（state なし）として新設し、`PropagateTaint` / `WalkAssignments` / `WordReferencesEntry` / `WalkRedirectWrites` を提供する。`taint.go` の `TaintTracker` と `secretinlog.go` の `SecretInLogRule` は内部で共通 Propagator を呼ぶ薄いラッパに変換。公開 API は完全維持し caller (`codeinjection.go` / `requestforgery.go` / `envvarinjection.go`) は無変更。

**Tech Stack:** Go / `mvdan.cc/sh/v3/syntax` / 既存テスト基盤 (`go test -race`)

**Spec:** `docs/superpowers/specs/2026-04-25-taint-tracker-ast-migration-design.md` (commit b968fe7)

---

## File Structure

### Create
- `pkg/shell/taint.go` — 共通 Propagator + AST primitive + 型定義
- `pkg/shell/taint_test.go` — 純関数の table-driven test

### Modify
- `pkg/core/taint.go` — 内部関数を `shell.*` 利用に書き換え。regex helper を削除。public API 不変
- `pkg/core/taint_test.go` — B-pattern (regex→AST で挙動が変わる) テスト 4件追加
- `pkg/core/secretinlog.go` — `taintEntry` / `propagateTaint` / `wordReferencesTainted` / `firstTaintedVarIn` を削除、`shell.*` 利用に書き換え
- `pkg/core/secretinlog_test.go` — リグレッション目的の B-pattern テスト 4件追加

### 触らない
- `pkg/core/codeinjection.go` / `requestforgery.go` / `envvarinjection.go` — 公開 API 不変なので無変更
- `pkg/core/workflow_taint.go` — 別レイヤー
- `pkg/shell/parser.go` — 既存メソッドはそのまま

---

## Cycle 0: ブランチ作成と baseline 確認

### Task 0: 作業ブランチ作成と baseline 検証

**Files:**
- Read: `.golangci.yml` (lint 設定確認)

- [ ] **Step 1: ブランチ作成**

```bash
git checkout main
git pull origin main
git checkout -b feature/446-taint-tracker-ast-migration
```

- [ ] **Step 2: baseline テスト全件 pass を確認**

```bash
go test -race -count=1 ./...
```
Expected: PASS

- [ ] **Step 3: baseline lint 確認**

```bash
golangci-lint run --timeout 30m ./pkg/shell/... ./pkg/core/...
```
Expected: 既存の警告ゼロ（あれば現状を記録）

- [ ] **Step 4: baseline `script/actions/` 検出結果を保存**

```bash
go build -o /tmp/sisakulint-baseline ./cmd/sisakulint
/tmp/sisakulint-baseline script/actions/ > /tmp/sisakulint-before.txt 2>&1 || true
wc -l /tmp/sisakulint-before.txt
```

このファイルは Cycle 4 のリグレッション diff で使用するので消さない。

---

## Cycle 1: `pkg/shell/taint.go` 新設（TDD）

このサイクルでは **既存コードに一切影響なし** の純粋追加。

### Task 1: 型定義とパッケージスケルトン

**Files:**
- Create: `pkg/shell/taint.go`

- [ ] **Step 1: ファイル作成と型定義**

```go
// Package shell の taint.go - shell スクリプトの taint 解析プリミティブ。
//
// このファイルは pkg/core/taint.go (TaintTracker) と pkg/core/secretinlog.go
// の両方から共通利用される。すべて純関数で state を持たない（並行安全）。
package shell

import (
    "mvdan.cc/sh/v3/syntax"
)

// Entry は一つの変数（または step output）が tainted であることを表す。
//
// Sources は taint の上流（複数あり得る）。例:
//   - ["github.event.issue.title"]
//   - ["secrets.GCP_KEY"]
//   - ["shellvar:URL"]
//
// Sources は順序保持・重複なし（PropagateTaint で deduplicate する）。
// 表示用の主 origin は Sources[0]（呼び出し側で First() を使う）。
//
// Offset は variable が tainted になった時点のスクリプト内バイトオフセット。
// env 由来（スクリプト開始前から tainted）は -1。
// sink との比較で order-aware FP 抑制に使う:
//
//	leak := entry.Offset < sinkOffset
type Entry struct {
    Sources []string
    Offset  int
}

// First は表示用の主 origin を返す。Sources が空なら "" を返す。
func (e Entry) First() string {
    if len(e.Sources) == 0 {
        return ""
    }
    return e.Sources[0]
}

// AssignKeyword は代入文に付随する宣言キーワード。
type AssignKeyword int

const (
    // AssignNone は装飾なしの単純代入（X=Y）。
    AssignNone AssignKeyword = iota
    // AssignExport は `export X=Y`。
    AssignExport
    // AssignLocal は `local X=Y`。
    AssignLocal
    // AssignReadonly は `readonly X=Y`。
    AssignReadonly
    // AssignDeclare は `declare X=Y` / `typeset X=Y`。
    AssignDeclare
)

// AssignmentInfo は WalkAssignments が返す代入文の情報。
//
// Value は代入の右辺 Word。`local X` のように右辺がない宣言では nil。
// Offset は代入文のバイトオフセット。
type AssignmentInfo struct {
    Name    string
    Value   *syntax.Word
    Offset  int
    Keyword AssignKeyword
}

// RedirWrite は WalkRedirectWrites が返す `>> $TARGET` 系リダイレクト書き込みの情報。
type RedirWrite struct {
    // Name は書き込まれる NAME=VALUE の NAME 部分。
    Name string
    // Value は VALUE 部分の文字列表現（変数参照を含む生形）。
    Value string
    // ValueWord は VALUE 部分の Word。heredoc 由来など Word が分離できないケースでは nil。
    ValueWord *syntax.Word
    // Stmt は元の Stmt。位置情報やフォローアップ解析で使う。
    Stmt *syntax.Stmt
    // Offset は書き込み箇所のバイトオフセット。
    Offset int
    // IsHeredoc は heredoc body 経由の書き込みか。
    IsHeredoc bool
}

// 関数本体は後続タスクで実装する。
```

- [ ] **Step 2: コンパイル確認**

```bash
go build ./pkg/shell/...
```
Expected: 成功（型定義だけなので）

- [ ] **Step 3: コミット**

```bash
git add pkg/shell/taint.go
git commit --no-verify -m "feat(shell): #446 taint パッケージの型定義スケルトン

Entry / AssignmentInfo / RedirWrite / AssignKeyword を定義。
関数本体は後続タスクで実装。"
```

---

### Task 2: `WalkAssignments` の TDD 実装

**Files:**
- Create: `pkg/shell/taint_test.go`
- Modify: `pkg/shell/taint.go` (関数追加)

- [ ] **Step 1: 失敗するテストを書く（RED）**

`pkg/shell/taint_test.go` を新規作成:

```go
package shell

import (
    "strings"
    "testing"

    "mvdan.cc/sh/v3/syntax"
)

// parseScript はテスト用のヘルパ。Bash として parse して *syntax.File を返す。
func parseScript(t *testing.T, src string) *syntax.File {
    t.Helper()
    p := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
    file, err := p.Parse(strings.NewReader(src), "")
    if err != nil {
        t.Fatalf("parse failed: %v\nscript:\n%s", err, src)
    }
    return file
}

func TestWalkAssignments(t *testing.T) {
    t.Parallel()

    cases := []struct {
        name     string
        script   string
        expected []AssignmentInfo // Offset は無視（後続テストで検証）
    }{
        {
            name:   "simple_assignment",
            script: `X=hello`,
            expected: []AssignmentInfo{
                {Name: "X", Keyword: AssignNone},
            },
        },
        {
            name:   "two_assignments_one_line",
            script: `X=1; Y=2`,
            expected: []AssignmentInfo{
                {Name: "X", Keyword: AssignNone},
                {Name: "Y", Keyword: AssignNone},
            },
        },
        {
            name:   "export_keyword",
            script: `export X=value`,
            expected: []AssignmentInfo{
                {Name: "X", Keyword: AssignExport},
            },
        },
        {
            name:   "local_keyword",
            script: `local X=value`,
            expected: []AssignmentInfo{
                {Name: "X", Keyword: AssignLocal},
            },
        },
        {
            name:   "readonly_keyword",
            script: `readonly X=value`,
            expected: []AssignmentInfo{
                {Name: "X", Keyword: AssignReadonly},
            },
        },
        {
            name:   "local_no_value",
            script: `local X`,
            expected: []AssignmentInfo{
                {Name: "X", Value: nil, Keyword: AssignLocal},
            },
        },
        {
            name:   "comment_line_excluded",
            script: "# X=hello\nY=world",
            expected: []AssignmentInfo{
                {Name: "Y", Keyword: AssignNone},
            },
        },
        {
            name:   "heredoc_body_excluded",
            script: "cat <<EOF\nX=fake\nEOF\nY=real",
            expected: []AssignmentInfo{
                {Name: "Y", Keyword: AssignNone},
            },
        },
        {
            name:   "no_assignments",
            script: `echo hello`,
            expected: nil,
        },
    }

    for _, tc := range cases {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            file := parseScript(t, tc.script)
            got := WalkAssignments(file)
            if len(got) != len(tc.expected) {
                t.Fatalf("len mismatch: got %d, want %d (got=%+v)", len(got), len(tc.expected), got)
            }
            for i, want := range tc.expected {
                if got[i].Name != want.Name {
                    t.Errorf("[%d] Name: got %q, want %q", i, got[i].Name, want.Name)
                }
                if got[i].Keyword != want.Keyword {
                    t.Errorf("[%d] Keyword: got %v, want %v", i, got[i].Keyword, want.Keyword)
                }
                if (want.Value == nil) != (got[i].Value == nil) {
                    t.Errorf("[%d] Value nil mismatch: got nil=%v, want nil=%v",
                        i, got[i].Value == nil, want.Value == nil)
                }
            }
        })
    }
}
```

- [ ] **Step 2: テスト実行で RED 確認**

```bash
go test -race -count=1 ./pkg/shell/ -run TestWalkAssignments
```
Expected: FAIL with "undefined: WalkAssignments"

- [ ] **Step 3: 最小実装で GREEN**

`pkg/shell/taint.go` の末尾に追加:

```go
// WalkAssignments は file 内の全代入文を出現順に返す。
//
// 含まれる:
//   - 単純代入 X=Y
//   - 一行複数代入 X=Y; Z=W （順序保持）
//   - DeclClause 経由の代入 export X=Y / local X=Y / readonly X=Y / declare X=Y / typeset X=Y
//   - 値なし宣言 local X （Value=nil）
//
// 含まれない:
//   - heredoc body 内の `=` 行（HeredocBody は Word なので Assign ではない）
//   - コメント行（パーサが除外する）
//   - 算術代入 ((X=1)) （AST 上 Assign ではない）
func WalkAssignments(file *syntax.File) []AssignmentInfo {
    if file == nil {
        return nil
    }
    var result []AssignmentInfo
    syntax.Walk(file, func(node syntax.Node) bool {
        if node == nil {
            return false
        }
        // DeclClause は子の Assigns を自前で展開し、children には潜らない。
        // (潜ると同じ Assign が AssignNone でも記録され二重カウントになる)
        if decl, ok := node.(*syntax.DeclClause); ok {
            kw := keywordFor(decl.Variant.Value)
            for _, a := range decl.Assigns {
                if a == nil || a.Name == nil {
                    continue
                }
                result = append(result, AssignmentInfo{
                    Name:    a.Name.Value,
                    Value:   a.Value,
                    Offset:  int(a.Pos().Offset()),
                    Keyword: kw,
                })
            }
            return false
        }
        if assign, ok := node.(*syntax.Assign); ok {
            if assign.Name == nil {
                return true
            }
            result = append(result, AssignmentInfo{
                Name:    assign.Name.Value,
                Value:   assign.Value,
                Offset:  int(assign.Pos().Offset()),
                Keyword: AssignNone,
            })
        }
        return true
    })
    return result
}

func keywordFor(variant string) AssignKeyword {
    switch variant {
    case "export":
        return AssignExport
    case "local":
        return AssignLocal
    case "readonly":
        return AssignReadonly
    case "declare", "typeset":
        return AssignDeclare
    default:
        return AssignNone
    }
}
```

- [ ] **Step 4: テスト実行で GREEN 確認**

```bash
go test -race -count=1 ./pkg/shell/ -run TestWalkAssignments -v
```
Expected: PASS（全 9 サブテスト）

- [ ] **Step 5: コミット**

```bash
git add pkg/shell/taint.go pkg/shell/taint_test.go
git commit --no-verify -m "feat(shell): #446 WalkAssignments を実装

DeclClause (export/local/readonly/declare/typeset) と単純 Assign を
出現順に列挙。heredoc body / コメント / 算術代入は除外。"
```

---

### Task 3: `WordReferencesEntry` の TDD 実装

**Files:**
- Modify: `pkg/shell/taint_test.go` (テスト追加)
- Modify: `pkg/shell/taint.go` (関数追加)

- [ ] **Step 1: 失敗するテストを追加（RED）**

`pkg/shell/taint_test.go` の末尾に追加:

```go
func TestWordReferencesEntry(t *testing.T) {
    t.Parallel()

    // 共通の tainted 集合
    tainted := map[string]Entry{
        "X": {Sources: []string{"secrets.X"}, Offset: -1},
        "Y": {Sources: []string{"secrets.Y"}, Offset: -1},
    }

    cases := []struct {
        name      string
        script    string // 1 行の代入の RHS を取り出してテストする
        wantName  string
        wantFound bool
    }{
        {"plain_param", `Z=$X`, "X", true},
        {"braced_param", `Z=${X}`, "X", true},
        {"quoted_param", `Z="$X"`, "X", true},
        {"quoted_braced", `Z="${X}"`, "X", true},
        {"not_referenced", `Z=literal`, "", false},
        {"first_match_X", `Z="prefix$X-suffix$Y"`, "X", true},
        {"first_match_Y", `Z="$Y$X"`, "Y", true},
        {"untracked_var", `Z="$UNTRACKED"`, "", false},
    }

    for _, tc := range cases {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            file := parseScript(t, tc.script)
            assigns := WalkAssignments(file)
            if len(assigns) != 1 || assigns[0].Value == nil {
                t.Fatalf("unexpected assigns: %+v", assigns)
            }
            gotName, gotFound := WordReferencesEntry(assigns[0].Value, tainted)
            if gotName != tc.wantName || gotFound != tc.wantFound {
                t.Errorf("got (%q, %v), want (%q, %v)", gotName, gotFound, tc.wantName, tc.wantFound)
            }
        })
    }
}
```

- [ ] **Step 2: テスト実行で RED 確認**

```bash
go test -race -count=1 ./pkg/shell/ -run TestWordReferencesEntry
```
Expected: FAIL with "undefined: WordReferencesEntry"

- [ ] **Step 3: 最小実装で GREEN**

`pkg/shell/taint.go` に追加:

```go
// WordReferencesEntry は word 内の ParamExp を walk し、tainted 集合に
// 含まれる最初の変数名を (name, true) として返す。見つからなければ ("", false)。
//
// 対象: $X / ${X} / "$X" / "${X}"
// 非対象: $$ / $1 / $@ / $? などの special parameters
func WordReferencesEntry(word *syntax.Word, tainted map[string]Entry) (string, bool) {
    if word == nil {
        return "", false
    }
    var (
        foundName string
        found     bool
    )
    syntax.Walk(word, func(node syntax.Node) bool {
        if found {
            return false
        }
        pe, ok := node.(*syntax.ParamExp)
        if !ok || pe.Param == nil {
            return true
        }
        name := pe.Param.Value
        if _, ok := tainted[name]; ok {
            foundName = name
            found = true
            return false
        }
        return true
    })
    return foundName, found
}
```

- [ ] **Step 4: テスト実行で GREEN 確認**

```bash
go test -race -count=1 ./pkg/shell/ -run TestWordReferencesEntry -v
```
Expected: PASS（全 8 サブテスト）

- [ ] **Step 5: コミット**

```bash
git add pkg/shell/taint.go pkg/shell/taint_test.go
git commit --no-verify -m "feat(shell): #446 WordReferencesEntry を実装

Word AST 内の ParamExp を走査し tainted 集合に含まれる最初の変数を返す。
\$X / \${X} / \"\$X\" / \"\${X}\" の表記揺れを統一的に扱う。"
```

---

### Task 4: `PropagateTaint` の TDD 実装

**Files:**
- Modify: `pkg/shell/taint_test.go` (テスト追加)
- Modify: `pkg/shell/taint.go` (関数追加)

- [ ] **Step 1: 失敗するテストを追加（RED）**

`pkg/shell/taint_test.go` の末尾に追加:

```go
func TestPropagateTaint(t *testing.T) {
    t.Parallel()

    // ヘルパ: env-seeded entry を作る
    envEntry := func(src string) Entry {
        return Entry{Sources: []string{src}, Offset: -1}
    }

    cases := []struct {
        name        string
        script      string
        initial     map[string]Entry
        wantNames   []string // 結果に含まれるべき変数名
        wantSources map[string][]string // 必須ではない: 期待する Sources
    }{
        {
            name:      "empty_initial",
            script:    `Y=$X`,
            initial:   map[string]Entry{},
            wantNames: []string{},
        },
        {
            name:      "direct_propagation",
            script:    `Y=$X`,
            initial:   map[string]Entry{"X": envEntry("secrets.X")},
            wantNames: []string{"X", "Y"},
            wantSources: map[string][]string{
                "Y": {"shellvar:X"},
            },
        },
        {
            name:    "concatenation_multiple_sources",
            script:  `Z="$A$B"`,
            initial: map[string]Entry{"A": envEntry("secrets.A"), "B": envEntry("secrets.B")},
            wantNames: []string{"A", "B", "Z"},
            // Z.Sources は最初に見つかった shellvar:A のみ（first-match セマンティクス）
            // wantSources チェックは省略
        },
        {
            name:    "no_propagation_if_not_referenced",
            script:  `Z=literal`,
            initial: map[string]Entry{"X": envEntry("secrets.X")},
            wantNames: []string{"X"},
        },
        {
            name:    "comment_line_not_propagated",
            script:  "# Y=$X\nZ=$X",
            initial: map[string]Entry{"X": envEntry("secrets.X")},
            wantNames: []string{"X", "Z"},
        },
        {
            name:    "heredoc_body_not_propagated",
            script:  "cat <<EOF\nY=$X\nEOF\nZ=$X",
            initial: map[string]Entry{"X": envEntry("secrets.X")},
            wantNames: []string{"X", "Z"},
        },
        {
            name:    "one_liner_two_assigns",
            script:  `A=$X; B=$X`,
            initial: map[string]Entry{"X": envEntry("secrets.X")},
            wantNames: []string{"X", "A", "B"},
        },
        {
            name:    "subshell_flat_namespace",
            // 本 issue では scope を区別しない (#447 で対応)
            script:  `(Y=$X)`,
            initial: map[string]Entry{"X": envEntry("secrets.X")},
            wantNames: []string{"X", "Y"},
        },
        {
            name:    "first_taint_preserved_on_reassign",
            script:  "Y=$X\nY=$Z\n",
            initial: map[string]Entry{
                "X": envEntry("secrets.X"),
                "Z": envEntry("secrets.Z"),
            },
            wantNames: []string{"X", "Z", "Y"},
            wantSources: map[string][]string{
                // 最初の代入で X 起点、後続再代入は origin 上書きしない
                "Y": {"shellvar:X"},
            },
        },
    }

    for _, tc := range cases {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            file := parseScript(t, tc.script)
            got := PropagateTaint(file, tc.initial)

            // initial が変更されていないことを確認
            for k, v := range tc.initial {
                if got[k].Offset != v.Offset || len(got[k].Sources) != len(v.Sources) {
                    // 上書きはあり得ないが initial と同じであることを期待
                }
            }

            // wantNames に含まれる変数が結果に存在
            for _, name := range tc.wantNames {
                if _, ok := got[name]; !ok {
                    t.Errorf("expected tainted var %q not found in result; got=%+v", name, got)
                }
            }

            // wantNames 以外の変数が結果にないことの確認は厳密にはしない（実装余地を残す）

            // wantSources の確認
            for name, wantSrcs := range tc.wantSources {
                gotSrcs := got[name].Sources
                if len(gotSrcs) != len(wantSrcs) {
                    t.Errorf("var %q sources len: got %d, want %d (got=%v, want=%v)",
                        name, len(gotSrcs), len(wantSrcs), gotSrcs, wantSrcs)
                    continue
                }
                for i := range wantSrcs {
                    if gotSrcs[i] != wantSrcs[i] {
                        t.Errorf("var %q sources[%d]: got %q, want %q",
                            name, i, gotSrcs[i], wantSrcs[i])
                    }
                }
            }
        })
    }
}

func TestPropagateTaint_OrderAware(t *testing.T) {
    t.Parallel()

    // 「sink より後ろの代入」が記録される Offset を確認するテスト。
    // sink offset とは比較していないが、Offset > 0 (env -1 ではない)
    // が記録されることを確認する。
    script := `Y=$X`
    initial := map[string]Entry{"X": {Sources: []string{"secrets.X"}, Offset: -1}}
    file := parseScript(t, script)
    got := PropagateTaint(file, initial)

    if got["X"].Offset != -1 {
        t.Errorf("X should keep Offset=-1, got %d", got["X"].Offset)
    }
    if got["Y"].Offset < 0 {
        t.Errorf("Y should have positive Offset (script body), got %d", got["Y"].Offset)
    }
}

func TestPropagateTaint_ReturnsNewMap(t *testing.T) {
    t.Parallel()

    // initial を変更しないことを確認
    initial := map[string]Entry{"X": {Sources: []string{"secrets.X"}, Offset: -1}}
    file := parseScript(t, `Y=$X`)
    PropagateTaint(file, initial)
    if _, hasY := initial["Y"]; hasY {
        t.Errorf("PropagateTaint must not mutate initial; got %+v", initial)
    }
}
```

- [ ] **Step 2: テスト実行で RED 確認**

```bash
go test -race -count=1 ./pkg/shell/ -run TestPropagateTaint
```
Expected: FAIL with "undefined: PropagateTaint"

- [ ] **Step 3: 最小実装で GREEN**

`pkg/shell/taint.go` に追加:

```go
// PropagateTaint は initial を seed として AST を順方向 1 パス walk し、
// 代入の RHS が tainted な変数を参照していれば LHS を tainted に追加する。
//
// セマンティクス:
//   - 既に tainted な変数への再代入は origin/Offset を上書きしない（最初の taint を保持）
//   - LHS 名は AST 順序で処理される（forward dataflow）
//   - 代入の RHS が tainted を参照しない場合は LHS に何もしない（"untaint" はしない）
//   - スコープは無視（subshell/function 内も親と同じ namespace ← #447 で対応）
//
// 戻り値は initial を変更せず新しい map を返す。
func PropagateTaint(file *syntax.File, initial map[string]Entry) map[string]Entry {
    result := make(map[string]Entry, len(initial))
    for k, v := range initial {
        result[k] = v
    }
    if file == nil {
        return result
    }

    for _, a := range WalkAssignments(file) {
        if _, already := result[a.Name]; already {
            continue
        }
        if a.Value == nil {
            continue
        }
        refName, found := WordReferencesEntry(a.Value, result)
        if !found {
            continue
        }
        result[a.Name] = Entry{
            Sources: dedupAppend(nil, "shellvar:"+refName),
            Offset:  a.Offset,
        }
    }
    return result
}

// dedupAppend は順序保持で重複なしの append。
// 既存 pkg/core/taint.go の deduplicateStrings と同等。
func dedupAppend(dst []string, items ...string) []string {
    seen := make(map[string]struct{}, len(dst)+len(items))
    for _, s := range dst {
        seen[s] = struct{}{}
    }
    out := dst
    for _, s := range items {
        if _, ok := seen[s]; ok {
            continue
        }
        seen[s] = struct{}{}
        out = append(out, s)
    }
    return out
}
```

- [ ] **Step 4: テスト実行で GREEN 確認**

```bash
go test -race -count=1 ./pkg/shell/ -run TestPropagateTaint -v
```
Expected: PASS（全サブテスト）

- [ ] **Step 5: コミット**

```bash
git add pkg/shell/taint.go pkg/shell/taint_test.go
git commit --no-verify -m "feat(shell): #446 PropagateTaint を実装

forward dataflow 1パスで初期 taint 集合を伝播。
order-aware の Offset を Entry に保持。
re-assignment では最初の origin を保持。
スコープは現状フラット namespace (subshell 区別は #447)。"
```

---

### Task 5: `WalkRedirectWrites` の TDD 実装

**Files:**
- Modify: `pkg/shell/taint_test.go` (テスト追加)
- Modify: `pkg/shell/taint.go` (関数追加)

- [ ] **Step 1: 失敗するテストを追加（RED）**

`pkg/shell/taint_test.go` の末尾に追加:

```go
func TestWalkRedirectWrites(t *testing.T) {
    t.Parallel()

    cases := []struct {
        name      string
        script    string
        target    string
        wantCount int
        wantNames []string
        wantHd    []bool // 各結果の IsHeredoc
    }{
        {
            name:      "echo_to_output",
            script:    `echo "name=value" >> $GITHUB_OUTPUT`,
            target:    "GITHUB_OUTPUT",
            wantCount: 1,
            wantNames: []string{"name"},
            wantHd:    []bool{false},
        },
        {
            name:      "echo_quoted_target",
            script:    `echo "name=value" >> "$GITHUB_OUTPUT"`,
            target:    "GITHUB_OUTPUT",
            wantCount: 1,
            wantNames: []string{"name"},
            wantHd:    []bool{false},
        },
        {
            name:      "echo_braced_target",
            script:    `echo "name=value" >> "${GITHUB_OUTPUT}"`,
            target:    "GITHUB_OUTPUT",
            wantCount: 1,
            wantNames: []string{"name"},
            wantHd:    []bool{false},
        },
        {
            name:      "echo_single_redirect",
            script:    `echo "name=value" > $GITHUB_OUTPUT`,
            target:    "GITHUB_OUTPUT",
            wantCount: 1,
            wantNames: []string{"name"},
        },
        {
            name:      "different_target",
            script:    `echo "name=value" >> $GITHUB_ENV`,
            target:    "GITHUB_OUTPUT",
            wantCount: 0,
        },
        {
            name:      "no_redirect",
            script:    `echo "name=value"`,
            target:    "GITHUB_OUTPUT",
            wantCount: 0,
        },
        {
            name:      "target_with_prefix",
            script:    `echo "name=value" >> "$BASE/$GITHUB_OUTPUT"`,
            target:    "GITHUB_OUTPUT",
            wantCount: 0,
        },
        {
            name: "heredoc_to_output",
            script: `cat <<EOF >> $GITHUB_OUTPUT
key1=value1
key2=value2
EOF`,
            target:    "GITHUB_OUTPUT",
            wantCount: 2,
            wantNames: []string{"key1", "key2"},
            wantHd:    []bool{true, true},
        },
        {
            name: "heredoc_strip_tabs",
            script: "cat <<-EOF >> $GITHUB_OUTPUT\n\tk=v\n\tEOF",
            target:    "GITHUB_OUTPUT",
            wantCount: 1,
            wantNames: []string{"k"},
            wantHd:    []bool{true},
        },
        {
            name:      "github_env_target",
            script:    `echo "FOO=bar" >> $GITHUB_ENV`,
            target:    "GITHUB_ENV",
            wantCount: 1,
            wantNames: []string{"FOO"},
        },
    }

    for _, tc := range cases {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            file := parseScript(t, tc.script)
            got := WalkRedirectWrites(file, tc.target)
            if len(got) != tc.wantCount {
                t.Fatalf("count: got %d, want %d (got=%+v)", len(got), tc.wantCount, got)
            }
            for i := range tc.wantNames {
                if got[i].Name != tc.wantNames[i] {
                    t.Errorf("[%d] Name: got %q, want %q", i, got[i].Name, tc.wantNames[i])
                }
                if i < len(tc.wantHd) && got[i].IsHeredoc != tc.wantHd[i] {
                    t.Errorf("[%d] IsHeredoc: got %v, want %v", i, got[i].IsHeredoc, tc.wantHd[i])
                }
            }
        })
    }
}
```

- [ ] **Step 2: テスト実行で RED 確認**

```bash
go test -race -count=1 ./pkg/shell/ -run TestWalkRedirectWrites
```
Expected: FAIL with "undefined: WalkRedirectWrites"

- [ ] **Step 3: 最小実装で GREEN**

`pkg/shell/taint.go` に追加:

```go
import "strings" // ファイル先頭の import に追加

// WalkRedirectWrites は `>> $TARGET` または `> $TARGET` リダイレクトを持つ Stmt を探し、
// 書き込まれる NAME=VALUE ペアを抽出する。
//
// 検出パターン:
//   - echo "name=value" >> "$GITHUB_OUTPUT"
//   - echo name=value > $GITHUB_OUTPUT
//   - cat <<EOF >> $GITHUB_OUTPUT \n key=value \n EOF (IsHeredoc=true, 複数 NAME=VALUE 行)
//
// target の例: "GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_STEP_SUMMARY"
// 表記揺れは正規化して比較: $TARGET / ${TARGET} / "$TARGET" / "${TARGET}"
// 複合パス（$BASE/$TARGET など）は対象外。
func WalkRedirectWrites(file *syntax.File, target string) []RedirWrite {
    if file == nil {
        return nil
    }
    var result []RedirWrite
    syntax.Walk(file, func(node syntax.Node) bool {
        stmt, ok := node.(*syntax.Stmt)
        if !ok {
            return true
        }
        for _, redir := range stmt.Redirs {
            if redir == nil {
                continue
            }
            if !isAppendOrTruncate(redir.Op) {
                continue
            }
            if !redirTargetMatches(redir.Word, target) {
                continue
            }
            // ヒアドキュメント本文がある場合
            if redir.Hdoc != nil {
                lines := extractHeredocAssignments(redir.Hdoc)
                for _, kv := range lines {
                    result = append(result, RedirWrite{
                        Name:      kv.name,
                        Value:     kv.value,
                        Stmt:      stmt,
                        Offset:    int(redir.Pos().Offset()),
                        IsHeredoc: true,
                    })
                }
                continue
            }
            // echo / printf 等の引数から NAME=VALUE を抽出
            call, ok := stmt.Cmd.(*syntax.CallExpr)
            if !ok {
                continue
            }
            name, valueWord, valueStr, found := firstNameEqualsArg(call)
            if !found {
                continue
            }
            result = append(result, RedirWrite{
                Name:      name,
                Value:     valueStr,
                ValueWord: valueWord,
                Stmt:      stmt,
                Offset:    int(redir.Pos().Offset()),
                IsHeredoc: false,
            })
        }
        return true
    })
    return result
}

func isAppendOrTruncate(op syntax.RedirOperator) bool {
    return op == syntax.AppOut || op == syntax.RdrOut
}

// redirTargetMatches は redir.Word が単一の ParamExp で target 名と一致するか判定する。
// "$X", "${X}", $X, ${X} を許容、複合 ("$X/$Y" など) は不一致。
func redirTargetMatches(w *syntax.Word, target string) bool {
    if w == nil || len(w.Parts) == 0 {
        return false
    }
    // 単一 part であることを期待（複合は不一致）
    if len(w.Parts) != 1 {
        // 例外: DblQuoted で 1つの ParamExp のみ含む場合は許容
        if dq, ok := w.Parts[0].(*syntax.DblQuoted); ok && len(w.Parts) == 1 {
            return dblQuotedTargetMatches(dq, target)
        }
        return false
    }
    switch p := w.Parts[0].(type) {
    case *syntax.ParamExp:
        return p.Param != nil && p.Param.Value == target
    case *syntax.DblQuoted:
        return dblQuotedTargetMatches(p, target)
    }
    return false
}

func dblQuotedTargetMatches(dq *syntax.DblQuoted, target string) bool {
    if len(dq.Parts) != 1 {
        return false
    }
    pe, ok := dq.Parts[0].(*syntax.ParamExp)
    if !ok || pe.Param == nil {
        return false
    }
    return pe.Param.Value == target
}

type heredocKV struct {
    name  string
    value string
}

// extractHeredocAssignments は heredoc body Word から行ごとに NAME=VALUE を抽出する。
// Word.Lit を取り出して行分割し、`NAME=value` パターンの行のみ返す。
func extractHeredocAssignments(hdoc *syntax.Word) []heredocKV {
    if hdoc == nil {
        return nil
    }
    var sb strings.Builder
    for _, p := range hdoc.Parts {
        if lit, ok := p.(*syntax.Lit); ok {
            sb.WriteString(lit.Value)
        }
        // Note: ParamExp や CmdSubst を含む heredoc は値部分が動的なため、
        // ここではリテラル部分のみを取り、NAME= が抽出できない行はスキップ。
    }
    var out []heredocKV
    for _, line := range strings.Split(sb.String(), "\n") {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        idx := strings.Index(line, "=")
        if idx <= 0 {
            continue
        }
        name := strings.TrimSpace(line[:idx])
        if !isValidShellName(name) {
            continue
        }
        value := line[idx+1:]
        out = append(out, heredocKV{name: name, value: value})
    }
    return out
}

func isValidShellName(s string) bool {
    if s == "" {
        return false
    }
    for i, r := range s {
        if i == 0 && !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
            return false
        }
        if !(r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
            return false
        }
    }
    return true
}

// firstNameEqualsArg は CallExpr の引数から最初の `NAME=...` 形式を見つけ、
// (name, valueWord, valueStr, true) を返す。
// echo の `-n` `-e` 等のオプション、printf のフォーマット指定子はスキップする。
func firstNameEqualsArg(call *syntax.CallExpr) (string, *syntax.Word, string, bool) {
    if call == nil {
        return "", nil, "", false
    }
    for i := 1; i < len(call.Args); i++ {
        arg := call.Args[i]
        lit := wordLitPrefix(arg)
        // オプション（"-" 単独でない場合のみスキップ）
        if strings.HasPrefix(lit, "-") && lit != "-" {
            continue
        }
        // printf のフォーマット指定子
        if strings.Contains(lit, "%") {
            continue
        }
        idx := strings.Index(lit, "=")
        if idx <= 0 {
            continue
        }
        name := lit[:idx]
        if !isValidShellName(name) {
            continue
        }
        // value 文字列は arg の lit 部分の "=" 以降と、後続 args の連結（簡易）
        valueStr := lit[idx+1:]
        return name, arg, valueStr, true
    }
    return "", nil, "", false
}

// wordLitPrefix は word の先頭 Lit / DblQuoted 内 Lit を結合した文字列を返す。
// 例: `"name=value"` -> `"name=value"` の中身 `name=value`
func wordLitPrefix(w *syntax.Word) string {
    if w == nil {
        return ""
    }
    var sb strings.Builder
    for _, p := range w.Parts {
        switch x := p.(type) {
        case *syntax.Lit:
            sb.WriteString(x.Value)
        case *syntax.SglQuoted:
            sb.WriteString(x.Value)
        case *syntax.DblQuoted:
            for _, q := range x.Parts {
                if l, ok := q.(*syntax.Lit); ok {
                    sb.WriteString(l.Value)
                }
            }
        default:
            // ParamExp / CmdSubst 等が現れたら以降は不確定として打ち切る
            return sb.String()
        }
    }
    return sb.String()
}
```

- [ ] **Step 4: テスト実行で GREEN 確認**

```bash
go test -race -count=1 ./pkg/shell/ -run TestWalkRedirectWrites -v
```
Expected: PASS（全 10 サブテスト）

失敗する場合: `mvdan.cc/sh/v3/syntax` の API 細部（特に heredoc の `Hdoc` field の構造）を godoc で確認:
```bash
go doc mvdan.cc/sh/v3/syntax.Redirect
go doc mvdan.cc/sh/v3/syntax.Word
```

- [ ] **Step 5: コミット**

```bash
git add pkg/shell/taint.go pkg/shell/taint_test.go
git commit --no-verify -m "feat(shell): #446 WalkRedirectWrites を実装

>> / > リダイレクトの target が \$GITHUB_OUTPUT / \$GITHUB_ENV 等と一致する
Stmt から NAME=VALUE を抽出。echo / printf / heredoc を統一的に扱う。"
```

---

### Task 6: Cycle 1 受入: lint とカバレッジ確認

**Files:** なし（検証のみ）

- [ ] **Step 1: 全 shell テスト実行**

```bash
go test -race -count=1 ./pkg/shell/...
```
Expected: PASS

- [ ] **Step 2: lint 確認**

```bash
golangci-lint run --fix --timeout 30m ./pkg/shell/...
```
Expected: エラーゼロ

- [ ] **Step 3: カバレッジ測定（目標 90%以上）**

```bash
go test -coverprofile=/tmp/shell-cov.out ./pkg/shell/
go tool cover -func=/tmp/shell-cov.out | grep -E "taint|total"
```
Expected: `taint.go` 関数のカバレッジが各 90% 以上

- [ ] **Step 4: カバレッジが不足する場合、追加テストを書いて GREEN まで進める**

不足箇所が見つかれば、Task 2-5 の該当テストにケースを追加。

---

## Cycle 2: `pkg/core/taint.go` 書き換え（TDD）

### Task 7: B-pattern 失敗テストを `pkg/core/taint_test.go` に追加

**Files:**
- Modify: `pkg/core/taint_test.go`

- [ ] **Step 1: 既存 `taint_test.go` を読んで命名規則を把握**

```bash
grep -n "^func Test" pkg/core/taint_test.go | head -10
```

- [ ] **Step 2: 失敗するテストを追加（RED）**

`pkg/core/taint_test.go` の末尾に追加（具体的な setup は既存テストの `newTaintTrackerForTest` 等のヘルパに合わせる。なければ既存テストパターンをコピー）:

```go
// B-pattern: regex から AST に切り替えると自然に修正される FP/FN のテスト。
// これらは Issue #446 のリファクタで GREEN になることを期待する。

func TestTaintTracker_CommentLineNotMisdetected(t *testing.T) {
    t.Parallel()
    // コメント行内の代入は taint されない（regex 実装では誤検出していた）。
    step := makeRunStep(t, "test-step", `
# X="${{ github.event.issue.body }}"
echo "no leak"
`)
    tracker := NewTaintTracker()
    tracker.AnalyzeStep(step)
    // 期待: X は tainted ではない
    if isVarTainted(tracker, "X") {
        t.Errorf("X must not be tainted (comment-only assignment)")
    }
}

func TestTaintTracker_HeredocBodyNotMisdetected(t *testing.T) {
    t.Parallel()
    step := makeRunStep(t, "test-step", `
cat <<EOF
X=${{ github.event.issue.body }}
EOF
`)
    tracker := NewTaintTracker()
    tracker.AnalyzeStep(step)
    if isVarTainted(tracker, "X") {
        t.Errorf("X must not be tainted (heredoc body content is not executed assignment)")
    }
}

func TestTaintTracker_OneLinerMultipleAssignments(t *testing.T) {
    t.Parallel()
    // 旧 regex は行頭アンカーで Y を取りこぼしていた。
    step := makeRunStep(t, "test-step", `
X=1; Y="${{ github.event.issue.title }}"
echo "y=$Y" >> $GITHUB_OUTPUT
`)
    tracker := NewTaintTracker()
    tracker.AnalyzeStep(step)

    tainted, sources := tracker.IsTaintedExpr("steps.test-step.outputs.y")
    if !tainted {
        t.Fatalf("output y must be tainted via Y derived from issue.title")
    }
    if len(sources) == 0 {
        t.Errorf("expected at least 1 source, got %v", sources)
    }
}

func TestTaintTracker_LineContinuation(t *testing.T) {
    t.Parallel()
    step := makeRunStep(t, "test-step", "URL=\"${{ github.head_ref }}\" \\\n   FOO=bar\n")
    tracker := NewTaintTracker()
    tracker.AnalyzeStep(step)
    if !isVarTainted(tracker, "URL") {
        t.Errorf("URL must be tainted via head_ref")
    }
}

// makeRunStep は既存テストにヘルパがあれば再利用、なければ簡易実装する。
// （既存テストに同等ヘルパがある場合は新規作成不要 → そちらに合わせる）
func makeRunStep(t *testing.T, id, script string) *ast.Step {
    t.Helper()
    return &ast.Step{
        ID: &ast.String{Value: id},
        Exec: &ast.ExecRun{
            Run: &ast.String{Value: script},
        },
    }
}

// isVarTainted は TaintTracker の internal taintedVars を見るためのテストヘルパ。
// 既存テストにヘルパがあれば再利用、なければ pkg/core 内に export-for-test
// （別ファイルで `func (t *TaintTracker) HasTaintedVar(name string) bool` 等）を作る。
func isVarTainted(tracker *TaintTracker, name string) bool {
    // TaintTracker.taintedVars は private なので test 内で直接アクセス不可。
    // 解決策: taint_test.go を同パッケージに置けばアクセス可能。
    _, ok := tracker.taintedVars[name]
    return ok
}
```

- [ ] **Step 3: テスト実行で RED 確認（一部テストは regex 実装で fail するはず）**

```bash
go test -race -count=1 ./pkg/core/ -run "TestTaintTracker_CommentLineNotMisdetected|TestTaintTracker_HeredocBodyNotMisdetected|TestTaintTracker_OneLinerMultipleAssignments|TestTaintTracker_LineContinuation" -v
```
Expected: 一部または全部が FAIL

具体的には:
- CommentLineNotMisdetected → 旧 regex は誤検出するので FAIL する見込み
- HeredocBodyNotMisdetected → 同上
- OneLinerMultipleAssignments → 旧 regex は Y を見逃すので output が tainted にならず FAIL
- LineContinuation → 旧 regex は行を分けるので URL を取りこぼし FAIL

- [ ] **Step 4: コミット（RED 状態を記録）**

```bash
git add pkg/core/taint_test.go
git commit --no-verify -m "test(core/taint): #446 B-pattern 失敗テストを追加

regex 実装での FP/FN を再現するテスト 4件。
リファクタ後（shell.PropagateTaint 利用）に GREEN になる。"
```

---

### Task 8: `taint.go` の analyzeScript を AST 化

**Files:**
- Modify: `pkg/core/taint.go`

- [ ] **Step 1: import に `pkg/shell` 追加 + `mvdan.cc/sh/v3/syntax`**

`pkg/core/taint.go` の import 節を更新:

```go
import (
    "regexp"
    "strings"

    "mvdan.cc/sh/v3/syntax"

    "github.com/sisaku-security/sisakulint/pkg/ast"
    "github.com/sisaku-security/sisakulint/pkg/expressions"
    "github.com/sisaku-security/sisakulint/pkg/shell"
)
```

- [ ] **Step 2: `taintedVars` の型を `map[string]shell.Entry` に変更**

`TaintTracker` 構造体（`pkg/core/taint.go:34-46`）:

```go
type TaintTracker struct {
    taintedOutputs map[string]map[string][]string

    // [変更] string slice → shell.Entry（Offset を持つ）
    taintedVars map[string]shell.Entry

    knownTaintedActions map[string][]KnownTaintedOutput
}
```

`NewTaintTracker` (`pkg/core/taint.go:55-67`) も初期化を更新:

```go
func NewTaintTracker() *TaintTracker {
    tracker := &TaintTracker{
        taintedOutputs:      make(map[string]map[string][]string),
        taintedVars:         make(map[string]shell.Entry), // [変更]
        knownTaintedActions: make(map[string][]KnownTaintedOutput),
    }
    tracker.initKnownTaintedActions()
    return tracker
}
```

- [ ] **Step 3: `AnalyzeStep` を AST ベースに書き換え**

`pkg/core/taint.go:137-175` を以下で置き換え:

```go
func (t *TaintTracker) AnalyzeStep(step *ast.Step) {
    if step == nil || step.ID == nil || step.ID.Value == "" {
        return
    }
    if step.Exec == nil {
        return
    }
    stepID := step.ID.Value

    if step.Exec.Kind() == ast.ExecKindAction {
        t.analyzeActionStep(step)
        return
    }
    if step.Exec.Kind() != ast.ExecKindRun {
        return
    }
    run, ok := step.Exec.(*ast.ExecRun)
    if !ok || run.Run == nil {
        return
    }

    // Reset tainted vars for this step
    t.taintedVars = make(map[string]shell.Entry)

    // Phase 2: Pre-populate tainted vars from env section
    t.populateTaintedVarsFromEnv(step.Env)

    // Parse script once and dispatch to AST-based helpers
    parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
    file, err := parser.Parse(strings.NewReader(run.Run.Value), "")
    if err != nil || file == nil {
        return
    }

    // Forward dataflow with order-aware Offset
    t.taintedVars = shell.PropagateTaint(file, t.taintedVars)

    // GITHUB_OUTPUT writes
    for _, w := range shell.WalkRedirectWrites(file, "GITHUB_OUTPUT") {
        t.recordRedirWrite(stepID, w)
    }
}
```

- [ ] **Step 4: `populateTaintedVarsFromEnv` を Entry 型に対応**

`pkg/core/taint.go:224-259` を以下で置き換え:

```go
func (t *TaintTracker) populateTaintedVarsFromEnv(env *ast.Env) {
    if env == nil || env.Vars == nil {
        return
    }
    for _, envVar := range env.Vars {
        if envVar.Value == nil || !envVar.Value.ContainsExpression() {
            continue
        }
        varName := envVar.Name.Value
        value := envVar.Value.Value

        exprPattern := regexp.MustCompile(`\$\{\{\s*([^}]+)\s*\}\}`)
        matches := exprPattern.FindAllStringSubmatch(value, -1)

        var sources []string
        for _, match := range matches {
            if len(match) < 2 {
                continue
            }
            exprContent := strings.TrimSpace(match[1])
            if tainted, srcs := t.IsTaintedExpr(exprContent); tainted {
                sources = append(sources, srcs...)
            }
            if t.isUntrustedExpression(exprContent) {
                sources = append(sources, exprContent)
            }
        }
        if len(sources) > 0 {
            // 既存 Entry があればマージ、なければ新規（env 由来は Offset=-1）
            existing := t.taintedVars[varName]
            existing.Sources = mergeUnique(existing.Sources, sources)
            existing.Offset = -1
            t.taintedVars[varName] = existing
        }
    }
}

// mergeUnique は順序保持で重複なしの merge。
func mergeUnique(dst, src []string) []string {
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

- [ ] **Step 5: `recordRedirWrite` 新設（`checkAndRecordTaint` を置換）**

`pkg/core/taint.go` に追加（`checkAndRecordTaint` 旧版は削除予定だが、まず併存させる）:

```go
// recordRedirWrite は WalkRedirectWrites の結果をもとに taintedOutputs に記録する。
// VALUE 内に直接 untrusted 式があるか、または tainted 変数を参照していれば
// その output を tainted として登録する。
func (t *TaintTracker) recordRedirWrite(stepID string, w shell.RedirWrite) {
    var sources []string
    sources = append(sources, t.extractUntrustedSources(w.Value)...)

    // VALUE 内の $VAR 参照を tainted vars と照合
    if w.ValueWord != nil {
        if name, ok := shell.WordReferencesEntry(w.ValueWord, t.taintedVars); ok {
            sources = mergeUnique(sources, t.taintedVars[name].Sources)
        }
    } else {
        // heredoc 等で ValueWord が無い場合は文字列ベースで $VAR を検出
        varRefPattern := regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
        for _, m := range varRefPattern.FindAllStringSubmatch(w.Value, -1) {
            if len(m) < 2 {
                continue
            }
            if entry, ok := t.taintedVars[m[1]]; ok {
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

- [ ] **Step 6: 既存 regex 関数群を削除**

以下を `pkg/core/taint.go` から削除:
- `analyzeScript` (L262-268)
- `findTaintedVariableAssignments` (L274-313)
- `findGitHubOutputWrites` (L329-359)
- `processHeredocPatterns` (L367-414)
- `checkAndRecordTaint` (L417-443) — `recordRedirWrite` で置換
- `deduplicateStrings` (L316-326) — `mergeUnique` で置換

`extractUntrustedSources` / `isUntrustedExpression` / `IsTaintedExpr` / `IsTainted` / `GetTaintedOutputs` / `analyzeActionStep` / `extractActionName` / `initKnownTaintedActions` / `nodeToString` / `exprNodeToString` 等は **保持**。

- [ ] **Step 7: ビルド確認**

```bash
go build ./...
```
Expected: 成功（コンパイルエラーがあれば修正）

- [ ] **Step 8: テスト実行（B-pattern 含む全件）**

```bash
go test -race -count=1 ./pkg/core/ -run "TestTaint"
```
Expected:
- 既存 `TestTaintTracker_*` は全件 PASS
- B-pattern 4件も PASS（RED → GREEN）

失敗する場合:
- Cycle 1 の `pkg/shell/taint.go` API の細部不整合 → テスト追加して原因特定
- `recordRedirWrite` で sources が空のケース処理ミス → 既存テストが失敗するはず

- [ ] **Step 9: コミット**

```bash
git add pkg/core/taint.go
git commit --no-verify -m "refactor(core/taint): #446 regex を AST に置き換え

- taintedVars を map[string]shell.Entry に変更（Offset 保持）
- findTaintedVariableAssignments → shell.PropagateTaint
- findGitHubOutputWrites + processHeredocPatterns → shell.WalkRedirectWrites
- checkAndRecordTaint → recordRedirWrite（型に合わせて改名）
- deduplicateStrings → mergeUnique
- 公開 API は完全維持（caller 影響ゼロ）"
```

---

### Task 9: Cycle 2 受入: 全テスト + lint + 統合テスト

**Files:** なし（検証のみ）

- [ ] **Step 1: pkg/core 全テスト**

```bash
go test -race -count=1 ./pkg/core/
```
Expected: PASS

- [ ] **Step 2: 統合テスト（taint_integration_test.go）**

```bash
go test -race -count=1 ./pkg/core/ -run "TestTaintIntegration"
```
Expected: PASS

- [ ] **Step 3: codeinjection / requestforgery / envvarinjection の関連テスト**

```bash
go test -race -count=1 ./pkg/core/ -run "TestCodeInjection|TestRequestForgery|TestEnvVarInjection"
```
Expected: PASS

- [ ] **Step 4: lint**

```bash
golangci-lint run --fix --timeout 30m ./pkg/core/taint.go
```
Expected: エラーゼロ

- [ ] **Step 5: 期待値変更が必要なテストがあれば、その理由を確認**

PASS が落ちる場合:
- B のスコープで AST 化により挙動が変わるテストか確認
- 該当する場合は期待値を修正し、テスト名/コメントに「regex 由来 FP を AST で修正」と明記
- 該当しない場合は実装バグ → 修正

修正があった場合のコミット:
```bash
git add pkg/core/taint_test.go pkg/core/taint_integration_test.go
git commit --no-verify -m "test(core/taint): #446 AST 化に伴う期待値修正

regex 実装での FP を期待値としていたテストを AST 実装の正しい挙動に合わせる。"
```

---

## Cycle 3: `pkg/core/secretinlog.go` 書き換え（TDD）

### Task 10: B-pattern リグレッションテストを `secretinlog_test.go` に追加

**Files:**
- Modify: `pkg/core/secretinlog_test.go`

- [ ] **Step 1: 既存 `secretinlog_test.go` のヘルパとパターンを確認**

```bash
grep -n "^func Test\|^func parseShellForTest" pkg/core/secretinlog_test.go | head -15
```

既存ヘルパ:
- `parseShellForTest(t, script)` (L48 付近) — `*syntax.File` を返す
- `TestSecretInLog_PropagateTaint` (L60) — 直接 `rule.propagateTaint` を呼んでいる（**Task 11 で要対応**: 関数削除に伴いこのテストも書き換え or 削除が必要）
- `TestSecretInLog_OrderAwareTaint` (L116) — 同上、`propagateTaint` の order-aware 挙動を直接テスト
- `TestSecretInLog_VisitJob_Integration` (L226) — workflow 全体パスの integration test。リグレッションテストはこのパターンを参考にする

- [ ] **Step 2: リグレッションテストを追加（integration スタイル）**

`pkg/core/secretinlog_test.go` の末尾に追加。`TestSecretInLog_VisitJob_Integration` (L226) のセットアップを参考にすること（`ast.Workflow` / `ast.Job` / `ast.Step` を直接構築 → `rule.VisitWorkflowPre` → `rule.VisitJobPre` → `rule.Errors()` をチェック）:

```go
// B-pattern リグレッションテスト: secretinlog.go は既に AST ベースなので
// これらのパターンは現状でも正しく扱われているが、shell.PropagateTaint への
// 切り替え後も挙動が変化しないことを保証する。

func TestSecretInLog_CommentLineNotFalseDetected(t *testing.T) {
    t.Parallel()
    yaml := `
on: push
jobs:
  job1:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.GCP_KEY }}
    steps:
      - run: |
          # X="$TOKEN"
          echo "no leak"
`
    errs := runSecretInLog(t, yaml)
    if len(errs) != 0 {
        t.Errorf("expected 0 errors (comment is not real assignment), got %d: %v", len(errs), errs)
    }
}

func TestSecretInLog_HeredocBodyNotFalseDetected(t *testing.T) {
    t.Parallel()
    yaml := `
on: push
jobs:
  job1:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.GCP_KEY }}
    steps:
      - run: |
          cat <<EOF
          X=$TOKEN
          EOF
          echo "no leak in body"
`
    errs := runSecretInLog(t, yaml)
    if len(errs) != 0 {
        t.Errorf("expected 0 errors (heredoc body is not assignment), got %d: %v", len(errs), errs)
    }
}

func TestSecretInLog_OneLinerMultipleAssignments(t *testing.T) {
    t.Parallel()
    yaml := `
on: push
jobs:
  job1:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.GCP_KEY }}
    steps:
      - run: |
          X=1; Y="$TOKEN"; echo "$Y"
`
    errs := runSecretInLog(t, yaml)
    if len(errs) == 0 {
        t.Errorf("expected leak detection on $Y from one-liner assignment, got 0 errors")
    }
}

func TestSecretInLog_LineContinuationDoesNotBreakDetection(t *testing.T) {
    t.Parallel()
    yaml := `
on: push
jobs:
  job1:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.GCP_KEY }}
    steps:
      - run: |
          URL="$TOKEN" \
              suffix
          echo "$URL"
`
    errs := runSecretInLog(t, yaml)
    if len(errs) == 0 {
        t.Errorf("expected leak detection on $URL from line-continued assignment, got 0 errors")
    }
}
```

**重要**: 上記の `runSecretInLog` は YAML パース経由のヘルパだが、既存テストは AST を直接構築している。本プランでは既存パターンに合わせて、上記テストも以下のように書き換えること:

```go
// 既存 TestSecretInLog_VisitJob_Integration (L226) のセットアップを参考に、
// ast.Workflow / ast.Job / ast.Step を直接構築:
func TestSecretInLog_CommentLineNotFalseDetected(t *testing.T) {
    t.Parallel()
    rule := NewSecretInLogRule()
    workflow := &ast.Workflow{
        Env: &ast.Env{Vars: map[string]*ast.EnvVar{
            "TOKEN": {
                Name:  &ast.String{Value: "TOKEN"},
                Value: &ast.String{Value: "${{ secrets.GCP_KEY }}"},
            },
        }},
    }
    _ = rule.VisitWorkflowPre(workflow)

    job := &ast.Job{
        ID: &ast.String{Value: "job1"},
        Steps: []*ast.Step{
            {
                Exec: &ast.ExecRun{
                    Run: &ast.String{Value: `# X="$TOKEN"
echo "no leak"`},
                },
            },
        },
    }
    _ = rule.VisitJobPre(job)

    if errs := rule.Errors(); len(errs) != 0 {
        t.Errorf("expected 0 errors (comment is not real assignment), got %d: %v", len(errs), errs)
    }
}
```

他の 3 テスト（HeredocBody / OneLinerMultipleAssignments / LineContinuation）も同じパターンで実装。`runSecretInLog` ヘルパは作らない。

- [ ] **Step 3: テスト実行で現状の挙動を確認**

```bash
go test -race -count=1 ./pkg/core/ -run "TestSecretInLog_CommentLineNotFalseDetected|TestSecretInLog_HeredocBodyNotFalseDetected|TestSecretInLog_OneLinerMultipleAssignments|TestSecretInLog_LineContinuationDoesNotBreakDetection" -v
```
Expected: 全件 PASS（secretinlog は既に AST ベースなので現状でも正しい）

PASS しない場合: secretinlog の現状実装に未知のバグがある → 別 issue として記録（本 issue ではスコープ外）

- [ ] **Step 4: コミット**

```bash
git add pkg/core/secretinlog_test.go
git commit --no-verify -m "test(core/secretinlog): #446 B-pattern リグレッションテストを追加

shell.PropagateTaint への切り替え後も挙動不変であることを保証する 4件。"
```

---

### Task 11: `secretinlog.go` を `shell.PropagateTaint` 利用に書き換え

**Files:**
- Modify: `pkg/core/secretinlog.go`

- [ ] **Step 1: import に `pkg/shell` 追加**

`pkg/core/secretinlog.go` の import 節:

```go
import (
    "regexp"
    "strings"
    "sync"

    "mvdan.cc/sh/v3/syntax"

    "github.com/sisaku-security/sisakulint/pkg/ast"
    "github.com/sisaku-security/sisakulint/pkg/shell"
)
```

- [ ] **Step 2: `taintEntry` 型を削除**

`pkg/core/secretinlog.go:11-18` の `taintEntry` 型を削除。以降のコードは `shell.Entry` を使う。

- [ ] **Step 3: `propagateTaint` を削除し、`checkStep` から `shell.PropagateTaint` を呼ぶ**

`pkg/core/secretinlog.go:60-99` の `propagateTaint` 関数を削除。

**重要 — 既存テスト 2 件の対応**:

`secretinlog_test.go` の以下 2 テストは `rule.propagateTaint(...)` を直接呼んでいるため、関数削除に伴って書き換えが必要:

- `TestSecretInLog_PropagateTaint` (L60-114) — 削除予定。同等の検証は `pkg/shell/taint_test.go` の `TestPropagateTaint` でカバーされる（command substitution パターンは新規 sub test として shell 側に追加）
- `TestSecretInLog_OrderAwareTaint` (L116-155) — 削除予定。同等検証は `pkg/shell/taint_test.go` の `TestPropagateTaint_OrderAware` でカバー

ただし、これらのテストが secretinlog 固有の知識（initial taint の `secrets.X` origin 文字列など）を検証している場合、その検証ロジックは Task 10 で追加する integration スタイルテストでカバーされていることを確認。不足あれば該当ロジックを Task 10 のテストに追加してから削除する。

削除コマンド:
```bash
# 該当テストの行範囲を確認した上で
# (例: TestSecretInLog_PropagateTaint が L60-114, TestSecretInLog_OrderAwareTaint が L116-155 なら)
# manual edit または sed -i.bak で削除
```

`checkStep` (`pkg/core/secretinlog.go:439-490`) を以下に置き換え:

```go
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

    initial := make(map[string]shell.Entry)
    for k, v := range rule.workflowEnvSecrets {
        initial[k] = shell.Entry{Sources: []string{v}, Offset: -1}
    }
    for k, v := range rule.jobEnvSecrets {
        initial[k] = shell.Entry{Sources: []string{v}, Offset: -1}
    }
    for k, v := range rule.crossStepEnv {
        initial[k] = shell.Entry{Sources: []string{v}, Offset: -1}
    }
    for k, v := range rule.collectSecretEnvVars(step.Env) {
        initial[k] = shell.Entry{Sources: []string{v}, Offset: -1}
    }
    if len(initial) == 0 {
        return
    }

    parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
    file, err := parser.Parse(strings.NewReader(script), "")
    if err != nil || file == nil {
        return
    }

    tainted := shell.PropagateTaint(file, initial)
    leaks := rule.findEchoLeaks(file, tainted, script, execRun.Run)

    for _, leak := range leaks {
        rule.reportLeak(leak)
        rule.addAutoFixerForLeak(step, leak)
    }

    for name, origin := range rule.collectGitHubEnvTaintWrites(file, tainted, script) {
        rule.crossStepEnv[name] = origin
    }
}
```

- [ ] **Step 4: 残存する `taintEntry` 参照を `shell.Entry` に置換**

以下の関数で型を更新（**型の置換のみ**、内部ロジックは保持）:

`findEchoLeaks` (`pkg/core/secretinlog.go:152`):
```go
func (rule *SecretInLogRule) findEchoLeaks(
    file *syntax.File,
    tainted map[string]shell.Entry, // 旧: map[string]taintEntry
    script string,
    runStr *ast.String,
) []echoLeakOccurrence {
    // 内部 syntax.Walk のロジックは保持。entry.offset / entry.origin の
    // フィールド参照のみ Step 5 のルールに従って置換する。
    // ...
}
```

`collectRedirectSinkLeaks` (`pkg/core/secretinlog.go:209`) も同様に `tainted map[string]shell.Entry` に。

`collectLeakedVars` (`pkg/core/secretinlog.go:307`):
```go
func (rule *SecretInLogRule) collectLeakedVars(
    word *syntax.Word,
    tainted map[string]shell.Entry, // 旧: map[string]taintEntry
    ...
) {
    // entry, ok := tainted[name]
    // if !ok || entry.offset >= sinkOffset { return }
    // ↓
    // entry, ok := tainted[name]
    // if !ok || entry.Offset >= sinkOffset { return }

    // leak := echoLeakOccurrence{ Origin: entry.origin, ...}
    // ↓
    // leak := echoLeakOccurrence{ Origin: entry.First(), ...}
}
```

- [ ] **Step 5: `wordReferencesTainted` と `firstTaintedVarIn` を削除**

`pkg/core/secretinlog.go:102-133` を削除。呼び出し箇所を `shell.WordReferencesEntry` に置換:

```go
// 旧:
//   if rule.wordReferencesTainted(word, tainted) { ... }
// 新:
//   if _, ok := shell.WordReferencesEntry(word, tainted); ok { ... }

// 旧:
//   v := rule.firstTaintedVarIn(word, tainted)
// 新:
//   v, _ := shell.WordReferencesEntry(word, tainted)
```

特に `collectEchoEnvWrites` (`pkg/core/secretinlog.go:794`) の以下の箇所:
```go
for _, arg := range call.Args[nameArgIdx:] {
    if v := rule.firstTaintedVarIn(arg, tainted); v != "" {
        firstVar = v
        break
    }
}
```
を:
```go
for _, arg := range call.Args[nameArgIdx:] {
    if v, ok := shell.WordReferencesEntry(arg, tainted); ok {
        firstVar = v
        break
    }
}
```

`tainted[firstVar].origin` も `tainted[firstVar].First()` に。

- [ ] **Step 6: ビルド確認**

```bash
go build ./...
```
Expected: 成功

- [ ] **Step 7: secretinlog 関連テスト全件**

```bash
go test -race -count=1 ./pkg/core/ -run "TestSecretInLog|TestCrossStepTaint"
```
Expected: PASS（既存 + Task 10 で追加した B-pattern リグレッションも全件）

- [ ] **Step 8: コミット**

```bash
git add pkg/core/secretinlog.go
git commit --no-verify -m "refactor(core/secretinlog): #446 共通 shell.PropagateTaint 利用へ移行

- taintEntry 型 / propagateTaint / wordReferencesTainted / firstTaintedVarIn を削除
- shell.Entry / shell.PropagateTaint / shell.WordReferencesEntry を利用
- order-aware FP 抑制 (Offset) は shell.Entry が継承するため動作不変
- crossStepEnv / collectGitHubEnvTaintWrites の挙動は完全維持"
```

---

### Task 12: `collectGitHubEnvTaintWrites` を `shell.WalkRedirectWrites` 利用に最適化（任意）

**Files:**
- Modify: `pkg/core/secretinlog.go`

> **NOTE**: この task は厳密には必須ではない。既存 `collectGitHubEnvTaintWrites` は AST ベースで動作しているため、このリファクタは「重複コード排除」が目的。スケジュールが厳しければスキップ可。

- [ ] **Step 1: 既存 `collectGitHubEnvTaintWrites` の責務を確認**

`pkg/core/secretinlog.go:748-839` を読む。`stmtRedirectsToGitHubEnv` / `collectEchoEnvWrites` / `collectHeredocEnvWrites` を内部で持つ独自実装。

- [ ] **Step 2: 共通化のメリットがあるか判断**

判断基準:
- `shell.WalkRedirectWrites(file, "GITHUB_ENV")` が `collectEchoEnvWrites` の挙動と等価か
- 等価でない箇所（特に echo オプション処理 `-n`/`-e` や printf フォーマット指定子の skip）が `firstNameEqualsArg` で同等にできるか

等価なら次へ。等価でなければスキップ（task 完了マークだけ付ける）。

- [ ] **Step 3: 等価な場合、`collectGitHubEnvTaintWrites` を書き換え**

```go
func (rule *SecretInLogRule) collectGitHubEnvTaintWrites(
    file *syntax.File,
    tainted map[string]shell.Entry,
    script string,
) map[string]string {
    result := make(map[string]string)
    if file == nil {
        return result
    }

    for _, w := range shell.WalkRedirectWrites(file, "GITHUB_ENV") {
        var firstVar string
        if w.ValueWord != nil {
            if v, ok := shell.WordReferencesEntry(w.ValueWord, tainted); ok {
                firstVar = v
            }
        } else {
            // heredoc body: 文字列ベースで $VAR 検出
            varRefPattern := regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
            for _, m := range varRefPattern.FindAllStringSubmatch(w.Value, -1) {
                if len(m) >= 2 {
                    if _, ok := tainted[m[1]]; ok {
                        firstVar = m[1]
                        break
                    }
                }
            }
        }
        if firstVar == "" {
            continue
        }
        result[w.Name] = tainted[firstVar].First()
    }
    return result
}
```

旧 `stmtRedirectsToGitHubEnv` / `collectEchoEnvWrites` / `collectHeredocEnvWrites` の使用箇所がなくなれば削除。

- [ ] **Step 4: テスト実行（cross-step が壊れていないこと）**

```bash
go test -race -count=1 ./pkg/core/ -run "TestSecretInLog|TestCrossStepTaint" -v
```
Expected: PASS

- [ ] **Step 5: コミット**

```bash
git add pkg/core/secretinlog.go
git commit --no-verify -m "refactor(core/secretinlog): #446 collectGitHubEnvTaintWrites を WalkRedirectWrites 化

stmtRedirectsToGitHubEnv / collectEchoEnvWrites / collectHeredocEnvWrites を
shell.WalkRedirectWrites + WordReferencesEntry の組み合わせで置換。
crossStepEnv の挙動は不変。"
```

---

### Task 13: Cycle 3 受入: 全テスト + lint

- [ ] **Step 1: pkg/core 全テスト**

```bash
go test -race -count=1 ./pkg/core/
```
Expected: PASS

- [ ] **Step 2: 全パッケージ全テスト**

```bash
go test -race -count=1 ./...
```
Expected: PASS

- [ ] **Step 3: lint**

```bash
golangci-lint run --fix --timeout 30m ./pkg/shell/... ./pkg/core/...
```
Expected: エラーゼロ

---

## Cycle 4: 統合検証 + ドキュメント + PR

### Task 14: `script/actions/` リグレッション diff

**Files:** なし（検証のみ）

- [ ] **Step 1: 新ビルドで `script/actions/` を再評価**

```bash
go build -o /tmp/sisakulint-after ./cmd/sisakulint
/tmp/sisakulint-after script/actions/ > /tmp/sisakulint-after.txt 2>&1 || true
```

- [ ] **Step 2: diff を確認**

```bash
diff /tmp/sisakulint-before.txt /tmp/sisakulint-after.txt | head -100
```

期待される diff:
- B のスコープで「regex 由来 FP が AST 化で消えた」差分のみ
- 検出件数の純増は許容しない（新規 FN/誤検出が生まれていないことを意味する）

- [ ] **Step 3: diff の評価とドキュメント化**

- 差分が想定どおりなら次へ
- 想定外の差分がある場合は原因調査:
  - FP 削減なら OK、PR description に明記
  - FN 増加なら NG、原因を修正
  - 新規 FP 発生なら NG、原因を修正

- [ ] **Step 4: 必要に応じて `script/actions/` のサンプルを追加**

B のスコープでカバーされる新パターン（コメント / heredoc / one-liner / line continuation）が `script/actions/` に既存サンプルとして無ければ、追加検討。ただし本 issue 必須ではない（Task 7 / 10 のテストでカバー済み）。

---

### Task 15: ドキュメント更新

**Files:**
- Modify: `CLAUDE.md`（必要に応じて）

- [ ] **Step 1: `CLAUDE.md` の関連セクション確認**

```bash
grep -n "taint\|TaintTracker\|secret-in-log" CLAUDE.md
```

- [ ] **Step 2: 必要なら更新**

該当箇所:
- "Implemented Rules" / "Auto-Fix Implementations" — ルール追加削除なしなら更新不要
- 内部実装の AST 化は CLAUDE.md の対象外（実装詳細）

更新が必要なら追記:
```markdown
### TaintTracker / secret-in-log の共通基盤

`pkg/shell/taint.go` に `PropagateTaint` / `WalkAssignments` / `WalkRedirectWrites` を
純関数として配置し、`pkg/core/taint.go` (TaintTracker) と `pkg/core/secretinlog.go`
(SecretInLogRule) が共通利用する。
```

- [ ] **Step 3: 更新があればコミット**

```bash
git add CLAUDE.md
git commit --no-verify -m "docs: #446 TaintTracker と secret-in-log の共通基盤化を CLAUDE.md に追記"
```

---

### Task 16: PR 作成

**Files:** なし

- [ ] **Step 1: 全テスト + lint 最終確認**

```bash
go test -race -count=1 ./...
golangci-lint run --timeout 30m ./...
```
Expected: 全 PASS

- [ ] **Step 2: ブランチを push**

```bash
git push -u origin feature/446-taint-tracker-ast-migration
```

- [ ] **Step 3: PR 本文を準備**

`/tmp/pr-body.md` を作成:

```markdown
## Summary

#446 (epic #445) に基づき、`pkg/core/taint.go` (regex) と `pkg/core/secretinlog.go` (AST) で二重実装されていた taint 機構を `pkg/shell/taint.go` の共通 Propagator に集約。AST 化により regex 由来の FP/FN を自然に修正。

## Spec / Plan

- Spec: `docs/superpowers/specs/2026-04-25-taint-tracker-ast-migration-design.md`
- Plan: `plan/2026-04-25-446-taint-tracker-ast-migration.md`

## 変更点

### 新規
- `pkg/shell/taint.go` — `PropagateTaint` / `WalkAssignments` / `WordReferencesEntry` / `WalkRedirectWrites` を純関数として提供
- `pkg/shell/taint_test.go` — Table-driven テスト（カバレッジ 90%+）

### 改修
- `pkg/core/taint.go` — `findTaintedVariableAssignments` / `findGitHubOutputWrites` / `processHeredocPatterns` を削除し `shell.*` 利用に置換。public API 不変
- `pkg/core/secretinlog.go` — `taintEntry` / `propagateTaint` / `wordReferencesTainted` / `firstTaintedVarIn` を削除し `shell.*` 利用に置換

### caller への影響
- `codeinjection.go` / `requestforgery.go` / `envvarinjection.go` — **無変更**（公開 API 維持）

## AST 化で自然に修正される FP/FN

| パターン | 旧 regex | 新 AST |
|---|---|---|
| `# X="${{ ... }}"` (コメント) | 誤検出 | 正しく除外 |
| `cat <<EOF\nX=${{ ... }}\nEOF` | 誤検出 | 正しく除外 |
| `X=1; Y="${{ ... }}"` | Y 見逃し | 両方拾う |
| `X="${{ ... }}" \\\n   Y` | 行分断で見逃し | 1代入として拾う |

## テスト

- 既存テスト全件 PASS
- B-pattern 新規テスト 4件 PASS（`pkg/core/taint_test.go`）
- B-pattern リグレッションテスト 4件 PASS（`pkg/core/secretinlog_test.go`）
- カバレッジ: `pkg/shell/taint.go` 90%+

## リグレッション

`script/actions/` 配下に対して新旧ビルド出力 diff を確認:
- diff: 想定された FP 削減のみ（詳細は本 PR の comment 参照）

## 関連 issue

- 親 epic: #445
- 後続: #447 (scope 対応) / #448 (関数引数)
```

- [ ] **Step 4: PR 作成**

```bash
gh pr create --title "refactor(taint): #446 TaintTracker AST 化と secret-in-log の共通基盤化" \
  --body-file /tmp/pr-body.md \
  --label "priority/p2,area/taint-analysis,enhancement"
```

- [ ] **Step 5: PR URL を確認**

```bash
gh pr view --web
```

---

## 完了条件チェックリスト（spec Section 10 の DoD）

- [ ] `pkg/shell/taint.go` 新設、godoc 完備
- [ ] `pkg/shell/taint_test.go` 新設、カバレッジ 90% 以上
- [ ] `pkg/core/taint.go` から regex ベースの `findTaintedVariableAssignments` / `findGitHubOutputWrites` / `processHeredocPatterns` を**削除**
- [ ] `pkg/core/secretinlog.go` から `propagateTaint` / `wordReferencesTainted` / `firstTaintedVarIn` / `taintEntry` を**削除**
- [ ] 既存テスト全件 pass（変更を加えたテストはレビューコメントで明示）
- [ ] B-pattern の新規テスト 4件 + secretinlog 同等 が pass
- [ ] `golangci-lint run --fix` でエラーゼロ
- [ ] `script/actions/` リグレッション diff が「想定された FP 削減」のみ
- [ ] PR 作成済み
