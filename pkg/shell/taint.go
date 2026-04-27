// Package shell の taint.go - shell スクリプトの taint 解析プリミティブ。
//
// このファイルは pkg/core/taint.go (TaintTracker) と pkg/core/secretinlog.go
// の両方から共通利用される。すべて純関数で state を持たない（並行安全）。
package shell

import (
	"maps"
	"path"
	"strings"

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
			for _, a := range decl.Args {
				if a == nil || a.Name == nil {
					continue
				}
				result = append(result, AssignmentInfo{
					Name:    a.Name.Value,
					Value:   a.Value,
					Offset:  int(a.Pos().Offset()), //nolint:gosec // file offsets fit in int
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
				Offset:  int(assign.Pos().Offset()), //nolint:gosec // file offsets fit in int
				Keyword: AssignNone,
			})
		}
		return true
	})
	return result
}

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

	root := &scopeFrame{kind: scopeRoot, local: maps.Clone(initial)}
	if root.local == nil {
		root.local = make(map[string]Entry)
	}
	current := root
	funcTable := make(map[string]*syntax.FuncDecl)
	visited := make(map[string]int)
	syntax.Walk(file, makeWalkFn(&current, result, funcTable, visited))

	// Final は root frame の最終状態 (subshell/funcdecl frame は pop 済み)
	maps.Copy(result.Final, root.local)
	return result
}

// makeWalkFn は scope frame stack を維持しつつ walk するクロージャを返す。
// `current` は現在の frame を指す pointer-to-pointer で、subshell/funcdecl 入退場時に
// 書き換える。
//
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
			// RHS Words (Args.Value) を別途 walk して、入れ子の Subshell / CmdSubst が
			// scope frame を push し、内側 Stmt が visibleAt を記録できるようにする。
			// Args.Name は Lit のみで taint semantics を持たないので skip。
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

// processAssign は単純代入 X=Y を current frame に書き込む。
// 既に tainted な変数の上書きはしない (最初の taint を保持)。
func processAssign(current *scopeFrame, a *syntax.Assign) {
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
		processAssign(current, a)
	}
}

// declHasGlobalFlag は DeclClause に -g (global) フラグが付いているか判定する。
//
// mvdan/sh では `declare -g X="$T"` のフラグは `*syntax.Assign{Name: nil,
// Value: Word{Parts: [Lit{Value: "-g"}]}}` として表現される (Name は代入の
// 左辺名なので、フラグでは nil)。代入 args は Name != nil 側にある。
// したがって Name == nil かつ Value Word の先頭 Lit が `-` で始まり 'g' を
// 含むものを探す。これで `-g` / `-gA` / `-Ag` 等を正しく検出できる
// (bash semantics: 単一のフラグ束に 'g' が含まれていれば global)。
func declHasGlobalFlag(decl *syntax.DeclClause) bool {
	for _, a := range decl.Args {
		if a == nil || a.Name != nil {
			// Name != nil は代入 (X=v) なのでフラグではない
			continue
		}
		flag := wordLitPrefix(a.Value)
		if strings.HasPrefix(flag, "-") && strings.ContainsRune(flag, 'g') {
			return true
		}
	}
	return false
}

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
		// 同一 Stmt に append/truncate と heredoc が同居する場合
		// (例: cat <<EOF >> $GITHUB_OUTPUT) のため、両方を別々に scan する。
		var (
			matchedRedir *syntax.Redirect
			heredocBody  *syntax.Word
		)
		for _, redir := range stmt.Redirs {
			if redir == nil {
				continue
			}
			switch {
			case isAppendOrTruncate(redir.Op) && redirTargetMatches(redir.Word, target):
				matchedRedir = redir
			case isHeredocOp(redir.Op):
				if redir.Hdoc != nil {
					heredocBody = redir.Hdoc
				}
			}
		}
		if matchedRedir == nil {
			return true
		}
		if heredocBody != nil {
			for _, kv := range extractHeredocAssignments(heredocBody) {
				result = append(result, RedirWrite{
					Name:      kv.name,
					Value:     kv.value,
					Stmt:      stmt,
					Offset:    int(matchedRedir.Pos().Offset()), //nolint:gosec // file offsets fit in int
					IsHeredoc: true,
				})
			}
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok {
			return true
		}
		name, valueWord, valueStr, found := firstNameEqualsArg(call)
		if !found {
			return true
		}
		result = append(result, RedirWrite{
			Name:      name,
			Value:     valueStr,
			ValueWord: valueWord,
			Stmt:      stmt,
			Offset:    int(matchedRedir.Pos().Offset()), //nolint:gosec // file offsets fit in int
			IsHeredoc: false,
		})
		return true
	})
	return result
}

func isAppendOrTruncate(op syntax.RedirOperator) bool {
	return op == syntax.AppOut || op == syntax.RdrOut
}

func isHeredocOp(op syntax.RedirOperator) bool {
	return op == syntax.Hdoc || op == syntax.DashHdoc
}

// redirTargetMatches は redir.Word が単一の ParamExp で target 名と一致するか判定する。
// "$X", "${X}", $X, ${X} を許容、複合 ("$X/$Y" など) は不一致。
func redirTargetMatches(w *syntax.Word, target string) bool {
	if w == nil || len(w.Parts) == 0 {
		return false
	}
	if len(w.Parts) != 1 {
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
// Word.Parts のうち *syntax.Lit のみを連結して行分割し、`NAME=value` パターンの
// 行のみ返す。
//
// 制限: ParamExp / CmdSubst / 算術展開などの非 Lit パーツは連結されないため、
// 例えば `KEY=$VAR` のような heredoc 行は value 部分が空文字になる。
// 呼び出し側 (例: pkg/core/taint.go の recordRedirWrite) はこの制限に依存し、
// ValueWord が nil の場合は文字列全体に対する正規表現で `$VAR` を検出する
// フォールバックを行っている。展開を含む複雑な heredoc では false negative が
// 出得るので、callers は「value 文字列に展開済みの内容が入っている」前提を
// 置いてはいけない。
func extractHeredocAssignments(hdoc *syntax.Word) []heredocKV {
	if hdoc == nil {
		return nil
	}
	var sb strings.Builder
	for _, p := range hdoc.Parts {
		if lit, ok := p.(*syntax.Lit); ok {
			sb.WriteString(lit.Value)
		}
	}
	out := make([]heredocKV, 0, 4)
	for line := range strings.SplitSeq(sb.String(), "\n") {
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
		if i == 0 && r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
		if r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// firstNameEqualsArg は CallExpr の引数から最初の `NAME=...` 形式を見つけ、
// (name, valueWord, valueStr, true) を返す。
// echo の `-n` `-e` 等のオプション、printf のフォーマット指定子はスキップする。
func firstNameEqualsArg(call *syntax.CallExpr) (string, *syntax.Word, string, bool) {
	if call == nil || len(call.Args) == 0 {
		return "", nil, "", false
	}
	// Only treat `%` in the NAME=... arg as a printf format specifier when the
	// command itself is `printf`; otherwise commands like `echo "PERCENT=50%"`
	// would be mis-handled (the value `50%` contains `%` but is not a format).
	// Use path.Base so absolute invocations like /usr/bin/printf are still
	// recognized as printf.
	isPrintf := path.Base(wordLitPrefix(call.Args[0])) == "printf"
	for i := 1; i < len(call.Args); i++ {
		arg := call.Args[i]
		lit := wordLitPrefix(arg)
		if strings.HasPrefix(lit, "-") && lit != "-" {
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
		afterEq := lit[idx+1:]
		// printf-style format string: `name=%s\n`. The actual value lives in a
		// subsequent argument. Treat the next arg as the ValueWord and
		// concatenate its literal text as the value-text-for-source-detection.
		if isPrintf && strings.Contains(afterEq, "%") {
			if i+1 >= len(call.Args) {
				continue
			}
			valueWord := call.Args[i+1]
			var sb strings.Builder
			for j := i + 1; j < len(call.Args); j++ {
				sb.WriteString(wordLitPrefix(call.Args[j]))
			}
			return name, valueWord, sb.String(), true
		}
		return name, arg, afterEq, true
	}
	return "", nil, "", false
}

// wordLitPrefix は word の先頭 Lit / DblQuoted 内 Lit を結合した文字列を返す。
// 例: `"name=value"` -> name=value
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
			return sb.String()
		}
	}
	return sb.String()
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
