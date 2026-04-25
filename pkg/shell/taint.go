// Package shell の taint.go - shell スクリプトの taint 解析プリミティブ。
//
// このファイルは pkg/core/taint.go (TaintTracker) と pkg/core/secretinlog.go
// の両方から共通利用される。すべて純関数で state を持たない（並行安全）。
package shell

import (
	"maps"
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
	maps.Copy(result, initial)
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
					Offset:    int(matchedRedir.Pos().Offset()),
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
			Offset:    int(matchedRedir.Pos().Offset()),
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
	}
	var out []heredocKV
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
		if strings.HasPrefix(lit, "-") && lit != "-" {
			continue
		}
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
		valueStr := lit[idx+1:]
		return name, arg, valueStr, true
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
