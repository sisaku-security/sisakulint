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
