package core

import (
	"regexp"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/shell"
)

// bareAddMaskReCache は "::add-mask::$VAR(境界)" 形式のチェック用正規表現をキャッシュする。
// hasAddMaskFor は tainted 変数 × echo 引数の回数だけ呼ばれるため、毎回コンパイルは避ける。
var bareAddMaskReCache sync.Map // map[string]*regexp.Regexp

func bareAddMaskRegex(varName string) *regexp.Regexp {
	if v, ok := bareAddMaskReCache.Load(varName); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`::add-mask::\$` + regexp.QuoteMeta(varName) + `($|[^A-Za-z0-9_])`)
	actual, _ := bareAddMaskReCache.LoadOrStore(varName, re)
	return actual.(*regexp.Regexp)
}

type SecretInLogRule struct {
	BaseRule
	workflowEnvSecrets map[string]string // populated in VisitWorkflowPre from workflow-level env:
	jobEnvSecrets      map[string]string // populated in VisitJobPre from job-level env:
	// crossStepEnv は同一 Job 内で前 step が `$GITHUB_ENV` 経由で書き出した tainted な
	// 環境変数を、後続 step の初期 taint source として引き継ぐためのマップ。
	// VisitJobPre の冒頭でリセットされ、各 step 処理後に $GITHUB_ENV 書き込みから
	// 追加される。クロスジョブ伝播は範囲外（follow-up issue）。
	crossStepEnv map[string]string
}

// NewSecretInLogRule は新規ルールインスタンスを返す。
// NOTE: クロスジョブ伝播対応時（follow-up issue #432）は新しいコンストラクタシグネチャを追加し、
// この関数はそれに nil を渡すラッパへ段階移行する。
func NewSecretInLogRule() *SecretInLogRule {
	return &SecretInLogRule{
		BaseRule: BaseRule{
			RuleName: "secret-in-log",
			RuleDesc: "Detects secret values being printed to build logs via echo/printf of " +
				"shell variables derived from secret-sourced environment variables. " +
				"See https://sisaku-security.github.io/lint/docs/rules/secretinlogrule/",
		},
	}
}

var secretEnvRefRe = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// echoLeakOccurrence は検出された echo/printf 出力箇所を表す。
type echoLeakOccurrence struct {
	VarName  string
	Origin   string
	Position *ast.Position
	Offset   int // sink のバイトオフセット（script 内での位置。offset-aware な add-mask 判定に使用）
	Command  string
}

// findEchoLeaks は echo/printf の引数に tainted 変数が含まれる箇所を収集する。
// 以下のケースはビルドログに出力されないためスキップする:
//   - コマンド置換 `$(...)` の内部（stdout はパイプに接続）
//   - stdout をファイルにリダイレクトする Stmt（例: `echo "$X" >> "$GITHUB_OUTPUT"`、`echo "$X" > file.txt`）
//   - `printf -v VAR` 形式（stdout を出さず変数に格納）
//
// ただし `>&2` / `/dev/stderr` / `/dev/stdout` / `/dev/tty` への出力は GitHub Actions の
// ビルドログに引き続き表示されるため、スキップ対象から除外する。
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
		// `printf -v VAR ...` は stdout へ出力しない（指定変数に格納する）ためスキップ。
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

// collectRedirectSinkLeaks は cat / tee / dd のように stdin をそのまま stdout に
// 出力するコマンドに対し、here-string (<<<) や heredoc (<<) で渡される本文内の
// tainted 変数参照を漏洩として収集する。
//
// 例:
//
//	cat <<< "$TOKEN"
//	tee /dev/stderr <<< "$TOKEN"
//	cat <<EOF
//	key=$TOKEN
//	EOF
//
// stdout をファイルにリダイレクトしている場合は呼び出し元の
// stmtRedirectsStdoutAwayFromLog で既に除外済み。tee のように常に stdout へも書く
// コマンドは file 引数があっても引き続きログに出るため flag する。
func (rule *SecretInLogRule) collectRedirectSinkLeaks(
	stmt *syntax.Stmt,
	tainted map[string]shell.Entry,
	script string,
	runStr *ast.String,
	leaks *[]echoLeakOccurrence,
) {
	if stmt == nil || stmt.Cmd == nil {
		return
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return
	}
	cmdName := firstWordLiteral(call.Args[0])
	switch cmdName {
	case "cat", "tee", "dd":
		// proceed
	default:
		return
	}
	for _, r := range stmt.Redirs {
		if r == nil {
			continue
		}
		switch r.Op {
		case syntax.WordHdoc:
			// here-string: コマンド <<< word — Word に taint があればログに出る
			if r.Word != nil {
				rule.collectLeakedVars(r.Word, tainted, script, runStr, cmdName, leaks)
			}
		case syntax.Hdoc, syntax.DashHdoc:
			// heredoc: コマンド << EOF ... EOF — 本文は Hdoc に格納される
			if r.Hdoc != nil {
				rule.collectLeakedVars(r.Hdoc, tainted, script, runStr, cmdName, leaks)
			}
		}
	}
}

// stmtRedirectsStdoutAwayFromLog は Stmt の Redirs に stdout をファイルへ送るものが
// 1 つ以上含まれていれば true を返す。`>&2` (DplOut) や `/dev/stderr` 等の
// ログに出力される宛先は除外する。
func stmtRedirectsStdoutAwayFromLog(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	for _, r := range stmt.Redirs {
		if r == nil {
			continue
		}
		// 対象は stdout への書き込み系オペレータのみ。
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob:
		default:
			continue
		}
		// fd 指定がある場合、stdout (fd1) 以外のリダイレクトは無視。
		if r.N != nil && r.N.Value != "" && r.N.Value != "1" {
			continue
		}
		// リダイレクト先がログに現れる特殊デバイス／fd の場合は「ログから逸らしていない」と判定。
		target := wordLiteralValue(r.Word)
		switch target {
		case "/dev/stderr", "/dev/stdout", "/dev/tty", "/dev/fd/1", "/dev/fd/2":
			continue
		}
		return true
	}
	return false
}

// wordLiteralValue は Word 全体を可能な限り文字列リテラルとして抽出する。
// ParamExp や CmdSubst を含む場合はそれらを空文字として無視し、残りを連結する。
// 厳密なシェル展開ではないが、既知のパス（/dev/stderr 等）検出には十分。
func wordLiteralValue(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	for _, p := range w.Parts {
		switch v := p.(type) {
		case *syntax.Lit:
			b.WriteString(v.Value)
		case *syntax.SglQuoted:
			b.WriteString(v.Value)
		case *syntax.DblQuoted:
			for _, dp := range v.Parts {
				if lit, ok := dp.(*syntax.Lit); ok {
					b.WriteString(lit.Value)
				}
			}
		}
	}
	return b.String()
}

// collectLeakedVars は単一の引数内で tainted 変数参照をすべて報告リストに追加する。
func (rule *SecretInLogRule) collectLeakedVars(
	arg *syntax.Word,
	tainted map[string]shell.Entry,
	script string,
	runStr *ast.String,
	cmdName string,
	leaks *[]echoLeakOccurrence,
) {
	syntax.Walk(arg, func(node syntax.Node) bool {
		pe, ok := node.(*syntax.ParamExp)
		if !ok || pe.Param == nil {
			return true
		}
		name := pe.Param.Value
		entry, ok := tainted[name]
		if !ok {
			return true
		}
		sinkOffset := int(pe.Pos().Offset())
		// Order-aware チェック: アサインが sink より後に現れる場合は FP なのでスキップ。
		// Offset=-1 の env 変数はスクリプト開始前に設定済みなので常に有効（< 任意の sinkOffset）。
		if entry.Offset >= 0 && entry.Offset >= sinkOffset {
			return true
		}
		// GitHub Actions の ::add-mask:: は発行後のログ出力にのみ適用されるため、
		// この sink より後に現れる add-mask は保護にならない。sink 位置より前に
		// 有効な add-mask が存在する場合のみスキップする。
		if hasAddMaskBefore(script, name, sinkOffset) {
			return true
		}
		pos := offsetToPosition(runStr, script, sinkOffset)
		*leaks = append(*leaks, echoLeakOccurrence{
			VarName:  name,
			Origin:   entry.First(),
			Position: pos,
			Offset:   sinkOffset,
			Command:  cmdName,
		})
		return true
	})
}

// firstWordLiteral は Word の先頭リテラル（コマンド名）を取り出す。
func firstWordLiteral(word *syntax.Word) string {
	if word == nil || len(word.Parts) == 0 {
		return ""
	}
	if lit, ok := word.Parts[0].(*syntax.Lit); ok {
		return lit.Value
	}
	return ""
}

// hasAddMaskFor は script 内に該当変数への ::add-mask:: 呼び出しがあれば true。
// ブレース形式 "${NAME}" は常に "}" で終端されるため単純検索で十分。
// ベア形式 "$NAME" は識別子境界チェックを行い、"$NAME_SUFFIX" の誤マッチを防ぐ。
// 位置依存チェックを行う場合は hasAddMaskBefore を使用する。
func hasAddMaskFor(script, varName string) bool {
	return hasAddMaskBefore(script, varName, -1)
}

// hasAddMaskBefore は script 内に該当変数への ::add-mask:: 呼び出しがあり、
// かつその呼び出し位置（バイトオフセット）が beforeOffset より前なら true を返す。
// beforeOffset に負の値（-1 など）を渡すと位置制約なし（ script 全域を検索）。
//
// GitHub Actions の ::add-mask:: ワークフローコマンドは発行 *後* のログ出力にのみ
// 適用されるため、sink（echo/printf）より後に記述された add-mask は保護にならない。
// 位置を考慮することで、後続の mask を保護とみなす偽陰性を回避する。
func hasAddMaskBefore(script, varName string, beforeOffset int) bool {
	// ブレース形式: ::add-mask::${NAME} — 終端が "}" で識別子は終わるため単純検索で OK
	brace := "::add-mask::${" + varName + "}"
	for i := 0; i < len(script); {
		idx := strings.Index(script[i:], brace)
		if idx < 0 {
			break
		}
		absIdx := i + idx
		if beforeOffset < 0 || absIdx < beforeOffset {
			return true
		}
		i = absIdx + len(brace)
	}
	// ベア形式: ::add-mask::$NAME — NAME の直後が識別子文字でないことを確認
	matches := bareAddMaskRegex(varName).FindAllStringIndex(script, -1)
	for _, m := range matches {
		if beforeOffset < 0 || m[0] < beforeOffset {
			return true
		}
	}
	return false
}

// offsetToPosition は script 内のバイトオフセットを ast.Position に変換する。
func offsetToPosition(runStr *ast.String, script string, offset int) *ast.Position {
	if offset < 0 || offset > len(script) {
		offset = 0
	}
	prefix := script[:offset]
	line := strings.Count(prefix, "\n")
	col := offset
	if lastNL := strings.LastIndex(prefix, "\n"); lastNL >= 0 {
		col = offset - lastNL - 1
	}
	pos := &ast.Position{
		Line: runStr.Pos.Line + line,
		Col:  col + 1,
	}
	if runStr.Literal {
		pos.Line++
	}
	return pos
}

// VisitWorkflowPre はワークフロールートの env: から secret taint 種を収集する。
func (rule *SecretInLogRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflowEnvSecrets = rule.collectSecretEnvVars(node.Env)
	return nil
}

// VisitJobPre は Job 内の各 Step を走査して secret 漏洩を検出する。
// Job 開始時に crossStepEnv をリセットし、ステップを順次処理することで
// 前 step の `$GITHUB_ENV` 書き込みを後続 step の taint source として引き継ぐ。
func (rule *SecretInLogRule) VisitJobPre(node *ast.Job) error {
	rule.jobEnvSecrets = rule.collectSecretEnvVars(node.Env)
	rule.crossStepEnv = make(map[string]string)
	for _, step := range node.Steps {
		rule.checkStep(step)
	}
	return nil
}

// checkStep は単一 Step の run スクリプトを解析して secret 漏洩を検出する。
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

	// 初期 taint 集合を構築: workflow env, job env, crossStepEnv, step env の順で merge。
	// 後から merge されるものが同名キーを上書きする（step env が最優先）。
	initialTainted := make(map[string]shell.Entry)
	for k, v := range rule.workflowEnvSecrets {
		initialTainted[k] = shell.Entry{Sources: []string{v}, Offset: -1}
	}
	for k, v := range rule.jobEnvSecrets {
		initialTainted[k] = shell.Entry{Sources: []string{v}, Offset: -1}
	}
	// crossStepEnv（前 step の $GITHUB_ENV 経由で伝播した taint）を merge。
	// step-level env より前に入れ、同名の場合は step-level が勝つようにする。
	for k, v := range rule.crossStepEnv {
		initialTainted[k] = shell.Entry{Sources: []string{v}, Offset: -1}
	}
	for k, v := range rule.collectSecretEnvVars(step.Env) {
		initialTainted[k] = shell.Entry{Sources: []string{v}, Offset: -1}
	}
	if len(initialTainted) == 0 {
		return
	}

	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(script), "")
	if err != nil || file == nil {
		return // パース失敗時は解析をスキップ（他ルールの管轄）
	}

	scoped := shell.PropagateTaint(file, initialTainted)
	leaks := rule.findEchoLeaks(file, scoped, script, execRun.Run)

	for _, leak := range leaks {
		rule.reportLeak(leak)
		rule.addAutoFixerForLeak(step, leak)
	}

	// この step の $GITHUB_ENV 書き込みから tainted な env var を抽出し、
	// 後続 step の crossStepEnv に伝播させる。
	// shellvar:X マーカーは autofix が変数アサイン直後への ::add-mask:: 挿入
	// 判定に使うため、ここでは展開せずそのまま流す (spec §5.2)。
	for name, origin := range rule.collectGitHubEnvTaintWrites(file, scoped, script) {
		rule.crossStepEnv[name] = origin
	}
}

// reportLeak は echoLeakOccurrence をエラーとして記録する。
func (rule *SecretInLogRule) reportLeak(leak echoLeakOccurrence) {
	rule.Errorf(
		leak.Position,
		"secret in log: variable $%s (origin: %s) is printed via '%s' without masking. "+
			"GitHub Actions only masks direct secrets.* values; values derived via shell expansion or "+
			"tools like jq are not masked and will appear in plaintext in build logs. "+
			"Add 'echo \"::add-mask::$%s\"' before any usage, or avoid printing the value. "+
			"See https://sisaku-security.github.io/lint/docs/rules/secretinlogrule/",
		leak.VarName, leak.Origin, leak.Command, leak.VarName,
	)
}

// addAutoFixerForLeak は add-mask 行を run スクリプトに挿入する auto-fixer を登録する。
func (rule *SecretInLogRule) addAutoFixerForLeak(step *ast.Step, leak echoLeakOccurrence) {
	fixer := &secretInLogFixer{
		step:       step,
		varName:    leak.VarName,
		origin:     leak.Origin,
		leakOffset: leak.Offset,
		ruleName:   rule.RuleName,
	}
	rule.AddAutoFixer(NewStepFixer(step, fixer))
}

// secretInLogFixer は add-mask 行をスクリプトに挿入する StepFixer 実装。
// origin が "secrets.*" の場合はスクリプト冒頭に挿入する（env var はスクリプト開始前に設定済み）。
// origin が "shellvar:*" の場合は対象変数のアサイン直後に挿入する（アサイン前にマスクすると空文字列をマスクしてしまう）。
type secretInLogFixer struct {
	step       *ast.Step
	varName    string
	origin     string // "secrets.X" or "shellvar:Y"
	leakOffset int    // sink のバイトオフセット。offset-aware な冪等性判定に使用
	ruleName   string
}

func (f *secretInLogFixer) RuleNames() string { return f.ruleName }

func (f *secretInLogFixer) FixStep(node *ast.Step) error {
	if node == nil || node.Exec == nil {
		return nil
	}
	execRun, ok := node.Exec.(*ast.ExecRun)
	if !ok || execRun.Run == nil {
		return nil
	}
	script := execRun.Run.Value

	maskTarget, ok := resolveMaskTarget(f.varName, f.origin)
	if !ok {
		// $@ / $* のリーク、または origin が shellvar:* でない positional →
		// 確実な single-var ターゲットが取れないため autofix は no-op。
		// lint diag 自体は既に出ているので、手動修正に委ねる。
		return nil
	}

	// sink 位置より前に有効な add-mask が既に存在していれば、追加挿入は不要。
	// leakOffset は元スクリプトにおける sink のオフセット。他の fixer が先に
	// insertAfterAssignment でスクリプトを書き換えた場合、挿入位置は常に元 sink より
	// 前（= アサイン直後 < 元 sink）で行われるため、leakOffset 基準でのチェックは
	// 書き換え後のスクリプトに対しても引き続き正しく機能する。
	if hasAddMaskBefore(script, maskTarget, f.leakOffset) {
		return nil
	}

	addMask := `echo "::add-mask::$` + maskTarget + `"`

	// origin が "shellvar:*" の場合、変数のアサイン直後に add-mask を挿入する。
	// env var 由来（"secrets.*"）の場合はスクリプト冒頭に挿入する。
	if strings.HasPrefix(f.origin, "shellvar:") {
		updated, ok := insertAfterAssignment(script, maskTarget, addMask)
		if ok {
			execRun.Run.Value = updated
			if execRun.Run.BaseNode != nil {
				execRun.Run.BaseNode.Value = updated
			}
			return nil
		}
		// アサインが見つからない／同一行に sink がある等、安全に挿入できない場合は
		// 冒頭挿入にフォールスルーしない。冒頭に mask を置くとアサイン前に空文字列を
		// マスクすることになり、「後続の派生値はマスクされない」という本ルールが
		// 検出した脆弱性を修正できない（むしろ誤った安心感を与える）。
		// 警告のみ残して no-op とし、手動修正に委ねる。
		return nil
	}

	var updated string
	if strings.HasPrefix(script, "#!") {
		nl := strings.Index(script, "\n")
		if nl == -1 {
			updated = script + "\n" + addMask
		} else {
			updated = script[:nl] + "\n" + addMask + "\n" + script[nl+1:]
		}
	} else {
		updated = addMask + "\n" + script
	}
	execRun.Run.Value = updated
	if execRun.Run.BaseNode != nil {
		execRun.Run.BaseNode.Value = updated
	}
	return nil
}

// resolveMaskTarget は autofix のマスク対象変数名を決定する。
//
// セマンティクス (#448):
//   - varName が positional ($1, $2, ...): origin が "shellvar:UPSTREAM" の場合は
//     UPSTREAM を返す (immediate upstream var をマスク対象にする)。
//     origin が shellvar:* でない (env var 由来 secrets.X 等) なら ("", false) を返す
//     → autofix no-op
//   - varName が "@" / "*": 確実な single-var ターゲットが取れないので ("", false) → autofix no-op
//   - 通常 var: そのまま返す (現状互換)
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

// isPositional は s が positional parameter ($1, $2, ...) を表す数値文字列か判定する。
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

// insertAfterAssignment はシェルスクリプト script 内で varName への最初のアサインを探し、
// その行の直後に addMaskLine を挿入した新しいスクリプトを返す。
// アサインが見つからなかった場合は ("", false) を返す。
func insertAfterAssignment(script, varName, addMaskLine string) (string, bool) {
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(script), "")
	if err != nil || file == nil {
		return "", false
	}

	// varName への最初のアサインのバイトオフセット（終端）を探す
	assignEndOffset := -1
	syntax.Walk(file, func(node syntax.Node) bool {
		if assignEndOffset >= 0 {
			return false
		}
		assign, ok := node.(*syntax.Assign)
		if !ok || assign.Name == nil {
			return true
		}
		if assign.Name.Value != varName {
			return true
		}
		assignEndOffset = int(assign.End().Offset())
		return false
	})
	if assignEndOffset < 0 {
		return "", false
	}

	// アサイン終端以降で最初の改行を探す
	rest := script[assignEndOffset:]
	nlIdx := strings.Index(rest, "\n")
	if nlIdx < 0 {
		// アサインの後に改行がない場合：
		//   - 単一行かつアサインのみ (例: `KEY=$(...)`) → sink が無いので fixer が呼ばれない想定
		//   - アサインと同一行に別コマンドがある複文 (例: `KEY=$(...); echo "$KEY"`)
		//     → 同一行の sink 手前へ安全に挿入する位置を AST から特定できないため、
		//       末尾に append すると sink より後に mask が来て無効な修正となる。
		// いずれの場合も安全側に倒して「修正不可」を返し、呼び出し側で no-op にする。
		return "", false
	}

	// アサイン行の先頭インデントを検出して合わせる
	insertPos := assignEndOffset + nlIdx + 1 // 改行の直後
	// アサイン行の先頭インデントを検出する
	lineStart := strings.LastIndex(script[:assignEndOffset], "\n")
	var indent string
	if lineStart >= 0 {
		line := script[lineStart+1 : assignEndOffset]
		for _, ch := range line {
			if ch == ' ' || ch == '\t' {
				indent += string(ch)
			} else {
				break
			}
		}
	}

	updated := script[:insertPos] + indent + addMaskLine + "\n" + script[insertPos:]
	return updated, true
}

// envAssignRe は `NAME=...` 形式の行先頭マッチ（heredoc 内 1 行用）。
var envAssignRe = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)=`)

// envAssignPrefixRe は Lit の先頭から NAME= 部分を切り出す（heredoc 以外、echo/printf 引数用）。
var envAssignPrefixRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=`)

// shellVarRefCache は 変数名 → `$NAME` / `${NAME}` の境界つき検出用 Regexp のキャッシュ。
var shellVarRefCache sync.Map // map[string]*regexp.Regexp

func shellVarRefRegex(varName string) *regexp.Regexp {
	if v, ok := shellVarRefCache.Load(varName); ok {
		return v.(*regexp.Regexp)
	}
	// $NAME（識別子境界）または ${NAME}（閉じブレース必須）
	re := regexp.MustCompile(`\$\{` + regexp.QuoteMeta(varName) + `\}|\$` + regexp.QuoteMeta(varName) + `($|[^A-Za-z0-9_])`)
	actual, _ := shellVarRefCache.LoadOrStore(varName, re)
	return actual.(*regexp.Regexp)
}

// wordIsEnvVarRef は Word が単一の env 変数参照（$NAME / ${NAME} / "$NAME" / "${NAME}"）の場合に
// その変数名を返し、それ以外は "" を返す。`$GITHUB_ENV` のリダイレクト先判定に使用する。
func wordIsEnvVarRef(w *syntax.Word) string {
	if w == nil || len(w.Parts) != 1 {
		return ""
	}
	switch p := w.Parts[0].(type) {
	case *syntax.ParamExp:
		if p.Param != nil {
			return p.Param.Value
		}
	case *syntax.DblQuoted:
		if len(p.Parts) != 1 {
			return ""
		}
		if pe, ok := p.Parts[0].(*syntax.ParamExp); ok && pe.Param != nil {
			return pe.Param.Value
		}
	}
	return ""
}

// stmtRedirectsToGitHubEnv は Stmt の Redirs に `> $GITHUB_ENV` / `>> $GITHUB_ENV` 系が
// 含まれていれば true。書き込み先の Word が $GITHUB_ENV の参照であるかを AST で判定する。
func stmtRedirectsToGitHubEnv(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	for _, r := range stmt.Redirs {
		if r == nil {
			continue
		}
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob:
		default:
			continue
		}
		if r.N != nil && r.N.Value != "" && r.N.Value != "1" {
			continue
		}
		if wordIsEnvVarRef(r.Word) == "GITHUB_ENV" {
			return true
		}
	}
	return false
}

// firstNameEqualsPrefix は Word の先頭 Lit 部分から `NAME=` 形式の NAME を取り出す。
// 形式に一致しなければ "" を返す。DblQuoted / SglQuoted 内の先頭 Lit も対象とする。
func firstNameEqualsPrefix(word *syntax.Word) string {
	if word == nil || len(word.Parts) == 0 {
		return ""
	}
	var s string
	switch p := word.Parts[0].(type) {
	case *syntax.Lit:
		s = p.Value
	case *syntax.DblQuoted:
		if len(p.Parts) > 0 {
			if lit, ok := p.Parts[0].(*syntax.Lit); ok {
				s = lit.Value
			}
		}
	case *syntax.SglQuoted:
		s = p.Value
	}
	m := envAssignPrefixRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// collectGitHubEnvTaintWrites は `>> $GITHUB_ENV` / `> $GITHUB_ENV` へ書き込む statement を
// 検索し、その中で tainted なシェル変数を参照して構築された `NAME=...` の NAME を抽出し、
// `NAME -> origin` のマップを返す。対象コマンドは echo / printf / cat（heredoc）。
//
// 戻り値は後続 step の crossStepEnv に merge される。origin は後続 step での
// 漏洩メッセージに表示される識別子（`secrets.X` or `shellvar:Y`）。
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
			// heredoc 経由で `>> $GITHUB_ENV` に流し込むパターン。
			// tee/dd も stdin を受け取って stdout（もしくは file 引数）に流すので
			// `cmd <<EOF >> $GITHUB_ENV ... EOF` 形式で taint を書き込みうる。
			// sink 検出側 (collectRedirectSinkLeaks) との対称性を保つ。
			rule.collectHeredocEnvWrites(stmt, visible, script, result)
		}
		return true
	})
	return result
}

// collectEchoEnvWrites は `echo "NAME=$VAL" >> $GITHUB_ENV` 形式の引数から
// NAME と origin を抽出して result に追加する。
//
// 先頭が `-n`/`-e`/`-E` などの echo オプションまたは `printf` のフォーマット指定子
// (`%s\n` 等) で始まる場合はそれらをスキップし、最初に `NAME=` 形式と一致する Word
// を NAME 候補として扱う。
//
// 複数 NAME=... が 1 行に並ぶケース（GitHub Actions がスペース含みの値として解釈する
// ため実質 1 assignment）は最初に一致した NAME のみを記録する。
func (rule *SecretInLogRule) collectEchoEnvWrites(
	call *syntax.CallExpr,
	tainted map[string]shell.Entry,
	result map[string]string,
) {
	if len(call.Args) < 2 {
		return
	}
	nameArgIdx := -1
	var name string
	for i := 1; i < len(call.Args); i++ {
		lit := firstWordLiteral(call.Args[i])
		// `-` 単独 (stdin 指定) は NAME= にはなり得ないが、スキップせずに探索を進める。
		if strings.HasPrefix(lit, "-") && lit != "-" {
			// 短いオプション群 (`-n`, `-e`, `-nE` 等) または long option を飛ばして次へ。
			continue
		}
		if n := firstNameEqualsPrefix(call.Args[i]); n != "" {
			name = n
			nameArgIdx = i
			break
		}
		// printf のフォーマット指定子 (`%s\n` など) は Lit としてリテラル値を持つ。
		// NAME= 形式でなければ次の引数で NAME= を探す。
		if strings.Contains(lit, "%") {
			continue
		}
		// それ以外の Lit (例: `--`) は option 終端とみなし、次の arg を NAME 候補にする。
	}
	if name == "" || nameArgIdx < 0 {
		return
	}
	var firstVar string
	for _, arg := range call.Args[nameArgIdx:] {
		if v, ok := shell.WordReferencesEntry(arg, tainted); ok {
			firstVar = v
			break
		}
	}
	if firstVar == "" {
		return
	}
	// origin は「起点の secret 名」を保持する。tainted[firstVar].First() は
	// 既に "secrets.X" または "shellvar:Y" の形を持つため、そのまま引き継ぐ。
	result[name] = tainted[firstVar].First()
}

// collectHeredocEnvWrites は `cat <<EOF >> $GITHUB_ENV ... EOF` 形式の heredoc 本文を
// 行単位で走査し、`NAME=...` 行のうち `...` 内で tainted 変数が参照されているものを
// result に追加する。heredoc 本文の取得は script のバイトオフセットから行う。
func (rule *SecretInLogRule) collectHeredocEnvWrites(
	stmt *syntax.Stmt,
	tainted map[string]shell.Entry,
	script string,
	result map[string]string,
) {
	for _, r := range stmt.Redirs {
		if r == nil {
			continue
		}
		if r.Op != syntax.Hdoc && r.Op != syntax.DashHdoc {
			continue
		}
		if r.Hdoc == nil {
			continue
		}
		start := int(r.Hdoc.Pos().Offset())
		end := int(r.Hdoc.End().Offset())
		if start < 0 || end > len(script) || start >= end {
			continue
		}
		body := script[start:end]
		// 変数名の走査順を決定的にしたいので、tainted のキーを sort する意味は薄い
		// （「いずれかの tainted 参照があれば 1 件記録」が仕様のため任意で良い）。
		// ただし map iteration の非決定性でテストが不安定にならないよう、
		// 明示的に tainted 集合からの探索順は body 上で「最初に現れた $REF」優先にする。
		for _, line := range strings.Split(body, "\n") {
			m := envAssignRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			name := m[1]
			origin := rule.firstTaintedRefOrigin(line, tainted)
			if origin == "" {
				continue
			}
			result[name] = origin
		}
	}
}

// firstTaintedRefOrigin は行内に現れる最初の tainted 変数参照の origin を返す。
// 現れる位置（バイトオフセット）が最小のものを選ぶことで map iteration の
// 非決定性を回避する。
func (rule *SecretInLogRule) firstTaintedRefOrigin(line string, tainted map[string]shell.Entry) string {
	minPos := -1
	var origin string
	for name, entry := range tainted {
		loc := shellVarRefRegex(name).FindStringIndex(line)
		if loc == nil {
			continue
		}
		if minPos < 0 || loc[0] < minPos {
			minPos = loc[0]
			origin = entry.First()
		}
	}
	return origin
}

func (rule *SecretInLogRule) collectSecretEnvVars(env *ast.Env) map[string]string {
	result := make(map[string]string)
	if env == nil || env.Vars == nil {
		return result
	}
	for key, envVar := range env.Vars {
		if envVar == nil || envVar.Value == nil {
			continue
		}
		all := secretEnvRefRe.FindAllStringSubmatch(envVar.Value.Value, -1)
		if len(all) == 0 {
			continue
		}
		name := key
		if envVar.Name != nil && envVar.Name.Value != "" {
			name = envVar.Name.Value
		}
		var origins []string
		for _, m := range all {
			origins = append(origins, "secrets."+m[1])
		}
		result[name] = strings.Join(origins, ",")
	}
	return result
}
