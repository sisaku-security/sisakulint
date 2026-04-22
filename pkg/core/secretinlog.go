package core

import (
	"regexp"
	"strings"
	"sync"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"mvdan.cc/sh/v3/syntax"
)

// taintEntry は taint 伝播で追跡される変数エントリ。
// offset は変数が taint された時点のスクリプト内バイトオフセット。
// env 変数（スクリプト開始前に設定済み）は -1 を使用し、常にあらゆる sink より前と扱う。
type taintEntry struct {
	origin string // "secrets.X" or "shellvar:Y"
	offset int    // -1 for env vars, >=0 for shell variable assignments
}

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

// propagateTaint は初期 taint 集合からスクリプトを前向きに一回走査し、
// シェル変数の taint 伝播を order-aware に計算する。
//
// アサインが sink より後に現れる場合は FP となるため、各エントリに
// アサイン位置オフセットを記録し findEchoLeaks での判定に使用する。
// env 変数はスクリプト開始前に設定済みなので offset=-1（常に有効）。
func (rule *SecretInLogRule) propagateTaint(file *syntax.File, initialTainted map[string]string) map[string]taintEntry {
	tainted := make(map[string]taintEntry, len(initialTainted))
	for k, v := range initialTainted {
		tainted[k] = taintEntry{origin: v, offset: -1}
	}
	if file == nil {
		return tainted
	}

	// 単一前向きパス: source 順に走査するため固定点反復は不要。
	// アサイン時点で既に tainted な変数を参照していれば LHS も taint する。
	syntax.Walk(file, func(node syntax.Node) bool {
		assign, ok := node.(*syntax.Assign)
		if !ok || assign.Name == nil {
			return true
		}
		lhs := assign.Name.Value
		if _, already := tainted[lhs]; already {
			return true
		}
		if assign.Value == nil {
			return true
		}
		if rule.wordReferencesTainted(assign.Value, tainted) {
			assignOffset := int(assign.Pos().Offset())
			tainted[lhs] = taintEntry{
				origin: "shellvar:" + rule.firstTaintedVarIn(assign.Value, tainted),
				offset: assignOffset,
			}
		}
		return true
	})
	return tainted
}

// wordReferencesTainted は Word 内で tainted 集合に属する変数が参照されていれば true。
func (rule *SecretInLogRule) wordReferencesTainted(word *syntax.Word, tainted map[string]taintEntry) bool {
	var found bool
	syntax.Walk(word, func(node syntax.Node) bool {
		pe, ok := node.(*syntax.ParamExp)
		if !ok || pe.Param == nil {
			return true
		}
		if _, t := tainted[pe.Param.Value]; t {
			found = true
			return false
		}
		return true
	})
	return found
}

// firstTaintedVarIn は Word 内で最初に見つかった tainted 変数名を返す（メッセージ用）。
func (rule *SecretInLogRule) firstTaintedVarIn(word *syntax.Word, tainted map[string]taintEntry) string {
	var name string
	syntax.Walk(word, func(node syntax.Node) bool {
		pe, ok := node.(*syntax.ParamExp)
		if !ok || pe.Param == nil {
			return true
		}
		if _, t := tainted[pe.Param.Value]; t {
			name = pe.Param.Value
			return false
		}
		return true
	})
	return name
}

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
func (rule *SecretInLogRule) findEchoLeaks(file *syntax.File, tainted map[string]taintEntry, script string, runStr *ast.String) []echoLeakOccurrence {
	if file == nil {
		return nil
	}
	var leaks []echoLeakOccurrence

	syntax.Walk(file, func(node syntax.Node) bool {
		// コマンド置換の内部は stdout がパイプに接続されるため、
		// echo/printf の出力はビルドログには現れない。子ノードの探索をスキップする。
		if _, isCmdSubst := node.(*syntax.CmdSubst); isCmdSubst {
			return false
		}
		// stdout を「ログに出ない先」へリダイレクトしている Stmt は子ノードごとスキップ。
		if stmt, isStmt := node.(*syntax.Stmt); isStmt && stmtRedirectsStdoutAwayFromLog(stmt) {
			return false
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
			rule.collectLeakedVars(arg, tainted, script, runStr, cmdName, &leaks)
		}
		return true
	})
	return leaks
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
	tainted map[string]taintEntry,
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
		// offset=-1 の env 変数はスクリプト開始前に設定済みなので常に有効（< 任意の sinkOffset）。
		if entry.offset >= 0 && entry.offset >= sinkOffset {
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
			Origin:   entry.origin,
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
func (rule *SecretInLogRule) VisitJobPre(node *ast.Job) error {
	rule.jobEnvSecrets = rule.collectSecretEnvVars(node.Env)
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

	initialTainted := make(map[string]string)
	for k, v := range rule.workflowEnvSecrets {
		initialTainted[k] = v
	}
	for k, v := range rule.jobEnvSecrets {
		initialTainted[k] = v
	}
	for k, v := range rule.collectSecretEnvVars(step.Env) {
		initialTainted[k] = v
	}
	if len(initialTainted) == 0 {
		return
	}

	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(script), "")
	if err != nil || file == nil {
		return // パース失敗時は解析をスキップ（他ルールの管轄）
	}

	tainted := rule.propagateTaint(file, initialTainted)
	leaks := rule.findEchoLeaks(file, tainted, script, execRun.Run)

	for _, leak := range leaks {
		rule.reportLeak(leak)
		rule.addAutoFixerForLeak(step, leak)
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
	// sink 位置より前に有効な add-mask が既に存在していれば、追加挿入は不要。
	// leakOffset は元スクリプトにおける sink のオフセット。他の fixer が先に
	// insertAfterAssignment でスクリプトを書き換えた場合、挿入位置は常に元 sink より
	// 前（= アサイン直後 < 元 sink）で行われるため、leakOffset 基準でのチェックは
	// 書き換え後のスクリプトに対しても引き続き正しく機能する。
	if hasAddMaskBefore(script, f.varName, f.leakOffset) {
		return nil
	}

	addMask := `echo "::add-mask::$` + f.varName + `"`

	// origin が "shellvar:*" の場合、変数のアサイン直後に add-mask を挿入する。
	// env var 由来（"secrets.*"）の場合はスクリプト冒頭に挿入する。
	if strings.HasPrefix(f.origin, "shellvar:") {
		updated, ok := insertAfterAssignment(script, f.varName, addMask)
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
