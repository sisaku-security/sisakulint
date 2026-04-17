package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"mvdan.cc/sh/v3/syntax"
)

type SecretInLogRule struct {
	BaseRule
	currentStep *ast.Step
	// workflowSecretTaintMap はクロスジョブ secret taint 伝播用の将来拡張フック。
	// MVP では未使用。follow-up issue（クロスジョブ secret 伝播）で *WorkflowSecretTaintMap に
	// 置換予定。interface{} にしているのは型未導入のため。
	workflowSecretTaintMap interface{} //nolint:unused
}

// NewSecretInLogRule は新規ルールインスタンスを返す。
// NOTE: クロスジョブ伝播対応時は NewSecretInLogRuleWithTaintMap を追加し、
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

// propagateTaint は初期 taint 集合から不動点反復でシェル変数の taint 伝播を計算する。
func (rule *SecretInLogRule) propagateTaint(file *syntax.File, initialTainted map[string]string) map[string]string {
	tainted := make(map[string]string, len(initialTainted))
	for k, v := range initialTainted {
		tainted[k] = v
	}
	if file == nil {
		return tainted
	}

	for {
		added := false
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
				tainted[lhs] = "shellvar:" + rule.firstTaintedVarIn(assign.Value, tainted)
				added = true
			}
			return true
		})
		if !added {
			break
		}
	}
	return tainted
}

// wordReferencesTainted は Word 内で tainted 集合に属する変数が参照されていれば true。
func (rule *SecretInLogRule) wordReferencesTainted(word *syntax.Word, tainted map[string]string) bool {
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
func (rule *SecretInLogRule) firstTaintedVarIn(word *syntax.Word, tainted map[string]string) string {
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
	Command  string
}

// findEchoLeaks は echo/printf の引数に tainted 変数が含まれる箇所を収集する。
// add-mask 済みの変数はスキップする。
// コマンド置換（$(...) ）内部の echo/printf はログに露出しないためスキップする。
func (rule *SecretInLogRule) findEchoLeaks(file *syntax.File, tainted map[string]string, script string, runStr *ast.String) []echoLeakOccurrence {
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
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		cmdName := firstWordLiteral(call.Args[0])
		if cmdName != "echo" && cmdName != "printf" {
			return true
		}
		for _, arg := range call.Args[1:] {
			rule.collectLeakedVars(arg, tainted, script, runStr, cmdName, &leaks)
		}
		return true
	})
	return leaks
}

// collectLeakedVars は単一の引数内で tainted 変数参照をすべて報告リストに追加する。
func (rule *SecretInLogRule) collectLeakedVars(
	arg *syntax.Word,
	tainted map[string]string,
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
		origin, ok := tainted[name]
		if !ok {
			return true
		}
		if hasAddMaskFor(script, name) {
			return true
		}
		pos := offsetToPosition(runStr, script, int(pe.Pos().Offset()))
		*leaks = append(*leaks, echoLeakOccurrence{
			VarName:  name,
			Origin:   origin,
			Position: pos,
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
// 現状は文字列検索（"::add-mask::$NAME" または "::add-mask::${NAME}"）。
func hasAddMaskFor(script, varName string) bool {
	patterns := []string{
		"::add-mask::$" + varName,
		"::add-mask::${" + varName + "}",
	}
	for _, p := range patterns {
		if strings.Contains(script, p) {
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

// VisitJobPre は Job 内の各 Step を走査して secret 漏洩を検出する。
func (rule *SecretInLogRule) VisitJobPre(node *ast.Job) error {
	for _, step := range node.Steps {
		rule.currentStep = step
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

	initialTainted := rule.collectSecretEnvVars(step.Env)
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

// addAutoFixerForLeak は add-mask 行を run スクリプト冒頭に挿入する auto-fixer を登録する。
func (rule *SecretInLogRule) addAutoFixerForLeak(step *ast.Step, leak echoLeakOccurrence) {
	fixer := &secretInLogFixer{
		step:     step,
		varName:  leak.VarName,
		ruleName: rule.RuleName,
	}
	rule.AddAutoFixer(NewStepFixer(step, fixer))
}

// secretInLogFixer は add-mask 行をスクリプト冒頭に挿入する StepFixer 実装。
type secretInLogFixer struct {
	step     *ast.Step
	varName  string
	ruleName string
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
	if hasAddMaskFor(script, f.varName) {
		return nil
	}

	addMask := `echo "::add-mask::$` + f.varName + `"`
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

func (rule *SecretInLogRule) collectSecretEnvVars(env *ast.Env) map[string]string {
	result := make(map[string]string)
	if env == nil || env.Vars == nil {
		return result
	}
	for key, envVar := range env.Vars {
		if envVar == nil || envVar.Value == nil {
			continue
		}
		m := secretEnvRefRe.FindStringSubmatch(envVar.Value.Value)
		if len(m) < 2 {
			continue
		}
		name := key
		if envVar.Name != nil && envVar.Name.Value != "" {
			name = envVar.Name.Value
		}
		result[name] = "secrets." + m[1]
	}
	return result
}
