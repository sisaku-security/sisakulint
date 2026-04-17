package core

import (
	"regexp"

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
