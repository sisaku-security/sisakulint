// TODO: Rule!
package core

import (
	"fmt"
	"regexp"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// deprecatedCommandsPatternは非推奨のworkflow commandを検出するための正規表現パターンです。
var deprecatedCommandsPattern = regexp.MustCompile(`(?:::(save-state|set-output|set-env)\s+name=[a-zA-Z][a-zA-Z_-]*::\S+|::(add-path)::\S+)`)

// RuleDeprecatedCommandsは非推奨のワークフローコマンドを検出するルールチェッカーです。
// 現在では'set-state'、'set-output'、`set-env'、'add-path'が非推奨として検出されます。
// * https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/
// * https://github.blog/changelog/2022-10-11-github-actions-deprecating-save-state-and-set-output-commands/
type RuleDeprecatedCommands struct {
	BaseRule
}

// DeprecatedCommandsRule()は新しいRuleDeprecatedCommandsインスタンスを作成します。
func DeprecatedCommandsRule() *RuleDeprecatedCommands {
	return &RuleDeprecatedCommands{
		BaseRule: BaseRule{
			RuleName: "deprecated-commands",
			RuleDesc: "Checks for deprecated \"set-output\", \"save-state\", \"set-env\", and \"add-path\" commands at \"run:\"",
		},
	}
}

// VisitStepはStepノードを訪れたときのcallback
func (rule *RuleDeprecatedCommands) VisitStep(step *ast.Step) error {
	// ExecRunタイプの実行をチェックします。
	if execRun, isExecRun := step.Exec.(*ast.ExecRun); isExecRun && execRun.Run != nil {
		// 非推奨のコマンドを検出し、エラーメッセージを出力します。
		for _, matches := range deprecatedCommandsPattern.FindAllStringSubmatch(execRun.Run.Value, -1) {
			command := matches[1]
			if len(command) == 0 {
				command = matches[2]
			}

			replacement := ""
			switch command {
			case "set-output":
				replacement = `echo "{name}={value}" >> $GITHUB_OUTPUT`
			case "save-state":
				replacement = `echo "{name}={value}" >> $GITHUB_STATE`
			case "set-env":
				replacement = `echo "{name}={value}" >> $GITHUB_ENV`
			case "add-path":
				replacement = `echo "{path}" >> $GITHUB_PATH`
			default:
				fmt.Println("unreachable")
			}

			rule.Errorf(
				execRun.Run.Pos,
				"workflow command %q was deprecated. You should use `%s` reference: https://sisaku-security.github.io/lint/docs/rules/deprecatedcommandsrule/",
				command,
				replacement,
			)
		}
	}
	return nil
}
