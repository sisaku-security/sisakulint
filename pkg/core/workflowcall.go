package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// RuleWorkflowCall は、jobs.<job_id>でのワークフローコールをチェックするルールチェッカーです。
type RuleWorkflowCall struct {
	BaseRule
	workflowCallEventPos *ast.Position
	workflowPath         string
	cache                *LocalReusableWorkflowCache
}

// WorkflowCall は新しいRuleWorkflowCallインスタンスを作成します。'workflowPath'はプロジェクトのルートディレクトリからの相対パスまたは絶対パスです。
func WorkflowCall(workflowPath string, cache *LocalReusableWorkflowCache) *RuleWorkflowCall {
	return &RuleWorkflowCall{
		BaseRule: BaseRule{
			RuleName: "workflow-call",
			RuleDesc: "Checks for reusable workflow calls. Inputs and outputs of called reusable workflow are checked",
		},
		workflowCallEventPos: nil,
		workflowPath:         workflowPath,
		cache:                cache,
	}
}

// VisitWorkflowPre は、Workflowノードを子ノードを訪問する前に呼び出されるコールバックです。
func (rule *RuleWorkflowCall) VisitWorkflowPre(n *ast.Workflow) error {
	for _, e := range n.On {
		if e, ok := e.(*ast.WorkflowCallEvent); ok {
			rule.workflowCallEventPos = e.Pos
			// この再利用可能なワークフローをキャッシュに登録して、他のワークフローによってこのワークフローが呼び出されたときに、このワークフローファイルを再度解析する必要がないようにします。
			rule.cache.WriteWorkflowCallEvent(rule.workflowPath, e)
			break
		}
	}
	return nil
}

// VisitJobPre は、Jobノードを子ノードを訪問する前に呼び出されるコールバックです。
func (rule *RuleWorkflowCall) VisitJobPre(n *ast.Job) error {
	if n.WorkflowCall == nil {
		return nil
	}

	u := n.WorkflowCall.Uses
	if u == nil || u.Value == "" || u.ContainsExpression() {
		return nil
	}

	if isWorkflowCallUsesLocalFormat(u.Value) {
		rule.checkWorkflowCallUsesLocal(n.WorkflowCall)
		return nil
	}

	if isWorkflowCallUsesRepoFormat(u.Value) {
		return nil
	}

	if strings.HasPrefix(u.Value, "./") {
		// 仕様が無効であり、ローカル再利用可能なワークフローコールである場合、キャッシュに `nil` を設定することでエラーが発生したことを記録します。これにより、'ワークフローコールを読み取れない'という冗長なエラーを防ぐことができます。
		rule.cache.writeCache(u.Value, nil)
	}

	rule.Errorf(
		u.Pos,
		"reusable workflow call %q at uses is not following the format \"owner/repo/path/to/workflow.yml@ref\" nor \"./path/to/workflow.yml\". please visit to https://sisaku-security.github.io/lint/docs/rules/workflowcall/ for more details",
		u.Value,
	)
	return nil
}

// checkWorkflowCallUsesLocal は、ローカルのワークフローコールをチェックする関数です。
func (rule *RuleWorkflowCall) checkWorkflowCallUsesLocal(call *ast.WorkflowCall) {
	u := call.Uses
	m, err := rule.cache.FindMetadata(u.Value)
	if err != nil {
		rule.Error(u.Pos, err.Error())
		return
	}
	if m == nil {
		rule.Debug("Skip workflow call %q since no metadata was found", u.Value)
		return
	}

	// 入力の検証
	for n, i := range m.Inputs {
		if i != nil && i.Required {
			if _, ok := call.Inputs[n]; !ok {
				rule.Errorf(u.Pos, "input %q is required by %q reusable workflow", i.Name, u.Value)
			}
		}
	}
	for n, i := range call.Inputs {
		if _, ok := m.Inputs[n]; !ok {
			note := "no input is defined"
			if len(m.Inputs) > 0 {
				is := make([]string, 0, len(m.Inputs))
				for _, i := range m.Inputs {
					is = append(is, i.Name)
				}
				if len(is) == 1 {
					note = fmt.Sprintf("defined input is %q", is[0])
				} else {
					note = "defined inputs are " + expressions.SortedQuotes(is)
				}
			}
			rule.Errorf(i.Name.Pos, "input %q is not defined in %q reusable workflow. %s", i.Name.Value, u.Value, note)
		}
	}

	// シークレットの検証
	if !call.InheritSecrets {
		for n, s := range m.Secrets {
			if s.Required {
				if _, ok := call.Secrets[n]; !ok {
					rule.Errorf(u.Pos, "secret %q is required by %q reusable workflow", s.Name, u.Value)
				}
			}
		}
		for n, s := range call.Secrets {
			if _, ok := m.Secrets[n]; !ok {
				note := "no secret is defined"
				if len(m.Secrets) > 0 {
					ss := make([]string, 0, len(m.Secrets))
					for _, s := range m.Secrets {
						ss = append(ss, s.Name)
					}
					if len(ss) == 1 {
						note = fmt.Sprintf("defined secret is %q", ss[0])
					} else {
						note = "defined secrets are " + expressions.SortedQuotes(ss)
					}
				}
				rule.Errorf(s.Name.Pos, "secret %q is not defined in %q reusable workflow. %s", s.Name.Value, u.Value, note)
			}
		}
	}
	rule.Debug("Validated reusable workflow %q", u.Value)
}

// ./{path/{filename} を解析する関数です。
// * https://docs.github.com/en/actions/learn-github-actions/reusing-workflows#calling-a-reusable-workflow
func isWorkflowCallUsesLocalFormat(u string) bool {
	if !strings.HasPrefix(u, "./") {
		return false
	}
	u = strings.TrimPrefix(u, "./")

	// refを含んではいけません
	idx := strings.IndexRune(u, '@')
	if idx > 0 {
		return false
	}

	return len(u) > 0
}

// {owner}/{repo}/{path to workflow.yml}@{ref} を解析する関数です。
// * https://docs.github.com/en/actions/learn-github-actions/reusing-workflows#calling-a-reusable-workflow
func isWorkflowCallUsesRepoFormat(u string) bool {
	// リポジトリ参照はオーナーから始まる必要があります
	if strings.HasPrefix(u, ".") {
		return false
	}

	idx := strings.IndexRune(u, '/')
	if idx <= 0 {
		return false
	}
	u = u[idx+1:] // オーナーを取り除く

	idx = strings.IndexRune(u, '/')
	if idx <= 0 {
		return false
	}
	u = u[idx+1:] // リポジトリを取り除く

	idx = strings.IndexRune(u, '@')
	if idx <= 0 {
		return false
	}
	u = u[idx+1:] // ワークフローパスを取り除く

	return len(u) > 0
}
