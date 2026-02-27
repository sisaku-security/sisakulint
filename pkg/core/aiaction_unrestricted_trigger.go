package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// knownAIActionPrefixes は検査対象の AI エージェントアクションのプレフィックスリスト
var knownAIActionPrefixes = []string{
	"anthropics/claude-code-action",
	"github/copilot-swe-agent",
	"openai/openai-actions",
}

// AIActionUnrestrictedTriggerRule は allowed_non_write_users: "*" を検出するルール。
//
// 脆弱なパターン:
//
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      allowed_non_write_users: "*"
//
// このような設定では、すべての GitHub ユーザーが AI エージェントをトリガーできるため、
// Clinejection 攻撃（任意ユーザーが悪意のある指示を注入してエージェントを操作する攻撃）のリスクがある。
//
// 安全なパターン:
//
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      # allowed_non_write_users を省略するか、特定のユーザーを指定する
//	      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
type AIActionUnrestrictedTriggerRule struct {
	BaseRule
}

// NewAIActionUnrestrictedTriggerRule は新しいルールインスタンスを返す。
func NewAIActionUnrestrictedTriggerRule() *AIActionUnrestrictedTriggerRule {
	return &AIActionUnrestrictedTriggerRule{
		BaseRule: BaseRule{
			RuleName: "ai-action-unrestricted-trigger",
			RuleDesc: "AI action allows any GitHub user to trigger agent execution",
		},
	}
}

// VisitStep は各ステップを訪問し、AI エージェントアクションの unrestricted trigger 設定を検出する。
func (r *AIActionUnrestrictedTriggerRule) VisitStep(node *ast.Step) error {
	action, ok := node.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	if action.Uses == nil {
		return nil
	}

	if !isKnownAIActionPrefix(action.Uses.Value) {
		return nil
	}

	// with.allowed_non_write_users が "*" かどうかを検査する
	if val, exists := action.Inputs["allowed_non_write_users"]; exists {
		if val != nil && val.Value != nil && strings.TrimSpace(val.Value.Value) == "*" {
			r.Errorf(
				node.Pos,
				`ai-action-unrestricted-trigger: action %q has "allowed_non_write_users: \"*\"" which allows any GitHub user to trigger AI agent execution with full tool access. Restrict to specific users or organization members.`,
				action.Uses.Value,
			)
		}
	}

	return nil
}

// isKnownAIActionPrefix は uses の値が既知の AI アクションプレフィックスに一致するかを確認する。
func isKnownAIActionPrefix(uses string) bool {
	usesLower := strings.ToLower(uses)
	for _, prefix := range knownAIActionPrefixes {
		if strings.HasPrefix(usesLower, prefix) {
			return true
		}
	}
	return false
}
