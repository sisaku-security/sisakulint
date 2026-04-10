package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// unsafeSandboxValues はサンドボックス保護を無効化する危険な safety-strategy の値。
var unsafeSandboxValues = []string{
	"unsafe",
	"danger-full-access",
}

// sandboxStrategyInputKeys は safety-strategy を指定する入力キー名の候補。
// GitHub Actions の with セクションではハイフン区切りとアンダースコア区切りの両方が使われうる。
var sandboxStrategyInputKeys = []string{
	"safety-strategy",
	"safety_strategy",
}

// AIActionUnsafeSandboxRule は AI エージェントアクションの安全でないサンドボックス設定を検出するルール。
//
// 脆弱なパターン:
//
//	steps:
//	  - uses: openai/codex-action@v1
//	    with:
//	      safety-strategy: unsafe
//
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      claude_args: --dangerouslySkipPermissions
//
// OpenAI Codex セキュリティチェックリストでは safety-strategy に "drop-sudo"（デフォルト）、
// "unprivileged-user"、"read-only" を推奨し、"unsafe" や "danger-full-access" の使用を警告している。
// claude-code-action では --dangerouslySkipPermissions フラグが同等のサンドボックスバイパスに該当する。
//
// 安全なパターン:
//
//	steps:
//	  - uses: openai/codex-action@v1
//	    with:
//	      safety-strategy: drop-sudo
type AIActionUnsafeSandboxRule struct {
	BaseRule
}

// NewAIActionUnsafeSandboxRule は新しいルールインスタンスを返す。
func NewAIActionUnsafeSandboxRule() *AIActionUnsafeSandboxRule {
	return &AIActionUnsafeSandboxRule{
		BaseRule: BaseRule{
			RuleName: "ai-action-unsafe-sandbox",
			RuleDesc: "AI action has unsafe sandbox or safety-strategy configuration",
		},
	}
}

// VisitStep は各ステップを訪問し、AI エージェントアクションの安全でないサンドボックス設定を検出する。
func (r *AIActionUnsafeSandboxRule) VisitStep(node *ast.Step) error {
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

	r.checkSafetyStrategy(node, action)
	r.checkDangerouslySkipPermissions(node, action)

	return nil
}

// checkSafetyStrategy は safety-strategy 入力の値を検査する。
func (r *AIActionUnsafeSandboxRule) checkSafetyStrategy(node *ast.Step, action *ast.ExecAction) {
	for _, key := range sandboxStrategyInputKeys {
		input, exists := action.Inputs[key]
		if !exists || input == nil || input.Value == nil {
			continue
		}

		val := strings.TrimSpace(strings.ToLower(input.Value.Value))
		for _, unsafeVal := range unsafeSandboxValues {
			if val == unsafeVal {
				r.Errorf(
					node.Pos,
					`action %q has safety-strategy set to %q which disables sandbox protections. Use "drop-sudo", "unprivileged-user", or "read-only" instead.`,
					action.Uses.Value,
					input.Value.Value,
				)
				return
			}
		}
	}
}

// checkDangerouslySkipPermissions は claude_args に --dangerouslySkipPermissions が含まれているかを検査する。
func (r *AIActionUnsafeSandboxRule) checkDangerouslySkipPermissions(node *ast.Step, action *ast.ExecAction) {
	claudeArgsInput, exists := action.Inputs["claude_args"]
	if !exists || claudeArgsInput == nil || claudeArgsInput.Value == nil {
		return
	}

	if strings.Contains(claudeArgsInput.Value.Value, "--dangerouslySkipPermissions") {
		r.Errorf(
			node.Pos,
			`action %q uses --dangerouslySkipPermissions in claude_args which bypasses all permission checks. Remove this flag and configure specific tool permissions instead.`,
			action.Uses.Value,
		)
	}
}
