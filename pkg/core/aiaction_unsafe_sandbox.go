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

// dangerouslySkipPermissionsFlag は Claude Code のパーミッションチェックを無効化するフラグ。
// CLI リファレンスに記載されているのはこのハイフン区切りの綴りだけである。
const dangerouslySkipPermissionsFlag = "--dangerously-skip-permissions"

// camelCaseDangerouslySkipPermissions は #647 以前にこのルールが照合していた綴り。
// Claude Code はこの綴りを "unknown option" として拒否するため、
// パーミッションチェックはバイパスされない。
const camelCaseDangerouslySkipPermissions = "--dangerouslySkipPermissions"

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
//	      claude_args: --dangerously-skip-permissions
//
// OpenAI Codex セキュリティチェックリストでは safety-strategy に "drop-sudo"（デフォルト）、
// "unprivileged-user"、"read-only" を推奨し、"unsafe" や "danger-full-access" の使用を警告している。
// claude-code-action では --dangerously-skip-permissions フラグが同等のサンドボックスバイパスに該当する。
// キャメルケースの --dangerouslySkipPermissions は Claude Code がオプションとして認識しないため、
// バイパスの意図がある設定として報告するが、メッセージではバイパスが成立したとは主張しない。
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
// safety-strategy が未設定の場合、デフォルト値は "drop-sudo"（安全）のため警告不要。
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

// checkDangerouslySkipPermissions は claude_args にパーミッションチェックを無効化する
// フラグが含まれているかを検査する。
func (r *AIActionUnsafeSandboxRule) checkDangerouslySkipPermissions(node *ast.Step, action *ast.ExecAction) {
	claudeArgsInput, exists := action.Inputs["claude_args"]
	if !exists || claudeArgsInput == nil || claudeArgsInput.Value == nil {
		return
	}

	claudeArgs := claudeArgsInput.Value.Value

	// 実際にパーミッションチェックを無効化するのはハイフン区切りの綴りだけである。
	if strings.Contains(claudeArgs, dangerouslySkipPermissionsFlag) {
		r.Errorf(
			node.Pos,
			`action %q passes %s in claude_args which disables Claude Code's permission checks. Remove this flag and grant only the tools the workflow needs instead (for example --allowedTools "Read,Glob,Grep").`,
			action.Uses.Value,
			dangerouslySkipPermissionsFlag,
		)
		return
	}

	// キャメルケースの綴りは Claude Code が "unknown option" として拒否するため、
	// バイパスは成立しない。バイパスの意図がある設定として報告するが、
	// メッセージはバイパスが起きたことを主張しない。
	if strings.Contains(claudeArgs, camelCaseDangerouslySkipPermissions) {
		r.Errorf(
			node.Pos,
			`action %q passes %s in claude_args. Claude Code rejects that spelling as an unknown option, so it does not bypass the permission checks; the flag that does is %s. Remove it and grant only the tools the workflow needs instead (for example --allowedTools "Read,Glob,Grep").`,
			action.Uses.Value,
			camelCaseDangerouslySkipPermissions,
			dangerouslySkipPermissionsFlag,
		)
	}
}
