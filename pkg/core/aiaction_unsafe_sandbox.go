package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// unsafeSandboxValues は safety-strategy 入力でサンドボックス保護を無効化する値。
//
// danger-full-access はここに含めない。codex-action が safety-strategy に定義して
// いるのは drop-sudo / unprivileged-user / read-only / unsafe の 4 つだけで、
// danger-full-access は別の入力（sandbox）の値である。
var unsafeSandboxValues = []string{
	"unsafe",
}

// sandboxStrategyInputKeys は safety-strategy を指定する入力キー名。
//
// codex-action は composite action で、宣言した "safety-strategy" だけを
// inputs['safety-strategy'] として読む。アンダースコア区切りの綴りは宣言されて
// いないため action には届かず、ステップは既定の drop-sudo で動く。
var sandboxStrategyInputKeys = []string{
	"safety-strategy",
}

// sandboxModeInputKeys は Codex のサンドボックスモードを選択する入力キー名。
//
// codex-action は "sandbox" を宣言している（値は workspace-write / read-only /
// danger-full-access）。sandbox_mode は Codex CLI の設定キーで codex-args 経由で
// 渡すものであり、"sandbox-mode" はどちらの入力でもないため、ここには含めない。
var sandboxModeInputKeys = []string{
	"sandbox",
}

// unsafeSandboxModes はサンドボックスを無効化する sandbox 入力の値。
var unsafeSandboxModes = []string{
	"danger-full-access",
}

// permissionProfileInputKeys は Codex の permission-profile を指定する入力キー名。
var permissionProfileInputKeys = []string{
	"permission-profile",
}

// unsafePermissionProfiles はサンドボックスを無効化する permission-profile の組み込み値。
// codex-home/config.toml で定義された名前付きプロファイルはワークフローから解決できないため、
// 組み込みの綴りだけを検査する。
var unsafePermissionProfiles = []string{
	":danger-full-access",
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
// "unprivileged-user"、"read-only" を推奨し、"unsafe" の使用を警告している。
// サンドボックスを無効化する "danger-full-access" は sandbox 入力の値で、その後継の
// permission-profile では ":danger-full-access" として指定する。
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

	// sandbox と permission-profile を宣言しているのは codex-action だけなので、
	// それ以外のアクションで同じキーが書かれても報告しない。
	if isCodexAction(action.Uses.Value) {
		r.checkSandboxMode(node, action)
		r.checkPermissionProfile(node, action)
	}

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

// isCodexAction は uses が openai/codex-action を指すかを判定する。
// プレフィックスの直後が '@'、'/'、または文字列終端であることも確認し、
// "openai/codex-action-fork" のような別アクションを拾わない。
func isCodexAction(uses string) bool {
	const prefix = "openai/codex-action"

	lower := strings.ToLower(strings.TrimSpace(uses))
	if !strings.HasPrefix(lower, prefix) {
		return false
	}

	rest := lower[len(prefix):]
	return rest == "" || rest[0] == '@' || rest[0] == '/'
}

// checkSandboxMode は sandbox 入力がサンドボックスを無効化していないか検査する。
// sandbox が未設定の場合、後継の permission-profile が使われるか、既定の
// workspace-write にフォールバックする。
func (r *AIActionUnsafeSandboxRule) checkSandboxMode(node *ast.Step, action *ast.ExecAction) {
	for _, key := range sandboxModeInputKeys {
		input, exists := action.Inputs[key]
		if !exists || input == nil || input.Value == nil {
			continue
		}

		val := strings.TrimSpace(strings.ToLower(input.Value.Value))
		for _, unsafeVal := range unsafeSandboxModes {
			if val == unsafeVal {
				r.Errorf(
					node.Pos,
					`action %q has %s set to %q which gives Codex unrestricted access to the runner. Use "workspace-write", "read-only", or permission-profile ":workspace" instead.`,
					action.Uses.Value,
					key,
					input.Value.Value,
				)
				return
			}
		}
	}
}

// checkPermissionProfile は permission-profile 入力が組み込みの無制限プロファイルを
// 選んでいないか検査する。codex-home/config.toml の名前付きプロファイルは
// ワークフローから解決できないため、組み込みの綴りだけを報告する。
func (r *AIActionUnsafeSandboxRule) checkPermissionProfile(node *ast.Step, action *ast.ExecAction) {
	for _, key := range permissionProfileInputKeys {
		input, exists := action.Inputs[key]
		if !exists || input == nil || input.Value == nil {
			continue
		}

		val := strings.TrimSpace(strings.ToLower(input.Value.Value))
		for _, unsafeVal := range unsafePermissionProfiles {
			if val == unsafeVal {
				r.Errorf(
					node.Pos,
					`action %q has %s set to %q which removes Codex's local sandbox restrictions. Only the built-in profile spelling can be checked: a named profile defined in codex-home/config.toml cannot be resolved from the workflow file. Use ":workspace" or ":read-only" instead.`,
					action.Uses.Value,
					key,
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
