package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"mvdan.cc/sh/v3/syntax"
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
	if claudeArgsPassFlag(claudeArgs, dangerouslySkipPermissionsFlag) {
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
	if claudeArgsPassFlag(claudeArgs, camelCaseDangerouslySkipPermissions) {
		r.Errorf(
			node.Pos,
			`action %q passes %s in claude_args. Claude Code rejects that spelling as an unknown option, so it does not bypass the permission checks; the flag that does is %s. Remove it and grant only the tools the workflow needs instead (for example --allowedTools "Read,Glob,Grep").`,
			action.Uses.Value,
			camelCaseDangerouslySkipPermissions,
			dangerouslySkipPermissionsFlag,
		)
	}
}

// claudeArgsPassFlag reports whether a claude_args value hands the given flag to Claude Code.
//
// A substring search is not enough: the action parses its arguments before the CLI sees
// them, so "--dangerously-skip-permis”sions" and "--dangerously-skip-permis\sions" both
// arrive as the real flag while a literal search finds neither. The value is therefore
// split into the words the parser would produce and each word is compared as a whole.
// When the value cannot be split - an unterminated quote, or a word containing an expansion
// whose value is only known at run time - the literal search is kept as the fallback, so a
// form this function cannot read is reported rather than silently missed.
func claudeArgsPassFlag(raw, flag string) bool {
	words, ok := splitClaudeArgs(raw)
	if !ok {
		return strings.Contains(raw, flag)
	}
	for _, word := range words {
		if word == flag || strings.HasPrefix(word, flag+"=") {
			return true
		}
	}
	return false
}

// splitClaudeArgs returns the words an argument parser would see, with quotes removed.
// The bool is false when the value cannot be read statically; callers must then fall back
// to a conservative check rather than treat "no match" as "no flag".
func splitClaudeArgs(raw string) ([]string, bool) {
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader("claude "+raw), "")
	if err != nil || len(file.Stmts) != 1 {
		return nil, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil, false
	}
	words := make([]string, 0, len(call.Args)-1)
	for _, arg := range call.Args[1:] {
		text, literal := literalArg(arg)
		if !literal {
			return nil, false
		}
		words = append(words, text)
	}
	return words, true
}

// literalArg returns the text of a word when none of its parts need run-time expansion.
func literalArg(word *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(unescapeOutsideQuotes(p.Value))
		case *syntax.SglQuoted:
			// Nothing is special inside single quotes, including the backslash.
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(unescapeInsideQuotes(lit.Value))
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// unescapeOutsideQuotes removes the escapes a shell removes in unquoted text, so that
// "permis\sions" is read as "permissions" - which is how the flag reaches the CLI even
// though the literal search cannot see it.
func unescapeOutsideQuotes(text string) string {
	var b strings.Builder
	var escaped bool
	for _, r := range text {
		if escaped {
			escaped = false
			if r == '\n' {
				continue
			}
			b.WriteRune(r)
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteRune('\\')
	}
	return b.String()
}

// unescapeInsideQuotes removes only the escapes a shell removes inside double quotes;
// every other backslash is a literal character there.
func unescapeInsideQuotes(text string) string {
	var b strings.Builder
	var escaped bool
	for _, r := range text {
		if escaped {
			escaped = false
			if strings.ContainsRune("$`\"\\\n", r) {
				if r != '\n' {
					b.WriteRune(r)
				}
				continue
			}
			b.WriteRune('\\')
			b.WriteRune(r)
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteRune('\\')
	}
	return b.String()
}
