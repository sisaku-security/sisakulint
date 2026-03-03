package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// dangerousAITools は AI エージェントが利用できる危険なツールのリスト。
// これらのツールはファイル書き込みやシェルコマンド実行を可能にするため、
// 信頼されていないトリガーと組み合わせると Clinejection 攻撃のリスクがある。
var dangerousAITools = []string{
	"Bash",
	"Write",
	"Edit",
	"NotebookEdit",
}

// aiExcessiveToolsUntrustedTriggers は信頼されていないユーザーからのトリガーイベント一覧。
// これらのイベントは任意の GitHub ユーザーが発生させることができる。
var aiExcessiveToolsUntrustedTriggers = map[string]bool{
	"issues":               true,
	"issue_comment":        true,
	"discussion":           true,
	"pull_request_target":  true,
	"workflow_run":         true,
}

// AIActionExcessiveToolsRule は信頼されていないトリガーで危険なツール (Bash/Write/Edit) を
// AI エージェントに付与しているパターンを検出するルール。
//
// 脆弱なパターン:
//
//	on:
//	  issues:
//	    types: [opened]
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      claude_args: --allowedTools "Bash,Read,Write,Edit"
//
// issues/issue_comment/discussion トリガーは任意の GitHub ユーザーが発生させることができる。
// そのような信頼されていないトリガーで Bash/Write/Edit などの危険なツールを許可すると、
// 攻撃者が悪意のある指示をコメントに埋め込んでエージェントを操作できてしまう (Clinejection 攻撃)。
//
// 安全なパターン:
//
//	on:
//	  issues:
//	    types: [opened]
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      claude_args: --allowedTools "Read,Glob,Grep"
type AIActionExcessiveToolsRule struct {
	BaseRule
	hasUntrustedTrigger bool
}

// NewAIActionExcessiveToolsRule は新しいルールインスタンスを返す。
func NewAIActionExcessiveToolsRule() *AIActionExcessiveToolsRule {
	return &AIActionExcessiveToolsRule{
		BaseRule: BaseRule{
			RuleName: "ai-action-excessive-tools",
			RuleDesc: "AI action grants dangerous tools (Bash/Write/Edit) in workflow triggered by untrusted users",
		},
	}
}

// VisitWorkflowPre はワークフローを訪問し、信頼されていないトリガーを収集する。
func (r *AIActionExcessiveToolsRule) VisitWorkflowPre(node *ast.Workflow) error {
	r.hasUntrustedTrigger = false

	for _, event := range node.On {
		webhookEvent, ok := event.(*ast.WebhookEvent)
		if !ok {
			continue
		}
		triggerName := webhookEvent.EventName()
		if aiExcessiveToolsUntrustedTriggers[triggerName] {
			r.hasUntrustedTrigger = true
			r.Debug("Detected untrusted trigger: %s", triggerName)
			break
		}
	}

	return nil
}

// VisitStep は各ステップを訪問し、信頼されていないトリガーで危険なツールを使用している
// AI エージェントアクションを検出する。
func (r *AIActionExcessiveToolsRule) VisitStep(node *ast.Step) error {
	if !r.hasUntrustedTrigger {
		return nil
	}

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

	claudeArgsInput, exists := action.Inputs["claude_args"]
	if !exists || claudeArgsInput == nil || claudeArgsInput.Value == nil {
		return nil
	}

	claudeArgs := claudeArgsInput.Value.Value
	foundTools := r.findDangerousTools(claudeArgs)
	if len(foundTools) == 0 {
		return nil
	}

	r.Errorf(
		node.Pos,
		`action %q grants dangerous tools [%s] via claude_args in a workflow triggered by untrusted events (issues, issue_comment, discussion, pull_request_target, workflow_run). This enables Clinejection attacks where malicious users can inject instructions. Use read-only tools (Read, Glob, Grep) instead.`,
		action.Uses.Value,
		strings.Join(foundTools, ", "),
	)

	return nil
}

// findDangerousTools は claude_args の値から危険なツール名を抽出して返す。
func (r *AIActionExcessiveToolsRule) findDangerousTools(claudeArgs string) []string {
	var found []string
	for _, tool := range dangerousAITools {
		// --allowedTools "Bash,Read,Write" のような形式でツール名が含まれているかを検索する。
		// 単語境界を模倣するため、カンマ・スペース・クォート・文字列末尾を区切り文字として扱う。
		if containsToolName(claudeArgs, tool) {
			found = append(found, tool)
		}
	}
	return found
}

// containsToolName はツール名が引数文字列に含まれているかを確認する。
// "BashExecutor" のような部分一致を避けるため、前後の区切り文字を確認する。
func containsToolName(args, toolName string) bool {
	idx := 0
	for {
		pos := strings.Index(args[idx:], toolName)
		if pos < 0 {
			return false
		}
		absPos := idx + pos

		// ツール名の前が区切り文字またはサブストリングの先頭であることを確認
		if absPos > 0 {
			prev := args[absPos-1]
			if !isToolSeparator(prev) {
				idx = absPos + 1
				continue
			}
		}

		// ツール名の後が区切り文字またはサブストリングの末尾であることを確認
		endPos := absPos + len(toolName)
		if endPos < len(args) {
			next := args[endPos]
			if !isToolSeparator(next) {
				idx = absPos + 1
				continue
			}
		}

		return true
	}
}

// isToolSeparator はツール名の区切り文字として使われる文字かどうかを判定する。
func isToolSeparator(c byte) bool {
	return c == ',' || c == '\t' || c == '"' || c == ' ' || c == '\n' || c == '\r' || c == '\''
}
