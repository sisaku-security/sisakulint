package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/core/chain"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// aiPromptInputParams は AI エージェントのプロンプトに関連するパラメータ名一覧。
// これらのパラメータに untrusted な入力が直接補間されると、プロンプトインジェクション攻撃のリスクがある。
var aiPromptInputParams = []string{
	"prompt",
	"direct_prompt",
	"custom_instructions",
	"system_prompt",
}

// AIActionPromptInjectionRule は AI エージェントアクションのプロンプトパラメータに
// 信頼されていないユーザー入力が直接補間されるパターンを検出するルール。
//
// 脆弱なパターン:
//
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
//	      prompt: "Please triage this issue: ${{ github.event.issue.title }}"
//
// issues/issue_comment などのトリガーで github.event.issue.title や
// github.event.comment.body などの untrusted 入力をプロンプトに直接埋め込むと、
// 攻撃者が悪意のある指示をコンテンツに混入してエージェントを操作できてしまう
// (Clinejection 攻撃 / プロンプトインジェクション攻撃)。
//
// 安全なパターン:
//
//	env:
//	  ISSUE_TITLE: ${{ github.event.issue.title }}
//	steps:
//	  - uses: anthropics/claude-code-action@v1
//	    with:
//	      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
//	      prompt: "Please triage the issue. Title is in env var ISSUE_TITLE."
type AIActionPromptInjectionRule struct {
	BaseRule
	// collector is the per-file SinkCollector for leakage-path chain
	// visualization (nil-safe: nil disables pushing).
	collector *chain.SinkCollector
	// currentJobID is the lowercased ID of the job currently being visited,
	// set in VisitJobPre.
	currentJobID string
}

// NewAIActionPromptInjectionRule は新しいルールインスタンスを返す。
func NewAIActionPromptInjectionRule() *AIActionPromptInjectionRule {
	return &AIActionPromptInjectionRule{
		BaseRule: BaseRule{
			RuleName: "ai-action-prompt-injection",
			RuleDesc: "Untrusted user input is directly interpolated into AI agent prompt",
		},
	}
}

// NewAIActionPromptInjectionRuleWithCollector is like NewAIActionPromptInjectionRule but
// additionally pushes a chain.SinkRecord to collector for every detected finding, feeding
// the leakage-path chain visualization (`-format "{{mermaid .}}"`). collector may be nil,
// in which case no records are pushed (equivalent to NewAIActionPromptInjectionRule).
func NewAIActionPromptInjectionRuleWithCollector(collector *chain.SinkCollector) *AIActionPromptInjectionRule {
	r := NewAIActionPromptInjectionRule()
	r.collector = collector
	return r
}

// VisitJobPre tracks the lowercased ID of the job currently being visited, so
// VisitStep's collector push can attribute findings to the right job.
func (r *AIActionPromptInjectionRule) VisitJobPre(node *ast.Job) error {
	if node.ID != nil {
		r.currentJobID = strings.ToLower(node.ID.Value)
	}
	return nil
}

// VisitStep は各ステップを訪問し、AI エージェントアクションのプロンプトパラメータに
// 信頼されていない入力が補間されているかを検出する。
func (r *AIActionPromptInjectionRule) VisitStep(node *ast.Step) error {
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

	for _, paramName := range aiPromptInputParams {
		input, exists := action.Inputs[paramName]
		if !exists || input == nil || input.Value == nil {
			continue
		}

		untrustedPaths := r.findUntrustedExpressions(input.Value.Value)
		if len(untrustedPaths) == 0 {
			continue
		}

		r.Errorf(
			node.Pos,
			`action %q has untrusted input %s directly interpolated into %q parameter. This enables prompt injection attacks (Clinejection). Pass untrusted values through environment variables instead of embedding them in the prompt.`,
			action.Uses.Value,
			formatPathList(untrustedPaths),
			paramName,
		)

		if r.collector != nil {
			sourceName := strings.Join(untrustedPaths, ", ")
			r.collector.Add(chain.SinkRecord{
				JobID:        r.currentJobID,
				StepPos:      node.Pos,
				StepSummary:  "uses: " + action.Uses.Value,
				SourceKind:   chain.SourceUntrusted,
				SourceName:   sourceName,
				SourceOrigin: sourceName,
				SinkKind:     chain.SinkLog,
				RuleName:     r.RuleNames(),
				Severity:     "high",
			})
		}
	}

	return nil
}

// findUntrustedExpressions は文字列中の ${{ ... }} 式を抽出し、
// untrusted な入力が含まれる式のパス一覧を返す。
func (r *AIActionPromptInjectionRule) findUntrustedExpressions(promptValue string) []string {
	var untrustedPaths []string
	offset := 0

	for {
		idx := strings.Index(promptValue[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx
		remaining := promptValue[start+3:]
		_, endOffset, err := expressions.AnalyzeExpressionSyntax(remaining)
		if err != nil {
			offset = start + 3
			continue
		}

		exprContent := strings.TrimSpace(remaining[:endOffset-2])
		paths := r.checkUntrustedExpression(exprContent)
		untrustedPaths = append(untrustedPaths, paths...)

		offset = start + 3 + endOffset
	}

	return untrustedPaths
}

// checkUntrustedExpression は式の内容を ExprSemanticsChecker で解析し、
// untrusted な入力パスの一覧を返す。
func (r *AIActionPromptInjectionRule) checkUntrustedExpression(exprContent string) []string {
	// ExprSemanticsChecker が期待する形式に補完する
	exprStr := exprContent
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}

	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	node, parseErr := p.Parse(l)
	if parseErr != nil || node == nil {
		return nil
	}

	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(node)

	var paths []string
	for _, err := range errs {
		if err.IsUntrustedInput {
			paths = append(paths, err.UntrustedPaths...)
		}
	}

	return paths
}

// formatPathList は untrusted パスの一覧を読みやすい文字列に変換する。
func formatPathList(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = fmt.Sprintf("%q", p)
	}
	return strings.Join(quoted, ", ")
}
