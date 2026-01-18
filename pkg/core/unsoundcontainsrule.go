package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// UnsoundContainsRule は不健全なcontains()関数の使用を検出するルールです。
// contains()関数の第1引数が文字列リテラルで、第2引数がユーザー制御可能な
// コンテキストの場合、攻撃者がブランチ名を操作することで条件をバイパスできる
// 可能性があります。
//
// 脆弱なパターン例:
//
//	if: contains('refs/heads/main refs/heads/develop', github.ref)
//
// 安全なパターン:
//
//	if: contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref)
type UnsoundContainsRule struct {
	BaseRule
	currentJob  *ast.Job
	currentStep *ast.Step
}

// NewUnsoundContainsRule は新しいUnsoundContainsRuleインスタンスを作成します。
func NewUnsoundContainsRule() *UnsoundContainsRule {
	return &UnsoundContainsRule{
		BaseRule: BaseRule{
			RuleName: "unsound-contains",
			RuleDesc: "Detects bypassable contains() function usage in conditions",
		},
	}
}

// userControllableContexts はユーザー制御可能なコンテキストのリストです。
var userControllableContexts = map[string]bool{
	"github.actor":             true,
	"github.base_ref":          true,
	"github.head_ref":          true,
	"github.ref":               true,
	"github.ref_name":          true,
	"github.sha":               true,
	"github.triggering_actor":  true,
	"github.event.sender.type": true,
}

// userControllableContextPrefixes はユーザー制御可能なコンテキストのプレフィックスです。
var userControllableContextPrefixes = []string{
	"env.",
	"inputs.",
	"github.event.",
}

func (rule *UnsoundContainsRule) VisitJobPre(n *ast.Job) error {
	rule.currentJob = n
	rule.checkCondition(n.If, "job", n, nil)
	return nil
}

func (rule *UnsoundContainsRule) VisitJobPost(_ *ast.Job) error {
	rule.currentJob = nil
	return nil
}

func (rule *UnsoundContainsRule) VisitStep(n *ast.Step) error {
	rule.currentStep = n
	rule.checkCondition(n.If, "step", nil, n)
	rule.currentStep = nil
	return nil
}

func (rule *UnsoundContainsRule) checkCondition(cond *ast.String, context string, job *ast.Job, step *ast.Step) {
	if cond == nil {
		return
	}

	var exprStr string
	if cond.ContainsExpression() {
		exprStr = extractExpressionContent(cond.Value)
	} else {
		exprStr = cond.Value
	}

	if exprStr == "" {
		return
	}

	p := expressions.NewMiniParser()
	src := exprStr + "}}"
	l := expressions.NewTokenizer(src)
	expr, err := p.Parse(l)
	if err != nil {
		return
	}

	rule.visitExprNode(expr, cond.Pos, context, job, step, cond)
}

func (rule *UnsoundContainsRule) visitExprNode(node expressions.ExprNode, pos *ast.Position, context string, job *ast.Job, step *ast.Step, condStr *ast.String) {
	expressions.VisitExprNode(node, func(n, _ expressions.ExprNode, entering bool) {
		if !entering {
			return
		}

		funcCall, ok := n.(*expressions.FuncCallNode)
		if !ok {
			return
		}

		if strings.ToLower(funcCall.Callee) != "contains" {
			return
		}

		if len(funcCall.Args) != 2 {
			return
		}

		_, isStringLiteral := funcCall.Args[0].(*expressions.StringNode)
		if !isStringLiteral {
			return
		}

		userControlledContext := rule.extractContextPath(funcCall.Args[1])
		if userControlledContext == "" {
			return
		}

		// Extract string literal from condition using regex (tokenizer has issues with StringNode.Value)
		stringLitValue := rule.extractStringLiteralFromCondition(condStr.Value, userControlledContext)
		if stringLitValue == "" {
			return
		}

		isHighSeverity := rule.isUserControllableContext(userControlledContext)

		var severity string
		if isHighSeverity {
			severity = "HIGH"
		} else {
			severity = "INFORMATIONAL"
		}

		rule.Errorf(
			pos,
			"[%s] Unsound use of contains() in %s condition. The first argument '%s' is a string literal and the second argument '%s' is user-controllable. An attacker could create a branch named '%s' to bypass this condition. Use fromJSON() with an array instead: contains(fromJSON('%s'), %s)",
			severity,
			context,
			stringLitValue,
			userControlledContext,
			stringLitValue,
			rule.convertToJSONArray(stringLitValue),
			userControlledContext,
		)

		if step != nil {
			fixer := &unsoundContainsStepFixer{
				step:        step,
				rule:        rule,
				stringLit:   stringLitValue,
				contextPath: userControlledContext,
			}
			rule.AddAutoFixer(NewStepFixer(step, fixer))
		} else if job != nil {
			fixer := &unsoundContainsJobFixer{
				job:         job,
				rule:        rule,
				stringLit:   stringLitValue,
				contextPath: userControlledContext,
			}
			rule.AddAutoFixer(NewJobFixer(job, fixer))
		}
	})
}

func (rule *UnsoundContainsRule) extractContextPath(node expressions.ExprNode) string {
	switch n := node.(type) {
	case *expressions.VariableNode:
		return n.Name
	case *expressions.ObjectDerefNode:
		receiver := rule.extractContextPath(n.Receiver)
		if receiver == "" {
			return ""
		}
		return receiver + "." + n.Property
	case *expressions.IndexAccessNode:
		operand := rule.extractContextPath(n.Operand)
		if operand == "" {
			return ""
		}
		if strNode, ok := n.Index.(*expressions.StringNode); ok {
			return operand + "." + strNode.Value
		}
		return operand + "[*]"
	default:
		return ""
	}
}

func (rule *UnsoundContainsRule) extractStringLiteralFromCondition(condValue, contextPath string) string {
	escapedContextPath := regexp.QuoteMeta(contextPath)

	patternSingle := fmt.Sprintf(`(?i)contains\s*\(\s*'([^']*)'\s*,\s*%s\s*\)`, escapedContextPath)
	re := regexp.MustCompile(patternSingle)
	matches := re.FindStringSubmatch(condValue)
	if len(matches) > 1 {
		return matches[1]
	}

	patternDouble := fmt.Sprintf(`(?i)contains\s*\(\s*"([^"]*)"\s*,\s*%s\s*\)`, escapedContextPath)
	re = regexp.MustCompile(patternDouble)
	matches = re.FindStringSubmatch(condValue)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func (rule *UnsoundContainsRule) isUserControllableContext(contextPath string) bool {
	if userControllableContexts[contextPath] {
		return true
	}

	for _, prefix := range userControllableContextPrefixes {
		if strings.HasPrefix(contextPath, prefix) {
			return true
		}
	}

	return false
}

func (rule *UnsoundContainsRule) convertToJSONArray(stringLiteral string) string {
	parts := regexp.MustCompile(`[,\s]+`).Split(stringLiteral, -1)

	var elements []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			elements = append(elements, fmt.Sprintf(`"%s"`, part))
		}
	}

	return "[" + strings.Join(elements, ", ") + "]"
}

func extractExpressionContent(value string) string {
	start := strings.Index(value, "${{")
	if start == -1 {
		return ""
	}
	end := strings.LastIndex(value, "}}")
	if end == -1 || end <= start {
		return ""
	}
	return strings.TrimSpace(value[start+3 : end])
}

type unsoundContainsStepFixer struct {
	step        *ast.Step
	rule        *UnsoundContainsRule
	stringLit   string
	contextPath string
}

func (f *unsoundContainsStepFixer) RuleNames() string {
	return f.rule.RuleName
}

func (f *unsoundContainsStepFixer) FixStep(_ *ast.Step) error {
	if f.step == nil || f.step.If == nil {
		return nil
	}
	newValue := f.replaceContainsPattern(f.step.If.Value)
	f.step.If.Value = newValue
	f.step.If.BaseNode.Value = newValue
	return nil
}

func (f *unsoundContainsStepFixer) replaceContainsPattern(value string) string {
	escapedStringLit := regexp.QuoteMeta(f.stringLit)
	escapedContextPath := regexp.QuoteMeta(f.contextPath)

	// Use (?i) flag for case-insensitive matching since GitHub Actions function names are case-insensitive
	patternSingle := fmt.Sprintf(`(?i)contains\s*\(\s*'%s'\s*,\s*%s\s*\)`, escapedStringLit, escapedContextPath)
	patternDouble := fmt.Sprintf(`(?i)contains\s*\(\s*"%s"\s*,\s*%s\s*\)`, escapedStringLit, escapedContextPath)

	newPattern := fmt.Sprintf("contains(fromJSON('%s'), %s)", f.rule.convertToJSONArray(f.stringLit), f.contextPath)

	re := regexp.MustCompile(patternSingle)
	result := re.ReplaceAllString(value, newPattern)
	if result != value {
		return result
	}

	re = regexp.MustCompile(patternDouble)
	return re.ReplaceAllString(value, newPattern)
}

type unsoundContainsJobFixer struct {
	job         *ast.Job
	rule        *UnsoundContainsRule
	stringLit   string
	contextPath string
}

func (f *unsoundContainsJobFixer) RuleNames() string {
	return f.rule.RuleName
}

func (f *unsoundContainsJobFixer) FixJob(_ *ast.Job) error {
	if f.job == nil || f.job.If == nil {
		return nil
	}
	newValue := f.replaceContainsPattern(f.job.If.Value)
	f.job.If.Value = newValue
	f.job.If.BaseNode.Value = newValue
	return nil
}

func (f *unsoundContainsJobFixer) replaceContainsPattern(value string) string {
	escapedStringLit := regexp.QuoteMeta(f.stringLit)
	escapedContextPath := regexp.QuoteMeta(f.contextPath)

	// Use (?i) flag for case-insensitive matching since GitHub Actions function names are case-insensitive
	patternSingle := fmt.Sprintf(`(?i)contains\s*\(\s*'%s'\s*,\s*%s\s*\)`, escapedStringLit, escapedContextPath)
	patternDouble := fmt.Sprintf(`(?i)contains\s*\(\s*"%s"\s*,\s*%s\s*\)`, escapedStringLit, escapedContextPath)

	newPattern := fmt.Sprintf("contains(fromJSON('%s'), %s)", f.rule.convertToJSONArray(f.stringLit), f.contextPath)

	re := regexp.MustCompile(patternSingle)
	result := re.ReplaceAllString(value, newPattern)
	if result != value {
		return result
	}

	re = regexp.MustCompile(patternDouble)
	return re.ReplaceAllString(value, newPattern)
}
