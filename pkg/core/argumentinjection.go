package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"github.com/sisaku-security/sisakulint/pkg/shell"
)

type ArgumentInjectionRule struct {
	BaseRule
	severityLevel   string
	checkPrivileged bool
	stepsWithUntrusted []*stepWithArgumentInjection
	workflow           *ast.Workflow
}

type stepWithArgumentInjection struct {
	step           *ast.Step
	untrustedExprs []argumentInjectionInfo
}

type argumentInjectionInfo struct {
	expr        parsedExpression
	paths       []string
	commandName string
}

var dangerousCommands = map[string]bool{
	"git":      true,
	"curl":     true,
	"wget":     true,
	"tar":      true,
	"zip":      true,
	"unzip":    true,
	"rsync":    true,
	"scp":      true,
	"ssh":      true,
	"npm":      true,
	"yarn":     true,
	"pip":      true,
	"python":   true,
	"python3":  true,
	"node":     true,
	"ruby":     true,
	"perl":     true,
	"php":      true,
	"go":       true,
	"cargo":    true,
	"docker":   true,
	"kubectl":  true,
	"helm":     true,
	"aws":      true,
	"az":       true,
	"gcloud":   true,
	"gh":       true,
	"jq":       true,
	"sed":      true,
	"awk":      true,
	"grep":     true,
	"find":     true,
	"xargs":    true,
	"env":      true,
	"bash":     true,
	"sh":       true,
	"zsh":      true,
	"pwsh":     true,
	"make":     true,
	"cmake":    true,
	"mvn":      true,
	"gradle":   true,
	"ant":      true,
}

var dangerousCmdNames []string

var commandsNotSupportingDoubleDash = map[string]bool{
	"docker":  true,
	"python":  true,
	"python3": true,
}

func init() {
	dangerousCmdNames = make([]string, 0, len(dangerousCommands))
	for cmd := range dangerousCommands {
		dangerousCmdNames = append(dangerousCmdNames, cmd)
	}
}

func newArgumentInjectionRule(severityLevel string, checkPrivileged bool) *ArgumentInjectionRule {
	var desc string

	if checkPrivileged {
		desc = "Checks for argument injection vulnerabilities when untrusted input is used as command-line arguments in privileged workflow triggers (pull_request_target, workflow_run, issue_comment). Attackers can inject malicious options like --output=/etc/passwd or --config=malicious.conf. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
	} else {
		desc = "Checks for argument injection vulnerabilities when untrusted input is used as command-line arguments in normal workflow triggers (pull_request, push, etc.). Attackers can inject malicious options like --output=/etc/passwd or --config=malicious.conf. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
	}

	return &ArgumentInjectionRule{
		BaseRule: BaseRule{
			RuleName: "argument-injection-" + severityLevel,
			RuleDesc: desc,
		},
		severityLevel:      severityLevel,
		checkPrivileged:    checkPrivileged,
		stepsWithUntrusted: make([]*stepWithArgumentInjection, 0),
	}
}

func (rule *ArgumentInjectionRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	return nil
}

func (rule *ArgumentInjectionRule) VisitJobPre(node *ast.Job) error {
	isPrivileged := rule.hasPrivilegedTriggers()
	if rule.checkPrivileged != isPrivileged {
		return nil
	}

	for _, s := range node.Steps {
		if s.Exec == nil || s.Exec.Kind() != ast.ExecKindRun {
			continue
		}

		run := s.Exec.(*ast.ExecRun)
		if run.Run == nil {
			continue
		}

		script := run.Run.Value
		exprs := rule.extractAndParseExpressions(run.Run)
		if len(exprs) == 0 {
			continue
		}

		untrustedSet := make(map[string][]string)
		for _, expr := range exprs {
			untrustedPaths := rule.checkUntrustedInput(expr)
			if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, s.Env) {
				untrustedSet[expr.raw] = untrustedPaths
			}
		}

		if len(untrustedSet) == 0 {
			continue
		}

		// Replace expressions with placeholders to make script parseable
		modifiedScript := script
		exprToPlaceholder := make(map[string]string)

		for i, expr := range exprs {
			exprPattern1 := fmt.Sprintf("${{ %s }}", expr.raw)
			exprPattern2 := fmt.Sprintf("${{%s}}", expr.raw)
			placeholderName := fmt.Sprintf("__SISAKULINT_ARGEXPR_%d__", i)

			modifiedScript = strings.ReplaceAll(modifiedScript, exprPattern1, "$"+placeholderName)
			modifiedScript = strings.ReplaceAll(modifiedScript, exprPattern2, "$"+placeholderName)

			exprToPlaceholder[expr.raw] = placeholderName
		}

		parser := shell.NewShellParser(modifiedScript)
		var stepUntrusted *stepWithArgumentInjection

		for i := range exprs {
			expr := &exprs[i]

			untrustedPaths, isUntrusted := untrustedSet[expr.raw]
			if !isUntrusted {
				continue
			}

			placeholderName := exprToPlaceholder[expr.raw]
			varUsages := parser.FindVarUsageAsCommandArg(placeholderName, dangerousCmdNames)

			for _, varUsage := range varUsages {
				if varUsage.IsAfterDoubleDash {
					continue
				}

				if stepUntrusted == nil {
					stepUntrusted = &stepWithArgumentInjection{step: s}
				}

				linePos := expr.pos
				if linePos == nil {
					linePos = run.Run.Pos
				}

				stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, argumentInjectionInfo{
					expr:        *expr,
					paths:       untrustedPaths,
					commandName: varUsage.CommandName,
				})

				if rule.checkPrivileged {
					rule.Errorf(
						linePos,
						"argument injection (critical): \"%s\" is potentially untrusted and used as command-line argument to '%s' in a workflow with privileged triggers. Attackers can inject malicious options (e.g., --output=/etc/passwd). Use '--' to end option parsing or pass through environment variables. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
						strings.Join(untrustedPaths, "\", \""),
						varUsage.CommandName,
					)
				} else {
					rule.Errorf(
						linePos,
						"argument injection (medium): \"%s\" is potentially untrusted and used as command-line argument to '%s'. Attackers can inject malicious options (e.g., --output=/etc/passwd). Use '--' to end option parsing or pass through environment variables. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
						strings.Join(untrustedPaths, "\", \""),
						varUsage.CommandName,
					)
				}
			}
		}

		if stepUntrusted != nil {
			rule.stepsWithUntrusted = append(rule.stepsWithUntrusted, stepUntrusted)
			rule.AddAutoFixer(NewStepFixer(s, rule))
		}
	}
	return nil
}

func (rule *ArgumentInjectionRule) hasPrivilegedTriggers() bool {
	if rule.workflow == nil || rule.workflow.On == nil {
		return false
	}

	privilegedTriggers := map[string]bool{
		"pull_request_target": true,
		"workflow_run":        true,
		"issue_comment":       true,
		"issues":              true,
		"discussion_comment":  true,
	}

	for _, event := range rule.workflow.On {
		eventName := strings.ToLower(event.EventName())
		if privilegedTriggers[eventName] {
			return true
		}
	}

	return false
}

func (rule *ArgumentInjectionRule) RuleNames() string {
	return rule.RuleName
}

func (rule *ArgumentInjectionRule) FixStep(step *ast.Step) error {
	var stepInfo *stepWithArgumentInjection
	for _, s := range rule.stepsWithUntrusted {
		if s.step == step {
			stepInfo = s
			break
		}
	}

	if stepInfo == nil {
		return nil
	}

	if step.Env == nil {
		step.Env = &ast.Env{
			Vars: make(map[string]*ast.EnvVar),
		}
	}
	if step.Env.Vars == nil {
		step.Env.Vars = make(map[string]*ast.EnvVar)
	}

	run := step.Exec.(*ast.ExecRun)
	if run.Run == nil {
		return nil
	}

	envVarMap := make(map[string]string)
	envVarsForYAML := make(map[string]string)

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		expr := untrustedInfo.expr
		envVarName := rule.generateEnvVarName(untrustedInfo.paths[0])

		if _, exists := envVarMap[expr.raw]; !exists {
			envVarMap[expr.raw] = envVarName

			if _, exists := step.Env.Vars[strings.ToLower(envVarName)]; !exists {
				step.Env.Vars[strings.ToLower(envVarName)] = &ast.EnvVar{
					Name: &ast.String{
						Value: envVarName,
						Pos:   expr.pos,
					},
					Value: &ast.String{
						Value: fmt.Sprintf("${{ %s }}", expr.raw),
						Pos:   expr.pos,
					},
				}
				envVarsForYAML[envVarName] = fmt.Sprintf("${{ %s }}", expr.raw)
			}
		}
	}

	if step.BaseNode != nil && len(envVarsForYAML) > 0 {
		if err := AddEnvVarsToStepNode(step.BaseNode, envVarsForYAML); err != nil {
			return fmt.Errorf("failed to add env vars to step node: %w", err)
		}
	}

	script := run.Run.Value
	for _, untrustedInfo := range stepInfo.untrustedExprs {
		envVarName := envVarMap[untrustedInfo.expr.raw]
		exprPattern1 := fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)
		exprPattern2 := fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)

		var newValue string
		if commandsNotSupportingDoubleDash[untrustedInfo.commandName] {
			newValue = fmt.Sprintf("\"$%s\"", envVarName)
		} else {
			newValue = fmt.Sprintf("-- \"$%s\"", envVarName)
		}
		script = strings.ReplaceAll(script, exprPattern1, newValue)
		script = strings.ReplaceAll(script, exprPattern2, newValue)
	}

	run.Run.Value = script

	if step.BaseNode != nil {
		if err := setRunScriptValue(step.BaseNode, script); err != nil {
			return fmt.Errorf("failed to update run script: %w", err)
		}
	}

	return nil
}

func (rule *ArgumentInjectionRule) generateEnvVarName(path string) string {
	if path == "" {
		return "UNTRUSTED_INPUT"
	}

	parts := strings.Split(path, ".")

	if len(parts) >= 4 && parts[0] == "github" && parts[1] == "event" {
		category := parts[2]
		field := parts[len(parts)-1]

		categoryUpper := strings.ToUpper(strings.ReplaceAll(category, "_", ""))
		fieldUpper := strings.ToUpper(field)

		if categoryUpper == "PULLREQUEST" {
			categoryUpper = "PR"
		}

		return fmt.Sprintf("%s_%s", categoryUpper, fieldUpper)
	}

	if len(parts) >= 2 && parts[0] == "github" && parts[1] == "head_ref" {
		return "HEAD_REF"
	}

	lastPart := parts[len(parts)-1]
	return strings.ToUpper(lastPart)
}

func (rule *ArgumentInjectionRule) extractAndParseExpressions(str *ast.String) []parsedExpression {
	if str == nil {
		return nil
	}

	value := str.Value
	var result []parsedExpression
	offset := 0

	for {
		idx := strings.Index(value[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx
		remaining := value[start+3:]
		_, endOffset, err := expressions.AnalyzeExpressionSyntax(remaining)
		if err != nil {
			offset = start + 3
			continue
		}

		exprContent := strings.TrimSpace(remaining[:endOffset-2])

		expr, parseErr := rule.parseExpression(exprContent)
		if parseErr == nil && expr != nil {
			lineIdx := strings.Count(value[:start], "\n")
			col := start
			if lastNewline := strings.LastIndex(value[:start], "\n"); lastNewline != -1 {
				col = start - lastNewline - 1
			}

			pos := &ast.Position{
				Line: str.Pos.Line + lineIdx,
				Col:  str.Pos.Col + col,
			}
			if str.Literal {
				pos.Line += 1
			}

			result = append(result, parsedExpression{
				raw:  exprContent,
				node: expr,
				pos:  pos,
			})
		}

		// Move past this expression
		offset = start + 3 + endOffset
	}

	return result
}

func (rule *ArgumentInjectionRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

func (rule *ArgumentInjectionRule) checkUntrustedInput(expr parsedExpression) []string {
	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(expr.node)

	var paths []string
	for _, err := range errs {
		msg := err.Message
		if strings.Contains(msg, "potentially untrusted") {
			// Extract all quoted paths from the error message
			// Handles both single path: "path" is potentially untrusted
			// And multiple paths: Object filter extracts potentially untrusted properties "path1", "path2"
			paths = append(paths, extractQuotedStrings(msg)...)
		}
	}

	return paths
}

func extractQuotedStrings(msg string) []string {
	var result []string
	remaining := msg

	for {
		startIdx := strings.Index(remaining, "\"")
		if startIdx == -1 {
			break
		}

		endIdx := strings.Index(remaining[startIdx+1:], "\"")
		if endIdx == -1 {
			break
		}

		quoted := remaining[startIdx+1 : startIdx+1+endIdx]
		// Filter out non-path strings (e.g., URLs, descriptive text)
		if isLikelyUntrustedPath(quoted) {
			result = append(result, quoted)
		}

		remaining = remaining[startIdx+1+endIdx+1:]
	}

	return result
}

func isLikelyUntrustedPath(s string) bool {
	if strings.HasPrefix(s, "github.") {
		return true
	}
	// Also check for paths that might be formatted differently
	if strings.Contains(s, ".") && !strings.Contains(s, " ") && !strings.HasPrefix(s, "http") {
		return true
	}
	return false
}

func (rule *ArgumentInjectionRule) isDefinedInEnv(expr parsedExpression, env *ast.Env) bool {
	if env == nil {
		return false
	}

	normalizedExpr := normalizeExpression(expr.raw)

	if env.Vars != nil {
		for _, envVar := range env.Vars {
			if envVar.Value != nil && envVar.Value.ContainsExpression() {
				envExprs := extractExpressionsFromString(envVar.Value.Value)
				for _, envExpr := range envExprs {
					if normalizeExpression(envExpr) == normalizedExpr {
						return true
					}
				}
			}
		}
	}

	if env.Expression != nil && env.Expression.ContainsExpression() {
		envExprs := extractExpressionsFromString(env.Expression.Value)
		for _, envExpr := range envExprs {
			if normalizeExpression(envExpr) == normalizedExpr {
				return true
			}
		}
	}

	return false
}
