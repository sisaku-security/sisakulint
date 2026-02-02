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
	severityLevel      string
	checkPrivileged    bool
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
	"git":     true,
	"curl":    true,
	"wget":    true,
	"tar":     true,
	"zip":     true,
	"unzip":   true,
	"rsync":   true,
	"scp":     true,
	"ssh":     true,
	"npm":     true,
	"yarn":    true,
	"pip":     true,
	"python":  true,
	"python3": true,
	"node":    true,
	"ruby":    true,
	"perl":    true,
	"php":     true,
	"go":      true,
	"cargo":   true,
	"docker":  true,
	"kubectl": true,
	"helm":    true,
	"aws":     true,
	"az":      true,
	"gcloud":  true,
	"gh":      true,
	"jq":      true,
	"sed":     true,
	"awk":     true,
	"grep":    true,
	"find":    true,
	"xargs":   true,
	"env":     true,
	"bash":    true,
	"sh":      true,
	"zsh":     true,
	"pwsh":    true,
	"make":    true,
	"cmake":   true,
	"mvn":     true,
	"gradle":  true,
	"ant":     true,
}

var dangerousCmdNames []string

// commandsNotSupportingDoubleDash lists commands that don't support "--" as
// an end-of-options marker, or where "--" has different semantics.
// For these commands, we only use environment variable quoting without "--".
var commandsNotSupportingDoubleDash = map[string]bool{
	"docker":  true, // docker uses subcommands; -- applies to subcommand args
	"python":  true, // python -c ignores --
	"python3": true, // python3 -c ignores --
	"node":    true, // node does not support -- for ending options
	"ruby":    true, // ruby -e ignores --
	"php":     true, // php does not support --
}

// Expression syntax constants
const (
	exprPrefix = "${{ "
	exprSuffix = " }}"
)

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
	if !rule.shouldProcessJob() {
		return nil
	}

	for _, s := range node.Steps {
		rule.processStep(s)
	}
	return nil
}

// shouldProcessJob checks if this job should be processed based on trigger type.
func (rule *ArgumentInjectionRule) shouldProcessJob() bool {
	isPrivileged := rule.hasPrivilegedTriggers()
	return rule.checkPrivileged == isPrivileged
}

// processStep analyzes a single step for argument injection vulnerabilities.
func (rule *ArgumentInjectionRule) processStep(s *ast.Step) {
	run := rule.extractRunExec(s)
	if run == nil {
		return
	}

	exprs := rule.extractAndParseExpressions(run.Run)
	if len(exprs) == 0 {
		return
	}

	untrustedSet := rule.buildUntrustedSet(exprs, s.Env)
	if len(untrustedSet) == 0 {
		return
	}

	modifiedScript, exprToPlaceholder := rule.prepareScriptForParsing(run.Run.Value, exprs)
	parser := shell.NewShellParser(modifiedScript)

	stepUntrusted := rule.analyzeExpressions(exprs, untrustedSet, exprToPlaceholder, parser, run, s)

	if stepUntrusted != nil {
		rule.stepsWithUntrusted = append(rule.stepsWithUntrusted, stepUntrusted)
		rule.AddAutoFixer(NewStepFixer(s, rule))
	}
}

// extractRunExec extracts the ExecRun from a step if it's a run step.
func (rule *ArgumentInjectionRule) extractRunExec(s *ast.Step) *ast.ExecRun {
	if s.Exec == nil || s.Exec.Kind() != ast.ExecKindRun {
		return nil
	}
	run := s.Exec.(*ast.ExecRun)
	if run.Run == nil {
		return nil
	}
	return run
}

// buildUntrustedSet builds a map of untrusted expressions and their paths.
func (rule *ArgumentInjectionRule) buildUntrustedSet(exprs []parsedExpression, env *ast.Env) map[string][]string {
	untrustedSet := make(map[string][]string)
	for _, expr := range exprs {
		untrustedPaths := rule.checkUntrustedInput(expr)
		if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, env) {
			untrustedSet[expr.raw] = untrustedPaths
		}
	}
	return untrustedSet
}

// prepareScriptForParsing replaces expressions with placeholders for shell parsing.
func (rule *ArgumentInjectionRule) prepareScriptForParsing(script string, exprs []parsedExpression) (string, map[string]string) {
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

	return modifiedScript, exprToPlaceholder
}

// analyzeExpressions checks each expression for argument injection vulnerabilities.
func (rule *ArgumentInjectionRule) analyzeExpressions(
	exprs []parsedExpression,
	untrustedSet map[string][]string,
	exprToPlaceholder map[string]string,
	parser *shell.ShellParser,
	run *ast.ExecRun,
	s *ast.Step,
) *stepWithArgumentInjection {
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

			rule.reportArgumentInjection(linePos, untrustedPaths, varUsage.CommandName)
		}
	}

	return stepUntrusted
}

// reportArgumentInjection reports an argument injection vulnerability.
func (rule *ArgumentInjectionRule) reportArgumentInjection(pos *ast.Position, paths []string, cmdName string) {
	severity := "medium"
	suffix := ""
	if rule.checkPrivileged {
		severity = "critical"
		suffix = " in a workflow with privileged triggers"
	}

	rule.Errorf(
		pos,
		"argument injection (%s): \"%s\" is potentially untrusted and used as command-line argument to '%s'%s. Attackers can inject malicious options (e.g., --output=/etc/passwd). Use '--' to end option parsing or pass through environment variables. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
		severity,
		strings.Join(paths, "\", \""),
		cmdName,
		suffix,
	)
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
	stepInfo := rule.findStepInfo(step)
	if stepInfo == nil {
		return nil
	}

	rule.initStepEnv(step)

	run := step.Exec.(*ast.ExecRun)
	if run.Run == nil {
		return nil
	}

	envVarMap, envVarsForYAML := rule.buildEnvVarMaps(stepInfo, step)

	if err := rule.addEnvVarsToStep(step, envVarsForYAML); err != nil {
		return err
	}

	script := rule.replaceExpressionsWithEnvVars(run.Run.Value, stepInfo, envVarMap)
	run.Run.Value = script

	return rule.updateStepRunScript(step, script)
}

// findStepInfo finds the stepWithArgumentInjection for a given step.
func (rule *ArgumentInjectionRule) findStepInfo(step *ast.Step) *stepWithArgumentInjection {
	for _, s := range rule.stepsWithUntrusted {
		if s.step == step {
			return s
		}
	}
	return nil
}

// initStepEnv initializes the step's environment if needed.
func (rule *ArgumentInjectionRule) initStepEnv(step *ast.Step) {
	if step.Env == nil {
		step.Env = &ast.Env{
			Vars: make(map[string]*ast.EnvVar),
		}
	}
	if step.Env.Vars == nil {
		step.Env.Vars = make(map[string]*ast.EnvVar)
	}
}

// buildEnvVarMaps builds the environment variable maps for auto-fix.
func (rule *ArgumentInjectionRule) buildEnvVarMaps(
	stepInfo *stepWithArgumentInjection,
	step *ast.Step,
) (map[string]string, map[string]string) {
	envVarMap := make(map[string]string)
	envVarsForYAML := make(map[string]string)

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		expr := untrustedInfo.expr
		envVarName := rule.generateEnvVarName(untrustedInfo.paths[0])

		if _, exists := envVarMap[expr.raw]; exists {
			continue
		}

		envVarMap[expr.raw] = envVarName

		if _, exists := step.Env.Vars[strings.ToLower(envVarName)]; exists {
			continue
		}

		exprValue := exprPrefix + expr.raw + exprSuffix
		step.Env.Vars[strings.ToLower(envVarName)] = &ast.EnvVar{
			Name:  &ast.String{Value: envVarName, Pos: expr.pos},
			Value: &ast.String{Value: exprValue, Pos: expr.pos},
		}
		envVarsForYAML[envVarName] = exprValue
	}

	return envVarMap, envVarsForYAML
}

// addEnvVarsToStep adds environment variables to the step's YAML node.
func (rule *ArgumentInjectionRule) addEnvVarsToStep(step *ast.Step, envVarsForYAML map[string]string) error {
	if step.BaseNode == nil || len(envVarsForYAML) == 0 {
		return nil
	}
	if err := AddEnvVarsToStepNode(step.BaseNode, envVarsForYAML); err != nil {
		return fmt.Errorf("failed to add env vars to step node: %w", err)
	}
	return nil
}

// replaceExpressionsWithEnvVars replaces untrusted expressions with environment variables.
func (rule *ArgumentInjectionRule) replaceExpressionsWithEnvVars(
	script string,
	stepInfo *stepWithArgumentInjection,
	envVarMap map[string]string,
) string {
	for _, untrustedInfo := range stepInfo.untrustedExprs {
		envVarName := envVarMap[untrustedInfo.expr.raw]
		exprPattern1 := exprPrefix + untrustedInfo.expr.raw + exprSuffix
		exprPattern2 := fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)

		newValue := rule.buildReplacementValue(envVarName, untrustedInfo.commandName)
		script = strings.ReplaceAll(script, exprPattern1, newValue)
		script = strings.ReplaceAll(script, exprPattern2, newValue)
	}
	return script
}

// buildReplacementValue builds the replacement value for an expression.
func (rule *ArgumentInjectionRule) buildReplacementValue(envVarName, commandName string) string {
	if commandsNotSupportingDoubleDash[commandName] {
		return fmt.Sprintf("\"$%s\"", envVarName)
	}
	return fmt.Sprintf("-- \"$%s\"", envVarName)
}

// updateStepRunScript updates the step's run script in the YAML node.
func (rule *ArgumentInjectionRule) updateStepRunScript(step *ast.Step, script string) error {
	if step.BaseNode == nil {
		return nil
	}
	if err := setRunScriptValue(step.BaseNode, script); err != nil {
		return fmt.Errorf("failed to update run script: %w", err)
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
