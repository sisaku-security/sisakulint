package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"github.com/sisaku-security/sisakulint/pkg/shell"
)

// ArgumentInjectionRule is a shared implementation for detecting argument injection vulnerabilities
// It detects when untrusted input is used as command-line arguments without proper sanitization
// It can be configured to check either privileged triggers (critical) or normal triggers (medium)
type ArgumentInjectionRule struct {
	BaseRule
	severityLevel      string // "critical" or "medium"
	checkPrivileged    bool   // true = check privileged triggers, false = check normal triggers
	stepsWithUntrusted []*stepWithArgumentInjection
	workflow           *ast.Workflow
}

// stepWithArgumentInjection tracks steps that need auto-fixing for argument injection
type stepWithArgumentInjection struct {
	step           *ast.Step
	untrustedExprs []argumentInjectionInfo
}

// argumentInjectionInfo contains information about an untrusted expression used as command argument
type argumentInjectionInfo struct {
	expr        parsedExpression
	paths       []string
	commandName string // The command that has the vulnerability (git, curl, etc.)
	fullLine    string // The full command line containing the vulnerability
}

// Dangerous commands that are susceptible to argument injection attacks
// These commands have options that can be exploited (e.g., --output, --config, etc.)
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

// Pattern to detect command execution with untrusted input as argument
// Matches patterns like: git diff ${{ ... }}, curl -o ${{ ... }}, etc.
var commandArgumentPattern = regexp.MustCompile(`(?m)^\s*(?:(?:sudo|nohup|time|nice|strace|timeout)\s+)*([a-zA-Z0-9_-]+)`)

// newArgumentInjectionRule creates a new argument injection rule with the specified severity level
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

// VisitWorkflowPre is called before visiting a workflow
func (rule *ArgumentInjectionRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	return nil
}

func (rule *ArgumentInjectionRule) VisitJobPre(node *ast.Job) error {
	// Check if workflow trigger matches what we're looking for
	isPrivileged := rule.hasPrivilegedTriggers()

	// Skip if trigger type doesn't match our severity level
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

		// Parse expressions from the script
		exprs := rule.extractAndParseExpressions(run.Run)
		if len(exprs) == 0 {
			continue
		}

		var stepUntrusted *stepWithArgumentInjection

		// Parse the script with ShellParser for accurate command boundary detection
		parser := shell.NewShellParser(script)

		// Get all dangerous command names
		dangerousCmdNames := make([]string, 0)
		for cmd := range dangerousCommands {
			dangerousCmdNames = append(dangerousCmdNames, cmd)
		}

		// Check each expression
		for _, expr := range exprs {
			untrustedPaths := rule.checkUntrustedInput(expr)
			if len(untrustedPaths) == 0 {
				continue
			}

			// Skip if expression is already passed via environment variable
			if rule.isDefinedInEnv(expr, s.Env) {
				continue
			}

			// Use ShellParser to find variable usages as command arguments
			// First, we need to replace expressions with environment variables to use them with ShellParser
			envVarName := rule.generateEnvVarName(untrustedPaths[0])

			// Find usages of this variable as command arguments
			varUsages := parser.FindVarUsageAsCommandArg(envVarName, dangerousCmdNames)

			// Also handle direct ${{ expr }} usage by checking if it appears after a command
			exprPattern1 := fmt.Sprintf("${{ %s }}", expr.raw)
			exprPattern2 := fmt.Sprintf("${{%s}}", expr.raw)

			lines := strings.Split(script, "\n")
			for lineIdx, line := range lines {
				// Check if expression is in this line
				if !strings.Contains(line, exprPattern1) && !strings.Contains(line, exprPattern2) {
					continue
				}

				// Skip empty lines and comments
				trimmedLine := strings.TrimSpace(line)
				if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
					continue
				}

				// Extract command name
				commandName := rule.extractCommandName(trimmedLine)
				if commandName == "" {
					continue
				}

				// Check if expression is used as command argument
				if !rule.isUsedAsArgument(line, expr.raw) {
					continue
				}

				// Check if `--` is used before the untrusted input (safe pattern)
				if rule.hasEndOfOptionsMarker(line, expr.raw) {
					continue
				}

				if stepUntrusted == nil {
					stepUntrusted = &stepWithArgumentInjection{step: s}
				}

				stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, argumentInjectionInfo{
					expr:        expr,
					paths:       untrustedPaths,
					commandName: commandName,
					fullLine:    trimmedLine,
				})

				// Calculate the actual line position
				linePos := &ast.Position{
					Line: run.Run.Pos.Line + lineIdx,
					Col:  run.Run.Pos.Col,
				}
				if run.Run.Literal {
					linePos.Line += 1
				}

				if rule.checkPrivileged {
					rule.Errorf(
						linePos,
						"argument injection (critical): \"%s\" is potentially untrusted and used as command-line argument to '%s' in a workflow with privileged triggers. Attackers can inject malicious options (e.g., --output=/etc/passwd). Use '--' to end option parsing or pass through environment variables. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
						strings.Join(untrustedPaths, "\", \""),
						commandName,
					)
				} else {
					rule.Errorf(
						linePos,
						"argument injection (medium): \"%s\" is potentially untrusted and used as command-line argument to '%s'. Attackers can inject malicious options (e.g., --output=/etc/passwd). Use '--' to end option parsing or pass through environment variables. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
						strings.Join(untrustedPaths, "\", \""),
						commandName,
					)
				}
			}

			// Also process variable usages found by ShellParser (if the variable was already in env)
			for _, varUsage := range varUsages {
				if varUsage.IsAfterDoubleDash {
					// Variable is after --, which is safe
					continue
				}

				if stepUntrusted == nil {
					stepUntrusted = &stepWithArgumentInjection{step: s}
				}

				// Find the line containing this usage
				lineIdx := strings.Count(script[:varUsage.StartPos], "\n")
				linePos := &ast.Position{
					Line: run.Run.Pos.Line + lineIdx,
					Col:  run.Run.Pos.Col,
				}
				if run.Run.Literal {
					linePos.Line += 1
				}

				stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, argumentInjectionInfo{
					expr:        expr,
					paths:       untrustedPaths,
					commandName: varUsage.CommandName,
					fullLine:    varUsage.Context,
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

// extractCommandName extracts the command name from a command line
func (rule *ArgumentInjectionRule) extractCommandName(line string) string {
	matches := commandArgumentPattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return ""
	}

	commandName := matches[1]

	// Only flag dangerous commands
	if dangerousCommands[commandName] {
		return commandName
	}

	return ""
}

// isUsedAsArgument checks if the expression is used as a command-line argument
func (rule *ArgumentInjectionRule) isUsedAsArgument(line, exprRaw string) bool {
	// Find the position of the expression in the line
	exprPattern1 := fmt.Sprintf("${{ %s }}", exprRaw)
	exprPattern2 := fmt.Sprintf("${{%s}}", exprRaw)

	exprPos := strings.Index(line, exprPattern1)
	if exprPos == -1 {
		exprPos = strings.Index(line, exprPattern2)
	}
	if exprPos == -1 {
		return false
	}

	// Find the command name position
	matches := commandArgumentPattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return false
	}

	commandName := matches[1]
	commandPos := strings.Index(line, commandName)
	if commandPos == -1 {
		return false
	}

	// The expression should appear after the command name
	if exprPos <= commandPos+len(commandName) {
		return false
	}

	return true
}

// hasEndOfOptionsMarker checks if `--` is used before the untrusted input
func (rule *ArgumentInjectionRule) hasEndOfOptionsMarker(line, exprRaw string) bool {
	exprPattern1 := fmt.Sprintf("${{ %s }}", exprRaw)
	exprPattern2 := fmt.Sprintf("${{%s}}", exprRaw)

	exprPos := strings.Index(line, exprPattern1)
	if exprPos == -1 {
		exprPos = strings.Index(line, exprPattern2)
	}
	if exprPos == -1 {
		return false
	}

	// Look for `--` followed by space before the expression
	beforeExpr := line[:exprPos]

	// Check if there's a standalone `--` (end of options marker)
	// This should not match things like `--option` or `---`
	endOfOptionsMatch := regexp.MustCompile(`\s--\s`)
	return endOfOptionsMatch.MatchString(beforeExpr + " ") // Add space to match `-- ${{ expr }}`
}

// hasPrivilegedTriggers checks if the workflow has privileged triggers
func (rule *ArgumentInjectionRule) hasPrivilegedTriggers() bool {
	if rule.workflow == nil || rule.workflow.On == nil {
		return false
	}

	// Check for privileged triggers
	// These triggers have write access or run with secrets
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

// RuleNames implements StepFixer interface
func (rule *ArgumentInjectionRule) RuleNames() string {
	return rule.RuleName
}

// FixStep implements StepFixer interface
func (rule *ArgumentInjectionRule) FixStep(step *ast.Step) error {
	// Find the stepWithArgumentInjection for this step
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

	// Ensure env exists in AST
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

	// Group expressions by their raw content to avoid duplicates
	envVarMap := make(map[string]string)      // expr.raw -> env var name
	envVarsForYAML := make(map[string]string) // env var name -> env var value

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		expr := untrustedInfo.expr

		// Generate environment variable name from the untrusted path
		envVarName := rule.generateEnvVarName(untrustedInfo.paths[0])

		// Check if we already created an env var for this expression
		if _, exists := envVarMap[expr.raw]; !exists {
			envVarMap[expr.raw] = envVarName

			// Add to env if not already present
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
				// Also track for BaseNode update
				envVarsForYAML[envVarName] = fmt.Sprintf("${{ %s }}", expr.raw)
			}
		}
	}

	// Update BaseNode with env vars
	if step.BaseNode != nil && len(envVarsForYAML) > 0 {
		if err := AddEnvVarsToStepNode(step.BaseNode, envVarsForYAML); err != nil {
			return fmt.Errorf("failed to add env vars to step node: %w", err)
		}
	}

	// Build replacement map for the run script
	// Replace ${{ expr }} or bare $ENV_VAR with -- "$ENV_VAR" (with end-of-options marker)
	script := run.Run.Value
	lines := strings.Split(script, "\n")

	for i, line := range lines {
		// Process each untrusted expression in this line
		for _, untrustedInfo := range stepInfo.untrustedExprs {
			envVarName := envVarMap[untrustedInfo.expr.raw]
			exprPattern1 := fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)
			exprPattern2 := fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)

			// Pattern for bare environment variable (already replaced by code-injection rule)
			bareEnvPattern := fmt.Sprintf("$%s", envVarName)

			if strings.Contains(line, exprPattern1) || strings.Contains(line, exprPattern2) {
				// Replace the expression with the safe pattern
				// Use -- before the argument if the command supports it
				newValue := fmt.Sprintf("\"$%s\"", envVarName)

				// Insert -- before the untrusted input if not already present
				if !rule.hasEndOfOptionsMarkerForExpr(line, exprPattern1, exprPattern2) {
					newValue = "-- " + newValue
				}

				line = strings.ReplaceAll(line, exprPattern1, newValue)
				line = strings.ReplaceAll(line, exprPattern2, newValue)
			} else if strings.Contains(line, bareEnvPattern) {
				// The expression was already replaced by code-injection rule
				// We need to add -- marker and quotes
				// Check if it's already properly quoted and has -- marker
				quotedPattern := fmt.Sprintf("\"$%s\"", envVarName)
				safePattern := fmt.Sprintf("-- \"$%s\"", envVarName)

				if strings.Contains(line, safePattern) {
					// Already safe, skip
					continue
				}

				if strings.Contains(line, quotedPattern) {
					// Has quotes but no -- marker
					if !rule.hasEndOfOptionsMarkerForEnvVar(line, envVarName) {
						line = strings.ReplaceAll(line, quotedPattern, safePattern)
					}
				} else {
					// Bare $ENV_VAR without quotes
					// Need to add both -- and quotes
					// But be careful not to match $ENV_VAR inside other strings
					// Use word boundary matching
					newValue := fmt.Sprintf("-- \"$%s\"", envVarName)

					if rule.hasEndOfOptionsMarkerForEnvVar(line, envVarName) {
						// Has -- marker, just add quotes
						newValue = fmt.Sprintf("\"$%s\"", envVarName)
					}

					// Replace bare $ENV_VAR with -- "$ENV_VAR"
					// Be careful with word boundaries
					line = rule.replaceBareEnvVar(line, envVarName, newValue)
				}
			}
		}
		lines[i] = line
	}

	newScript := strings.Join(lines, "\n")

	// Update AST
	run.Run.Value = newScript

	// Update BaseNode
	if step.BaseNode != nil {
		if err := setRunScriptValue(step.BaseNode, newScript); err != nil {
			return fmt.Errorf("failed to update run script: %w", err)
		}
	}

	return nil
}

// hasEndOfOptionsMarkerForExpr checks if `--` is used before the expression pattern
func (rule *ArgumentInjectionRule) hasEndOfOptionsMarkerForExpr(line, exprPattern1, exprPattern2 string) bool {
	exprPos := strings.Index(line, exprPattern1)
	if exprPos == -1 {
		exprPos = strings.Index(line, exprPattern2)
	}
	if exprPos == -1 {
		return false
	}

	beforeExpr := line[:exprPos]
	endOfOptionsMatch := regexp.MustCompile(`\s--\s`)
	return endOfOptionsMatch.MatchString(beforeExpr + " ")
}

// hasEndOfOptionsMarkerForEnvVar checks if `--` is used before the environment variable
func (rule *ArgumentInjectionRule) hasEndOfOptionsMarkerForEnvVar(line, envVarName string) bool {
	// Look for $ENV_VAR or "$ENV_VAR"
	patterns := []string{
		fmt.Sprintf("$%s", envVarName),
		fmt.Sprintf("\"$%s\"", envVarName),
	}

	minPos := -1
	for _, pattern := range patterns {
		pos := strings.Index(line, pattern)
		if pos != -1 && (minPos == -1 || pos < minPos) {
			minPos = pos
		}
	}

	if minPos == -1 {
		return false
	}

	beforeExpr := line[:minPos]
	endOfOptionsMatch := regexp.MustCompile(`\s--\s`)
	return endOfOptionsMatch.MatchString(beforeExpr + " ")
}

// replaceBareEnvVar replaces bare $ENV_VAR with newValue, being careful about word boundaries
func (rule *ArgumentInjectionRule) replaceBareEnvVar(line, envVarName, newValue string) string {
	barePattern := fmt.Sprintf("$%s", envVarName)
	pos := 0

	for {
		idx := strings.Index(line[pos:], barePattern)
		if idx == -1 {
			break
		}

		actualPos := pos + idx
		endPos := actualPos + len(barePattern)

		// Check if this is a word boundary (not part of a longer variable name)
		// Valid end characters: space, newline, quote, end of string, or non-alphanumeric
		isWordBoundary := endPos >= len(line) ||
			!isAlphanumericOrUnderscore(line[endPos])

		if isWordBoundary {
			// Replace this occurrence
			line = line[:actualPos] + newValue + line[endPos:]
			pos = actualPos + len(newValue)
		} else {
			pos = endPos
		}
	}

	return line
}

// isAlphanumericOrUnderscore checks if a byte is alphanumeric or underscore
func isAlphanumericOrUnderscore(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// generateEnvVarName generates an environment variable name from an untrusted path
func (rule *ArgumentInjectionRule) generateEnvVarName(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "UNTRUSTED_INPUT"
	}

	// Common patterns
	if len(parts) >= 4 && parts[0] == "github" && parts[1] == "event" {
		category := parts[2]         // pull_request, issue, comment, etc.
		field := parts[len(parts)-1] // title, body, ref, etc.

		// Convert to uppercase and join
		categoryUpper := strings.ToUpper(strings.ReplaceAll(category, "_", ""))
		fieldUpper := strings.ToUpper(field)

		// Create readable name
		if categoryUpper == "PULLREQUEST" {
			categoryUpper = "PR"
		}

		return fmt.Sprintf("%s_%s", categoryUpper, fieldUpper)
	}

	// Handle github.head_ref pattern
	if len(parts) >= 2 && parts[0] == "github" && parts[1] == "head_ref" {
		return "HEAD_REF"
	}

	// Fallback: use last part
	lastPart := parts[len(parts)-1]
	return strings.ToUpper(lastPart)
}

// extractAndParseExpressions extracts all expressions from string and parses them
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
		endIdx := strings.Index(value[start:], "}}")
		if endIdx == -1 {
			break
		}

		exprContent := value[start+3 : start+endIdx]
		exprContent = strings.TrimSpace(exprContent)

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

		offset = start + endIdx + 2
	}

	return result
}

// parseExpression parses a single expression string into an AST node
func (rule *ArgumentInjectionRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput checks if the expression contains untrusted input
func (rule *ArgumentInjectionRule) checkUntrustedInput(expr parsedExpression) []string {
	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(expr.node)

	var paths []string
	for _, err := range errs {
		msg := err.Message
		if strings.Contains(msg, "potentially untrusted") {
			if idx := strings.Index(msg, "\""); idx != -1 {
				endIdx := strings.Index(msg[idx+1:], "\"")
				if endIdx != -1 {
					path := msg[idx+1 : idx+1+endIdx]
					paths = append(paths, path)
				}
			}
		}
	}

	return paths
}

// isDefinedInEnv checks if the expression is defined in the step's env section
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
