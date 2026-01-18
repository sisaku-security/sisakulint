package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"gopkg.in/yaml.v3"
)

// EnvPathInjectionRule is a shared implementation for detecting PATH injection vulnerabilities
// It detects when untrusted input is written to $GITHUB_PATH without proper sanitization
// It can be configured to check either privileged triggers (critical) or normal triggers (medium)
type EnvPathInjectionRule struct {
	BaseRule
	severityLevel      string // "critical" or "medium"
	checkPrivileged    bool   // true = check privileged triggers, false = check normal triggers
	stepsWithUntrusted []*stepWithEnvPathInjection
	workflow           *ast.Workflow
}

// stepWithEnvPathInjection tracks steps that need auto-fixing for PATH injection
type stepWithEnvPathInjection struct {
	step           *ast.Step
	untrustedExprs []envPathUntrustedExprInfo
}

// envPathUntrustedExprInfo contains information about an untrusted expression in $GITHUB_PATH
type envPathUntrustedExprInfo struct {
	expr  parsedExpression
	paths []string
	line  string // The line containing the GITHUB_PATH redirect
}

// Pattern to detect writes to $GITHUB_PATH
// Matches various formats of GITHUB_PATH redirects:
//
//	>> $GITHUB_PATH          (standard format)
//	>> "$GITHUB_PATH"        (double quoted)
//	>> '$GITHUB_PATH'        (single quoted)
//	>> ${GITHUB_PATH}        (with braces)
//	>>$GITHUB_PATH           (no space after >>)
//	>> "${GITHUB_PATH}"      (braces with quotes)
//
// This helps catch all common patterns of PATH writes
var githubPathPattern = regexp.MustCompile(`>>\s*["']?\$\{?GITHUB_PATH\}?["']?`)

// newEnvPathInjectionRule creates a new PATH injection rule with the specified severity level
func newEnvPathInjectionRule(severityLevel string, checkPrivileged bool) *EnvPathInjectionRule {
	var desc string

	if checkPrivileged {
		desc = "Checks for PATH injection vulnerabilities when untrusted input is written to $GITHUB_PATH in privileged workflow triggers (pull_request_target, workflow_run, issue_comment). See https://codeql.github.com/codeql-query-help/actions/actions-envpath-injection-critical/"
	} else {
		desc = "Checks for PATH injection vulnerabilities when untrusted input is written to $GITHUB_PATH in normal workflow triggers (pull_request, push, etc.). See https://codeql.github.com/codeql-query-help/actions/actions-envpath-injection-medium/"
	}

	return &EnvPathInjectionRule{
		BaseRule: BaseRule{
			RuleName: "envpath-injection-" + severityLevel,
			RuleDesc: desc,
		},
		severityLevel:      severityLevel,
		checkPrivileged:    checkPrivileged,
		stepsWithUntrusted: make([]*stepWithEnvPathInjection, 0),
	}
}

// VisitWorkflowPre is called before visiting a workflow
func (rule *EnvPathInjectionRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	return nil
}

func (rule *EnvPathInjectionRule) VisitJobPre(node *ast.Job) error {
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

		// Check if the run script writes to $GITHUB_PATH
		script := run.Run.Value
		if !githubPathPattern.MatchString(script) {
			continue
		}

		// Parse expressions from the script
		exprs := rule.extractAndParseExpressions(run.Run)
		if len(exprs) == 0 {
			continue
		}

		var stepUntrusted *stepWithEnvPathInjection

		// Split script into lines to find which lines write to GITHUB_PATH
		lines := strings.Split(script, "\n")
		for lineIdx, line := range lines {
			// Check if this line writes to GITHUB_PATH
			if !githubPathPattern.MatchString(line) {
				continue
			}

			// Check if this line contains any untrusted expressions
			for _, expr := range exprs {
				// Check if the expression is in this line
				if !strings.Contains(line, fmt.Sprintf("${{ %s }}", expr.raw)) &&
					!strings.Contains(line, fmt.Sprintf("${{%s}}", expr.raw)) {
					continue
				}

				untrustedPaths := rule.checkUntrustedInput(expr)
				if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, s.Env) {
					if stepUntrusted == nil {
						stepUntrusted = &stepWithEnvPathInjection{step: s}
					}

					stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, envPathUntrustedExprInfo{
						expr:  expr,
						paths: untrustedPaths,
						line:  line,
					})

					// Calculate the actual line position
					linePos := &ast.Position{
						Line: run.Run.Pos.Line + lineIdx,
						Col:  run.Run.Pos.Col,
					}
					if run.Run.Literal {
						linePos.Line++
					}

					if rule.checkPrivileged {
						rule.Errorf(
							linePos,
							"PATH injection (critical): \"%s\" is potentially untrusted and written to $GITHUB_PATH in a workflow with privileged triggers. This can allow attackers to hijack command execution by prepending a malicious directory to PATH. Validate the path or use absolute paths instead. See https://codeql.github.com/codeql-query-help/actions/actions-envpath-injection-critical/",
							strings.Join(untrustedPaths, "\", \""),
						)
					} else {
						rule.Errorf(
							linePos,
							"PATH injection (medium): \"%s\" is potentially untrusted and written to $GITHUB_PATH. This can allow attackers to hijack command execution by prepending a malicious directory to PATH. Validate the path or use absolute paths instead. See https://codeql.github.com/codeql-query-help/actions/actions-envpath-injection-medium/",
							strings.Join(untrustedPaths, "\", \""),
						)
					}
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

// hasPrivilegedTriggers checks if the workflow has privileged triggers
func (rule *EnvPathInjectionRule) hasPrivilegedTriggers() bool {
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
func (rule *EnvPathInjectionRule) RuleNames() string {
	return rule.RuleName
}

// FixStep implements StepFixer interface
func (rule *EnvPathInjectionRule) FixStep(step *ast.Step) error {
	// Find the stepWithEnvPathInjection for this step
	var stepInfo *stepWithEnvPathInjection
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
	// For each untrusted expression in GITHUB_PATH writes, replace with validated version
	replacements := make(map[string]string)

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		envVarName := envVarMap[untrustedInfo.expr.raw]

		// Replace ${{ expr }} with validated path using realpath
		// realpath resolves the path and ensures it's absolute and canonical
		oldPattern := fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)
		newPattern := fmt.Sprintf("$(realpath \"$%s\")", envVarName)
		replacements[oldPattern] = newPattern

		// Also handle no-space variant
		oldPatternNoSpace := fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)
		replacements[oldPatternNoSpace] = newPattern
	}

	// Apply replacements to the run script
	newScript := run.Run.Value
	for old, new := range replacements {
		newScript = strings.ReplaceAll(newScript, old, new)
	}

	// Additional pass: validate env var references in GITHUB_PATH lines
	// Split into lines and process each line that writes to GITHUB_PATH
	lines := strings.Split(newScript, "\n")
	for i, line := range lines {
		if githubPathPattern.MatchString(line) {
			// This line writes to GITHUB_PATH
			// Replace any $ENV_VAR references (that aren't already wrapped) with validated version
			for _, untrustedInfo := range stepInfo.untrustedExprs {
				envVarName := envVarMap[untrustedInfo.expr.raw]

				// Pattern to match $ENV_VAR but not $(realpath "$ENV_VAR")
				// and not "$GITHUB_PATH"
				plainVarPattern := fmt.Sprintf("$%s", envVarName)

				// Only replace if it's not already wrapped in validation
				if strings.Contains(line, plainVarPattern) &&
					!strings.Contains(line, fmt.Sprintf("$(realpath \"$%s\")", envVarName)) {
					// Replace $ENV_VAR with $(realpath "$ENV_VAR")
					validatedVar := fmt.Sprintf("$(realpath \"$%s\")", envVarName)
					line = strings.ReplaceAll(line, plainVarPattern, validatedVar)
				}
			}
			lines[i] = line
		}
	}
	newScript = strings.Join(lines, "\n")

	// Update AST
	run.Run.Value = newScript

	// Update BaseNode
	if step.BaseNode != nil {
		// Directly update the run script value in the YAML node
		if err := setRunScriptValueForPath(step.BaseNode, newScript); err != nil {
			return fmt.Errorf("failed to update run script: %w", err)
		}
	}

	return nil
}

// setRunScriptValueForPath directly sets the run script value in a step's YAML node
func setRunScriptValueForPath(stepNode *yaml.Node, newValue string) error {
	if stepNode == nil || stepNode.Kind != yaml.MappingNode {
		return fmt.Errorf("step node must be a mapping node")
	}

	// Find 'run' section
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == SBOMRun {
			runNode := stepNode.Content[i+1]
			if runNode.Kind == yaml.ScalarNode {
				runNode.Value = newValue
				return nil
			}
		}
	}

	return fmt.Errorf("run section not found in step node")
}

// generateEnvVarName generates an environment variable name from an untrusted path
func (rule *EnvPathInjectionRule) generateEnvVarName(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "UNTRUSTED_PATH"
	}

	// Common patterns
	if len(parts) >= 4 && parts[0] == "github" && parts[1] == "event" {
		category := parts[2]         // pull_request, issue, comment, etc.
		field := parts[len(parts)-1] // title, body, etc.

		// Convert to uppercase and join
		categoryUpper := strings.ToUpper(strings.ReplaceAll(category, "_", ""))
		fieldUpper := strings.ToUpper(field)

		// Create readable name
		if categoryUpper == "PULLREQUEST" {
			categoryUpper = "PR"
		}

		return fmt.Sprintf("%s_%s_PATH", categoryUpper, fieldUpper)
	}

	// Fallback: use last part
	lastPart := parts[len(parts)-1]
	return strings.ToUpper(lastPart) + "_PATH"
}

// extractAndParseExpressions extracts all expressions from string and parses them
func (rule *EnvPathInjectionRule) extractAndParseExpressions(str *ast.String) []parsedExpression {
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
				pos.Line++
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
func (rule *EnvPathInjectionRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput checks if the expression contains untrusted input
func (rule *EnvPathInjectionRule) checkUntrustedInput(expr parsedExpression) []string {
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
func (rule *EnvPathInjectionRule) isDefinedInEnv(expr parsedExpression, env *ast.Env) bool {
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
