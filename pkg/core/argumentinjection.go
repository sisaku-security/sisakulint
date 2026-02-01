package core

import (
	"fmt"
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
	commandName string // The command where this expression is used
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

// dangerousCmdNames is cached slice of dangerous command names for shell parser
var dangerousCmdNames []string

// commandsNotSupportingDoubleDash lists commands that don't treat -- as end-of-options marker
var commandsNotSupportingDoubleDash = map[string]bool{
	"docker":  true, // Docker treats -- as part of image name or command
	"python":  true, // Python passes -- to the script
	"python3": true,
	"node":    true, // Node passes -- to the script
	"ruby":    true, // Ruby passes -- to the script
	"perl":    true, // Perl passes -- to the script
	"php":     true, // PHP passes -- to the script
}

func init() {
	dangerousCmdNames = make([]string, 0, len(dangerousCommands))
	for cmd := range dangerousCommands {
		dangerousCmdNames = append(dangerousCmdNames, cmd)
	}
}

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

		// 1. Extract all expressions from the script
		exprs := rule.extractAndParseExpressions(run.Run)
		if len(exprs) == 0 {
			continue
		}

		// 2. Identify untrusted expressions (but we'll replace ALL expressions for parsing)
		untrustedSet := make(map[string][]string) // expr.raw -> untrusted paths
		for _, expr := range exprs {
			untrustedPaths := rule.checkUntrustedInput(expr)
			if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, s.Env) {
				untrustedSet[expr.raw] = untrustedPaths
			}
		}

		if len(untrustedSet) == 0 {
			continue
		}

		// 3. Replace ALL expressions with placeholder variables to make script parseable
		// This is necessary because ${{ }} is not valid shell syntax
		modifiedScript := script
		exprToPlaceholder := make(map[string]string) // expr.raw -> placeholder name

		for i, expr := range exprs {
			exprPattern1 := fmt.Sprintf("${{ %s }}", expr.raw)
			exprPattern2 := fmt.Sprintf("${{%s}}", expr.raw)
			placeholderName := fmt.Sprintf("__SISAKULINT_ARGEXPR_%d__", i)

			// Replace with placeholder in the script
			modifiedScript = strings.ReplaceAll(modifiedScript, exprPattern1, "$"+placeholderName)
			modifiedScript = strings.ReplaceAll(modifiedScript, exprPattern2, "$"+placeholderName)

			exprToPlaceholder[expr.raw] = placeholderName
		}

		// 4. Parse the modified script with shell parser
		parser := shell.NewShellParser(modifiedScript)

		// 5. Check each placeholder in command arguments (only for untrusted expressions)
		var stepUntrusted *stepWithArgumentInjection

		for i := range exprs {
			expr := &exprs[i]

			// Skip trusted expressions
			untrustedPaths, isUntrusted := untrustedSet[expr.raw]
			if !isUntrusted {
				continue
			}

			placeholderName := exprToPlaceholder[expr.raw]

			// Find variable usages as command arguments
			varUsages := parser.FindVarUsageAsCommandArg(placeholderName, dangerousCmdNames)

			for _, varUsage := range varUsages {
				// Skip if the variable is after --, which is safe
				if varUsage.IsAfterDoubleDash {
					continue
				}

				if stepUntrusted == nil {
					stepUntrusted = &stepWithArgumentInjection{step: s}
				}

				// Calculate line position based on expression position
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

	// Replace ${{ expr }} with $ENV_VAR in the script
	// For commands that support --, use -- "$ENV_VAR" pattern
	// For commands that don't support --, just use "$ENV_VAR"
	script := run.Run.Value
	for _, untrustedInfo := range stepInfo.untrustedExprs {
		envVarName := envVarMap[untrustedInfo.expr.raw]
		exprPattern1 := fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)
		exprPattern2 := fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)

		var newValue string
		if commandsNotSupportingDoubleDash[untrustedInfo.commandName] {
			// Commands like docker, python don't support -- as end-of-options marker
			// Just use quoted environment variable (better than raw expression)
			newValue = fmt.Sprintf("\"$%s\"", envVarName)
		} else {
			// Use -- "$ENV_VAR" pattern for safety
			newValue = fmt.Sprintf("-- \"$%s\"", envVarName)
		}
		script = strings.ReplaceAll(script, exprPattern1, newValue)
		script = strings.ReplaceAll(script, exprPattern2, newValue)
	}

	// Update AST
	run.Run.Value = script

	// Update BaseNode
	if step.BaseNode != nil {
		if err := setRunScriptValue(step.BaseNode, script); err != nil {
			return fmt.Errorf("failed to update run script: %w", err)
		}
	}

	return nil
}

// generateEnvVarName generates an environment variable name from an untrusted path
func (rule *ArgumentInjectionRule) generateEnvVarName(path string) string {
	if path == "" {
		return "UNTRUSTED_INPUT"
	}

	parts := strings.Split(path, ".")

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
