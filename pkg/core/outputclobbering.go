package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"gopkg.in/yaml.v3"
)

// OutputClobberingRule is a shared implementation for detecting output clobbering vulnerabilities
// It detects when untrusted input is written to $GITHUB_OUTPUT without proper sanitization
// Attackers can inject newlines in issue title/body to overwrite other output variables
// It can be configured to check either privileged triggers (critical) or normal triggers (medium)
type OutputClobberingRule struct {
	BaseRule
	severityLevel      string // "critical" or "medium"
	checkPrivileged    bool   // true = check privileged triggers, false = check normal triggers
	stepsWithUntrusted []*stepWithOutputClobbering
	workflow           *ast.Workflow
}

// stepWithOutputClobbering tracks steps that need auto-fixing for output clobbering
type stepWithOutputClobbering struct {
	step           *ast.Step
	untrustedExprs []outputClobberingUntrustedExprInfo
}

// outputClobberingUntrustedExprInfo contains information about an untrusted expression in $GITHUB_OUTPUT
type outputClobberingUntrustedExprInfo struct {
	expr  parsedExpression
	paths []string
	line  string // The line containing the GITHUB_OUTPUT redirect
}

// Pattern to detect writes to $GITHUB_OUTPUT
// Matches various formats of GITHUB_OUTPUT redirects:
//
//	>> $GITHUB_OUTPUT          (standard format)
//	>> "$GITHUB_OUTPUT"        (double quoted)
//	>> '$GITHUB_OUTPUT'        (single quoted)
//	>> ${GITHUB_OUTPUT}        (with braces)
//	>>$GITHUB_OUTPUT           (no space after >>)
//	>> "${GITHUB_OUTPUT}"      (braces with quotes)
//
// This helps catch all common patterns of output writes
var githubOutputPattern = regexp.MustCompile(`>>\s*["']?\$\{?GITHUB_OUTPUT\}?["']?`)

// Pattern to detect heredoc/delimiter syntax (safe pattern)
// Matches patterns like:
//
//	name<<EOF
//	name<<$DELIMITER
//	name<<RANDOM_DELIM
//
// These are safe because they don't allow newline injection
var heredocPattern = regexp.MustCompile(`[a-zA-Z_][a-zA-Z0-9_]*<<[^\s]+`)

// newOutputClobberingRule creates a new output clobbering rule with the specified severity level
func newOutputClobberingRule(severityLevel string, checkPrivileged bool) *OutputClobberingRule {
	var desc string

	if checkPrivileged {
		desc = "Checks for output clobbering vulnerabilities when untrusted input is written to $GITHUB_OUTPUT in privileged workflow triggers (pull_request_target, workflow_run, issue_comment). Attackers can inject newlines to overwrite other output variables. Use heredoc syntax with unique delimiters to prevent injection."
	} else {
		desc = "Checks for output clobbering vulnerabilities when untrusted input is written to $GITHUB_OUTPUT in normal workflow triggers (pull_request, push, etc.). Attackers can inject newlines to overwrite other output variables. Use heredoc syntax with unique delimiters to prevent injection."
	}

	return &OutputClobberingRule{
		BaseRule: BaseRule{
			RuleName: "output-clobbering-" + severityLevel,
			RuleDesc: desc,
		},
		severityLevel:      severityLevel,
		checkPrivileged:    checkPrivileged,
		stepsWithUntrusted: make([]*stepWithOutputClobbering, 0),
	}
}

// VisitWorkflowPre is called before visiting a workflow
func (rule *OutputClobberingRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	return nil
}

func (rule *OutputClobberingRule) VisitJobPre(node *ast.Job) error {
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

		// Check if the run script writes to $GITHUB_OUTPUT
		script := run.Run.Value
		if !githubOutputPattern.MatchString(script) {
			continue
		}

		// Parse expressions from the script
		exprs := rule.extractAndParseExpressions(run.Run)
		if len(exprs) == 0 {
			continue
		}

		var stepUntrusted *stepWithOutputClobbering

		// Split script into lines to find which lines write to GITHUB_OUTPUT
		lines := strings.Split(script, "\n")
		for lineIdx, line := range lines {
			// Check if this line writes to GITHUB_OUTPUT
			if !githubOutputPattern.MatchString(line) {
				continue
			}

			// Check if this line uses heredoc syntax (safe pattern)
			if rule.usesHeredocSyntax(lines, lineIdx) {
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
						stepUntrusted = &stepWithOutputClobbering{step: s}
					}

					stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, outputClobberingUntrustedExprInfo{
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
							"output clobbering (critical): \"%s\" is potentially untrusted and written to $GITHUB_OUTPUT in a workflow with privileged triggers. Attackers can inject newlines to overwrite other output variables. Use heredoc syntax with unique delimiters: 'name<<EOF\\nvalue\\nEOF'",
							strings.Join(untrustedPaths, "\", \""),
						)
					} else {
						rule.Errorf(
							linePos,
							"output clobbering (medium): \"%s\" is potentially untrusted and written to $GITHUB_OUTPUT. Attackers can inject newlines to overwrite other output variables. Use heredoc syntax with unique delimiters: 'name<<EOF\\nvalue\\nEOF'",
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

// usesHeredocSyntax checks if the line or surrounding context uses heredoc syntax
// This checks for patterns like:
//
//	name<<EOF
//	echo "value"
//	echo EOF
//
// which are safe against newline injection
func (rule *OutputClobberingRule) usesHeredocSyntax(lines []string, currentLineIdx int) bool {
	currentLine := lines[currentLineIdx]

	// Check if current line has heredoc pattern before the GITHUB_OUTPUT redirect
	// Pattern: name<<DELIMITER >> $GITHUB_OUTPUT (all on one line is NOT safe)
	// But: echo "name<<DELIMITER" >> $GITHUB_OUTPUT (on first line, then value, then delimiter) IS safe

	// Look for heredoc start pattern in the same line
	if heredocPattern.MatchString(currentLine) {
		// If heredoc pattern and GITHUB_OUTPUT redirect are on the same line,
		// we need to check if the untrusted value is written within a heredoc block

		// Look backwards for a heredoc start on a previous line
		for i := currentLineIdx - 1; i >= 0 && i >= currentLineIdx-10; i-- {
			prevLine := lines[i]
			if heredocPattern.MatchString(prevLine) && githubOutputPattern.MatchString(prevLine) {
				// Found a heredoc start with GITHUB_OUTPUT - this write might be within a heredoc block
				return true
			}
		}
	}

	// Look backwards for a heredoc start that writes to GITHUB_OUTPUT
	// This handles multi-line heredocs
	for i := currentLineIdx - 1; i >= 0 && i >= currentLineIdx-10; i-- {
		prevLine := lines[i]
		if heredocPattern.MatchString(prevLine) && githubOutputPattern.MatchString(prevLine) {
			// Found a heredoc start with GITHUB_OUTPUT on a previous line
			// Current line might be the value or delimiter line
			return true
		}
	}

	return false
}

// hasPrivilegedTriggers checks if the workflow has privileged triggers
func (rule *OutputClobberingRule) hasPrivilegedTriggers() bool {
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
func (rule *OutputClobberingRule) RuleNames() string {
	return rule.RuleName
}

// FixStep implements StepFixer interface
func (rule *OutputClobberingRule) FixStep(step *ast.Step) error {
	// Find the stepWithOutputClobbering for this step
	var stepInfo *stepWithOutputClobbering
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

	// Transform the run script to use heredoc syntax for each vulnerable line
	newScript := rule.transformToHeredocSyntax(run.Run.Value, stepInfo, envVarMap)

	// Update AST
	run.Run.Value = newScript

	// Update BaseNode
	if step.BaseNode != nil {
		// Directly update the run script value in the YAML node
		if err := setRunScriptValueForOutput(step.BaseNode, newScript); err != nil {
			return fmt.Errorf("failed to update run script: %w", err)
		}
	}

	return nil
}

// transformToHeredocSyntax transforms vulnerable output writes to use heredoc syntax
func (rule *OutputClobberingRule) transformToHeredocSyntax(script string, stepInfo *stepWithOutputClobbering, envVarMap map[string]string) string {
	lines := strings.Split(script, "\n")
	var result []string

	// Track which lines have been transformed
	transformedLines := make(map[int]bool)

	// First, identify lines that need transformation
	for i, line := range lines {
		if !githubOutputPattern.MatchString(line) {
			continue
		}

		// Check if this line has any untrusted expressions
		for _, untrustedInfo := range stepInfo.untrustedExprs {
			exprPattern1 := fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)
			exprPattern2 := fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)

			if strings.Contains(line, exprPattern1) || strings.Contains(line, exprPattern2) {
				transformedLines[i] = true
				break
			}
		}
	}

	// Transform lines
	for i, line := range lines {
		if !transformedLines[i] {
			result = append(result, line)
			continue
		}

		// Parse the line to extract output name and value
		// Common patterns:
		// echo "name=value" >> $GITHUB_OUTPUT
		// echo "name=${{ expr }}" >> $GITHUB_OUTPUT
		// printf "name=value" >> $GITHUB_OUTPUT

		transformed := rule.transformOutputLine(line, stepInfo, envVarMap)
		result = append(result, transformed...)
	}

	return strings.Join(result, "\n")
}

// transformOutputLine transforms a single output line to use heredoc syntax
func (rule *OutputClobberingRule) transformOutputLine(line string, stepInfo *stepWithOutputClobbering, envVarMap map[string]string) []string {
	// Extract the output name from patterns like:
	// echo "name=value" >> $GITHUB_OUTPUT
	// echo 'name=value' >> $GITHUB_OUTPUT

	// Find the echo/printf command and extract content
	outputPattern := regexp.MustCompile(`(echo|printf)\s+["']?([^"'=]+)=`)
	matches := outputPattern.FindStringSubmatch(line)

	var outputName string
	if len(matches) >= 3 {
		outputName = matches[2]
	} else {
		// Try to find output name from the content
		// Pattern: something=value
		contentPattern := regexp.MustCompile(`["']([a-zA-Z_][a-zA-Z0-9_]*)=`)
		contentMatches := contentPattern.FindStringSubmatch(line)
		if len(contentMatches) >= 2 {
			outputName = contentMatches[1]
		} else {
			outputName = "OUTPUT"
		}
	}

	// Replace untrusted expressions with env var references
	newLine := line
	for _, untrustedInfo := range stepInfo.untrustedExprs {
		envVarName := envVarMap[untrustedInfo.expr.raw]
		if envVarName == "" {
			continue
		}

		exprPattern1 := fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)
		exprPattern2 := fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)

		newLine = strings.ReplaceAll(newLine, exprPattern1, fmt.Sprintf("$%s", envVarName))
		newLine = strings.ReplaceAll(newLine, exprPattern2, fmt.Sprintf("$%s", envVarName))
	}

	// Now transform to heredoc syntax
	// Generate a unique delimiter
	delimiter := "EOF_SISAKULINT"

	// Create heredoc-style output
	// {
	//   echo "name<<EOF_SISAKULINT"
	//   echo "$ENV_VAR"
	//   echo "EOF_SISAKULINT"
	// } >> "$GITHUB_OUTPUT"

	// Extract the value part from the original line
	// Pattern: echo "name=$value" -> we want $value
	valuePattern := regexp.MustCompile(`["']?[a-zA-Z_][a-zA-Z0-9_]*=([^"']*(?:\$[a-zA-Z_][a-zA-Z0-9_]*[^"']*)*)["']?\s*>>`)
	valueMatches := valuePattern.FindStringSubmatch(newLine)

	var valuePart string
	if len(valueMatches) >= 2 {
		valuePart = valueMatches[1]
	} else {
		// Fallback: extract everything after = and before >>
		eqIdx := strings.Index(newLine, "=")
		gtIdx := strings.Index(newLine, ">>")
		if eqIdx != -1 && gtIdx != -1 && eqIdx < gtIdx {
			valuePart = strings.TrimSpace(newLine[eqIdx+1 : gtIdx])
			// Remove surrounding quotes if present
			valuePart = strings.Trim(valuePart, `"'`)
		}
	}

	// Clean up value part
	valuePart = strings.TrimSpace(valuePart)

	return []string{
		"{",
		fmt.Sprintf(`  echo "%s<<%s"`, outputName, delimiter),
		fmt.Sprintf(`  echo "%s"`, valuePart),
		fmt.Sprintf(`  echo "%s"`, delimiter),
		`} >> "$GITHUB_OUTPUT"`,
	}
}

// setRunScriptValueForOutput directly sets the run script value in a step's YAML node
func setRunScriptValueForOutput(stepNode *yaml.Node, newValue string) error {
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
func (rule *OutputClobberingRule) generateEnvVarName(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "UNTRUSTED_OUTPUT"
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

		return fmt.Sprintf("%s_%s", categoryUpper, fieldUpper)
	}

	// Fallback: use last part
	lastPart := parts[len(parts)-1]
	return strings.ToUpper(lastPart)
}

// extractAndParseExpressions extracts all expressions from string and parses them
func (rule *OutputClobberingRule) extractAndParseExpressions(str *ast.String) []parsedExpression {
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
func (rule *OutputClobberingRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput checks if the expression contains untrusted input
func (rule *OutputClobberingRule) checkUntrustedInput(expr parsedExpression) []string {
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
func (rule *OutputClobberingRule) isDefinedInEnv(expr parsedExpression, env *ast.Env) bool {
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
