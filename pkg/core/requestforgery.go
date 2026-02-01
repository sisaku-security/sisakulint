package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"github.com/sisaku-security/sisakulint/pkg/shell"
)

// RequestForgeryRule is a shared implementation for detecting Server-Side Request Forgery (SSRF) vulnerabilities
// It detects when untrusted input is used in network request URLs, hosts, or parameters
// It can be configured to check either privileged triggers (critical) or normal triggers (medium)
type RequestForgeryRule struct {
	BaseRule
	severityLevel      string // "critical" or "medium"
	checkPrivileged    bool   // true = check privileged triggers, false = check normal triggers
	stepsWithUntrusted []*stepWithRequestForgery
	workflow           *ast.Workflow
}

// stepWithRequestForgery tracks steps that need auto-fixing for request forgery
type stepWithRequestForgery struct {
	step           *ast.Step
	untrustedExprs []requestForgeryExprInfo
}

// requestForgeryExprInfo contains information about an untrusted expression in network requests
type requestForgeryExprInfo struct {
	expr     parsedExpression
	paths    []string
	line     string                 // The line containing the network request
	severity RequestForgerySeverity // Severity level based on where untrusted input is used
	command  string                 // The network command detected (curl, wget, fetch, etc.)
}

// RequestForgerySeverity represents the severity level of the SSRF vulnerability
type RequestForgerySeverity int

const (
	// RequestForgerySeverityURL - Untrusted input used as full URL (most dangerous)
	RequestForgerySeverityURL RequestForgerySeverity = iota
	// RequestForgerySeverityHost - Untrusted input used as host/domain
	RequestForgerySeverityHost
	// RequestForgerySeverityPath - Untrusted input used as path/query parameters
	RequestForgerySeverityPath
)

// Cloud metadata URLs that are commonly targeted in SSRF attacks
var cloudMetadataURLs = []string{
	"169.254.169.254", // AWS/GCP/Azure metadata service
	"metadata.google", // GCP metadata
	"169.254.170.2",   // AWS ECS metadata
	"fd00:ec2::254",   // AWS metadata IPv6
	"[fd00:ec2::254]", // AWS metadata IPv6 bracketed
	"100.100.100.200", // Alibaba Cloud metadata
	"192.0.0.192",     // Oracle Cloud metadata
}

// Network request commands to detect
// Pattern matches command with potential flags/options before URL argument
var networkCommandPatterns = []*regexp.Regexp{
	// curl patterns - must be at start of line or after whitespace/operators
	regexp.MustCompile(`(?:^|[\s|&;])(curl)\b`),
	// wget patterns
	regexp.MustCompile(`(?:^|[\s|&;])(wget)\b`),
	// PowerShell Invoke-WebRequest and Invoke-RestMethod
	regexp.MustCompile(`(?:^|[\s|&;])(Invoke-WebRequest)\b`),
	regexp.MustCompile(`(?:^|[\s|&;])(Invoke-RestMethod)\b`),
	regexp.MustCompile(`(?:^|[\s|&;])(iwr)\b`),
	regexp.MustCompile(`(?:^|[\s|&;])(irm)\b`),
	// fetch in Node.js/Deno (actions/github-script)
	regexp.MustCompile(`\b(fetch)\s*\(`),
	// axios
	regexp.MustCompile(`\b(axios)\.(get|post|put|delete|patch|head|options|request)\s*\(`),
	regexp.MustCompile(`\b(axios)\s*\(`),
	// node-fetch, got, request
	regexp.MustCompile(`\brequire\s*\(\s*['"]node-fetch['"]\s*\)`),
	regexp.MustCompile(`\b(got)\s*\(`),
	regexp.MustCompile(`\b(request)\s*\(`),
	// Python requests
	regexp.MustCompile(`\brequests\.(get|post|put|delete|patch|head|options)\s*\(`),
	// Python urllib
	regexp.MustCompile(`\burllib\.(request\.)?urlopen\s*\(`),
	// nc/netcat
	regexp.MustCompile(`\bnc\b[^|&;]*`),
	regexp.MustCompile(`\bnetcat\b[^|&;]*`),
}

// newRequestForgeryRule creates a new request forgery rule with the specified severity level
func newRequestForgeryRule(severityLevel string, checkPrivileged bool) *RequestForgeryRule {
	var desc string

	if checkPrivileged {
		desc = "Checks for Server-Side Request Forgery (SSRF) vulnerabilities when untrusted input is used in network requests with privileged workflow triggers (pull_request_target, workflow_run, issue_comment). Attackers can access internal services, cloud metadata, or pivot to internal networks. See https://cwe.mitre.org/data/definitions/918.html"
	} else {
		desc = "Checks for Server-Side Request Forgery (SSRF) vulnerabilities when untrusted input is used in network requests with normal workflow triggers (pull_request, push, etc.). Attackers can access internal services, cloud metadata, or pivot to internal networks. See https://cwe.mitre.org/data/definitions/918.html"
	}

	return &RequestForgeryRule{
		BaseRule: BaseRule{
			RuleName: "request-forgery-" + severityLevel,
			RuleDesc: desc,
		},
		severityLevel:      severityLevel,
		checkPrivileged:    checkPrivileged,
		stepsWithUntrusted: make([]*stepWithRequestForgery, 0),
	}
}

// VisitWorkflowPre is called before visiting a workflow
func (rule *RequestForgeryRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	return nil
}

func (rule *RequestForgeryRule) VisitJobPre(node *ast.Job) error {
	// Check if workflow trigger matches what we're looking for
	isPrivileged := rule.hasPrivilegedTriggers()

	// Skip if trigger type doesn't match our severity level
	if rule.checkPrivileged != isPrivileged {
		return nil
	}

	for _, s := range node.Steps {
		if s.Exec == nil {
			continue
		}

		var stepUntrusted *stepWithRequestForgery

		// Check run: scripts
		if s.Exec.Kind() == ast.ExecKindRun {
			run := s.Exec.(*ast.ExecRun)
			if run.Run == nil {
				continue
			}

			script := run.Run.Value
			stepUntrusted = rule.checkScript(script, run.Run, s)
		}

		// Check actions/github-script script: parameter
		if s.Exec.Kind() == ast.ExecKindAction {
			action := s.Exec.(*ast.ExecAction)
			if action.Uses != nil && strings.HasPrefix(action.Uses.Value, "actions/github-script@") {
				if scriptInput, ok := action.Inputs["script"]; ok && scriptInput != nil && scriptInput.Value != nil {
					stepUntrusted = rule.checkScript(scriptInput.Value.Value, scriptInput.Value, s)
				}
			}
		}

		if stepUntrusted != nil && len(stepUntrusted.untrustedExprs) > 0 {
			rule.stepsWithUntrusted = append(rule.stepsWithUntrusted, stepUntrusted)
			rule.AddAutoFixer(NewStepFixer(s, rule))
		}
	}
	return nil
}

// checkScript analyzes a script for SSRF vulnerabilities
func (rule *RequestForgeryRule) checkScript(script string, pos *ast.String, step *ast.Step) *stepWithRequestForgery {
	// First check for cloud metadata URL references
	rule.checkCloudMetadataReferences(script, pos)

	// Parse expressions from the script
	exprs := rule.extractAndParseExpressions(pos)
	if len(exprs) == 0 {
		return nil
	}

	var stepUntrusted *stepWithRequestForgery

	// Use ShellParser for AST-based network command detection
	parser := shell.NewShellParser(script)
	cmdCalls := parser.FindNetworkCommands()

	// If AST parsing found network commands, use them
	if len(cmdCalls) > 0 {
		stepUntrusted = rule.checkScriptWithAST(cmdCalls, exprs, pos, step)
	}

	// Fallback to line-based detection for cases AST doesn't handle
	// (e.g., scripts with ${{ }} that fail to parse)
	if stepUntrusted == nil {
		stepUntrusted = rule.checkScriptWithLines(script, exprs, pos, step)
	}

	return stepUntrusted
}

// checkScriptWithAST uses AST-based detection for network commands
func (rule *RequestForgeryRule) checkScriptWithAST(cmdCalls []shell.NetworkCommandCall, exprs []parsedExpression, pos *ast.String, step *ast.Step) *stepWithRequestForgery {
	var stepUntrusted *stepWithRequestForgery

	for _, cmdCall := range cmdCalls {
		// Check each argument of the network command
		for _, arg := range cmdCall.Args {
			// Check if argument contains GHA expressions
			for _, ghaExpr := range arg.GHAExprs {
				// Find matching parsed expression
				for _, expr := range exprs {
					if strings.TrimSpace(expr.raw) != strings.TrimSpace(ghaExpr) {
						continue
					}

					untrustedPaths := rule.checkUntrustedInput(expr)
					if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, step.Env) {
						if stepUntrusted == nil {
							stepUntrusted = &stepWithRequestForgery{step: step}
						}

						// Determine severity based on argument position
						severity := rule.determineSeverityFromArg(arg, cmdCall)

						stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, requestForgeryExprInfo{
							expr:     expr,
							paths:    untrustedPaths,
							line:     arg.Value,
							severity: severity,
							command:  cmdCall.CommandName,
						})

						rule.reportError(pos.Pos, untrustedPaths, cmdCall.CommandName, severity)
					}
				}
			}
		}
	}

	return stepUntrusted
}

// checkScriptWithLines uses line-based detection as fallback
func (rule *RequestForgeryRule) checkScriptWithLines(script string, exprs []parsedExpression, pos *ast.String, step *ast.Step) *stepWithRequestForgery {
	var stepUntrusted *stepWithRequestForgery

	lines := strings.Split(script, "\n")
	for lineIdx, line := range lines {
		// Skip comments
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Check if this line contains a network request command
		networkCmd := rule.detectNetworkCommand(line)
		if networkCmd == "" {
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
			if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, step.Env) {
				if stepUntrusted == nil {
					stepUntrusted = &stepWithRequestForgery{step: step}
				}

				// Determine severity based on where untrusted input is used
				severity := rule.determineSeverity(line, expr)

				stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, requestForgeryExprInfo{
					expr:     expr,
					paths:    untrustedPaths,
					line:     line,
					severity: severity,
					command:  networkCmd,
				})

				// Calculate the actual line position
				linePos := &ast.Position{
					Line: pos.Pos.Line + lineIdx,
					Col:  pos.Pos.Col,
				}
				if pos.Literal {
					linePos.Line += 1
				}

				rule.reportError(linePos, untrustedPaths, networkCmd, severity)
			}
		}
	}

	return stepUntrusted
}

// determineSeverityFromArg determines severity based on command argument
func (rule *RequestForgeryRule) determineSeverityFromArg(arg shell.CommandArg, _ shell.NetworkCommandCall) RequestForgerySeverity {
	// Flags like -d, --data, -H are typically path/data severity
	if arg.IsFlag {
		return RequestForgerySeverityPath
	}

	// Check if argument looks like a URL
	value := arg.Value
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		// If expression is in host position: https://${{ expr }}/...
		if strings.Contains(value, "${{") {
			idx := strings.Index(value, "${{")
			prefix := value[:idx]
			if strings.HasSuffix(prefix, "://") || strings.HasSuffix(prefix, "://\"") || strings.HasSuffix(prefix, "://'") {
				return RequestForgerySeverityHost
			}
		}
		return RequestForgerySeverityPath
	}

	// If the argument is just a ${{ expr }}, it's likely a full URL
	if strings.HasPrefix(strings.TrimSpace(value), "${{") {
		return RequestForgerySeverityURL
	}

	return RequestForgerySeverityPath
}

// checkCloudMetadataReferences checks for direct references to cloud metadata URLs
func (rule *RequestForgeryRule) checkCloudMetadataReferences(script string, pos *ast.String) {
	lines := strings.Split(script, "\n")
	for lineIdx, line := range lines {
		for _, metadataURL := range cloudMetadataURLs {
			if strings.Contains(line, metadataURL) {
				linePos := &ast.Position{
					Line: pos.Pos.Line + lineIdx,
					Col:  pos.Pos.Col,
				}
				if pos.Literal {
					linePos.Line += 1
				}

				rule.Errorf(
					linePos,
					"request forgery (%s): Reference to cloud metadata service URL '%s' detected. This endpoint can expose sensitive instance credentials and configuration. Ensure this is intentional and properly secured.",
					rule.severityLevel,
					metadataURL,
				)
			}
		}
	}
}

// detectNetworkCommand checks if a line contains a network request command
func (rule *RequestForgeryRule) detectNetworkCommand(line string) string {
	for _, pattern := range networkCommandPatterns {
		// Use FindStringSubmatch to get captured groups
		if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
			// Return the first captured group (the command name)
			cmd := matches[1]
			// Handle cases like "fetch(" -> "fetch"
			cmd = strings.TrimSuffix(cmd, "(")
			return cmd
		} else if match := pattern.FindString(line); match != "" {
			// Fallback for patterns without capture groups
			words := strings.Fields(match)
			if len(words) > 0 {
				cmd := words[0]
				cmd = strings.TrimSuffix(cmd, "(")
				// Handle axios.get -> axios
				if idx := strings.Index(cmd, "."); idx != -1 {
					cmd = cmd[:idx]
				}
				return cmd
			}
		}
	}
	return ""
}

// determineSeverity determines the severity based on where untrusted input is used
func (rule *RequestForgeryRule) determineSeverity(line string, expr parsedExpression) RequestForgerySeverity {
	exprPattern := fmt.Sprintf("${{ %s }}", expr.raw)
	exprPatternNoSpace := fmt.Sprintf("${{%s}}", expr.raw)

	// Check if expression is used as full URL (most dangerous)
	// Pattern: curl ${{ input }} or wget ${{ input }}
	fullURLPattern := regexp.MustCompile(`\b(curl|wget|http|https|fetch|axios)\s+["']?` + regexp.QuoteMeta(exprPattern))
	fullURLPatternNoSpace := regexp.MustCompile(`\b(curl|wget|http|https|fetch|axios)\s+["']?` + regexp.QuoteMeta(exprPatternNoSpace))
	if fullURLPattern.MatchString(line) || fullURLPatternNoSpace.MatchString(line) {
		return RequestForgerySeverityURL
	}

	// Check if expression is used as host
	// Pattern: curl https://${{ input }}/path or curl http://${{ input }}
	hostPattern := regexp.MustCompile(`https?://` + regexp.QuoteMeta(exprPattern))
	hostPatternNoSpace := regexp.MustCompile(`https?://` + regexp.QuoteMeta(exprPatternNoSpace))
	if hostPattern.MatchString(line) || hostPatternNoSpace.MatchString(line) {
		return RequestForgerySeverityHost
	}

	// Default to path/query severity
	return RequestForgerySeverityPath
}

// reportError reports an SSRF error with appropriate severity
func (rule *RequestForgeryRule) reportError(pos *ast.Position, untrustedPaths []string, command string, severity RequestForgerySeverity) {
	var severityStr string
	var riskDesc string

	switch severity {
	case RequestForgerySeverityURL:
		severityStr = "high"
		riskDesc = "used as the full URL"
	case RequestForgerySeverityHost:
		severityStr = "high"
		riskDesc = "used as the host/domain"
	case RequestForgerySeverityPath:
		severityStr = "medium"
		riskDesc = "used in the URL path or query parameters"
	}

	if rule.checkPrivileged {
		rule.Errorf(
			pos,
			"request forgery (critical/%s): \"%s\" is potentially untrusted and %s in '%s' command within a workflow with privileged triggers. This can allow Server-Side Request Forgery (SSRF) attacks to access internal services, cloud metadata endpoints (169.254.169.254), or pivot to internal networks. Validate and sanitize the URL, or use an allowlist of permitted hosts. See https://cwe.mitre.org/data/definitions/918.html",
			severityStr,
			strings.Join(untrustedPaths, "\", \""),
			riskDesc,
			command,
		)
	} else {
		rule.Errorf(
			pos,
			"request forgery (medium/%s): \"%s\" is potentially untrusted and %s in '%s' command. This can allow Server-Side Request Forgery (SSRF) attacks to access internal services or cloud metadata endpoints. Validate and sanitize the URL, or use an allowlist of permitted hosts. See https://cwe.mitre.org/data/definitions/918.html",
			severityStr,
			strings.Join(untrustedPaths, "\", \""),
			riskDesc,
			command,
		)
	}
}

// hasPrivilegedTriggers checks if the workflow has privileged triggers
func (rule *RequestForgeryRule) hasPrivilegedTriggers() bool {
	if rule.workflow == nil || rule.workflow.On == nil {
		return false
	}

	// Check for privileged triggers
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
func (rule *RequestForgeryRule) RuleNames() string {
	return rule.RuleName
}

// FixStep implements StepFixer interface
func (rule *RequestForgeryRule) FixStep(step *ast.Step) error {
	// Find the stepWithRequestForgery for this step
	var stepInfo *stepWithRequestForgery
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

	// Build replacement maps
	runReplacements := make(map[string]string)
	scriptReplacements := make(map[string]string)

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		envVarName := envVarMap[untrustedInfo.expr.raw]

		if step.Exec.Kind() == ast.ExecKindRun {
			// For run: scripts, use $ENV_VAR
			runReplacements[fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)] = fmt.Sprintf("$%s", envVarName)
			runReplacements[fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)] = fmt.Sprintf("$%s", envVarName)

			// Update AST
			run := step.Exec.(*ast.ExecRun)
			if run.Run != nil {
				run.Run.Value = strings.ReplaceAll(
					run.Run.Value,
					fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw),
					fmt.Sprintf("$%s", envVarName),
				)
				run.Run.Value = strings.ReplaceAll(
					run.Run.Value,
					fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw),
					fmt.Sprintf("$%s", envVarName),
				)
			}
		} else if step.Exec.Kind() == ast.ExecKindAction {
			// For github-script, use process.env.ENV_VAR
			scriptReplacements[fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)] = fmt.Sprintf("process.env.%s", envVarName)
			scriptReplacements[fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)] = fmt.Sprintf("process.env.%s", envVarName)

			// Update AST
			action := step.Exec.(*ast.ExecAction)
			if scriptInput, ok := action.Inputs["script"]; ok && scriptInput != nil && scriptInput.Value != nil {
				scriptInput.Value.Value = strings.ReplaceAll(
					scriptInput.Value.Value,
					fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw),
					fmt.Sprintf("process.env.%s", envVarName),
				)
				scriptInput.Value.Value = strings.ReplaceAll(
					scriptInput.Value.Value,
					fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw),
					fmt.Sprintf("process.env.%s", envVarName),
				)
			}
		}
	}

	// Update BaseNode with replacements
	if step.BaseNode != nil {
		if len(runReplacements) > 0 {
			if err := ReplaceInRunScript(step.BaseNode, runReplacements); err != nil {
				if !strings.Contains(err.Error(), "run section not found") {
					return fmt.Errorf("failed to replace in run script: %w", err)
				}
			}
		}
		if len(scriptReplacements) > 0 {
			if err := ReplaceInGitHubScript(step.BaseNode, scriptReplacements); err != nil {
				if !strings.Contains(err.Error(), "section not found") && !strings.Contains(err.Error(), "field not found") {
					return fmt.Errorf("failed to replace in github-script: %w", err)
				}
			}
		}
	}

	return nil
}

// generateEnvVarName generates an environment variable name from an untrusted path
func (rule *RequestForgeryRule) generateEnvVarName(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "UNTRUSTED_URL"
	}

	// Common patterns
	if len(parts) >= 4 && parts[0] == ContextGithub && parts[1] == EventCategory {
		category := parts[2]         // pull_request, issue, comment, etc.
		field := parts[len(parts)-1] // title, body, etc.

		categoryUpper := strings.ToUpper(strings.ReplaceAll(category, "_", ""))
		fieldUpper := strings.ToUpper(field)

		if categoryUpper == EventCategoryPR {
			categoryUpper = "PR"
		}

		return fmt.Sprintf("%s_%s", categoryUpper, fieldUpper)
	}

	// Fallback: use last part
	lastPart := parts[len(parts)-1]
	return strings.ToUpper(lastPart)
}

// extractAndParseExpressions extracts all expressions from string and parses them
func (rule *RequestForgeryRule) extractAndParseExpressions(str *ast.String) []parsedExpression {
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
func (rule *RequestForgeryRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput checks if the expression contains untrusted input
func (rule *RequestForgeryRule) checkUntrustedInput(expr parsedExpression) []string {
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
func (rule *RequestForgeryRule) isDefinedInEnv(expr parsedExpression, env *ast.Env) bool {
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
