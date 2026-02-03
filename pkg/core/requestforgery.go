package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"github.com/sisaku-security/sisakulint/pkg/shell"
)

// RequestForgeryRule detects SSRF vulnerabilities in network requests
type RequestForgeryRule struct {
	BaseRule
	severityLevel      string // "critical" or "medium"
	checkPrivileged    bool   // true = check privileged triggers, false = check normal triggers
	stepsWithUntrusted []*stepWithRequestForgery
	workflow           *ast.Workflow
}

type stepWithRequestForgery struct {
	step           *ast.Step
	untrustedExprs []requestForgeryExprInfo
}

type requestForgeryExprInfo struct {
	expr     parsedExpression
	paths    []string
	line     string
	severity RequestForgerySeverity
	command  string
}

type RequestForgerySeverity int

const (
	RequestForgerySeverityURL RequestForgerySeverity = iota
	RequestForgerySeverityHost
	RequestForgerySeverityPath
)

var cloudMetadataURLs = []string{
	"169.254.169.254",
	"metadata.google",
	"169.254.170.2",
	"fd00:ec2::254",
	"[fd00:ec2::254]",
	"100.100.100.200",
	"192.0.0.192",
}

var networkCommandPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:^|[\s|&;(])(curl)\b`),
	regexp.MustCompile(`(?:^|[\s|&;(])(wget)\b`),
	regexp.MustCompile(`(?:^|[\s|&;(])(Invoke-WebRequest)\b`),
	regexp.MustCompile(`(?:^|[\s|&;(])(Invoke-RestMethod)\b`),
	regexp.MustCompile(`(?:^|[\s|&;(])(iwr)\b`),
	regexp.MustCompile(`(?:^|[\s|&;(])(irm)\b`),
	regexp.MustCompile(`\b(fetch)\s*\(`),
	regexp.MustCompile(`\b(axios)\.(get|post|put|delete|patch|head|options|request)\s*\(`),
	regexp.MustCompile(`\b(axios)\s*\(`),
	regexp.MustCompile(`\brequire\s*\(\s*['"]node-fetch['"]\s*\)`),
	regexp.MustCompile(`\b(got)\s*\(`),
	regexp.MustCompile(`\b(request)\s*\(`),
	regexp.MustCompile(`\brequests\.(get|post|put|delete|patch|head|options)\s*\(`),
	regexp.MustCompile(`\burllib\.(request\.)?urlopen\s*\(`),
	regexp.MustCompile(`(?:^|[\s|&;(])(nc)\b`),
	regexp.MustCompile(`(?:^|[\s|&;(])(netcat)\b`),
}

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

func (rule *RequestForgeryRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	return nil
}

func (rule *RequestForgeryRule) VisitJobPre(node *ast.Job) error {
	isPrivileged := rule.hasPrivilegedTriggers()
	if rule.checkPrivileged != isPrivileged {
		return nil
	}

	for _, s := range node.Steps {
		if s.Exec == nil {
			continue
		}

		var stepUntrusted *stepWithRequestForgery

		if s.Exec.Kind() == ast.ExecKindRun {
			run := s.Exec.(*ast.ExecRun)
			if run.Run == nil {
				continue
			}

			script := run.Run.Value
			stepUntrusted = rule.checkScript(script, run.Run, s)
		}

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

func (rule *RequestForgeryRule) checkScript(script string, pos *ast.String, step *ast.Step) *stepWithRequestForgery {
	rule.checkCloudMetadataReferences(script, pos)
	exprs := rule.extractAndParseExpressions(pos)
	if len(exprs) == 0 {
		return nil
	}

	var stepUntrusted *stepWithRequestForgery

	parser := shell.NewShellParser(script)
	cmdCalls := parser.FindNetworkCommands()

	if len(cmdCalls) > 0 {
		stepUntrusted = rule.checkScriptWithAST(cmdCalls, exprs, pos, step)
	}

	if stepUntrusted == nil {
		stepUntrusted = rule.checkScriptWithLines(script, exprs, pos, step)
	}

	return stepUntrusted
}

func (rule *RequestForgeryRule) checkScriptWithAST(cmdCalls []shell.NetworkCommandCall, exprs []parsedExpression, pos *ast.String, step *ast.Step) *stepWithRequestForgery {
	var stepUntrusted *stepWithRequestForgery

	for _, cmdCall := range cmdCalls {
		for _, arg := range cmdCall.Args {
			for _, ghaExpr := range arg.GHAExprs {
				for _, expr := range exprs {
					if strings.TrimSpace(expr.raw) != strings.TrimSpace(ghaExpr) {
						continue
					}

					untrustedPaths := rule.checkUntrustedInput(expr)
					if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, step.Env) {
						if stepUntrusted == nil {
							stepUntrusted = &stepWithRequestForgery{step: step}
						}

						severity := rule.determineSeverityFromArg(arg)

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

func (rule *RequestForgeryRule) checkScriptWithLines(script string, exprs []parsedExpression, pos *ast.String, step *ast.Step) *stepWithRequestForgery {
	var stepUntrusted *stepWithRequestForgery

	lines := strings.Split(script, "\n")
	for lineIdx, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		networkCmd := rule.detectNetworkCommand(line)
		if networkCmd == "" {
			continue
		}

		for _, expr := range exprs {
			if !strings.Contains(line, fmt.Sprintf("${{ %s }}", expr.raw)) &&
				!strings.Contains(line, fmt.Sprintf("${{%s}}", expr.raw)) {
				continue
			}

			untrustedPaths := rule.checkUntrustedInput(expr)
			if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, step.Env) {
				if stepUntrusted == nil {
					stepUntrusted = &stepWithRequestForgery{step: step}
				}

				severity := rule.determineSeverity(line, expr)

				stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, requestForgeryExprInfo{
					expr:     expr,
					paths:    untrustedPaths,
					line:     line,
					severity: severity,
					command:  networkCmd,
				})

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

func (rule *RequestForgeryRule) determineSeverityFromArg(arg shell.CommandArg) RequestForgerySeverity {
	if arg.IsFlag {
		return RequestForgerySeverityPath
	}

	value := arg.LiteralValue
	if value == "" {
		value = arg.Value
	}

	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if strings.Contains(value, "${{") {
			idx := strings.Index(value, "${{")
			prefix := value[:idx]
			if strings.HasSuffix(prefix, "://") {
				return RequestForgerySeverityHost
			}
		}
		return RequestForgerySeverityPath
	}

	if strings.HasPrefix(strings.TrimSpace(value), "${{") {
		return RequestForgerySeverityURL
	}

	return RequestForgerySeverityPath
}

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

func (rule *RequestForgeryRule) detectNetworkCommand(line string) string {
	for _, pattern := range networkCommandPatterns {
		if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
			cmd := matches[1]
			cmd = strings.TrimSuffix(cmd, "(")
			return cmd
		} else if match := pattern.FindString(line); match != "" {
			words := strings.Fields(match)
			if len(words) > 0 {
				cmd := words[0]
				cmd = strings.TrimSuffix(cmd, "(")
				if idx := strings.Index(cmd, "."); idx != -1 {
					cmd = cmd[:idx]
				}
				return cmd
			}
		}
	}
	return ""
}

func (rule *RequestForgeryRule) determineSeverity(line string, expr parsedExpression) RequestForgerySeverity {
	exprPattern := fmt.Sprintf("${{ %s }}", expr.raw)
	exprPatternNoSpace := fmt.Sprintf("${{%s}}", expr.raw)

	fullURLPattern := regexp.MustCompile(`\b(curl|wget|http|https|fetch|axios)\s+["']?` + regexp.QuoteMeta(exprPattern))
	fullURLPatternNoSpace := regexp.MustCompile(`\b(curl|wget|http|https|fetch|axios)\s+["']?` + regexp.QuoteMeta(exprPatternNoSpace))
	if fullURLPattern.MatchString(line) || fullURLPatternNoSpace.MatchString(line) {
		return RequestForgerySeverityURL
	}

	hostPattern := regexp.MustCompile(`https?://` + regexp.QuoteMeta(exprPattern))
	hostPatternNoSpace := regexp.MustCompile(`https?://` + regexp.QuoteMeta(exprPatternNoSpace))
	if hostPattern.MatchString(line) || hostPatternNoSpace.MatchString(line) {
		return RequestForgerySeverityHost
	}

	return RequestForgerySeverityPath
}

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

func (rule *RequestForgeryRule) hasPrivilegedTriggers() bool {
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

func (rule *RequestForgeryRule) RuleNames() string {
	return rule.RuleName
}

func (rule *RequestForgeryRule) FixStep(step *ast.Step) error {
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

	if step.Env == nil {
		step.Env = &ast.Env{
			Vars: make(map[string]*ast.EnvVar),
		}
	}
	if step.Env.Vars == nil {
		step.Env.Vars = make(map[string]*ast.EnvVar)
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

	runReplacements := make(map[string]string)
	scriptReplacements := make(map[string]string)

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		envVarName := envVarMap[untrustedInfo.expr.raw]

		if step.Exec.Kind() == ast.ExecKindRun {
			runReplacements[fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)] = fmt.Sprintf("$%s", envVarName)
			runReplacements[fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)] = fmt.Sprintf("$%s", envVarName)

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
			scriptReplacements[fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)] = fmt.Sprintf("process.env.%s", envVarName)
			scriptReplacements[fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)] = fmt.Sprintf("process.env.%s", envVarName)

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

func (rule *RequestForgeryRule) generateEnvVarName(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "UNTRUSTED_URL"
	}

	var name string

	if len(parts) >= 4 && parts[0] == ContextGithub && parts[1] == EventCategory {
		category := parts[2]
		field := parts[len(parts)-1]

		categoryUpper := strings.ToUpper(strings.ReplaceAll(category, "_", ""))
		fieldUpper := strings.ToUpper(field)

		if categoryUpper == EventCategoryPR {
			categoryUpper = "PR"
		}

		name = fmt.Sprintf("%s_%s", categoryUpper, fieldUpper)
	} else {
		lastPart := parts[len(parts)-1]
		name = strings.ToUpper(lastPart)
	}

	name = sanitizeEnvVarName(name)

	return name
}

func sanitizeEnvVarName(name string) string {
	var result strings.Builder
	for i, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			if i == 0 && r >= '0' && r <= '9' {
				result.WriteRune('_')
			}
			result.WriteRune(r)
		} else if r >= 'a' && r <= 'z' {
			result.WriteRune(r - 'a' + 'A')
		} else {
			result.WriteRune('_')
		}
	}

	if result.Len() == 0 {
		return "VAR"
	}

	return result.String()
}

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

func (rule *RequestForgeryRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

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
