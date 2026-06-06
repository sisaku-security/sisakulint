package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"gopkg.in/yaml.v3"
	"mvdan.cc/sh/v3/syntax"
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
	step *ast.Step
	// job is the enclosing job at the time the step was recorded. Retained
	// so FixStep can consult job-level env vars (and reach workflow.Env via
	// the rule) when deciding whether a generated env var name would
	// shadow an inherited variable.
	job            *ast.Job
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
		desc = "Checks for PATH injection vulnerabilities when untrusted input is written to $GITHUB_PATH in privileged workflow triggers (pull_request_target, workflow_run, issue_comment). See https://sisaku-security.github.io/lint/docs/rules/envpathinjectioncritical/"
	} else {
		desc = "Checks for PATH injection vulnerabilities when untrusted input is written to $GITHUB_PATH in normal workflow triggers (pull_request, push, etc.). See https://sisaku-security.github.io/lint/docs/rules/envpathinjectionmedium/"
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
						stepUntrusted = &stepWithEnvPathInjection{step: s, job: node}
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
							"PATH injection (critical): \"%s\" is potentially untrusted and written to $GITHUB_PATH in a workflow with privileged triggers. This can allow attackers to hijack command execution by prepending a malicious directory to PATH. Validate the path or use absolute paths instead. See https://sisaku-security.github.io/lint/docs/rules/envpathinjectioncritical/",
							strings.Join(untrustedPaths, "\", \""),
						)
					} else {
						rule.Errorf(
							linePos,
							"PATH injection (medium): \"%s\" is potentially untrusted and written to $GITHUB_PATH. This can allow attackers to hijack command execution by prepending a malicious directory to PATH. Validate the path or use absolute paths instead. See https://sisaku-security.github.io/lint/docs/rules/envpathinjectionmedium/",
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
	return HasPrivilegedTriggers(rule.workflow)
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
	envVarMap := make(map[string]string)      // expr.raw -> chosen env var name
	envVarsForYAML := make(map[string]string) // env var name -> env var value

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		expr := untrustedInfo.expr

		// Generate environment variable name from the untrusted path
		baseEnvVarName := rule.generateEnvVarName(untrustedInfo.paths[0])

		// Check if we already created an env var for this expression
		if _, exists := envVarMap[expr.raw]; !exists {
			exprValue := fmt.Sprintf("${{ %s }}", expr.raw)
			envVarName := rule.envVarNameForExpression(step, stepInfo.job, run.Run.Value, baseEnvVarName, exprValue, expr.pos, envVarsForYAML)
			envVarMap[expr.raw] = envVarName
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

				// Only rewrite the env var actually chosen for this expression.
				// When envVarNameForExpression suffixes the name (e.g., PR_BODY_2)
				// because the base name is occupied by an unrelated user value,
				// the base name must be left untouched — otherwise the user's
				// `$PR_BODY` references on GITHUB_PATH lines get silently
				// rewritten to the attacker-controlled value.
				validatedVar := fmt.Sprintf("$(realpath \"$%s\")", envVarName)
				if strings.Contains(line, validatedVar) {
					continue
				}
				line = replaceShellEnvVarRef(line, envVarName, validatedVar)
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

func (rule *EnvPathInjectionRule) envVarNameForExpression(
	step *ast.Step,
	job *ast.Job,
	runScript string,
	baseName string,
	exprValue string,
	pos *ast.Position,
	envVarsForYAML map[string]string,
) string {
	for suffix := 0; ; suffix++ {
		candidate := baseName
		if suffix > 0 {
			candidate = fmt.Sprintf("%s_%d", baseName, suffix+1)
		}

		key := strings.ToLower(candidate)
		if existing, exists := lookupEnvVar(step.Env, key); exists {
			// Linux shell env vars are case-sensitive; the AST keys
			// envs by lowercase name but preserves the original casing
			// in Name.Value. Always return the inherited casing so a
			// later `$NAME` rewrite resolves to the real env var.
			if existing.value == exprValue {
				return existing.actualName
			}
			continue
		}
		// GitHub Actions env precedence is step > job > workflow. A
		// step-level env var with the same name would silently shadow
		// any inherited value for the rest of the step, redirecting any
		// command that consumes the inherited env var (curl, kubectl,
		// etc.) to the attacker-controlled body. Treat job-level and
		// workflow-level env entries as collisions, reusing the name
		// only when the inherited value is the exact same expression
		// the autofix would emit. Return the inherited variable's
		// actual casing for the same reason as the step lookup above.
		if inherited, has := lookupInheritedEnvVar(rule.workflow, job, key); has {
			if inherited.value == exprValue {
				return inherited.actualName
			}
			continue
		}
		// When creating a new env var (not reusing an existing one with the
		// same expression), make sure the chosen name does not collide with
		// a shell variable the run script already assigns or references.
		// Otherwise the autofix would silently shadow the user's `$NAME`
		// reference with the new env var's attacker-controlled value.
		if scriptUsesShellName(runScript, candidate) {
			continue
		}

		step.Env.Vars[key] = &ast.EnvVar{
			Name:  &ast.String{Value: candidate, Pos: pos},
			Value: &ast.String{Value: exprValue, Pos: pos},
		}
		envVarsForYAML[candidate] = exprValue
		return candidate
	}
}

// envVarLookup carries the case-preserving name and raw value of an
// existing env var entry. actualName falls back to the lookup key only
// when the entry stores no Name.Value (defensive — the parser should
// always populate it).
type envVarLookup struct {
	actualName string
	value      string
}

func lookupEnvVar(env *ast.Env, key string) (envVarLookup, bool) {
	if env == nil || env.Vars == nil {
		return envVarLookup{}, false
	}
	ev, ok := env.Vars[key]
	if !ok {
		return envVarLookup{}, false
	}
	out := envVarLookup{actualName: key}
	if ev != nil {
		if ev.Name != nil && ev.Name.Value != "" {
			out.actualName = ev.Name.Value
		}
		if ev.Value != nil {
			out.value = ev.Value.Value
		}
	}
	return out, true
}

// lookupInheritedEnvVar walks job.Env then workflow.Env in GitHub Actions
// precedence order and returns the first matching entry. The lookup is
// keyed by the already-lowercased candidate name.
func lookupInheritedEnvVar(workflow *ast.Workflow, job *ast.Job, key string) (envVarLookup, bool) {
	if job != nil {
		if lk, ok := lookupEnvVar(job.Env, key); ok {
			return lk, true
		}
	}
	if workflow != nil {
		if lk, ok := lookupEnvVar(workflow.Env, key); ok {
			return lk, true
		}
	}
	return envVarLookup{}, false
}

// scriptUsesShellName reports whether the run script assigns to or
// references a shell variable with the given name. GitHub Actions
// `${{ ... }}` expressions are stripped first so they cannot
// false-positive on path components like `${{ github.event.NAME }}`.
//
// Detection uses the bash AST when the sanitized script parses cleanly:
// every ParamExp `Param.Value` and Assign `Name.Value` is collected, so
// all parameter-expansion shapes are recognized — `${NAME}`,
// `${NAME:-default}`, `${NAME:+alt}`, `${NAME#prefix}`, `${NAME%suffix}`,
// `${NAME/pat/repl}`, `${NAME^^}`, `${#NAME}`, `${!NAME}`, etc. — plus
// plain `$NAME` and `NAME=...` (including `export NAME=...`,
// `local NAME=...`). On parse failure (best-effort), falls back to a
// regex that catches the common `${NAME}`, `$NAME`, and `NAME=` forms.
//
// Used by envVarNameForExpression to keep the autofix from generating
// an env var name that would shadow a script-level shell variable.
func scriptUsesShellName(script, name string) bool {
	if name == "" || script == "" {
		return false
	}
	sanitized, _ := sanitizeForShellParse(script)

	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(sanitized), "")
	if err != nil || file == nil {
		return scriptUsesShellNameRegex(sanitized, name)
	}

	var found bool
	syntax.Walk(file, func(node syntax.Node) bool {
		if found || node == nil {
			return false
		}
		switch x := node.(type) {
		case *syntax.ParamExp:
			if x.Param != nil && x.Param.Value == name {
				found = true
				return false
			}
		case *syntax.Assign:
			if x.Name != nil && x.Name.Value == name {
				found = true
				return false
			}
		case *syntax.CallExpr:
			// Built-ins like `read NAME`, `mapfile NAME`, `readarray NAME`
			// bind the named variable but are represented as plain CallExpr
			// (not Assign) in the AST. Recognize the common ones so the
			// autofix doesn't shadow a user-assigned shell variable.
			if callAssignsName(x, name) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// callAssignsName reports whether a CallExpr is a built-in command that
// assigns to the named variable (e.g., `read NAME`, `mapfile NAME`,
// `readarray NAME`). The flag-and-operand grammar of these built-ins is
// approximated: anything that does not start with `-` and isn't `--` is
// treated as a candidate variable name. False positives only cause the
// autofix to suffix more aggressively, which is conservative.
func callAssignsName(call *syntax.CallExpr, name string) bool {
	if len(call.Args) < 2 {
		return false
	}
	cmd := wordLitValue(call.Args[0])
	switch cmd {
	case "read", "mapfile", "readarray":
		for _, arg := range call.Args[1:] {
			v := wordLitValue(arg)
			if v == "" || v == "--" || strings.HasPrefix(v, "-") {
				continue
			}
			if v == name {
				return true
			}
		}
	}
	return false
}

// wordLitValue returns the literal-string value of a Word when it is
// composed of plain Lits (and/or DblQuoted-wrapped Lits). Returns "" for
// Words containing expansions, command substitutions, etc.
func wordLitValue(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit:
			b.WriteString(x.Value)
		case *syntax.SglQuoted:
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, inner := range x.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return ""
				}
				b.WriteString(lit.Value)
			}
		default:
			return ""
		}
	}
	return b.String()
}

// scriptUsesShellNameRegex is the best-effort fallback used when the
// shell parser cannot parse the sanitized run script. It catches the
// common shapes but does not understand all parameter-expansion
// operators. Prefer the AST path; this exists only so a parse error
// does not silently bypass the collision check.
func scriptUsesShellNameRegex(sanitized, name string) bool {
	q := regexp.QuoteMeta(name)
	re := regexp.MustCompile(
		`\$\{#?!?` + q + `(?:[}:#%/^,@]|$)` +
			`|\$` + q + `(?:[^A-Za-z0-9_]|$)` +
			`|(?:^|[^A-Za-z0-9_.])` + q + `=`,
	)
	return re.MatchString(sanitized)
}

func replaceShellEnvVarRef(line, envVarName, replacement string) string {
	if envVarName == "" {
		return line
	}

	// Match both `${NAME}` and `$NAME` (word-boundary terminated) in a
	// single non-overlapping pass so that a `$NAME` produced inside the
	// replacement (e.g. `$(realpath "$PR_BODY")`) is not re-rewritten by a
	// subsequent pass and double-wrapped. ReplaceAllStringFunc returns the
	// callback output as-is — no `$name` Expand interpretation — so the
	// replacement is treated as a pure literal.
	q := regexp.QuoteMeta(envVarName)
	re := regexp.MustCompile(`\$\{` + q + `\}|\$` + q + `([^A-Za-z0-9_]|$)`)
	plainPrefix := "$" + envVarName
	return re.ReplaceAllStringFunc(line, func(match string) string {
		if strings.HasPrefix(match, "${") {
			return replacement
		}
		if match == plainPrefix {
			return replacement
		}
		return replacement + match[len(plainPrefix):]
	})
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
	path = stripTaintAnnotation(path)
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "UNTRUSTED_INPUT"
	}

	// Common patterns
	if len(parts) >= 4 && parts[0] == ContextGithub && parts[1] == EventCategory {
		category := parts[2]         // pull_request, issue, comment, etc.
		field := parts[len(parts)-1] // title, body, etc.

		// Convert to uppercase and join
		categoryUpper := strings.ToUpper(strings.ReplaceAll(category, "_", ""))
		fieldUpper := sanitizeEnvVarNameComponent(field)

		// Create readable name
		if categoryUpper == EventCategoryPR {
			categoryUpper = "PR"
		}

		return sanitizeEnvVarNameComponent(fmt.Sprintf("%s_%s", categoryUpper, fieldUpper))
	}

	// Fallback: use last part
	lastPart := parts[len(parts)-1]
	if name := sanitizeEnvVarNameComponent(lastPart); name != "" {
		return name
	}
	return "UNTRUSTED_INPUT"
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
