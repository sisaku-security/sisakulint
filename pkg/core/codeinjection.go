package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// CodeInjectionRule is a shared implementation for detecting code injection vulnerabilities
// It can be configured to check either privileged triggers (critical) or normal triggers (medium)
type CodeInjectionRule struct {
	BaseRule
	severityLevel      string // "critical" or "medium"
	checkPrivileged    bool   // true = check privileged triggers, false = check normal triggers
	stepsWithUntrusted []*stepWithUntrustedInput
	workflow           *ast.Workflow
	taintTracker       *TaintTracker // Tracks taint propagation through step outputs
	// workflowTriggers stores all trigger names from the workflow
	workflowTriggers []string
	// jobHasMatchingTriggers indicates if the current job can execute on matching triggers
	// (privileged for critical, normal for medium)
	jobHasMatchingTriggers bool
	// workflowTaintMap is shared between Critical and Medium rule instances.
	// Nil if cross-job taint propagation is disabled (e.g., in unit tests).
	workflowTaintMap *WorkflowTaintMap
	// pendingCrossJobChecks holds checks that couldn't be resolved because the upstream
	// job hadn't been processed yet (reverse yaml order). Flushed in VisitWorkflowPost.
	pendingCrossJobChecks []pendingCrossJobCheck
}

// reportCodeInjectionError emits the appropriate Errorf for a code injection finding.
// It centralises the message formatting that is shared between VisitJobPre (normal path)
// and VisitWorkflowPost (deferred cross-job path).
func (rule *CodeInjectionRule) reportCodeInjectionError(pos *ast.Position, taintPath string, isInRunScript bool) {
	scriptType := "github-script"
	if isInRunScript {
		scriptType = "inline scripts"
	}

	if rule.checkPrivileged {
		rule.Errorf(
			pos,
			"code injection (critical): \"%s\" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in %s. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/",
			taintPath, scriptType,
		)
	} else {
		rule.Errorf(
			pos,
			"code injection (medium): \"%s\" is potentially untrusted. Avoid using it directly in %s. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectionmedium/",
			taintPath, scriptType,
		)
	}
}

// pendingCrossJobCheck stores a cross-job taint check that needs to be retried in VisitWorkflowPost.
type pendingCrossJobCheck struct {
	expr          parsedExpression
	needsJobID    string
	outputName    string
	step          *ast.Step  // the step containing the expression; needed for isDefinedInEnv and auto-fix
	isInRunScript bool       // true = run: script, false = actions/github-script
	scriptInput   *ast.Input // non-nil when isInRunScript is false
}

// stepWithUntrustedInput tracks steps that need auto-fixing
type stepWithUntrustedInput struct {
	step           *ast.Step
	untrustedExprs []untrustedExprInfo
}

// untrustedExprInfo contains information about an untrusted expression
type untrustedExprInfo struct {
	expr          parsedExpression
	paths         []string
	isInRunScript bool       // true for run:, false for script: in github-script
	scriptInput   *ast.Input // only set if isInRunScript is false
}

// parsedExpression represents a parsed expression with its position and AST node
type parsedExpression struct {
	raw  string               // Original expression content
	node expressions.ExprNode // Parsed AST node
	pos  *ast.Position        // Position in source
}

// newCodeInjectionRule creates a new code injection rule with the specified severity level.
// wfTaintMap is shared between Critical and Medium instances; pass nil to disable cross-job tracking.
func newCodeInjectionRule(severityLevel string, checkPrivileged bool, wfTaintMap *WorkflowTaintMap) *CodeInjectionRule {
	var desc string

	if checkPrivileged {
		desc = "Checks for code injection vulnerabilities when untrusted input is used directly in run scripts or script actions with privileged workflow triggers (pull_request_target, workflow_run, issue_comment). See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/"
	} else {
		desc = "Checks for code injection vulnerabilities when untrusted input is used directly in run scripts or script actions with normal workflow triggers (pull_request, push, etc.). See https://sisaku-security.github.io/lint/docs/rules/codeinjectionmedium/"
	}

	return &CodeInjectionRule{
		BaseRule: BaseRule{
			RuleName: "code-injection-" + severityLevel,
			RuleDesc: desc,
		},
		severityLevel:      severityLevel,
		checkPrivileged:    checkPrivileged,
		stepsWithUntrusted: make([]*stepWithUntrustedInput, 0),
		workflowTaintMap:   wfTaintMap,
	}
}

// VisitWorkflowPre is called before visiting a workflow
func (rule *CodeInjectionRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	rule.workflowTriggers = nil
	rule.jobHasMatchingTriggers = false

	// Collect all workflow triggers
	for _, event := range node.On {
		switch e := event.(type) {
		case *ast.WebhookEvent:
			if e.Hook != nil {
				rule.workflowTriggers = append(rule.workflowTriggers, e.Hook.Value)
			}
		case *ast.WorkflowCallEvent:
			rule.workflowTriggers = append(rule.workflowTriggers, "workflow_call")
		}
	}

	// Reset WorkflowTaintMap for this workflow
	if rule.workflowTaintMap != nil {
		rule.workflowTaintMap.Reset()
		rule.pendingCrossJobChecks = nil
	}

	return nil
}

func (rule *CodeInjectionRule) VisitJobPre(node *ast.Job) error {
	// Reset job-level state
	rule.jobHasMatchingTriggers = false

	// Use JobTriggerAnalyzer to determine effective triggers for this job
	// This considers job-level if conditions that may filter out certain triggers
	analyzer := NewJobTriggerAnalyzer(rule.workflowTriggers)
	effectiveTriggers := analyzer.AnalyzeJobTriggers(node)

	// Check if this job can run on privileged triggers
	hasPrivileged := false
	hasNormal := false
	for _, trigger := range effectiveTriggers {
		if isPrivilegedTrigger(trigger) {
			hasPrivileged = true
		} else {
			hasNormal = true
		}
	}

	// Determine if this job matches what we're looking for
	if rule.checkPrivileged {
		// Critical rule: only check jobs that can run on privileged triggers
		rule.jobHasMatchingTriggers = hasPrivileged
	} else {
		// Medium rule: only check jobs that can run on normal triggers
		// but NOT on privileged triggers (to avoid duplicate warnings)
		rule.jobHasMatchingTriggers = hasNormal && !hasPrivileged
	}

	// Initialize taint tracker per job to avoid cross-job contamination.
	// This must happen for every job (not just matching ones) so that
	// RegisterJobOutputs can analyze outputs for downstream cross-job tracking.
	rule.taintTracker = NewTaintTracker()

	// First pass: collect taint information from all steps
	// This allows us to detect tainted step outputs before checking for code injection
	for _, s := range node.Steps {
		rule.taintTracker.AnalyzeStep(s)
	}

	// Register this job's outputs into WorkflowTaintMap for downstream jobs.
	// Done before the trigger-match skip so that even skipped jobs contribute their
	// outputs to the cross-job taint graph.
	if rule.workflowTaintMap != nil && node.ID != nil {
		rule.workflowTaintMap.RegisterJobOutputs(node.ID.Value, rule.taintTracker, node.Outputs)
	}

	// Skip injection checks if this job doesn't match our trigger criteria
	if !rule.jobHasMatchingTriggers {
		return nil
	}

	// Second pass: check for code injection vulnerabilities
	for _, s := range node.Steps {
		if s.Exec == nil {
			continue
		}

		var stepUntrusted *stepWithUntrustedInput

		// Check run: scripts
		if s.Exec.Kind() == ast.ExecKindRun {
			run := s.Exec.(*ast.ExecRun)
			exprs := rule.extractAndParseExpressions(run.Run)

			for _, expr := range exprs {
				// Use checkUntrustedInputWithTaint to also detect tainted step outputs
				untrustedPaths, crossJobPending := rule.checkUntrustedInputWithTaint(expr)
				if crossJobPending {
					rule.addPendingCrossJobCheck(expr, s, true, nil)
				}
				if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, s.Env) {
					if stepUntrusted == nil {
						stepUntrusted = &stepWithUntrustedInput{step: s}
					}
					stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, untrustedExprInfo{
						expr:          expr,
						paths:         untrustedPaths,
						isInRunScript: true,
					})

					rule.reportCodeInjectionError(expr.pos, strings.Join(untrustedPaths, "\", \""), true)
				}
			}
		}

		// Check actions/github-script script: parameter
		if s.Exec.Kind() == ast.ExecKindAction {
			action := s.Exec.(*ast.ExecAction)
			if action.Uses != nil && strings.HasPrefix(action.Uses.Value, "actions/github-script@") {
				if scriptInput, ok := action.Inputs["script"]; ok && scriptInput != nil && scriptInput.Value != nil {
					exprs := rule.extractAndParseExpressions(scriptInput.Value)

					for _, expr := range exprs {
						// Use checkUntrustedInputWithTaint to also detect tainted step outputs
						untrustedPaths, crossJobPending := rule.checkUntrustedInputWithTaint(expr)
						if crossJobPending {
							rule.addPendingCrossJobCheck(expr, s, false, scriptInput)
						}
						if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, s.Env) {
							if stepUntrusted == nil {
								stepUntrusted = &stepWithUntrustedInput{step: s}
							}
							stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, untrustedExprInfo{
								expr:          expr,
								paths:         untrustedPaths,
								isInRunScript: false,
								scriptInput:   scriptInput,
							})

							rule.reportCodeInjectionError(expr.pos, strings.Join(untrustedPaths, "\", \""), false)
						}
					}
				}
			}
		}

		if stepUntrusted != nil {
			rule.stepsWithUntrusted = append(rule.stepsWithUntrusted, stepUntrusted)
			rule.AddAutoFixer(NewStepFixer(s, rule))
		}

		envVarsWithUntrusted := rule.extractEnvVarsWithUntrustedInput(s)
		if len(envVarsWithUntrusted) > 0 {
			rule.checkShellMetacharacterInjection(s, envVarsWithUntrusted)
		}
		rule.checkDangerousShellPatterns(s)
	}
	return nil
}

// VisitWorkflowPost is called after all jobs have been visited.
// It flushes pending cross-job taint checks that couldn't be resolved during VisitJobPre
// (e.g., when a downstream job appears before its upstream job in the yaml file).
func (rule *CodeInjectionRule) VisitWorkflowPost(node *ast.Workflow) error {
	if rule.workflowTaintMap == nil || len(rule.pendingCrossJobChecks) == 0 {
		return nil
	}

	for _, pending := range rule.pendingCrossJobChecks {
		sources, stillPending := rule.workflowTaintMap.ResolveFromExprNode(pending.expr.node)
		if stillPending {
			// This can happen when the upstream job ID referenced in the expression
			// (needs.<jobID>.outputs.<name>) was never registered in the workflow taint map,
			// e.g., a typo in the job ID or a conditional job that was excluded from analysis.
			rule.Debug("cross-job taint check still pending after all jobs visited: expr=%q, needsJobID=%q, outputName=%q", pending.expr.raw, pending.needsJobID, pending.outputName)
			continue
		}
		if len(sources) == 0 {
			continue
		}

		// Mirror the normal-path filter: skip if the expression is already
		// assigned to an env variable in the same step.
		if pending.step != nil && rule.isDefinedInEnv(pending.expr, pending.step.Env) {
			continue
		}

		taintPath := fmt.Sprintf("%s (tainted via %s)", pending.expr.raw, strings.Join(sources, ", "))

		rule.reportCodeInjectionError(pending.expr.pos, taintPath, pending.isInRunScript)

		// Wire up auto-fix, mirroring the normal path.
		if pending.step != nil {
			var stepUntrusted *stepWithUntrustedInput
			for _, s := range rule.stepsWithUntrusted {
				if s.step == pending.step {
					stepUntrusted = s
					break
				}
			}
			if stepUntrusted == nil {
				stepUntrusted = &stepWithUntrustedInput{step: pending.step}
				rule.stepsWithUntrusted = append(rule.stepsWithUntrusted, stepUntrusted)
				rule.AddAutoFixer(NewStepFixer(pending.step, rule))
			}
			stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, untrustedExprInfo{
				expr:          pending.expr,
				paths:         []string{taintPath},
				isInRunScript: pending.isInRunScript,
				scriptInput:   pending.scriptInput,
			})
		}
	}

	rule.pendingCrossJobChecks = nil
	return nil
}

// RuleNames implements StepFixer interface
func (rule *CodeInjectionRule) RuleNames() string {
	return rule.RuleName
}

// FixStep implements StepFixer interface
func (rule *CodeInjectionRule) FixStep(step *ast.Step) error {
	// Find the stepWithUntrustedInput for this step
	var stepInfo *stepWithUntrustedInput
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
	envVarsForYAML := make(map[string]string) // env var name -> env var value (for BaseNode)

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

	// Build replacement maps for run: and script:
	runReplacements := make(map[string]string)
	scriptReplacements := make(map[string]string)

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		envVarName := envVarMap[untrustedInfo.expr.raw]

		if untrustedInfo.isInRunScript {
			// For run: scripts, use $ENV_VAR
			runReplacements[fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)] = fmt.Sprintf("$%s", envVarName)
			runReplacements[fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)] = fmt.Sprintf("$%s", envVarName)

			// Also update AST
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
		} else {
			// For github-script, use process.env.ENV_VAR
			scriptReplacements[fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)] = fmt.Sprintf("process.env.%s", envVarName)
			scriptReplacements[fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)] = fmt.Sprintf("process.env.%s", envVarName)

			// Also update AST
			if untrustedInfo.scriptInput != nil && untrustedInfo.scriptInput.Value != nil {
				untrustedInfo.scriptInput.Value.Value = strings.ReplaceAll(
					untrustedInfo.scriptInput.Value.Value,
					fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw),
					fmt.Sprintf("process.env.%s", envVarName),
				)
				untrustedInfo.scriptInput.Value.Value = strings.ReplaceAll(
					untrustedInfo.scriptInput.Value.Value,
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
				// Ignore error if run section doesn't exist (might be github-script)
				if !strings.Contains(err.Error(), "run section not found") {
					return fmt.Errorf("failed to replace in run script: %w", err)
				}
			}
		}
		if len(scriptReplacements) > 0 {
			if err := ReplaceInGitHubScript(step.BaseNode, scriptReplacements); err != nil {
				// Ignore error if with/script section doesn't exist (might be run:)
				if !strings.Contains(err.Error(), "section not found") && !strings.Contains(err.Error(), "field not found") {
					return fmt.Errorf("failed to replace in github-script: %w", err)
				}
			}
		}
	}

	return nil
}

// generateEnvVarName generates an environment variable name from an untrusted path
func (rule *CodeInjectionRule) generateEnvVarName(path string) string {
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
		fieldUpper := strings.ToUpper(field)

		// Create readable name
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
func (rule *CodeInjectionRule) extractAndParseExpressions(str *ast.String) []parsedExpression {
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

			var pos *ast.Position
			if str.Pos != nil {
				pos = &ast.Position{
					Line: str.Pos.Line + lineIdx,
					Col:  str.Pos.Col + col,
				}
				if str.Literal {
					pos.Line += 1
				}
			} else {
				pos = &ast.Position{Line: lineIdx + 1, Col: col + 1}
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
func (rule *CodeInjectionRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput checks if the expression contains untrusted input
func (rule *CodeInjectionRule) checkUntrustedInput(expr parsedExpression) []string {
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

// checkUntrustedInputWithTaint checks if the expression contains untrusted input,
// including tainted step outputs tracked by TaintTracker.
// This extends checkUntrustedInput to detect indirect taint propagation.
//
// The second return value is true when the expression references a cross-job
// needs output whose upstream job has not yet been processed.  In that case
// the caller is responsible for recording a pendingCrossJobCheck with the
// full step context so that VisitWorkflowPost can re-evaluate and emit errors.
//
// Example: If step "get-ref" writes untrusted input to $GITHUB_OUTPUT,
// then steps.get-ref.outputs.ref will be detected as tainted.
func (rule *CodeInjectionRule) checkUntrustedInputWithTaint(expr parsedExpression) ([]string, bool) {
	// Check built-in untrusted inputs
	paths := rule.checkUntrustedInput(expr)

	// Check intra-job tainted step outputs (steps.X.outputs.Y)
	if rule.taintTracker != nil {
		if tainted, sources := rule.taintTracker.IsTainted(expr.node); tainted {
			for _, source := range sources {
				taintPath := fmt.Sprintf("%s (tainted via %s)", expr.raw, source)
				paths = append(paths, taintPath)
			}
		}
	}

	// Check cross-job tainted needs outputs (needs.X.outputs.Y)
	if rule.workflowTaintMap != nil {
		sources, pending := rule.workflowTaintMap.ResolveFromExprNode(expr.node)
		if pending {
			// Upstream job not yet processed; signal the caller to defer.
			return paths, true
		} else if len(sources) > 0 {
			for _, source := range sources {
				taintPath := fmt.Sprintf("%s (tainted via %s)", expr.raw, source)
				paths = append(paths, taintPath)
			}
		}
	}

	return paths, false
}

// addPendingCrossJobCheck parses expr for needs.X.outputs.Y and stores it for retry in VisitWorkflowPost.
// step, isInRunScript, and scriptInput carry the context from the calling site so that
// VisitWorkflowPost can call isDefinedInEnv and wire up auto-fix correctly.
func (rule *CodeInjectionRule) addPendingCrossJobCheck(expr parsedExpression, step *ast.Step, isInRunScript bool, scriptInput *ast.Input) {
	exprStr := exprNodeToString(expr.node)
	lower := strings.ToLower(exprStr)
	parts := strings.Split(lower, ".")
	if len(parts) < 4 || parts[0] != "needs" || parts[2] != "outputs" {
		return
	}
	rule.pendingCrossJobChecks = append(rule.pendingCrossJobChecks, pendingCrossJobCheck{
		expr:          expr,
		needsJobID:    parts[1],
		outputName:    strings.Join(parts[3:], "."),
		step:          step,
		isInRunScript: isInRunScript,
		scriptInput:   scriptInput,
	})
}

// isDefinedInEnv checks if the expression is defined in the step's env section
func (rule *CodeInjectionRule) isDefinedInEnv(expr parsedExpression, env *ast.Env) bool {
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

// extractExpressionsFromString extracts expression contents from a string containing ${{ }}
func extractExpressionsFromString(s string) []string {
	var results []string
	offset := 0

	for {
		idx := strings.Index(s[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx + 3
		endIdx := strings.Index(s[start:], "}}")
		if endIdx == -1 {
			break
		}

		exprContent := strings.TrimSpace(s[start : start+endIdx])
		results = append(results, exprContent)

		offset = start + endIdx + 2
	}

	return results
}

// normalizeExpression normalizes an expression by removing extra whitespace
func normalizeExpression(expr string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(expr)), " ")
}
