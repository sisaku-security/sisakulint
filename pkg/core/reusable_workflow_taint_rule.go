package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// ReusableWorkflowTaintRule detects when untrusted inputs are passed to reusable workflows
// and tracks tainted inputs within the callee workflow.
//
// Attack scenario:
// 1. Caller workflow passes ${{ github.event.pull_request.title }} as input to reusable workflow
// 2. Reusable workflow uses ${{ inputs.title }} in a run script
// 3. This creates a code injection vulnerability through the reusable workflow
//
// This rule tracks the flow:
// - Detects untrusted inputs being passed via `with:` in workflow_call jobs
// - Tracks `inputs.*` context as tainted when called with untrusted values
// - Reports when tainted inputs are used in dangerous contexts within reusable workflows
type ReusableWorkflowTaintRule struct {
	BaseRule
	workflow             *ast.Workflow
	workflowPath         string
	cache                *LocalReusableWorkflowCache
	isReusableWorkflow   bool
	hasPrivilegedTrigger bool
	// stepsWithTaintedInputs tracks steps that use tainted inputs
	stepsWithTaintedInputs []*stepWithTaintedInput
}

// stepWithTaintedInput tracks steps that use tainted inputs
type stepWithTaintedInput struct {
	step        *ast.Step
	taintedInfo []taintedInputInfo
}

// taintedInputInfo contains information about a tainted input usage
type taintedInputInfo struct {
	inputName     string // e.g., "title"
	inputPath     string // e.g., "inputs.title"
	pos           *ast.Position
	isInRunScript bool
}

// NewReusableWorkflowTaintRule creates a new instance of ReusableWorkflowTaintRule
func NewReusableWorkflowTaintRule(workflowPath string, cache *LocalReusableWorkflowCache) *ReusableWorkflowTaintRule {
	return &ReusableWorkflowTaintRule{
		BaseRule: BaseRule{
			RuleName: "reusable-workflow-taint",
			RuleDesc: "Detects when untrusted inputs are passed to reusable workflows and used in dangerous contexts. See https://sisaku-security.github.io/lint/docs/rules/reusableworkflowtaint/",
		},
		workflowPath: workflowPath,
		cache:        cache,
	}
}

// VisitWorkflowPre is called before visiting workflow children
func (rule *ReusableWorkflowTaintRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	rule.isReusableWorkflow = false
	rule.hasPrivilegedTrigger = false

	// Check if this is a reusable workflow (has workflow_call trigger)
	for _, event := range node.On {
		if _, ok := event.(*ast.WorkflowCallEvent); ok {
			rule.isReusableWorkflow = true
		}
		// Check for privileged triggers
		eventName := strings.ToLower(event.EventName())
		if isPrivilegedTrigger(eventName) {
			rule.hasPrivilegedTrigger = true
		}
	}

	return nil
}

// VisitJobPre is called before visiting job children
func (rule *ReusableWorkflowTaintRule) VisitJobPre(node *ast.Job) error {
	// Case 1: This job calls a reusable workflow - check if untrusted inputs are passed
	if node.WorkflowCall != nil {
		rule.checkWorkflowCallInputs(node)
	}

	// Case 2: This workflow IS a reusable workflow - check for tainted input usage in steps
	if rule.isReusableWorkflow && len(node.Steps) > 0 {
		rule.checkTaintedInputUsageInSteps(node)
	}

	return nil
}

// checkWorkflowCallInputs checks if untrusted values are passed to reusable workflow inputs
func (rule *ReusableWorkflowTaintRule) checkWorkflowCallInputs(job *ast.Job) {
	call := job.WorkflowCall
	if call == nil || call.Uses == nil {
		return
	}

	for inputName, input := range call.Inputs {
		if input == nil || input.Value == nil {
			continue
		}

		// Check if the input value contains untrusted expressions
		untrustedPaths := rule.findUntrustedExpressionsInString(input.Value)
		if len(untrustedPaths) > 0 {
			// Get severity based on whether this workflow has privileged triggers
			severity := "medium"
			if rule.hasPrivilegedTrigger {
				severity = "critical"
			}

			rule.Errorf(
				input.Value.Pos,
				"reusable workflow input taint (%s): input %q receives untrusted value %q which may be used unsafely in the called workflow %q. Consider validating or sanitizing the input. See https://sisaku-security.github.io/lint/docs/rules/reusableworkflowtaint/",
				severity,
				inputName,
				strings.Join(untrustedPaths, ", "),
				call.Uses.Value,
			)
		}
	}
}

// checkTaintedInputUsageInSteps checks if inputs.* are used in dangerous contexts
// This is called when analyzing a reusable workflow
func (rule *ReusableWorkflowTaintRule) checkTaintedInputUsageInSteps(job *ast.Job) {
	for _, step := range job.Steps {
		if step.Exec == nil {
			continue
		}

		var stepTainted *stepWithTaintedInput

		// Check run: scripts
		if step.Exec.Kind() == ast.ExecKindRun {
			run := step.Exec.(*ast.ExecRun)
			if run.Run != nil {
				taintedUsages := rule.findTaintedInputUsagesInString(run.Run)
				for _, usage := range taintedUsages {
					if !rule.isDefinedInEnv(usage.inputPath, step.Env) {
						if stepTainted == nil {
							stepTainted = &stepWithTaintedInput{step: step}
						}
						usage.isInRunScript = true
						stepTainted.taintedInfo = append(stepTainted.taintedInfo, usage)

						rule.Errorf(
							usage.pos,
							"tainted input in reusable workflow: %q may contain untrusted data passed from the caller workflow. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/reusableworkflowtaint/",
							usage.inputPath,
						)
					}
				}
			}
		}

		// Check actions/github-script script: parameter
		if step.Exec.Kind() == ast.ExecKindAction {
			action := step.Exec.(*ast.ExecAction)
			if action.Uses != nil && strings.HasPrefix(action.Uses.Value, "actions/github-script@") {
				if scriptInput, ok := action.Inputs["script"]; ok && scriptInput != nil && scriptInput.Value != nil {
					taintedUsages := rule.findTaintedInputUsagesInString(scriptInput.Value)
					for _, usage := range taintedUsages {
						if !rule.isDefinedInEnv(usage.inputPath, step.Env) {
							if stepTainted == nil {
								stepTainted = &stepWithTaintedInput{step: step}
							}
							usage.isInRunScript = false
							stepTainted.taintedInfo = append(stepTainted.taintedInfo, usage)

							rule.Errorf(
								usage.pos,
								"tainted input in reusable workflow: %q may contain untrusted data passed from the caller workflow. Avoid using it directly in github-script. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/reusableworkflowtaint/",
								usage.inputPath,
							)
						}
					}
				}
			}
		}

		if stepTainted != nil {
			rule.stepsWithTaintedInputs = append(rule.stepsWithTaintedInputs, stepTainted)
			rule.AddAutoFixer(NewStepFixer(step, rule))
		}
	}
}

// findUntrustedExpressionsInString finds all untrusted expression paths in a string
func (rule *ReusableWorkflowTaintRule) findUntrustedExpressionsInString(str *ast.String) []string {
	if str == nil {
		return nil
	}

	var untrustedPaths []string
	value := str.Value
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

		// Parse and check the expression
		expr, err := rule.parseExpression(exprContent)
		if err == nil && expr != nil {
			paths := rule.checkUntrustedPaths(expr)
			untrustedPaths = append(untrustedPaths, paths...)
		}

		offset = start + endIdx + 2
	}

	return untrustedPaths
}

// findTaintedInputUsagesInString finds all inputs.* usages in a string
func (rule *ReusableWorkflowTaintRule) findTaintedInputUsagesInString(str *ast.String) []taintedInputInfo {
	if str == nil {
		return nil
	}

	var usages []taintedInputInfo
	value := str.Value
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

		// Check if this expression references inputs.*
		inputPaths := rule.findInputReferences(exprContent)
		for _, inputPath := range inputPaths {
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

			// Extract input name from path (e.g., "inputs.title" -> "title")
			inputName := ""
			if suffix, found := strings.CutPrefix(inputPath, "inputs."); found {
				inputName = suffix
				// Handle nested properties
				if dotIdx := strings.Index(inputName, "."); dotIdx != -1 {
					inputName = inputName[:dotIdx]
				}
			}

			usages = append(usages, taintedInputInfo{
				inputName: inputName,
				inputPath: inputPath,
				pos:       pos,
			})
		}

		offset = start + endIdx + 2
	}

	return usages
}

// findInputReferences finds all inputs.* references in an expression
func (rule *ReusableWorkflowTaintRule) findInputReferences(exprStr string) []string {
	// Parse the expression
	expr, err := rule.parseExpression(exprStr)
	if err != nil || expr == nil {
		return nil
	}

	// Find all inputs.* references
	var refs []string
	rule.collectInputRefsFromNode(expr, &refs)
	return refs
}

// collectInputRefsFromNode recursively collects inputs.* references from an expression node
func (rule *ReusableWorkflowTaintRule) collectInputRefsFromNode(node expressions.ExprNode, refs *[]string) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *expressions.ObjectDerefNode:
		// Check if this is inputs.something
		path := rule.buildPropertyPath(n)
		if strings.HasPrefix(path, "inputs.") {
			*refs = append(*refs, path)
		}
		rule.collectInputRefsFromNode(n.Receiver, refs)
	case *expressions.IndexAccessNode:
		// Check if this is inputs["something"]
		if varNode, ok := n.Operand.(*expressions.VariableNode); ok {
			if varNode.Name == ContextInputs {
				if strNode, ok := n.Index.(*expressions.StringNode); ok {
					*refs = append(*refs, fmt.Sprintf("inputs.%s", strNode.Value))
				} else {
					// Dynamic access like inputs[some_var]
					*refs = append(*refs, "inputs.*")
				}
			}
		}
		rule.collectInputRefsFromNode(n.Operand, refs)
		rule.collectInputRefsFromNode(n.Index, refs)
	case *expressions.FuncCallNode:
		for _, arg := range n.Args {
			rule.collectInputRefsFromNode(arg, refs)
		}
	case *expressions.NotOpNode:
		rule.collectInputRefsFromNode(n.Operand, refs)
	case *expressions.CompareOpNode:
		rule.collectInputRefsFromNode(n.Left, refs)
		rule.collectInputRefsFromNode(n.Right, refs)
	case *expressions.LogicalOpNode:
		rule.collectInputRefsFromNode(n.Left, refs)
		rule.collectInputRefsFromNode(n.Right, refs)
	}
}

// buildPropertyPath builds a property path from an ObjectDerefNode chain
func (rule *ReusableWorkflowTaintRule) buildPropertyPath(node *expressions.ObjectDerefNode) string {
	var parts []string

	current := node
	for current != nil {
		parts = append([]string{current.Property}, parts...)
		if varNode, ok := current.Receiver.(*expressions.VariableNode); ok {
			parts = append([]string{varNode.Name}, parts...)
			break
		}
		if objNode, ok := current.Receiver.(*expressions.ObjectDerefNode); ok {
			current = objNode
		} else {
			break
		}
	}

	return strings.Join(parts, ".")
}

// parseExpression parses a single expression string into an AST node
func (rule *ReusableWorkflowTaintRule) parseExpression(exprStr string) (expressions.ExprNode, error) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	node, err := p.Parse(l)
	if err != nil {
		return nil, err
	}
	return node, nil
}

// checkUntrustedPaths checks if an expression contains untrusted input paths
func (rule *ReusableWorkflowTaintRule) checkUntrustedPaths(expr expressions.ExprNode) []string {
	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(expr)

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

// isDefinedInEnv checks if the input path is defined in the step's env section
func (rule *ReusableWorkflowTaintRule) isDefinedInEnv(inputPath string, env *ast.Env) bool {
	if env == nil {
		return false
	}

	if env.Vars != nil {
		for _, envVar := range env.Vars {
			if envVar.Value != nil && envVar.Value.ContainsExpression() {
				envExprs := extractExpressionsFromString(envVar.Value.Value)
				for _, envExpr := range envExprs {
					normalizedEnv := normalizeExpression(envExpr)
					normalizedInput := normalizeExpression(inputPath)
					if normalizedEnv == normalizedInput {
						return true
					}
				}
			}
		}
	}

	return false
}

// RuleNames returns the rule name for the fixer interface
func (rule *ReusableWorkflowTaintRule) RuleNames() string {
	return rule.RuleName
}

// FixStep implements the StepFixer interface
func (rule *ReusableWorkflowTaintRule) FixStep(step *ast.Step) error {
	// Find the stepWithTaintedInput for this step
	var stepInfo *stepWithTaintedInput
	for _, s := range rule.stepsWithTaintedInputs {
		if s.step == step {
			stepInfo = s
			break
		}
	}

	if stepInfo == nil {
		return nil
	}

	// Ensure env exists
	if step.Env == nil {
		step.Env = &ast.Env{
			Vars: make(map[string]*ast.EnvVar),
		}
	}
	if step.Env.Vars == nil {
		step.Env.Vars = make(map[string]*ast.EnvVar)
	}

	// Track env vars we need to add
	envVarMap := make(map[string]string)      // inputPath -> env var name
	envVarsForYAML := make(map[string]string) // env var name -> value

	for _, taintedInfo := range stepInfo.taintedInfo {
		// Generate env var name from input name
		envVarName := rule.generateEnvVarName(taintedInfo.inputName)

		if _, exists := envVarMap[taintedInfo.inputPath]; !exists {
			envVarMap[taintedInfo.inputPath] = envVarName

			// Add to env if not already present
			if _, exists := step.Env.Vars[strings.ToLower(envVarName)]; !exists {
				step.Env.Vars[strings.ToLower(envVarName)] = &ast.EnvVar{
					Name: &ast.String{
						Value: envVarName,
						Pos:   taintedInfo.pos,
					},
					Value: &ast.String{
						Value: fmt.Sprintf("${{ %s }}", taintedInfo.inputPath),
						Pos:   taintedInfo.pos,
					},
				}
				envVarsForYAML[envVarName] = fmt.Sprintf("${{ %s }}", taintedInfo.inputPath)
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

	for _, taintedInfo := range stepInfo.taintedInfo {
		envVarName := envVarMap[taintedInfo.inputPath]

		if taintedInfo.isInRunScript {
			runReplacements[fmt.Sprintf("${{ %s }}", taintedInfo.inputPath)] = fmt.Sprintf("$%s", envVarName)
			runReplacements[fmt.Sprintf("${{%s}}", taintedInfo.inputPath)] = fmt.Sprintf("$%s", envVarName)

			// Update AST
			run := step.Exec.(*ast.ExecRun)
			if run.Run != nil {
				run.Run.Value = strings.ReplaceAll(
					run.Run.Value,
					fmt.Sprintf("${{ %s }}", taintedInfo.inputPath),
					fmt.Sprintf("$%s", envVarName),
				)
				run.Run.Value = strings.ReplaceAll(
					run.Run.Value,
					fmt.Sprintf("${{%s}}", taintedInfo.inputPath),
					fmt.Sprintf("$%s", envVarName),
				)
			}
		} else {
			scriptReplacements[fmt.Sprintf("${{ %s }}", taintedInfo.inputPath)] = fmt.Sprintf("process.env.%s", envVarName)
			scriptReplacements[fmt.Sprintf("${{%s}}", taintedInfo.inputPath)] = fmt.Sprintf("process.env.%s", envVarName)

			// Update AST for github-script
			if step.Exec.Kind() == ast.ExecKindAction {
				action := step.Exec.(*ast.ExecAction)
				if scriptInput, ok := action.Inputs["script"]; ok && scriptInput != nil && scriptInput.Value != nil {
					scriptInput.Value.Value = strings.ReplaceAll(
						scriptInput.Value.Value,
						fmt.Sprintf("${{ %s }}", taintedInfo.inputPath),
						fmt.Sprintf("process.env.%s", envVarName),
					)
					scriptInput.Value.Value = strings.ReplaceAll(
						scriptInput.Value.Value,
						fmt.Sprintf("${{%s}}", taintedInfo.inputPath),
						fmt.Sprintf("process.env.%s", envVarName),
					)
				}
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

// generateEnvVarName generates an environment variable name from an input name
func (rule *ReusableWorkflowTaintRule) generateEnvVarName(inputName string) string {
	if inputName == "" {
		return "UNTRUSTED_INPUT"
	}

	// Convert to uppercase with underscores
	name := strings.ToUpper(inputName)
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")

	return fmt.Sprintf("INPUT_%s", name)
}

// isPrivilegedTrigger checks if an event name is a privileged trigger
// Note: workflow_call is NOT included here because it's not a runtime event name.
// When a reusable workflow is called, github.event_name reflects the CALLER's event,
// not "workflow_call". For detecting potential danger in reusable workflows,
// use isDangerousTriggerForAnalysis which includes workflow_call.
func isPrivilegedTrigger(eventName string) bool {
	privilegedTriggers := map[string]bool{
		"pull_request_target": true,
		"workflow_run":        true,
		"issue_comment":       true,
		"issues":              true,
		"discussion_comment":  true,
	}
	return privilegedTriggers[eventName]
}

// isDangerousTriggerForAnalysis checks if an event name should be considered
// dangerous for security analysis purposes. This includes workflow_call because
// reusable workflows may be called from privileged contexts.
func isDangerousTriggerForAnalysis(eventName string) bool {
	if isPrivilegedTrigger(eventName) {
		return true
	}
	return eventName == "workflow_call"
}
