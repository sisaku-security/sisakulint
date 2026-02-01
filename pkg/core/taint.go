package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// TaintTracker tracks taint propagation through step outputs.
// Phase 1 focuses on tracking $GITHUB_OUTPUT writes with untrusted inputs.
// Phase 2 extends this to track step output to step output propagation.
//
// Example of tracked vulnerability (GHSL-2024-325):
//
//   - id: get-ref
//     run: echo "ref=${{ github.head_ref }}" >> $GITHUB_OUTPUT
//   - env:
//     BRANCH: ${{ steps.get-ref.outputs.ref }}  # This is now tainted
//     run: git push origin HEAD:${BRANCH}         # Code injection!
//
// Phase 2 example (step output to step output):
//
//   - id: step-a
//     run: echo "val=${{ github.head_ref }}" >> $GITHUB_OUTPUT
//   - id: step-b
//     env:
//     INPUT: ${{ steps.step-a.outputs.val }}  # Tainted via step-a
//     run: echo "derived=$INPUT" >> $GITHUB_OUTPUT  # Output is also tainted
//   - env:
//     FINAL: ${{ steps.step-b.outputs.derived }}  # Tainted via step-b -> step-a
//     run: echo $FINAL  # Code injection!
type TaintTracker struct {
	// taintedOutputs maps stepID -> outputName -> taint sources
	// Example: {"get-ref": {"ref": ["github.head_ref"]}}
	taintedOutputs map[string]map[string][]string

	// taintedVars tracks variables in the current script that hold tainted values
	// Used for intra-step variable propagation
	taintedVars map[string][]string

	// knownTaintedActions maps action patterns to their tainted outputs
	// Phase 3: Used to infer taint from known action behaviors
	knownTaintedActions map[string][]KnownTaintedOutput
}

// KnownTaintedOutput represents a known tainted output from an action.
type KnownTaintedOutput struct {
	OutputName  string // Name of the output that is tainted
	TaintSource string // Description of where the taint comes from
}

// NewTaintTracker creates a new TaintTracker instance.
func NewTaintTracker() *TaintTracker {
	tracker := &TaintTracker{
		taintedOutputs:      make(map[string]map[string][]string),
		taintedVars:         make(map[string][]string),
		knownTaintedActions: make(map[string][]KnownTaintedOutput),
	}

	// Phase 3: Initialize known tainted actions database
	// These actions are known to expose untrusted PR/issue data as outputs
	tracker.initKnownTaintedActions()

	return tracker
}

// initKnownTaintedActions initializes the database of known actions with tainted outputs.
// Phase 3: This allows detection of taint from action outputs without analyzing action code.
func (t *TaintTracker) initKnownTaintedActions() {
	// gotson/pull-request-comment-branch - exposes PR branch info from comments
	// Used in GHSL-2024-325 vulnerability
	t.knownTaintedActions["gotson/pull-request-comment-branch"] = []KnownTaintedOutput{
		{OutputName: "head_ref", TaintSource: "github.event.pull_request.head.ref (via action)"},
		{OutputName: "head_sha", TaintSource: "github.event.pull_request.head.sha (via action)"},
		{OutputName: "base_ref", TaintSource: "github.event.pull_request.base.ref (via action)"},
		{OutputName: "base_sha", TaintSource: "github.event.pull_request.base.sha (via action)"},
	}

	// xt0rted/pull-request-comment-branch - similar to gotson
	t.knownTaintedActions["xt0rted/pull-request-comment-branch"] = []KnownTaintedOutput{
		{OutputName: "head_ref", TaintSource: "github.event.pull_request.head.ref (via action)"},
		{OutputName: "head_sha", TaintSource: "github.event.pull_request.head.sha (via action)"},
		{OutputName: "base_ref", TaintSource: "github.event.pull_request.base.ref (via action)"},
		{OutputName: "base_sha", TaintSource: "github.event.pull_request.base.sha (via action)"},
	}

	// actions/github-script - if inputs contain untrusted data, outputs may be tainted
	// Note: This is handled dynamically based on script content, not here

	// peter-evans/find-comment - extracts comment body which is untrusted
	t.knownTaintedActions["peter-evans/find-comment"] = []KnownTaintedOutput{
		{OutputName: "comment-body", TaintSource: "github.event.comment.body (via action)"},
		{OutputName: "comment-author", TaintSource: "github.event.comment.user.login (via action)"},
	}

	// actions/create-github-app-token - outputs are safe (tokens are not user-controlled)
	// Not adding to tainted list

	// EndBug/add-and-commit - if inputs contain untrusted data, may propagate
	// Outputs are generally safe (commit sha)
}

// AnalyzeStep analyzes a step for $GITHUB_OUTPUT writes with tainted values.
// It tracks which outputs become tainted based on the script content.
// Phase 2: Also considers env vars that reference tainted step outputs.
// Phase 3: Also handles action steps with known tainted outputs.
func (t *TaintTracker) AnalyzeStep(step *ast.Step) {
	if step == nil || step.ID == nil || step.ID.Value == "" {
		return
	}

	if step.Exec == nil {
		return
	}

	stepID := step.ID.Value

	// Phase 3: Handle action steps
	if step.Exec.Kind() == ast.ExecKindAction {
		t.analyzeActionStep(step)
		return
	}

	// Handle run: steps
	if step.Exec.Kind() != ast.ExecKindRun {
		return
	}

	run, ok := step.Exec.(*ast.ExecRun)
	if !ok || run.Run == nil {
		return
	}

	script := run.Run.Value

	// Reset tainted vars for this step
	t.taintedVars = make(map[string][]string)

	// Phase 2: Pre-populate tainted vars from env section
	// If env vars reference tainted step outputs, those vars are also tainted
	t.populateTaintedVarsFromEnv(step.Env)

	// Analyze script for tainted variable assignments and GITHUB_OUTPUT writes
	t.analyzeScript(stepID, script)
}

// analyzeActionStep checks if an action step uses a known tainted action.
// Phase 3: If the action is known to expose untrusted data, mark its outputs as tainted.
func (t *TaintTracker) analyzeActionStep(step *ast.Step) {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return
	}

	stepID := step.ID.Value
	uses := action.Uses.Value

	// Extract action name (without version)
	actionName := strings.ToLower(t.extractActionName(uses))

	// Check if this action is known to have tainted outputs
	taintedOutputs, exists := t.knownTaintedActions[actionName]
	if !exists {
		return
	}

	// Mark all known tainted outputs for this step
	if t.taintedOutputs[stepID] == nil {
		t.taintedOutputs[stepID] = make(map[string][]string)
	}

	for _, output := range taintedOutputs {
		t.taintedOutputs[stepID][output.OutputName] = []string{output.TaintSource}
	}
}

// extractActionName extracts the action name from a uses string.
// Example: "gotson/pull-request-comment-branch@v1" -> "gotson/pull-request-comment-branch"
func (t *TaintTracker) extractActionName(uses string) string {
	// Remove version suffix (`@v1`, `@main`, `@sha`, etc.)
	if idx := strings.Index(uses, "@"); idx != -1 {
		return uses[:idx]
	}
	return uses
}

// populateTaintedVarsFromEnv checks env vars for tainted step output references.
// Phase 2: If an env var references a tainted step output, that var becomes tainted.
//
// Example:
//
//	env:
//	  INPUT: ${{ steps.step-a.outputs.val }}  # If step-a.outputs.val is tainted, INPUT is tainted
func (t *TaintTracker) populateTaintedVarsFromEnv(env *ast.Env) {
	if env == nil || env.Vars == nil {
		return
	}

	for _, envVar := range env.Vars {
		if envVar.Value == nil || !envVar.Value.ContainsExpression() {
			continue
		}

		varName := envVar.Name.Value
		value := envVar.Value.Value

		// Find all ${{ }} expressions in the env var value
		exprPattern := regexp.MustCompile(`\$\{\{\s*([^}]+)\s*\}\}`)
		matches := exprPattern.FindAllStringSubmatch(value, -1)

		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			exprContent := strings.TrimSpace(match[1])

			// Check if this expression references a tainted step output
			if tainted, sources := t.IsTaintedExpr(exprContent); tainted {
				// Propagate taint: the env var is now tainted via the step output
				t.taintedVars[varName] = append(t.taintedVars[varName], sources...)
			}

			// Also check for direct untrusted expressions
			if t.isUntrustedExpression(exprContent) {
				t.taintedVars[varName] = append(t.taintedVars[varName], exprContent)
			}
		}
	}
}

// analyzeScript parses the script and tracks taint propagation.
func (t *TaintTracker) analyzeScript(stepID, script string) {
	// First pass: find variable assignments with untrusted expressions
	t.findTaintedVariableAssignments(script)

	// Second pass: find $GITHUB_OUTPUT writes
	t.findGitHubOutputWrites(stepID, script)
}

// findTaintedVariableAssignments finds shell variable assignments that contain untrusted input.
// Example: VAR="${{ github.event.issue.title }}"
// Also handles: export VAR=..., local VAR=..., readonly VAR=...
// Also propagates taint from referenced variables: VAR=$INPUT (where INPUT is tainted)
func (t *TaintTracker) findTaintedVariableAssignments(script string) {
	// Pattern: VAR=value or VAR="value" or VAR='value'
	// Also handles optional keyword prefixes: export, local, readonly
	// We look for assignments that contain ${{ }} expressions or references to tainted variables
	varAssignPattern := regexp.MustCompile(`(?m)^\s*(?:(?:export|local|readonly)\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

	matches := varAssignPattern.FindAllStringSubmatch(script, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		varName := match[1]
		value := match[2]

		var taintSources []string

		// Check if value contains direct untrusted expressions
		untrustedSources := t.extractUntrustedSources(value)
		taintSources = append(taintSources, untrustedSources...)

		// Check if value references other tainted variables
		// Handle both $VAR and ${VAR} forms
		varRefPattern := regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
		varMatches := varRefPattern.FindAllStringSubmatch(value, -1)
		for _, varMatch := range varMatches {
			if len(varMatch) >= 2 {
				referencedVar := varMatch[1]
				if sources, exists := t.taintedVars[referencedVar]; exists {
					// Propagate taint from referenced variable
					taintSources = append(taintSources, sources...)
				}
			}
		}

		// Deduplicate taint sources
		if len(taintSources) > 0 {
			t.taintedVars[varName] = deduplicateStrings(taintSources)
		}
	}
}

// deduplicateStrings removes duplicate strings from a slice while preserving order.
func deduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(input))
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// findGitHubOutputWrites finds writes to $GITHUB_OUTPUT and tracks which outputs become tainted.
func (t *TaintTracker) findGitHubOutputWrites(stepID, script string) {
	// Pattern 1: echo "name=value" >> $GITHUB_OUTPUT
	echoPattern := regexp.MustCompile(`echo\s+["']?([^=\s]+)=([^"'\n]+)["']?\s*>>\s*"?\$\{?GITHUB_OUTPUT\}?"?`)

	// Pattern 2: printf pattern - printf "name=%s" "$VAR" >> $GITHUB_OUTPUT
	printfPattern := regexp.MustCompile(`printf\s+["']([^=]+)=.*?["'].*?>>\s*"?\$\{?GITHUB_OUTPUT\}?"?`)

	// Process echo patterns
	echoMatches := echoPattern.FindAllStringSubmatch(script, -1)
	for _, match := range echoMatches {
		if len(match) >= 3 {
			outputName := strings.TrimSpace(match[1])
			value := match[2]
			t.checkAndRecordTaint(stepID, outputName, value)
		}
	}

	// Process heredoc patterns manually (Go regexp doesn't support backreferences)
	t.processHeredocPatterns(stepID, script)

	// Process printf patterns (simplified - just detect the output name)
	printfMatches := printfPattern.FindAllStringSubmatch(script, -1)
	for _, match := range printfMatches {
		if len(match) >= 2 {
			outputName := strings.TrimSpace(match[1])
			// For printf, we need to check the full line for tainted variables
			fullLine := match[0]
			t.checkAndRecordTaint(stepID, outputName, fullLine)
		}
	}
}

// processHeredocPatterns manually parses heredoc patterns since Go regexp doesn't support backreferences.
// Example: cat <<EOF >> $GITHUB_OUTPUT
//
//	name=value
//
// EOF
func (t *TaintTracker) processHeredocPatterns(stepID, script string) {
	// Find heredoc start pattern
	heredocStartPattern := regexp.MustCompile(`cat\s+<<['"]?(\w+)['"]?\s*>>\s*"?\$\{?GITHUB_OUTPUT\}?"?`)
	matches := heredocStartPattern.FindAllStringSubmatchIndex(script, -1)

	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		// Extract delimiter
		delimiter := script[match[2]:match[3]]

		// Find content after the heredoc start (after newline)
		startPos := match[1]
		remaining := script[startPos:]

		// Find the first newline
		newlineIdx := strings.Index(remaining, "\n")
		if newlineIdx == -1 {
			continue
		}

		contentStart := newlineIdx + 1
		contentRemaining := remaining[contentStart:]

		// Find the closing delimiter (must be on its own line)
		endPattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(delimiter) + `\s*$`)
		endMatch := endPattern.FindStringIndex(contentRemaining)
		if endMatch == nil {
			continue
		}

		// Extract heredoc content
		content := contentRemaining[:endMatch[0]]

		// Parse lines inside heredoc
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if idx := strings.Index(line, "="); idx > 0 {
				outputName := strings.TrimSpace(line[:idx])
				value := line[idx+1:]
				t.checkAndRecordTaint(stepID, outputName, value)
			}
		}
	}
}

// checkAndRecordTaint checks if a value contains tainted data and records it.
func (t *TaintTracker) checkAndRecordTaint(stepID, outputName, value string) {
	var taintSources []string

	// Check for direct untrusted expressions in value
	directSources := t.extractUntrustedSources(value)
	taintSources = append(taintSources, directSources...)

	// Check for tainted variable references in value
	varRefPattern := regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	varMatches := varRefPattern.FindAllStringSubmatch(value, -1)
	for _, match := range varMatches {
		if len(match) >= 2 {
			varName := match[1]
			if sources, exists := t.taintedVars[varName]; exists {
				taintSources = append(taintSources, sources...)
			}
		}
	}

	// Record taint if any sources found
	if len(taintSources) > 0 {
		if t.taintedOutputs[stepID] == nil {
			t.taintedOutputs[stepID] = make(map[string][]string)
		}
		t.taintedOutputs[stepID][outputName] = taintSources
	}
}

// extractUntrustedSources extracts untrusted expression paths from a string.
// Example: "${{ github.event.issue.title }}" -> ["github.event.issue.title"]
func (t *TaintTracker) extractUntrustedSources(value string) []string {
	var sources []string

	// Find all ${{ }} expressions
	exprPattern := regexp.MustCompile(`\$\{\{\s*([^}]+)\s*\}\}`)
	matches := exprPattern.FindAllStringSubmatch(value, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		exprContent := strings.TrimSpace(match[1])

		// Parse and check if untrusted
		if t.isUntrustedExpression(exprContent) {
			sources = append(sources, exprContent)
		}
	}

	return sources
}

// isUntrustedExpression checks if an expression contains untrusted input.
func (t *TaintTracker) isUntrustedExpression(exprContent string) bool {
	// Parse the expression
	l := expressions.NewTokenizer(exprContent + "}}")
	p := expressions.NewMiniParser()
	node, err := p.Parse(l)
	if err != nil {
		return false
	}

	// Use the existing semantic checker
	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(node)

	// Check if any error indicates untrusted input
	for _, e := range errs {
		if strings.Contains(e.Message, "potentially untrusted") {
			return true
		}
	}

	return false
}

// IsTaintedExpr checks if an expression string references a tainted step output.
// Returns true and the taint sources if tainted.
//
// Example:
//
//	IsTaintedExpr("steps.get-ref.outputs.ref") -> (true, ["github.head_ref"])
func (t *TaintTracker) IsTaintedExpr(exprStr string) (bool, []string) {
	// Check if this is a steps.*.outputs.* reference
	if !strings.HasPrefix(exprStr, "steps.") {
		return false, nil
	}

	parts := strings.Split(exprStr, ".")
	// Expected format: steps.<step-id>.outputs.<output-name>
	if len(parts) < 4 || parts[2] != "outputs" {
		return false, nil
	}

	stepID := parts[1]
	outputName := parts[3]

	// Check if this output is tainted
	if outputs, exists := t.taintedOutputs[stepID]; exists {
		if sources, outputExists := outputs[outputName]; outputExists {
			return true, sources
		}
	}

	return false, nil
}

// IsTainted checks if an expression AST node references a tainted step output.
// This is the primary method to use when integrating with CodeInjectionRule.
func (t *TaintTracker) IsTainted(node expressions.ExprNode) (bool, []string) {
	// Convert AST node to string representation for checking
	exprStr := t.nodeToString(node)
	return t.IsTaintedExpr(exprStr)
}

// nodeToString converts an expression AST node to its string representation.
func (t *TaintTracker) nodeToString(node expressions.ExprNode) string {
	switch n := node.(type) {
	case *expressions.ObjectDerefNode:
		return t.buildObjectDerefString(n)
	case *expressions.IndexAccessNode:
		return t.buildIndexAccessString(n)
	case *expressions.VariableNode:
		return n.Name
	default:
		return ""
	}
}

// buildObjectDerefString builds the string representation of a property access chain.
func (t *TaintTracker) buildObjectDerefString(node *expressions.ObjectDerefNode) string {
	var parts []string

	var current expressions.ExprNode = node
	for current != nil {
		switch n := current.(type) {
		case *expressions.ObjectDerefNode:
			parts = append([]string{n.Property}, parts...)
			current = n.Receiver
		case *expressions.VariableNode:
			parts = append([]string{n.Name}, parts...)
			current = nil
		default:
			current = nil
		}
	}

	return strings.Join(parts, ".")
}

// buildIndexAccessString builds the string representation of an index access.
func (t *TaintTracker) buildIndexAccessString(node *expressions.IndexAccessNode) string {
	operandStr := t.nodeToString(node.Operand)
	if operandStr == "" {
		return ""
	}

	// For string index, append it as a property
	if strNode, ok := node.Index.(*expressions.StringNode); ok {
		return operandStr + "." + strNode.Value
	}

	return operandStr
}

// GetTaintedOutputs returns all tracked tainted outputs (for testing/debugging).
func (t *TaintTracker) GetTaintedOutputs() map[string]map[string][]string {
	return t.taintedOutputs
}
