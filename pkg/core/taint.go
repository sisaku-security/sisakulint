package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// TaintTracker tracks taint propagation through step outputs.
// Phase 1 focuses on tracking $GITHUB_OUTPUT writes with untrusted inputs.
//
// Example of tracked vulnerability (GHSL-2024-325):
//
//   - id: get-ref
//     run: echo "ref=${{ github.head_ref }}" >> $GITHUB_OUTPUT
//   - env:
//     BRANCH: ${{ steps.get-ref.outputs.ref }}  # This is now tainted
//     run: git push origin HEAD:${BRANCH}         # Code injection!
type TaintTracker struct {
	// taintedOutputs maps stepID -> outputName -> taint sources
	// Example: {"get-ref": {"ref": ["github.head_ref"]}}
	taintedOutputs map[string]map[string][]string

	// taintedVars tracks variables in the current script that hold tainted values
	// Used for intra-step variable propagation
	taintedVars map[string][]string
}

// NewTaintTracker creates a new TaintTracker instance.
func NewTaintTracker() *TaintTracker {
	return &TaintTracker{
		taintedOutputs: make(map[string]map[string][]string),
		taintedVars:    make(map[string][]string),
	}
}

// AnalyzeStep analyzes a step for $GITHUB_OUTPUT writes with tainted values.
// It tracks which outputs become tainted based on the script content.
func (t *TaintTracker) AnalyzeStep(step *ast.Step) {
	if step == nil || step.ID == nil || step.ID.Value == "" {
		return
	}

	if step.Exec == nil || step.Exec.Kind() != ast.ExecKindRun {
		return
	}

	run, ok := step.Exec.(*ast.ExecRun)
	if !ok || run.Run == nil {
		return
	}

	stepID := step.ID.Value
	script := run.Run.Value

	// Reset tainted vars for this step
	t.taintedVars = make(map[string][]string)

	// Analyze script for tainted variable assignments and GITHUB_OUTPUT writes
	t.analyzeScript(stepID, script)
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
func (t *TaintTracker) findTaintedVariableAssignments(script string) {
	// Pattern: VAR=value or VAR="value" or VAR='value'
	// We look for assignments that contain ${{ }} expressions
	varAssignPattern := regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

	matches := varAssignPattern.FindAllStringSubmatch(script, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		varName := match[1]
		value := match[2]

		// Check if value contains untrusted expressions
		untrustedSources := t.extractUntrustedSources(value)
		if len(untrustedSources) > 0 {
			t.taintedVars[varName] = untrustedSources
		}
	}
}

// findGitHubOutputWrites finds writes to $GITHUB_OUTPUT and tracks which outputs become tainted.
func (t *TaintTracker) findGitHubOutputWrites(stepID, script string) {
	// Pattern 1: echo "name=value" >> $GITHUB_OUTPUT
	echoPattern := regexp.MustCompile(`echo\s+["']?([^=\s]+)=([^"'\n]+)["']?\s*>>\s*\$GITHUB_OUTPUT`)

	// Pattern 2: printf pattern - printf "name=%s" "$VAR" >> $GITHUB_OUTPUT
	printfPattern := regexp.MustCompile(`printf\s+["']([^=]+)=.*?["'].*?>>\s*\$GITHUB_OUTPUT`)

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
	heredocStartPattern := regexp.MustCompile(`cat\s+<<['"]?(\w+)['"]?\s*>>\s*\$GITHUB_OUTPUT`)
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
