package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// JobTriggerAnalyzer analyzes job-level if conditions to determine
// which workflow triggers can actually execute the job.
// This helps avoid false positives when workflows use job-level conditionals
// to restrict which triggers actually execute specific jobs.
type JobTriggerAnalyzer struct {
	workflowTriggers []string
}

// NewJobTriggerAnalyzer creates a new JobTriggerAnalyzer with the given workflow triggers.
func NewJobTriggerAnalyzer(workflowTriggers []string) *JobTriggerAnalyzer {
	return &JobTriggerAnalyzer{
		workflowTriggers: workflowTriggers,
	}
}

// AnalyzeJobTriggers returns the set of triggers that can actually execute the job,
// considering both workflow-level triggers and job-level if conditions.
// If the job has no if condition or the condition cannot be analyzed,
// it returns all workflow triggers (conservative approach).
func (a *JobTriggerAnalyzer) AnalyzeJobTriggers(job *ast.Job) []string {
	if job.If == nil || job.If.Value == "" {
		return a.workflowTriggers
	}

	// Parse the if condition
	condStr := job.If.Value

	// Remove ${{ }} wrapper if present
	condStr = strings.TrimSpace(condStr)
	if strings.HasPrefix(condStr, "${{") && strings.HasSuffix(condStr, "}}") {
		condStr = strings.TrimPrefix(condStr, "${{")
		condStr = strings.TrimSuffix(condStr, "}}")
		condStr = strings.TrimSpace(condStr)
	}

	// Parse the expression
	tokenizer := expressions.NewTokenizer(condStr + "}}")
	parser := expressions.NewMiniParser()
	exprNode, err := parser.Parse(tokenizer)
	if err != nil {
		// Cannot parse - return all triggers (conservative)
		return a.workflowTriggers
	}

	// Analyze the expression to find event_name constraints
	constraints := a.extractEventNameConstraints(exprNode)
	if constraints == nil {
		// No event_name constraints found - return all triggers
		return a.workflowTriggers
	}

	// Apply constraints to workflow triggers
	return a.applyConstraints(constraints)
}

// HasPrivilegedTrigger returns true if the job can execute on a privileged trigger
// (pull_request_target, workflow_run, issue_comment) or workflow_call.
// workflow_call is included because reusable workflows may be called from privileged contexts.
func (a *JobTriggerAnalyzer) HasPrivilegedTrigger(job *ast.Job) bool {
	effectiveTriggers := a.AnalyzeJobTriggers(job)
	for _, trigger := range effectiveTriggers {
		if isDangerousTriggerForAnalysis(trigger) {
			return true
		}
	}
	return false
}

// HasUnsafeTrigger returns true if the job can execute on an unsafe trigger
// (pull_request_target, workflow_run, issue_comment).
// This is similar to HasPrivilegedTrigger but uses the IsUnsafeTrigger check.
func (a *JobTriggerAnalyzer) HasUnsafeTrigger(job *ast.Job) bool {
	effectiveTriggers := a.AnalyzeJobTriggers(job)
	for _, trigger := range effectiveTriggers {
		if IsUnsafeTrigger(trigger) {
			return true
		}
	}
	return false
}

// eventNameConstraint represents a constraint on github.event_name
type eventNameConstraint struct {
	// included is a set of event names that are explicitly included (from == or contains)
	included map[string]bool
	// excluded is a set of event names that are explicitly excluded (from !=)
	excluded map[string]bool
}

// extractEventNameConstraints extracts event_name constraints from an expression.
// Returns nil if no constraints can be determined.
func (a *JobTriggerAnalyzer) extractEventNameConstraints(node expressions.ExprNode) *eventNameConstraint {
	switch n := node.(type) {
	case *expressions.CompareOpNode:
		return a.extractFromCompareOp(n)

	case *expressions.LogicalOpNode:
		return a.extractFromLogicalOp(n)

	case *expressions.NotOpNode:
		inner := a.extractEventNameConstraints(n.Operand)
		if inner == nil {
			return nil
		}
		// Invert the constraint
		return &eventNameConstraint{
			included: inner.excluded,
			excluded: inner.included,
		}

	case *expressions.FuncCallNode:
		return a.extractFromFuncCall(n)

	default:
		return nil
	}
}

// extractFromCompareOp extracts constraints from a comparison operation
func (a *JobTriggerAnalyzer) extractFromCompareOp(node *expressions.CompareOpNode) *eventNameConstraint {
	// Check if this is comparing github.event_name
	var eventNameSide expressions.ExprNode
	var valueSide expressions.ExprNode

	if a.isEventNameAccess(node.Left) {
		eventNameSide = node.Left
		valueSide = node.Right
	} else if a.isEventNameAccess(node.Right) {
		eventNameSide = node.Right
		valueSide = node.Left
	}

	if eventNameSide == nil {
		return nil
	}

	// Get the string value being compared
	strValue := a.getStringValue(valueSide)
	if strValue == "" {
		return nil
	}

	switch node.Kind {
	case expressions.CompareOpNodeKindEq:
		return &eventNameConstraint{
			included: map[string]bool{strValue: true},
		}
	case expressions.CompareOpNodeKindNotEq:
		return &eventNameConstraint{
			excluded: map[string]bool{strValue: true},
		}
	default:
		return nil
	}
}

// extractFromLogicalOp extracts constraints from logical operations (&&, ||)
func (a *JobTriggerAnalyzer) extractFromLogicalOp(node *expressions.LogicalOpNode) *eventNameConstraint {
	leftConstraint := a.extractEventNameConstraints(node.Left)
	rightConstraint := a.extractEventNameConstraints(node.Right)

	switch node.Kind {
	case expressions.LogicalOpNodeKindAnd:
		// For AND, we intersect the constraints
		// If one side has no constraint, use the other side
		if leftConstraint == nil {
			return rightConstraint
		}
		if rightConstraint == nil {
			return leftConstraint
		}
		return a.intersectConstraints(leftConstraint, rightConstraint)

	case expressions.LogicalOpNodeKindOr:
		// For OR, we union the constraints
		// If one side has no constraint, we cannot determine the result
		if leftConstraint == nil || rightConstraint == nil {
			return nil
		}
		return a.unionConstraints(leftConstraint, rightConstraint)

	default:
		return nil
	}
}

// extractFromFuncCall extracts constraints from function calls like contains(fromJson(...), github.event_name)
func (a *JobTriggerAnalyzer) extractFromFuncCall(node *expressions.FuncCallNode) *eventNameConstraint {
	if strings.ToLower(node.Callee) != "contains" || len(node.Args) != 2 {
		return nil
	}

	// Check if the second argument is github.event_name
	if !a.isEventNameAccess(node.Args[1]) {
		return nil
	}

	// Check if the first argument is fromJson with a string array
	values := a.extractFromJsonArray(node.Args[0])
	if len(values) == 0 {
		return nil
	}

	included := make(map[string]bool)
	for _, v := range values {
		included[v] = true
	}

	return &eventNameConstraint{
		included: included,
	}
}

// extractFromJsonArray extracts string values from a fromJson('[...]') call
func (a *JobTriggerAnalyzer) extractFromJsonArray(node expressions.ExprNode) []string {
	funcCall, ok := node.(*expressions.FuncCallNode)
	if !ok || strings.ToLower(funcCall.Callee) != "fromjson" || len(funcCall.Args) != 1 {
		return nil
	}

	strNode, ok := funcCall.Args[0].(*expressions.StringNode)
	if !ok {
		return nil
	}

	// Parse the JSON array manually (simple parsing for string arrays)
	// StringNode.Value includes the outer quotes from tokenizer (e.g., '[\"push\", \"pull_request\"]')
	jsonStr := strNode.Value

	// Remove outer single quotes from the tokenizer (e.g., '["push"]' -> ["push"])
	if strings.HasPrefix(jsonStr, "'") && strings.HasSuffix(jsonStr, "'") {
		jsonStr = jsonStr[1 : len(jsonStr)-1]
	}

	// Simple JSON array parsing
	if !strings.HasPrefix(jsonStr, "[") || !strings.HasSuffix(jsonStr, "]") {
		return nil
	}

	jsonStr = strings.TrimPrefix(jsonStr, "[")
	jsonStr = strings.TrimSuffix(jsonStr, "]")

	var values []string
	parts := strings.Split(jsonStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		// Remove JSON string quotes (double quotes in JSON)
		part = strings.Trim(part, "\"")
		// Also handle escaped quotes that might appear
		part = strings.ReplaceAll(part, "\\\"", "\"")
		if part != "" {
			values = append(values, part)
		}
	}

	return values
}

// isEventNameAccess checks if the node accesses github.event_name
func (a *JobTriggerAnalyzer) isEventNameAccess(node expressions.ExprNode) bool {
	deref, ok := node.(*expressions.ObjectDerefNode)
	if !ok {
		return false
	}

	if deref.Property != "event_name" {
		return false
	}

	// Check if receiver is "github"
	varNode, ok := deref.Receiver.(*expressions.VariableNode)
	if !ok {
		return false
	}

	return varNode.Name == "github"
}

// getStringValue extracts the string value from a node
func (a *JobTriggerAnalyzer) getStringValue(node expressions.ExprNode) string {
	strNode, ok := node.(*expressions.StringNode)
	if !ok {
		return ""
	}
	// StringNode.Value includes the outer single quotes from tokenizer (e.g., 'pull_request')
	value := strNode.Value
	if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") && len(value) >= 2 {
		value = value[1 : len(value)-1]
	}
	return value
}

// intersectConstraints intersects two constraints (for AND operations)
func (a *JobTriggerAnalyzer) intersectConstraints(left, right *eventNameConstraint) *eventNameConstraint {
	result := &eventNameConstraint{
		included: make(map[string]bool),
		excluded: make(map[string]bool),
	}

	// For AND, included must be in both (if both have included lists)
	// If one has included and one has excluded, apply both
	if len(left.included) > 0 && len(right.included) > 0 {
		// Intersection of included sets
		for k := range left.included {
			if right.included[k] {
				result.included[k] = true
			}
		}
	} else if len(left.included) > 0 {
		for k := range left.included {
			result.included[k] = true
		}
	} else if len(right.included) > 0 {
		for k := range right.included {
			result.included[k] = true
		}
	}

	// Union of excluded sets for AND
	for k := range left.excluded {
		result.excluded[k] = true
	}
	for k := range right.excluded {
		result.excluded[k] = true
	}

	return result
}

// unionConstraints unions two constraints (for OR operations)
func (a *JobTriggerAnalyzer) unionConstraints(left, right *eventNameConstraint) *eventNameConstraint {
	result := &eventNameConstraint{
		included: make(map[string]bool),
		excluded: make(map[string]bool),
	}

	// For OR, union of included sets
	for k := range left.included {
		result.included[k] = true
	}
	for k := range right.included {
		result.included[k] = true
	}

	// For OR, intersection of excluded sets (both must exclude)
	if len(left.excluded) > 0 && len(right.excluded) > 0 {
		for k := range left.excluded {
			if right.excluded[k] {
				result.excluded[k] = true
			}
		}
	}

	return result
}

// applyConstraints applies the constraints to the workflow triggers
func (a *JobTriggerAnalyzer) applyConstraints(constraints *eventNameConstraint) []string {
	var result []string

	for _, trigger := range a.workflowTriggers {
		// If there's an included list, the trigger must be in it
		if len(constraints.included) > 0 {
			if !constraints.included[trigger] {
				continue
			}
		}

		// If the trigger is excluded, skip it
		if constraints.excluded[trigger] {
			continue
		}

		result = append(result, trigger)
	}

	return result
}
