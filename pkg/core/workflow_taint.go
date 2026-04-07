package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// WorkflowTaintMap tracks taint propagation across job boundaries via needs.*.outputs.*.
// It is created once per workflow analysis and shared between CodeInjectionCritical and
// CodeInjectionMedium rules via a pointer.
//
// Example of tracked vulnerability:
//
//	jobs:
//	  extract:
//	    outputs:
//	      pr_title: ${{ steps.meta.outputs.title }}   # tainted via github.event.pull_request.title
//	    steps:
//	      - id: meta
//	        run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT
//	  process:
//	    needs: extract
//	    steps:
//	      - run: echo "${{ needs.extract.outputs.pr_title }}"  # detected!
type WorkflowTaintMap struct {
	// jobOutputTaints: jobID (lowercase) -> outputName (lowercase) -> []taintSource
	// A job that is registered but has no tainted outputs is represented by an empty inner map.
	jobOutputTaints map[string]map[string][]string
}

// NewWorkflowTaintMap creates a new WorkflowTaintMap instance.
func NewWorkflowTaintMap() *WorkflowTaintMap {
	return &WorkflowTaintMap{
		jobOutputTaints: make(map[string]map[string][]string),
	}
}

// Reset clears all registered job outputs. Called in VisitWorkflowPre to reset per workflow.
func (m *WorkflowTaintMap) Reset() {
	m.jobOutputTaints = make(map[string]map[string][]string)
}

// markJobAsRegistered marks a job as processed even if it has no tainted outputs.
// This allows IsTaintedNeedsOutput to distinguish "job not yet processed" from "job has clean outputs".
func (m *WorkflowTaintMap) markJobAsRegistered(jobID string) {
	jobID = strings.ToLower(jobID)
	if _, exists := m.jobOutputTaints[jobID]; !exists {
		m.jobOutputTaints[jobID] = make(map[string][]string)
	}
}

// setJobOutputTaint records a tainted output for a job. Idempotent: duplicate sources are deduplicated.
func (m *WorkflowTaintMap) setJobOutputTaint(jobID, outputName string, sources []string) {
	jobID = strings.ToLower(jobID)
	outputName = strings.ToLower(outputName)

	if m.jobOutputTaints[jobID] == nil {
		m.jobOutputTaints[jobID] = make(map[string][]string)
	}

	merged := append(m.jobOutputTaints[jobID][outputName], sources...)
	m.jobOutputTaints[jobID][outputName] = deduplicateStrings(merged)
}

// IsTaintedNeedsOutput checks if needs.jobID.outputs.outputName carries taint.
// Returns (sources, registered):
//   - len(sources) > 0, true  → output is tainted
//   - nil, true               → job is registered but output is clean (safe)
//   - nil, false              → job has not been processed yet (caller should add to pending)
func (m *WorkflowTaintMap) IsTaintedNeedsOutput(jobID, outputName string) (sources []string, registered bool) {
	jobID = strings.ToLower(jobID)
	outputName = strings.ToLower(outputName)

	outputs, exists := m.jobOutputTaints[jobID]
	if !exists {
		return nil, false
	}

	return outputs[outputName], true
}

// RegisterJobOutputs analyzes a job's outputs and records any that are tainted.
// It checks two patterns in output value expressions:
//  1. ${{ steps.X.outputs.Y }} → looks up in tracker (intra-job taint)
//  2. ${{ needs.X.outputs.Y }} → looks up in self (cross-job taint for multi-hop)
//
// After calling this, IsTaintedNeedsOutput(jobID, *) will return registered=true.
func (m *WorkflowTaintMap) RegisterJobOutputs(jobID string, tracker *TaintTracker, outputs map[string]*ast.Output) {
	// Always mark the job as registered, even if it has no tainted outputs.
	m.markJobAsRegistered(jobID)

	for outputName, output := range outputs {
		if output == nil || output.Value == nil || output.Value.Value == "" {
			continue
		}

		value := output.Value.Value
		sources := m.extractTaintSourcesFromValue(value, tracker)

		if len(sources) > 0 {
			m.setJobOutputTaint(jobID, outputName, sources)
		}
	}
}

// extractTaintSourcesFromValue extracts taint sources from an output value expression string.
// Handles both steps.X.outputs.Y (via tracker) and needs.X.outputs.Y (via self).
// Uses extractExpressionsFromString (which searches for "}}" as a delimiter) so that
// expressions containing single "}" characters (e.g. format('{0}', ...)) are handled correctly.
func (m *WorkflowTaintMap) extractTaintSourcesFromValue(value string, tracker *TaintTracker) []string {
	var sources []string

	for _, exprContent := range extractExpressionsFromString(value) {
		lower := strings.ToLower(exprContent)

		// Pattern 1: steps.X.outputs.Y → check TaintTracker
		if strings.HasPrefix(lower, "steps.") {
			if tainted, taintSources := tracker.IsTaintedExpr(exprContent); tainted {
				sources = append(sources, taintSources...)
			}
			continue
		}

		// Pattern 2: needs.X.outputs.Y → check self (multi-hop)
		if strings.HasPrefix(lower, "needs.") {
			if selfSources, _ := m.resolveFromExprStr(exprContent); len(selfSources) > 0 {
				sources = append(sources, selfSources...)
			}
		}
	}

	return sources
}

// ResolveFromExprNode extracts needs.X.outputs.Y from an AST node and looks up taint.
// Returns (sources, pending) where pending=true means the job isn't registered yet.
func (m *WorkflowTaintMap) ResolveFromExprNode(node expressions.ExprNode) (sources []string, pending bool) {
	exprStr := exprNodeToString(node)
	return m.resolveFromExprStr(exprStr)
}

// resolveFromExprStr parses needs.X.outputs.Y and looks up taint.
func (m *WorkflowTaintMap) resolveFromExprStr(exprStr string) (sources []string, pending bool) {
	lower := strings.ToLower(exprStr)
	parts := strings.Split(lower, ".")

	// needs.jobID.outputs.outputName
	if len(parts) < 4 || parts[0] != "needs" || parts[2] != "outputs" {
		return nil, false
	}

	jobID := parts[1]
	outputName := strings.Join(parts[3:], ".")

	src, registered := m.IsTaintedNeedsOutput(jobID, outputName)
	if !registered {
		return nil, true // pending
	}
	return src, false
}
