package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// UntrustedCheckoutTOCTOUCriticalRule detects Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities
// in GitHub Actions workflows. This rule identifies scenarios where label-based approval
// mechanisms can be bypassed due to using mutable branch references instead of immutable commit SHAs.
//
// TOCTOU vulnerability occurs when:
// 1. A workflow is triggered by 'labeled' event type (indicating label-based approval)
// 2. The checkout step uses a mutable reference (branch name) instead of a commit SHA
// 3. An attacker can modify the code after the label is applied but before/during execution
//
// This implements detection for CWE-367 (Time-of-check Time-of-use Race Condition).
// Security severity: 9.3 (Critical)
//
// Vulnerable pattern:
//
//	on:
//	  pull_request_target:
//	    types: [labeled]
//	jobs:
//	  test:
//	    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
//	    steps:
//	      - uses: actions/checkout@v4
//	        with:
//	          ref: ${{ github.event.pull_request.head.ref }}  # Mutable reference!
//
// Safe pattern:
//
//	on:
//	  pull_request_target:
//	    types: [labeled]
//	jobs:
//	  test:
//	    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
//	    steps:
//	      - uses: actions/checkout@v4
//	        with:
//	          ref: ${{ github.event.pull_request.head.sha }}  # Immutable reference
//
// References:
// - https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-toctou-critical/
// - CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
type UntrustedCheckoutTOCTOUCriticalRule struct {
	BaseRule
	// workflowTriggerInfos stores all workflow trigger names and positions for job-level filtering
	workflowTriggerInfos []TriggerInfo
	// labeledTriggerEvents maps event names that have the 'labeled' type to their trigger positions
	// e.g., {"pull_request_target": pos} when pull_request_target has types: [labeled]
	labeledTriggerEvents map[string]*ast.Position
	// jobHasLabeledTrigger indicates if the current job can execute on a labeled trigger
	// This is set per-job in VisitJobPre after analyzing job-level if conditions
	jobHasLabeledTrigger bool
	// jobLabeledTriggerName stores the matched trigger name for error reporting
	jobLabeledTriggerName string
	// jobLabeledTriggerPos stores the matched trigger position for error reporting
	jobLabeledTriggerPos *ast.Position
}

// NewUntrustedCheckoutTOCTOUCriticalRule creates a new instance of the TOCTOU critical rule.
func NewUntrustedCheckoutTOCTOUCriticalRule() *UntrustedCheckoutTOCTOUCriticalRule {
	return &UntrustedCheckoutTOCTOUCriticalRule{
		BaseRule: BaseRule{
			RuleName: "untrusted-checkout-toctou/critical",
			RuleDesc: "Detects TOCTOU vulnerabilities with label-based approval and mutable checkout references",
		},
	}
}

// VisitWorkflowPre analyzes the workflow triggers for labeled event types.
func (rule *UntrustedCheckoutTOCTOUCriticalRule) VisitWorkflowPre(n *ast.Workflow) error {
	// Reset state for each workflow
	rule.workflowTriggerInfos = nil
	rule.labeledTriggerEvents = make(map[string]*ast.Position)
	rule.jobHasLabeledTrigger = false
	rule.jobLabeledTriggerName = ""
	rule.jobLabeledTriggerPos = nil

	// Check all workflow triggers
	for _, event := range n.On {
		webhookEvent, ok := event.(*ast.WebhookEvent)
		if !ok {
			continue
		}

		eventName := webhookEvent.EventName()

		// Collect all triggers for job-level filtering via JobTriggerAnalyzer
		rule.workflowTriggerInfos = append(rule.workflowTriggerInfos, TriggerInfo{
			Name: eventName,
			Pos:  webhookEvent.Pos,
		})

		// Only check pull_request_target and pull_request events for labeled type
		// These are the events that can be triggered by external contributors
		if eventName != EventPullRequestTarget && eventName != "pull_request" {
			continue
		}

		// Check if 'labeled' is in the types
		for _, eventType := range webhookEvent.Types {
			if eventType.Value == EventTypeLabeled {
				rule.labeledTriggerEvents[eventName] = eventType.Pos
				rule.Debug("Found 'labeled' event type for %s at %s", eventName, eventType.Pos)
				break
			}
		}
	}

	return nil
}

// VisitStep checks for dangerous checkout patterns in steps.
func (rule *UntrustedCheckoutTOCTOUCriticalRule) VisitStep(step *ast.Step) error {
	// Skip if the current job cannot execute on a labeled trigger
	if !rule.jobHasLabeledTrigger {
		return nil
	}

	// Check if this step is an action (not a run script)
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	// Check if this is actions/checkout
	if !strings.HasPrefix(action.Uses.Value, "actions/checkout@") {
		return nil
	}

	rule.Debug("Found checkout action at %s", step.Pos)

	// Check if the checkout uses mutable ref
	if !rule.usesMutableRef(action) {
		return nil
	}

	// Report the vulnerability
	rule.Errorf(
		step.Pos,
		"TOCTOU vulnerability: checkout uses mutable reference with 'labeled' event type on '%s' trigger (line %d). "+
			"An attacker can modify code after label approval. The checked-out code may differ from what was reviewed. "+
			"Use immutable '${{ github.event.pull_request.head.sha }}' instead of mutable branch references. "+
			"See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckouttoctoucritical/",
		rule.jobLabeledTriggerName,
		rule.jobLabeledTriggerPos.Line,
	)

	// Add auto-fixer
	rule.AddAutoFixer(newTOCTOUCriticalFixer(rule.RuleName, step))

	return nil
}

// usesMutableRef checks if the checkout action uses a mutable branch reference.
func (rule *UntrustedCheckoutTOCTOUCriticalRule) usesMutableRef(action *ast.ExecAction) bool {
	if action.Inputs == nil {
		return false
	}

	refInput, exists := action.Inputs["ref"]
	if !exists || refInput.Value == nil {
		return false
	}

	refValue := refInput.Value.Value

	// Check for mutable ref patterns
	mutableRefPatterns := []string{
		"github.event.pull_request.head.ref",
		"github.head_ref",
	}

	for _, pattern := range mutableRefPatterns {
		if strings.Contains(refValue, pattern) {
			rule.Debug("Found mutable ref pattern '%s' in ref value: %s", pattern, refValue)
			return true
		}
	}

	return false
}

// VisitWorkflowPost resets state after workflow processing.
func (rule *UntrustedCheckoutTOCTOUCriticalRule) VisitWorkflowPost(_ *ast.Workflow) error {
	rule.workflowTriggerInfos = nil
	rule.labeledTriggerEvents = nil
	rule.jobHasLabeledTrigger = false
	rule.jobLabeledTriggerName = ""
	rule.jobLabeledTriggerPos = nil
	return nil
}

// VisitJobPre analyzes job-level if conditions to determine if the job
// can actually execute on a trigger with 'labeled' event type.
// This prevents false positives when workflows use job-level conditionals
// to restrict which triggers run specific jobs.
func (rule *UntrustedCheckoutTOCTOUCriticalRule) VisitJobPre(node *ast.Job) error {
	// Reset job-level state
	rule.jobHasLabeledTrigger = false
	rule.jobLabeledTriggerName = ""
	rule.jobLabeledTriggerPos = nil

	// Skip if no labeled triggers in workflow
	if len(rule.labeledTriggerEvents) == 0 {
		return nil
	}

	// Use JobTriggerAnalyzer to determine which triggers this job can actually execute on
	analyzer := NewJobTriggerAnalyzerWithPositions(rule.workflowTriggerInfos)
	effectiveTriggers := analyzer.AnalyzeJobTriggers(node)

	// Check if any of the effective triggers have the labeled event type
	for _, trigger := range effectiveTriggers {
		if pos, ok := rule.labeledTriggerEvents[trigger]; ok {
			rule.jobHasLabeledTrigger = true
			rule.jobLabeledTriggerName = trigger
			rule.jobLabeledTriggerPos = pos
			jobID := "<nil>"
			if node.ID != nil {
				jobID = node.ID.Value
			}
			rule.Debug("Job '%s' can execute on labeled trigger '%s'", jobID, trigger)
			break
		}
	}

	if !rule.jobHasLabeledTrigger {
		jobID := "<nil>"
		if node.ID != nil {
			jobID = node.ID.Value
		}
		rule.Debug("Job '%s' filtered out labeled triggers via if condition", jobID)
	}

	return nil
}

// VisitJobPost resets job-specific state.
func (rule *UntrustedCheckoutTOCTOUCriticalRule) VisitJobPost(_ *ast.Job) error {
	rule.jobHasLabeledTrigger = false
	rule.jobLabeledTriggerName = ""
	rule.jobLabeledTriggerPos = nil
	return nil
}

// toctouCriticalFixer implements the auto-fixer for TOCTOU critical vulnerabilities.
type toctouCriticalFixer struct {
	BaseAutoFixer
	step *ast.Step
}

// newTOCTOUCriticalFixer creates a new fixer for TOCTOU critical issues.
func newTOCTOUCriticalFixer(ruleName string, step *ast.Step) AutoFixer {
	return &toctouCriticalFixer{
		BaseAutoFixer: BaseAutoFixer{ruleName: ruleName},
		step:          step,
	}
}

// Fix implements the AutoFixer interface.
// It replaces mutable branch references with immutable commit SHA references.
func (f *toctouCriticalFixer) Fix() error {
	action, ok := f.step.Exec.(*ast.ExecAction)
	if !ok {
		return FormattedError(f.step.Pos, f.ruleName, "step is not an action")
	}

	if !strings.HasPrefix(action.Uses.Value, "actions/checkout@") {
		return FormattedError(f.step.Pos, f.ruleName, "not a checkout action")
	}

	if action.Inputs == nil {
		return FormattedError(f.step.Pos, f.ruleName, "checkout action has no inputs")
	}

	refInput, exists := action.Inputs["ref"]
	if !exists || refInput.Value == nil {
		return FormattedError(f.step.Pos, f.ruleName, "checkout action has no ref parameter")
	}

	// Replace mutable references with immutable SHA
	oldValue := refInput.Value.Value
	newValue := strings.ReplaceAll(oldValue, "github.event.pull_request.head.ref", "github.event.pull_request.head.sha")
	newValue = strings.ReplaceAll(newValue, "github.head_ref", "github.event.pull_request.head.sha")

	if refInput.Value.BaseNode != nil {
		refInput.Value.BaseNode.Value = newValue
	}
	refInput.Value.Value = newValue

	return nil
}
