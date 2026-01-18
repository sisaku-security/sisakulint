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
	// hasLabeledTrigger indicates if the workflow uses 'labeled' event type
	hasLabeledTrigger bool
	// labeledTriggerPos stores the position of the labeled trigger for error reporting
	labeledTriggerPos *ast.Position
	// triggerEventName stores the event name (pull_request_target, pull_request, etc.)
	triggerEventName string
	// webhookEvent stores the webhook event for reference
	webhookEvent *ast.WebhookEvent
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
	rule.hasLabeledTrigger = false
	rule.labeledTriggerPos = nil
	rule.triggerEventName = ""
	rule.webhookEvent = nil

	// Check all workflow triggers
	for _, event := range n.On {
		webhookEvent, ok := event.(*ast.WebhookEvent)
		if !ok {
			continue
		}

		eventName := webhookEvent.EventName()
		// Only check pull_request_target and pull_request events
		// These are the events that can be triggered by external contributors
		if eventName != EventPullRequestTarget && eventName != "pull_request" {
			continue
		}

		// Check if 'labeled' is in the types
		for _, eventType := range webhookEvent.Types {
			if eventType.Value == EventTypeLabeled {
				rule.hasLabeledTrigger = true
				rule.labeledTriggerPos = eventType.Pos
				rule.triggerEventName = eventName
				rule.webhookEvent = webhookEvent
				rule.Debug("Found 'labeled' event type for %s at %s", eventName, eventType.Pos)
				break
			}
		}

		if rule.hasLabeledTrigger {
			break
		}
	}

	return nil
}

// VisitStep checks for dangerous checkout patterns in steps.
func (rule *UntrustedCheckoutTOCTOUCriticalRule) VisitStep(step *ast.Step) error {
	// Skip if no labeled trigger found
	if !rule.hasLabeledTrigger {
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
			"See https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-toctou-critical/",
		rule.triggerEventName,
		rule.labeledTriggerPos.Line,
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
	rule.hasLabeledTrigger = false
	rule.labeledTriggerPos = nil
	rule.triggerEventName = ""
	rule.webhookEvent = nil
	return nil
}

// VisitJobPre is required by the TreeVisitor interface but not used.
func (rule *UntrustedCheckoutTOCTOUCriticalRule) VisitJobPre(_ *ast.Job) error {
	return nil
}

// VisitJobPost is required by the TreeVisitor interface but not used.
func (rule *UntrustedCheckoutTOCTOUCriticalRule) VisitJobPost(_ *ast.Job) error {
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
