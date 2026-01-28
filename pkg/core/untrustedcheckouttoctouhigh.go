package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// UntrustedCheckoutTOCTOUHighRule detects Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities
// in GitHub Actions workflows. This rule identifies scenarios where deployment environment
// approval mechanisms can be bypassed due to using mutable branch references instead of
// immutable commit SHAs.
//
// TOCTOU vulnerability occurs when:
// 1. A job uses a deployment environment (which typically requires approval)
// 2. The checkout step uses a mutable reference (branch name) instead of a commit SHA
// 3. An attacker can modify the code after approval is granted but before/during execution
//
// This implements detection for CWE-367 (Time-of-check Time-of-use Race Condition).
// Security severity: 7.5 (High)
//
// Vulnerable pattern:
//
//	on: pull_request_target
//	jobs:
//	  deploy:
//	    environment: production  # Requires manual approval
//	    steps:
//	      - uses: actions/checkout@v4
//	        with:
//	          ref: ${{ github.event.pull_request.head.ref }}  # Mutable reference!
//
// Safe pattern:
//
//	on: pull_request_target
//	jobs:
//	  deploy:
//	    environment: production
//	    steps:
//	      - uses: actions/checkout@v4
//	        with:
//	          ref: ${{ github.event.pull_request.head.sha }}  # Immutable reference
//
// References:
// - https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-toctou-high/
// - CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
type UntrustedCheckoutTOCTOUHighRule struct {
	BaseRule
	// hasPRTrigger indicates if the workflow uses pull_request or pull_request_target trigger
	hasPRTrigger bool
	// prTriggerPos stores the position of the PR trigger for error reporting
	prTriggerPos *ast.Position
	// triggerEventName stores the event name (pull_request_target, pull_request)
	triggerEventName string
	// currentJob stores the current job being analyzed
	currentJob *ast.Job
	// hasEnvironment indicates if the current job has an environment configured
	hasEnvironment bool
	// environmentName stores the name of the environment
	environmentName string
}

// NewUntrustedCheckoutTOCTOUHighRule creates a new instance of the TOCTOU high rule.
func NewUntrustedCheckoutTOCTOUHighRule() *UntrustedCheckoutTOCTOUHighRule {
	return &UntrustedCheckoutTOCTOUHighRule{
		BaseRule: BaseRule{
			RuleName: "untrusted-checkout-toctou/high",
			RuleDesc: "Detects TOCTOU vulnerabilities with deployment environment approval and mutable checkout references",
		},
	}
}

// VisitWorkflowPre analyzes the workflow triggers for PR-related events.
func (rule *UntrustedCheckoutTOCTOUHighRule) VisitWorkflowPre(n *ast.Workflow) error {
	// Reset state for each workflow
	rule.hasPRTrigger = false
	rule.prTriggerPos = nil
	rule.triggerEventName = ""
	rule.currentJob = nil
	rule.hasEnvironment = false
	rule.environmentName = ""

	// Check all workflow triggers
	for _, event := range n.On {
		webhookEvent, ok := event.(*ast.WebhookEvent)
		if !ok {
			continue
		}

		eventName := webhookEvent.EventName()
		// Only check pull_request_target and pull_request events
		if eventName == EventPullRequestTarget || eventName == "pull_request" {
			rule.hasPRTrigger = true
			rule.prTriggerPos = webhookEvent.Pos
			rule.triggerEventName = eventName
			rule.Debug("Found PR trigger '%s' at %s", eventName, webhookEvent.Pos)
			break
		}
	}

	return nil
}

// VisitJobPre checks if the job has a deployment environment configured.
func (rule *UntrustedCheckoutTOCTOUHighRule) VisitJobPre(node *ast.Job) error {
	rule.currentJob = node
	rule.hasEnvironment = false
	rule.environmentName = ""

	// Skip if no PR trigger
	if !rule.hasPRTrigger {
		return nil
	}

	// Check if the job has an environment
	if node.Environment != nil {
		rule.hasEnvironment = true
		if node.Environment.Name != nil {
			rule.environmentName = node.Environment.Name.Value
		}
		rule.Debug("Found job with environment '%s' at %s", rule.environmentName, node.Pos)
	}

	return nil
}

// VisitStep checks for dangerous checkout patterns in steps.
func (rule *UntrustedCheckoutTOCTOUHighRule) VisitStep(step *ast.Step) error {
	// Skip if no PR trigger or no environment
	if !rule.hasPRTrigger || !rule.hasEnvironment {
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

	rule.Debug("Found checkout action at %s in job with environment '%s'", step.Pos, rule.environmentName)

	// Check if the checkout uses mutable ref
	if !rule.usesMutableRef(action) {
		return nil
	}

	// Report the vulnerability
	envInfo := rule.environmentName
	if envInfo == "" {
		envInfo = "(unnamed)"
	}

	rule.Errorf(
		step.Pos,
		"TOCTOU vulnerability: checkout uses mutable reference in job with deployment environment '%s' on '%s' trigger. "+
			"An attacker can modify code after environment approval is granted. The checked-out code may differ from what was approved. "+
			"Use immutable '${{ github.event.pull_request.head.sha }}' instead of mutable branch references. "+
			"See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckouttoctouhigh/",
		envInfo,
		rule.triggerEventName,
	)

	// Add auto-fixer
	rule.AddAutoFixer(newTOCTOUHighFixer(rule.RuleName, step))

	return nil
}

// usesMutableRef checks if the checkout action uses a mutable branch reference.
func (rule *UntrustedCheckoutTOCTOUHighRule) usesMutableRef(action *ast.ExecAction) bool {
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
func (rule *UntrustedCheckoutTOCTOUHighRule) VisitWorkflowPost(_ *ast.Workflow) error {
	rule.hasPRTrigger = false
	rule.prTriggerPos = nil
	rule.triggerEventName = ""
	rule.currentJob = nil
	rule.hasEnvironment = false
	rule.environmentName = ""
	return nil
}

// VisitJobPost resets job-specific state.
func (rule *UntrustedCheckoutTOCTOUHighRule) VisitJobPost(_ *ast.Job) error {
	rule.currentJob = nil
	rule.hasEnvironment = false
	rule.environmentName = ""
	return nil
}

// toctouHighFixer implements the auto-fixer for TOCTOU high vulnerabilities.
type toctouHighFixer struct {
	BaseAutoFixer
	step *ast.Step
}

// newTOCTOUHighFixer creates a new fixer for TOCTOU high issues.
func newTOCTOUHighFixer(ruleName string, step *ast.Step) AutoFixer {
	return &toctouHighFixer{
		BaseAutoFixer: BaseAutoFixer{ruleName: ruleName},
		step:          step,
	}
}

// Fix implements the AutoFixer interface.
// It replaces mutable branch references with immutable commit SHA references.
func (f *toctouHighFixer) Fix() error {
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
