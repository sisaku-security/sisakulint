package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// ImproperAccessControlRule detects improper access control vulnerabilities in GitHub Actions workflows.
// This rule identifies scenarios where label-based approval mechanisms can be bypassed due to:
// 1. Using 'synchronize' event type which allows code changes after label approval
// 2. Using mutable branch references (head.ref) instead of immutable commit SHAs (head.sha)
//
// This implements detection for CWE-285 (Improper Access Control).
//
// Vulnerable pattern:
//
//	on:
//	  pull_request_target:
//	    types: [opened, synchronize]
//	jobs:
//	  test:
//	    steps:
//	      - uses: actions/checkout@v3
//	        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
//	        with:
//	          ref: ${{ github.event.pull_request.head.ref }}
//
// Safe pattern:
//
//	on:
//	  pull_request_target:
//	    types: [labeled]
//	jobs:
//	  test:
//	    steps:
//	      - uses: actions/checkout@v3
//	        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
//	        with:
//	          ref: ${{ github.event.pull_request.head.sha }}
//
// References:
// - https://codeql.github.com/codeql-query-help/actions/actions-improper-access-control/
// - https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
type ImproperAccessControlRule struct {
	BaseRule
	// hasPullRequestTarget indicates if the workflow uses pull_request_target trigger
	hasPullRequestTarget bool
	// hasSynchronizeType indicates if pull_request_target includes 'synchronize' type
	hasSynchronizeType bool
	// pullRequestTargetPos stores the position of pull_request_target for error reporting
	pullRequestTargetPos *ast.Position
	// webhookEvent stores the webhook event for auto-fix
	webhookEvent *ast.WebhookEvent
	// currentWorkflow stores the current workflow being analyzed
	currentWorkflow *ast.Workflow
}

// NewImproperAccessControlRule creates a new instance of the improper access control rule
func NewImproperAccessControlRule() *ImproperAccessControlRule {
	return &ImproperAccessControlRule{
		BaseRule: BaseRule{
			RuleName: "improper-access-control",
			RuleDesc: "Detects improper access control in workflows using label-based approval with synchronize events",
		},
	}
}

// VisitWorkflowPre analyzes the workflow triggers for improper access control patterns
func (rule *ImproperAccessControlRule) VisitWorkflowPre(n *ast.Workflow) error {
	// Reset state for each workflow
	rule.hasPullRequestTarget = false
	rule.hasSynchronizeType = false
	rule.pullRequestTargetPos = nil
	rule.webhookEvent = nil
	rule.currentWorkflow = n

	// Check all workflow triggers
	for _, event := range n.On {
		webhookEvent, ok := event.(*ast.WebhookEvent)
		if !ok {
			continue
		}

		if webhookEvent.EventName() != EventPullRequestTarget {
			continue
		}

		rule.hasPullRequestTarget = true
		rule.pullRequestTargetPos = webhookEvent.Pos
		rule.webhookEvent = webhookEvent

		// If 'types' is not specified, GitHub Actions defaults to [opened, synchronize, reopened]
		// See: https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target
		if len(webhookEvent.Types) == 0 {
			rule.hasSynchronizeType = true
			rule.Debug("Found pull_request_target with implicit 'synchronize' type (types unspecified) at %s", webhookEvent.Pos)
		} else {
			// Check if 'synchronize' is explicitly in the types
			for _, eventType := range webhookEvent.Types {
				if eventType.Value == EventTypeSynchronize {
					rule.hasSynchronizeType = true
					rule.Debug("Found pull_request_target with explicit 'synchronize' type at %s", webhookEvent.Pos)
					break
				}
			}
		}
	}

	return nil
}

// VisitStep checks for dangerous checkout patterns in steps
func (rule *ImproperAccessControlRule) VisitStep(step *ast.Step) error {
	// Skip if not pull_request_target with synchronize
	if !rule.hasPullRequestTarget || !rule.hasSynchronizeType {
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

	// Check if the step has a label-based condition
	hasLabelCondition := rule.hasLabelBasedCondition(step)

	// Check if the checkout uses mutable ref
	usesMutableRef := rule.usesMutableRef(action)

	// If both conditions are met, this is a vulnerability
	if hasLabelCondition && usesMutableRef {
		rule.Errorf(
			step.Pos,
			"improper access control: checkout uses label-based approval with 'synchronize' event type and mutable ref. "+
				"An attacker can modify code after label approval. "+
				"Fix: 1) Change trigger types from 'synchronize' to 'labeled', "+
				"2) Use immutable 'github.event.pull_request.head.sha' instead of mutable 'head.ref'. "+
				"See https://codeql.github.com/codeql-query-help/actions/actions-improper-access-control/",
		)
		// Add auto-fixer with captured webhook event reference
		rule.AddAutoFixer(newImproperAccessControlFixer(rule.RuleName, step, rule.webhookEvent))
	} else if usesMutableRef {
		// Even without label condition, using mutable ref with synchronize is risky
		rule.Errorf(
			step.Pos,
			"improper access control: checkout uses mutable ref '${{ github.event.pull_request.head.ref }}' with 'synchronize' event type. "+
				"This allows code to change after initial review. "+
				"Use immutable '${{ github.event.pull_request.head.sha }}' instead. "+
				"See https://codeql.github.com/codeql-query-help/actions/actions-improper-access-control/",
		)
		// Add auto-fixer with captured webhook event reference
		rule.AddAutoFixer(newImproperAccessControlFixer(rule.RuleName, step, rule.webhookEvent))
	}

	return nil
}

// hasLabelBasedCondition checks if the step or its job has a label-based condition
func (rule *ImproperAccessControlRule) hasLabelBasedCondition(step *ast.Step) bool {
	// Check step-level condition
	if step.If != nil && step.If.Value != "" {
		if rule.isLabelCondition(step.If.Value) {
			return true
		}
	}
	return false
}

// isLabelCondition checks if a condition string references label-based checks
func (rule *ImproperAccessControlRule) isLabelCondition(condition string) bool {
	labelPatterns := []string{
		"github.event.pull_request.labels",
		"contains(github.event.pull_request.labels",
		"github.event.label",
	}

	for _, pattern := range labelPatterns {
		if strings.Contains(condition, pattern) {
			return true
		}
	}
	return false
}

// usesMutableRef checks if the checkout action uses a mutable branch reference
func (rule *ImproperAccessControlRule) usesMutableRef(action *ast.ExecAction) bool {
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
			return true
		}
	}

	return false
}

// VisitWorkflowPost resets state after workflow processing
func (rule *ImproperAccessControlRule) VisitWorkflowPost(n *ast.Workflow) error {
	rule.hasPullRequestTarget = false
	rule.hasSynchronizeType = false
	rule.pullRequestTargetPos = nil
	rule.webhookEvent = nil
	rule.currentWorkflow = nil
	return nil
}

// VisitJobPre is required by the TreeVisitor interface but not used
func (rule *ImproperAccessControlRule) VisitJobPre(node *ast.Job) error {
	return nil
}

// VisitJobPost is required by the TreeVisitor interface but not used
func (rule *ImproperAccessControlRule) VisitJobPost(node *ast.Job) error {
	return nil
}

// improperAccessControlFixer is a custom fixer that captures the webhook event reference
// at the time of detection, ensuring the fix can be applied after the visitor completes
type improperAccessControlFixer struct {
	BaseAutoFixer
	step         *ast.Step
	webhookEvent *ast.WebhookEvent
}

// newImproperAccessControlFixer creates a new fixer with captured references
func newImproperAccessControlFixer(ruleName string, step *ast.Step, webhookEvent *ast.WebhookEvent) AutoFixer {
	return &improperAccessControlFixer{
		BaseAutoFixer: BaseAutoFixer{ruleName: ruleName},
		step:          step,
		webhookEvent:  webhookEvent,
	}
}

// Fix implements the AutoFixer interface
func (f *improperAccessControlFixer) Fix() error {
	// Get the action from the step
	action, ok := f.step.Exec.(*ast.ExecAction)
	if !ok {
		return FormattedError(f.step.Pos, f.ruleName, "step is not an action")
	}

	// Check if this is actions/checkout
	if !strings.HasPrefix(action.Uses.Value, "actions/checkout@") {
		return FormattedError(f.step.Pos, f.ruleName, "not a checkout action")
	}

	// Fix 1: Replace mutable ref with immutable sha
	if action.Inputs != nil {
		if refInput, exists := action.Inputs["ref"]; exists && refInput.Value != nil {
			oldValue := refInput.Value.Value
			newValue := strings.ReplaceAll(oldValue, "github.event.pull_request.head.ref", "github.event.pull_request.head.sha")
			newValue = strings.ReplaceAll(newValue, "github.head_ref", "github.event.pull_request.head.sha")

			if refInput.Value.BaseNode != nil {
				refInput.Value.BaseNode.Value = newValue
			}
			refInput.Value.Value = newValue
		}
	}

	// Fix 2: Modify webhook event types to use 'labeled' instead of 'synchronize'
	if f.webhookEvent != nil {
		f.fixWebhookEventTypes()
	}

	return nil
}

// fixWebhookEventTypes modifies the webhook event types to replace 'synchronize' with 'labeled'
func (f *improperAccessControlFixer) fixWebhookEventTypes() {
	if f.webhookEvent == nil {
		return
	}

	// If 'types' is not specified, GitHub Actions defaults to [opened, synchronize, reopened]
	// We need to add explicit 'types: [labeled]' to avoid implicit synchronize
	if len(f.webhookEvent.Types) == 0 {
		// Create new 'labeled' type entry
		labeledType := &ast.String{
			Value: "labeled",
			Pos:   f.webhookEvent.Pos,
		}
		f.webhookEvent.Types = []*ast.String{labeledType}
		return
	}

	hasLabeled := false
	synchronizeIdx := -1

	for i, eventType := range f.webhookEvent.Types {
		if eventType.Value == EventTypeLabeled {
			hasLabeled = true
		}
		if eventType.Value == EventTypeSynchronize {
			synchronizeIdx = i
		}
	}

	// If 'synchronize' exists, replace it with 'labeled' (if 'labeled' doesn't already exist)
	if synchronizeIdx >= 0 {
		if !hasLabeled {
			f.webhookEvent.Types[synchronizeIdx].Value = EventTypeLabeled
			if f.webhookEvent.Types[synchronizeIdx].BaseNode != nil {
				f.webhookEvent.Types[synchronizeIdx].BaseNode.Value = EventTypeLabeled
			}
		} else {
			// Remove 'synchronize' if 'labeled' already exists
			f.webhookEvent.Types = append(
				f.webhookEvent.Types[:synchronizeIdx],
				f.webhookEvent.Types[synchronizeIdx+1:]...,
			)
		}
	}
}
