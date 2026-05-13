package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// UntrustedCheckoutRule checks for dangerous combinations of privileged triggers
// and untrusted code checkout. This rule detects the pattern where workflows
// triggered by pull_request_target, issue_comment, workflow_run, or workflow_call events
// explicitly check out code from pull request HEAD, which can allow malicious
// actors to execute code with access to repository secrets.
//
// This implements detection for CICD-SEC-4 (Poisoned Pipeline Execution)
// and maps to CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).
//
// Vulnerable pattern:
//
//	on: pull_request_target
//	jobs:
//	  build:
//	    steps:
//	      - uses: actions/checkout@v4
//	        with:
//	          ref: ${{ github.event.pull_request.head.sha }}
//
// Safe alternatives:
// 1. Use 'pull_request' trigger instead (no secrets access)
// 2. Don't checkout PR HEAD code when using privileged triggers
// 3. Use workflow_run pattern to separate privileged and unprivileged work
//
// References:
// - https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-critical/
// - https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections
// - https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
type UntrustedCheckoutRule struct {
	BaseRule
	// workflowTriggerInfos stores all trigger info (name + position) from the workflow
	workflowTriggerInfos []TriggerInfo
	// dangerousTriggerPos stores the position of the dangerous trigger for error reporting
	// This is updated per-job to reflect the actual trigger that matches the job's if condition
	dangerousTriggerPos *ast.Position
	// dangerousTriggerName stores the name of the dangerous trigger (e.g., "pull_request_target")
	// This is updated per-job to reflect the actual trigger that matches the job's if condition
	dangerousTriggerName string
	// jobHasDangerousTrigger indicates if the current job can execute on a dangerous trigger
	// This is set in VisitJobPre after analyzing job-level if conditions
	jobHasDangerousTrigger bool
}

// NewUntrustedCheckoutRule creates a new instance of the untrusted checkout rule
func NewUntrustedCheckoutRule() *UntrustedCheckoutRule {
	return &UntrustedCheckoutRule{
		BaseRule: BaseRule{
			RuleName: "untrusted-checkout",
			RuleDesc: "Detects checkout of untrusted code in workflows with privileged triggers that have access to secrets",
		},
	}
}

// VisitWorkflowPre collects all workflow triggers and identifies dangerous ones
// Dangerous triggers: pull_request_target, issue_comment, workflow_run, workflow_call
// These triggers run in the context of the base repository with access to secrets
func (rule *UntrustedCheckoutRule) VisitWorkflowPre(n *ast.Workflow) error {
	// Reset state for each workflow
	rule.workflowTriggerInfos = nil
	rule.dangerousTriggerPos = nil
	rule.dangerousTriggerName = ""
	rule.jobHasDangerousTrigger = false

	// Collect all workflow triggers with their positions
	for _, event := range n.On {
		var triggerName string
		var triggerPos *ast.Position

		// Check for WebhookEvent (pull_request_target, issue_comment, workflow_run)
		if webhookEvent, ok := event.(*ast.WebhookEvent); ok {
			triggerName = webhookEvent.EventName()
			triggerPos = webhookEvent.Pos
		} else if workflowCallEvent, ok := event.(*ast.WorkflowCallEvent); ok {
			// Check for WorkflowCallEvent (workflow_call)
			triggerName = workflowCallEvent.EventName()
			triggerPos = workflowCallEvent.Pos
		}

		if triggerName != "" {
			rule.workflowTriggerInfos = append(rule.workflowTriggerInfos, TriggerInfo{
				Name: triggerName,
				Pos:  triggerPos,
			})
			rule.Debug("Collected trigger '%s' at %s", triggerName, triggerPos)
		}
	}

	return nil
}

// VisitStep checks if a step performs an untrusted checkout
func (rule *UntrustedCheckoutRule) VisitStep(step *ast.Step) error {
	// Skip if this job cannot execute on dangerous triggers
	// This considers job-level if conditions that may filter out dangerous triggers
	if !rule.jobHasDangerousTrigger {
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

	// Check if the checkout has a 'ref' parameter
	// If no ref is specified, the default is safe (checks out the trigger SHA)
	if action.Inputs == nil {
		return nil
	}

	refInput, exists := action.Inputs["ref"]
	if !exists {
		return nil
	}

	refValue := refInput.Value
	if refValue == nil {
		return nil
	}

	rule.Debug("Checkout has ref parameter: %s", refValue.Value)

	// Check if the ref uses untrusted input from PR
	if rule.isUntrustedPRRef(refValue) {
		rule.Errorf(
			refValue.Pos,
			"checking out untrusted code from pull request in workflow with privileged trigger '%s' (line %d). This allows potentially malicious code from external contributors to execute with access to repository secrets. "+
				"Use 'pull_request' trigger instead, or avoid checking out PR code when using '%s'. "+
				"See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details",
			rule.dangerousTriggerName,
			rule.dangerousTriggerPos.Line,
			rule.dangerousTriggerName,
		)
		// Add auto-fixer to replace dangerous ref with safe default
		rule.AddAutoFixer(NewStepFixer(step, rule))
	}

	return nil
}

// isUntrustedPRRef checks if a ref value points to untrusted PR code
func (rule *UntrustedCheckoutRule) isUntrustedPRRef(refValue *ast.String) bool {
	if refValue == nil {
		return false
	}
	return IsUnsafeCheckoutRef(refValue.Value)
}

// VisitWorkflowPost resets state after workflow processing
func (rule *UntrustedCheckoutRule) VisitWorkflowPost(n *ast.Workflow) error {
	// Reset state for next workflow
	rule.workflowTriggerInfos = nil
	rule.dangerousTriggerPos = nil
	rule.dangerousTriggerName = ""
	rule.jobHasDangerousTrigger = false
	return nil
}

// VisitJobPre analyzes job-level if conditions to determine if the job
// can actually execute on dangerous triggers. This prevents false positives
// when workflows use job-level conditionals to restrict which triggers run specific jobs.
func (rule *UntrustedCheckoutRule) VisitJobPre(node *ast.Job) error {
	// Reset job-level state
	rule.jobHasDangerousTrigger = false
	rule.dangerousTriggerName = ""
	rule.dangerousTriggerPos = nil

	// If no triggers in workflow, skip
	if len(rule.workflowTriggerInfos) == 0 {
		return nil
	}

	// Use JobTriggerAnalyzer with positions to check if this job can execute on dangerous triggers
	// and get the specific matched trigger info for accurate diagnostics
	analyzer := NewJobTriggerAnalyzerWithPositions(rule.workflowTriggerInfos)
	matchedTrigger := analyzer.GetMatchedPrivilegedTrigger(node)

	jobID := "<nil>"
	if node.ID != nil {
		jobID = node.ID.Value
	}

	if matchedTrigger != nil {
		rule.jobHasDangerousTrigger = true
		rule.dangerousTriggerName = matchedTrigger.Name
		rule.dangerousTriggerPos = matchedTrigger.Pos
		if matchedTrigger.Pos != nil {
			rule.Debug("Job '%s' can execute on privileged trigger '%s' at line %d",
				jobID, matchedTrigger.Name, matchedTrigger.Pos.Line)
		} else {
			rule.Debug("Job '%s' can execute on privileged trigger '%s'",
				jobID, matchedTrigger.Name)
		}
	} else {
		rule.Debug("Job '%s' filtered out privileged triggers via if condition", jobID)
	}

	return nil
}

// VisitJobPost is required by the TreeVisitor interface but not used
func (rule *UntrustedCheckoutRule) VisitJobPost(node *ast.Job) error {
	return nil
}

// FixStep implements the StepFixer interface to auto-fix untrusted checkout issues
// The fix replaces the dangerous ref parameter with a safe default (github.sha)
//
// BEHAVIOR WITH MIXED LITERALS AND EXPRESSIONS:
// When the ref contains both literals and expressions (e.g., "pr-${{ github.event.pull_request.head.ref }}"),
// the auto-fixer will replace the ENTIRE value with "${{ github.sha }}". This ensures security
// but may change the workflow behavior if the literal prefix was meaningful.
//
// Example:
//
//	Before: ref: pr-${{ github.event.pull_request.head.ref }}
//	After:  ref: ${{ github.sha }}
//
// This is intentional - security takes priority over preserving custom ref formats.
// Users can review and adjust the fix if needed, as auto-fix is opt-in with -fix flag.
//
// See: https://github.com/sisaku-security/sisakulint/pull/226#discussion_r2658870256
func (rule *UntrustedCheckoutRule) FixStep(step *ast.Step) error {
	// Get the action from the step
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return FormattedError(step.Pos, rule.RuleName, "step is not an action")
	}

	// Check if this is actions/checkout
	if !strings.HasPrefix(action.Uses.Value, "actions/checkout@") {
		return FormattedError(step.Pos, rule.RuleName, "not a checkout action")
	}

	// Check if the checkout has inputs
	if action.Inputs == nil {
		return FormattedError(step.Pos, rule.RuleName, "checkout action has no inputs")
	}

	// Get the ref input
	refInput, exists := action.Inputs["ref"]
	if !exists {
		return FormattedError(step.Pos, rule.RuleName, "checkout action has no ref parameter")
	}

	// Replace the dangerous ref with a safe default (github.sha)
	// github.sha is the SHA of the base branch, which is safe to checkout
	// This is equivalent to removing the ref parameter, but more explicit
	if refInput.Value.BaseNode != nil {
		refInput.Value.BaseNode.Value = "${{ github.sha }}"
	}
	refInput.Value.Value = "${{ github.sha }}"

	rule.Debug("Fixed untrusted checkout at %s: replaced ref with github.sha", step.Pos)

	return nil
}
