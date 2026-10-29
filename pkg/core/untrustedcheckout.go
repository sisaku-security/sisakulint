package core

import (
	"strconv"
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

// checkoutForkPRProtectionMinVersions maps an actions/checkout major version to the
// first release that refuses to check out fork pull request code unless
// `allow-unsafe-pr-checkout` is set. The protection was backported to every
// maintained major on 2026-07-20; each boundary below was checked against the tag's
// own action.yml: v2.8.0, v3.7.0, v4.4.0, v5.1.0, v6.1.0 and v7.0.0 carry the input,
// while v2.7.x, v3.6.0, v4.3.9, v5.0.0 and v6.0.3 do not.
var checkoutForkPRProtectionMinVersions = map[int][3]int{
	2: {2, 8, 0},
	3: {3, 7, 0},
	4: {4, 4, 0},
	5: {5, 1, 0},
	6: {6, 1, 0},
	7: {7, 0, 0},
}

// checkoutProtection describes what can be said about the protection in the
// referenced actions/checkout build.
type checkoutProtection int

const (
	// protectionAbsent: a dated release that predates the backport.
	protectionAbsent checkoutProtection = iota
	// protectionPresent: the build refuses fork PR checkouts unless opted out.
	protectionPresent
	// protectionUnknown: a commit SHA or branch, which cannot be dated.
	protectionUnknown
)

// checkoutForkPRProtection dates the referenced actions/checkout build.
//
// A floating major tag (v4) tracks the newest release and therefore has the
// protection. A pinned semver is compared against the backport table. A commit SHA
// or a branch cannot be dated: the caller must not claim it either has the
// protection or lacks it, because a SHA pinned to v4.4.0 or later has it and is
// refused at runtime exactly like the tag.
func checkoutForkPRProtection(uses string) checkoutProtection {
	_, ref, found := strings.Cut(uses, "@")
	if !found || ref == "" {
		return protectionUnknown
	}
	version := strings.TrimPrefix(strings.TrimSpace(ref), "v")
	parts := strings.SplitN(version, "-", 2) // ignore a pre-release suffix
	fields := strings.Split(parts[0], ".")
	major, err := strconv.Atoi(fields[0])
	if err != nil {
		return protectionUnknown // SHA or branch
	}
	min, known := checkoutForkPRProtectionMinVersions[major]
	if !known {
		if major > 7 {
			return protectionPresent // a future major contains it
		}
		return protectionUnknown
	}
	if len(fields) == 1 {
		return protectionPresent // floating major tag
	}
	var got [3]int
	for i := 0; i < 3 && i < len(fields); i++ {
		n, err := strconv.Atoi(fields[i])
		if err != nil {
			return protectionUnknown
		}
		got[i] = n
	}
	for i := 0; i < 3; i++ {
		if got[i] != min[i] {
			if got[i] > min[i] {
				return protectionPresent
			}
			return protectionAbsent
		}
	}
	return protectionPresent
}

// checkoutInputTrue reports whether a boolean checkout input is set to true.
func checkoutInputTrue(input *ast.Input) bool {
	if input == nil || input.Value == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(input.Value.Value), "true")
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

	if action.Inputs == nil {
		return nil
	}

	// Two inputs can select pull request code: `ref` names a commit or branch, and
	// `repository` names the repository the code comes from. The rule used to return
	// early when `ref` was absent, so `repository: ...head.repo.full_name` on its own
	// was invisible even with the escape hatch enabled.
	var refValue, repoValue *ast.String
	if refInput, ok := action.Inputs["ref"]; ok && refInput != nil {
		refValue = refInput.Value
	}
	if repoInput, ok := action.Inputs["repository"]; ok && repoInput != nil {
		repoValue = repoInput.Value
	}

	refUnsafe := rule.isUntrustedPRRef(refValue)
	repoUnsafe := repoValue != nil && IsUnsafeCheckoutRepository(repoValue.Value)
	if !refUnsafe && !repoUnsafe {
		return nil
	}

	position := step.Pos
	switch {
	case refUnsafe:
		position = refValue.Pos
		rule.Debug("Checkout has unsafe ref parameter: %s", refValue.Value)
	case repoUnsafe:
		position = repoValue.Pos
		rule.Debug("Checkout has unsafe repository parameter: %s", repoValue.Value)
	}

	// `allow-unsafe-pr-checkout: true` is the documented opt-out from checkout's own
	// fork-PR protection: an explicitly enabled unsafe checkout, not an accident.
	optOut := checkoutInputTrue(action.Inputs["allow-unsafe-pr-checkout"])

	// Whether the referenced build has the protection changes what the reader can
	// conclude - but so does the trigger: checkout only refuses fork pull request code
	// on pull_request_target and workflow_run. Under issue_comment or workflow_call the
	// protection never applies, so the checkout proceeds regardless of the pin.
	protection := checkoutForkPRProtection(action.Uses.Value)
	guardedTrigger := rule.dangerousTriggerName == "pull_request_target"

	var consequence string
	switch {
	case optOut:
		consequence = "allow-unsafe-pr-checkout: true turns off checkout's fork-PR protection, so the checkout proceeds with untrusted code"
	case !guardedTrigger && rule.dangerousTriggerName == "workflow_run":
		consequence = "checkout's fork-PR protection only applies when the upstream workflow_run came from a fork, which this file cannot show, so the checkout may proceed"
	case !guardedTrigger:
		consequence = "checkout's fork-PR protection does not apply to '" + rule.dangerousTriggerName + "' workflows, so the checkout proceeds with untrusted code"
	case protection == protectionPresent:
		consequence = "this actions/checkout version contains the fork-PR protection, so the checkout is refused at runtime unless allow-unsafe-pr-checkout is enabled - the workflow becomes exploitable the moment that input is added"
	case protection == protectionAbsent:
		consequence = "the pinned actions/checkout version predates the fork-PR protection and no allow-unsafe-pr-checkout opt-out is needed for the checkout to proceed"
	default:
		consequence = "the referenced actions/checkout build cannot be dated (a commit SHA or branch), so whether it refuses the checkout is unknown; treat it as unprotected unless the ref is pinned to a protected release"
	}

	rule.Errorf(
		position,
		"checking out untrusted code from pull request in workflow with privileged trigger '%s' (line %d). This allows potentially malicious code from external contributors to execute with access to repository secrets. "+
			"%s. Use 'pull_request' trigger instead, or avoid checking out PR code when using '%s'. "+
			"See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details",
		rule.dangerousTriggerName,
		rule.dangerousTriggerPos.Line,
		consequence,
		rule.dangerousTriggerName,
	)

	// A ref can be replaced with the safe default; a `repository`-only checkout has no
	// ref for the fixer to rewrite, so no auto-fix is offered for that case.
	if refUnsafe {
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
