package core

import (
	"regexp"
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

// VisitStep checks if a step performs an untrusted checkout.
// Two flavors of untrusted checkout are detected:
//  1. actions/checkout with a ref that points at untrusted PR code.
//  2. Run scripts that pull untrusted PR code into the workspace with git/gh
//     commands (gh pr checkout, git fetch origin pull/<n>/head,
//     git checkout $PR_SHA -- tasks/, git reset --hard <pr-sha>, git switch).
//
// Flavor 2 closes a detection gap: workflows that fetch PR head refs with
// `gh pr checkout` or `git fetch ... pull/N/head` instead of actions/checkout
// run the exact same Poisoned Pipeline Execution pattern while remaining
// invisible to a rule that only inspects actions/checkout inputs.
func (rule *UntrustedCheckoutRule) VisitStep(step *ast.Step) error {
	// Skip if this job cannot execute on dangerous triggers
	// This considers job-level if conditions that may filter out dangerous triggers
	if !rule.jobHasDangerousTrigger {
		return nil
	}

	// Collect env var names whose values are tainted with PR-derived refs; the
	// run-script scanner needs them to resolve `$PR_SHA`-style tokens below.
	taintedEnvVars := rule.collectTaintedRefEnvVars(step)

	if run, ok := step.Exec.(*ast.ExecRun); ok && run.Run != nil {
		rule.checkRunScriptUntrustedCheckout(step, run.Run.Value, taintedEnvVars)
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

// collectTaintedRefEnvVars collects the names of step-level env vars whose
// values are derived from PR head refs (e.g. PR_SHA: ${{ needs.*.outputs.pr_sha }}).
// The run-script scanner uses these to resolve `$PR_SHA`-style tokens.
func (rule *UntrustedCheckoutRule) collectTaintedRefEnvVars(step *ast.Step) map[string]bool {
	result := map[string]bool{}
	if step.Env == nil {
		return result
	}
	for _, envVar := range step.Env.Vars {
		if envVar.Value == nil {
			continue
		}
		// Only consider expressions/literals that reference PR-derived refs.
		if IsUnsafeCheckoutRef(envVar.Value.Value) {
			result[strings.ToLower(envVar.Name.Value)] = true
		}
	}
	return result
}

var (
	// reGHPRCheckout matches `gh pr checkout` — it always pulls the PR head for
	// the current issue/PR, so any use in a privileged-trigger job is a flag.
	reGHPRCheckout = regexp.MustCompile(`(?i)\bgh\s+pr\s+checkout\b`)
	// reGitFetchPullHead matches fetching a PR head ref:
	//   git fetch origin pull/123/head
	//   git fetch origin pull/${{ env.PR_NUMBER }}/head
	//   git fetch origin pull/${PR_NUMBER}/head
	reGitFetchPullHead = regexp.MustCompile(`(?i)\bgit\s+fetch\b[^\n]*\bpull/\s*\$?\{?\{?\s*[^}\s]*\s*\}?\}?\s*/head\b`)
	// reGitCheckoutRef matches ref-checkouts: `git checkout <ref> -- <path>` and
	// plain `git checkout <ref>`. The ref token is validated separately so
	// `git checkout main` stays clean while `git checkout $PR_SHA -- tasks/`
	// (or with a tainted expr ref) is caught.
	reGitCheckoutRef  = regexp.MustCompile(`(?i)\bgit\s+checkout\b`)
	reGitSwitchRef    = regexp.MustCompile(`(?i)\bgit\s+switch\b`)
	reGitResetHardRef = regexp.MustCompile(`(?i)\bgit\s+reset\s+--hard\b`)
	reGitRestoreRef   = regexp.MustCompile(`(?i)\bgit\s+restore\b`)
)

// checkRunScriptUntrustedCheckout detects untrusted PR code being pulled into
// the workspace via git/gh commands in a run script. It mirrors the
// actions/checkout detection for the same Poisoned Pipeline Execution pattern.
func (rule *UntrustedCheckoutRule) checkRunScriptUntrustedCheckout(step *ast.Step, script string, taintedEnvVars map[string]bool) {
	if strings.TrimSpace(script) == "" {
		return
	}

	report := func(reason string) {
		rule.Errorf(
			step.Pos,
			"checking out untrusted code from pull request via git/gh commands in workflow with privileged trigger '%s' (line %d). %s This allows potentially malicious code from external contributors to execute with access to repository secrets. "+
				"Use 'pull_request' trigger instead, or avoid checking out PR code when using '%s'. "+
				"See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details",
			rule.dangerousTriggerName,
			rule.dangerousTriggerPos.Line,
			reason,
			rule.dangerousTriggerName,
		)
	}

	// Quick pre-filter: nothing interesting in the script.
	if !reGHPRCheckout.MatchString(script) &&
		!reGitFetchPullHead.MatchString(script) &&
		!strings.Contains(strings.ToLower(script), "git checkout") &&
		!strings.Contains(strings.ToLower(script), "git switch") &&
		!strings.Contains(strings.ToLower(script), "git reset --hard") &&
		!strings.Contains(strings.ToLower(script), "git restore") {
		return
	}

	// gh pr checkout: unconditional.
	if reGHPRCheckout.MatchString(script) {
		report("'gh pr checkout' always checks out the untrusted PR head.")
	}

	// git fetch ... pull/<n>/head: unconditional (the pulled ref is PR code).
	if reGitFetchPullHead.MatchString(script) {
		report("'git fetch' of a 'pull/*/head' ref pulls untrusted PR head code into the workspace.")
	}

	// Tokenize for ref-validated commands: git checkout/switch/reset --hard/restore.
	// A token is "unsafe" when it references an untrusted PR ref, either directly
	// (github.event.pull_request.*, refs/pull/, *head_sha*, *pr_sha*, *head_ref*)
	// or via a step env var whose value is tainted (collected above).
	tokens := strings.Fields(script)
	for i := 0; i+1 < len(tokens); i++ {
		// Look for `git <subcommand>` sequences (tokens may be split by the
		// quote/space rules of the literal script text).
		normalized := strings.ToLower(strings.Trim(tokens[i], "\"'"))
		if normalized != "git" && normalized != "gh" {
			// `gh pr checkout` is handled by the unconditional regex above; no
			// ref-validated scanning needed for gh here.
			continue
		}
		sub := strings.ToLower(strings.Trim(tokens[i+1], "\"'"))
		switch sub {
		case "checkout", "switch", "restore":
			// Skip: `git checkout -- <paths>` (path checkout without a ref).
			if i+2 < len(tokens) && tokens[i+2] == "--" {
				continue
			}
			// Inspect the next 2 tokens: the ref (or, for `git switch -c`, the
			// target after the flag).
			for j := i + 2; j < len(tokens) && j <= i+3; j++ {
				refTok := strings.ToLower(strings.Trim(tokens[j], "\"'"))
				if refTok == "--" || refTok == "-c" || refTok == "-b" || refTok == "-f" {
					continue
				}
				if strings.HasPrefix(refTok, "-") {
					break
				}
				if isUnsafePRRefToken(refTok, taintedEnvVars) {
					report("'git " + sub + "' switches/checks out an untrusted PR head ref.")
					break
				}
				break
			}
		case "reset":
			// `git reset --hard <ref>` — the ref is one or two tokens after reset.
			for j := i + 2; j < len(tokens) && j <= i+3; j++ {
				refTok := strings.ToLower(strings.Trim(tokens[j], "\"'"))
				if refTok == "--hard" || refTok == "-hard" || refTok == "--" {
					continue
				}
				if strings.HasPrefix(refTok, "-") {
					break
				}
				if isUnsafePRRefToken(refTok, taintedEnvVars) {
					report("'git reset --hard' resets the workspace to an untrusted PR head ref.")
					break
				}
				break
			}
		}
	}
}

// isUnsafePRRefToken reports whether a command token references an untrusted
// PR head ref, either via known expressions/patterns or via a tainted env var.
func isUnsafePRRefToken(token string, taintedEnvVars map[string]bool) bool {
	if token == "" {
		return false
	}
	// Environment variable reference: $PR_SHA / ${PR_SHA}.
	if strings.HasPrefix(token, "$") {
		name := strings.TrimPrefix(strings.TrimPrefix(token, "${"), "$")
		name = strings.TrimSuffix(name, "}")
		return taintedEnvVars[strings.ToLower(name)]
	}
	// Direct expression/literal reference to PR-derived refs.
	return IsUnsafeCheckoutRef(token)
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
