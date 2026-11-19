package rules

import (
	"context"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// UntrustedCheckoutToctou is the rule untrusted-checkout-toctou: a job
// that a person approves (a label, an environment's reviewers) checks out
// the code of a pull request by what its author can move (a branch,
// refs/pull/<n>/head), so a push after the approval runs code no one
// approved with the job's secrets and token.
var UntrustedCheckoutToctou lint.Rule = withExamples(lint.WithView[ir.UntrustedCheckoutToctouReader](untrustedCheckoutToctou{}, ir.UntrustedCheckoutToctouView))

// UntrustedCheckoutToctouID is the ID of untrusted-checkout-toctou;
// PinHeadSHAID and PinHeadSHAReviewID the kinds of its fixes.
var (
	UntrustedCheckoutToctouID = lint.MustRuleID("untrusted-checkout-toctou")
	PinHeadSHAID              = lint.MustFixKindID(ir.FixPinHeadSHA.String())
	PinHeadSHAReviewID        = lint.MustFixKindID(ir.FixPinHeadSHAReview.String())
)

type untrustedCheckoutToctou struct{}

func (untrustedCheckoutToctou) Meta() lint.Meta { return untrustedCheckoutToctouMeta }

func (untrustedCheckoutToctou) Check(ctx context.Context, c *lint.RuleContext, v ir.UntrustedCheckoutToctouReader) error {
	for _, s := range v.CheckoutSites() {
		if len(s.PRCodeOn()) == 0 {
			continue // only workflow_dispatch: untrusted-checkout reports its input
		}
		if s.Approval() == analysis.ApprovalNone {
			continue // untrusted-checkout reads it
		}
		approvalKind, env := s.Approval(), s.Environment()
		if auto := s.AutomaticApproval(); approvalKind == analysis.ApprovalLabel && freeLabel(c, auto) {
			if auto.Environment == (facts.EnvironmentName{}) {
				continue // no person approves: untrusted-checkout reports it
			}
			approvalKind, env = analysis.ApprovalEnvironment, auto.Environment // the required reviewers of the environment approve it
		}
		if s.CheckoutCode() == analysis.CodeUnknown && approvalKind == analysis.ApprovalLabel {
			unexamined(c, s.Dynamic(), s.InconclusiveValues(), s.At(), nil) // with an environment, untrusted-checkout reports it
			continue
		}
		evs, guard, ok := guarded(s.PRCodeOn(), s.Guard(), s.SHA())
		if !ok {
			continue
		}
		if s.CheckoutCode() != analysis.CodePR || !s.Mutable() {
			continue
		}
		refs := s.Refs()
		i := movingRef(refs)
		r := refs[i]
		f := lint.FindingDraft{
			Location: c.At(r.At),
			Args:     UntrustedCheckoutToctouMutableRef{Uses: s.UsesText(), CheckoutRef: r.Text, PRCodeOn: eventsOf(evs), Approval: approvalKind},
		}
		var approval *lint.Condition
		if approvalKind == analysis.ApprovalEnvironment {
			q := facts.RepoEnvironmentProtected{Repo: c.Repo(), Environment: env}
			approval = factCond(q, true)
			// untrusted-checkout fixes the same ref when the environment
			// approves nothing; fix it here only when it is known to approve
			if a := q.Ask(ctx, c.Resolver); a.State != facts.StateFound || !a.Value {
				f.NoFix = &lint.NoFix{Reason: ir.NoFixReasonFact, Queries: []facts.Query{q},
					Note: "whether the environment " + env.String() + " has required reviewers is not known; untrusted-checkout gives the fix for when it has none"}
			}
		}
		f.Condition = allOf(approval, guard)
		if f.NoFix == nil {
			f.Fix, f.NoFix = fixOf(s.PinHeadSHA(i, evs))
		}
		c.Report(f)
	}
	return nil
}

// movingRef is the index in refs of the reference that can move: a
// branch's name with the fork, or refs/pull/<n>/…; else the fork itself.
func movingRef(refs []ir.CheckoutRef) int {
	for i, r := range refs {
		if r.Mutable {
			return i
		}
	}
	return 0
}

// toctouBase is the CVSS of untrusted-checkout-toctou: the attacker must
// push after the approval and before a checkout of the run, or of a re-run
// of it, and a person approves; what the code does in the job is that of
// untrusted-checkout.
var toctouBase = func() lint.CVSS {
	b := checkoutBase
	b.AT = metric(lint.AttackRequirementsPresent, "the push must come after the approval and before a checkout fetches the ref: in the run itself (the time from the label to the step, seconds to minutes), or before a re-run of the run, which a credential with write access to the permission Actions may start within 30 days, such as the credential of an attacker whose only write access is to the permission Actions, and which runs with the payload of the approval, so that a label taken off since still lets the job run (observed on 2026-09-28)", pwnRequests, reRuns)
	b.UI = metric(lint.UserInteractionActive, "a maintainer adds the label, or approves the environment, after looking at the pull request")
	return b
}()

var (
	approvedPre     = lint.MustPreconditionID("approved")
	movableCheckout = lint.MustPreconditionID("movable-checkout")
)

var untrustedCheckoutToctouMeta = lint.Meta{
	ID:       UntrustedCheckoutToctouID,
	Problem:  "a privileged job that a person approves checks out the code of a pull request by what its author can move, so a push after the approval runs code no one approved",
	Expected: "a job that a person approves checks out the commit the approval saw (github.event.pull_request.head.sha)",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessUntrustedCodeExecution}, AttackMeans: []lint.AttackMeans{lint.AttackMeansCode, lint.AttackMeansOperation}},
	FindingKinds: []lint.FindingKind{{
		FindingText:     textUntrustedCheckoutToctouMutableRef,
		Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor},
		Preconditions:   []lint.PreconditionID{privilegedEvent, prTree, noGuard, approvedPre, movableCheckout, callersEvents},
		FactKinds:       []facts.Kind{facts.KindRepoEnvironmentProtected, facts.KindGitCommitContains},
		Fixes:           []lint.FixKindID{PinHeadSHAID, PinHeadSHAReviewID},
		CVSS:            toctouBase,
		ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "GitHub Security Lab reported the race in label-gated workflows, and a checkout of refs/pull/<n>/head after a maintainer's comment (GHSL-2026-166); no attack in the wild was found", ghsl2026166),
	}},
	Threat: lint.Threat{
		Actors: []lint.Actor{{Attacker: lint.AttackerForkPRAuthor, Via: "pushes to the pull request's branch after a maintainer approves it",
			Events: onPRTargetAndRun, RunStarters: startedBy(onPRTargetAndRun, workflow.EventNamePullRequestTarget), Gains: jobGains}},
		Preconditions: []lint.Precondition{
			callersEventsPre,
			privilegedEventPre,
			prTreePre,
			noGuardPre,
			{
				ID:    approvedPre,
				Text:  "a person approves the run: a job that runs only on pull_request_target with the activity type labeled, whose label needs a credential with write access to the permission Issues or Pull requests, which the credential premise assumes no attacker holds, and no workflow of the same repository runs actions/labeler that adds the label to the pull request of an attacker with a token other than the GITHUB_TOKEN; or a job whose environment has required reviewers (repo.environment-protected)",
				Cites: []lint.Citation{pwnRequests},
			},
			{
				ID:   movableCheckout,
				Text: "the checkout fetches what the author moves: refs/pull/<n>/head or merge, or a branch of the fork; github.event.pull_request.head.sha is the head when the label was added",
				Observed: []lint.Observation{
					{Date: observedCheckout, Runner: runner, What: "a commit pushed after the label, while the labeled run waited, was fetched by refs/pull/<n>/head; github.event.pull_request.head.sha fetched the head of the time of the label; the push ran no labeled run"},
				},
			},
		},
	},
	Citations:          []lint.Citation{cvss},
	Targets:            []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms:    withRemoteCallee(append(append([]lint.UndetectedForm(nil), checkoutLimits...), append(append(slices.Clone(toctouLimits), ifLimits...), automaticLabelCheckoutLimit)...)),
	InconclusiveKinds:  withRemoteCalleeUnknown(checkoutGaps),
	FalsePositiveForms: []lint.FalsePositiveForm{},
	FixKinds: []lint.FixKind{
		{ID: PinHeadSHAID, Title: "check out the commit the approval saw: " + ir.HeadSHAContext + " in place of a branch or refs/pull/<n>/head", FactKinds: []facts.Kind{facts.KindRepoEnvironmentProtected}, Safety: lint.SafetySafe},
		{ID: PinHeadSHAReviewID, Title: "check out the head the approval saw in place of refs/pull/<n>/merge", FactKinds: []facts.Kind{facts.KindRepoEnvironmentProtected}, Safety: lint.SafetyReview, PossibleSideEffects: []ir.SideEffect{ir.SideEffectMergeCommitReplaced}},
	},
}

var (
	ghsl2026166      = lint.MustCitation("https://securitylab.github.com/advisories/GHSL-2026-166_MongoDB_Node_js_Driver/")
	onPRTargetAndRun = []workflow.EventName{workflow.EventNamePullRequestTarget, workflow.EventNameWorkflowRun}

	toctouLimits = []lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("sha-ref"), Text: "a checkout of the commit the event names (github.event.pull_request.head.sha): when the author pushes a commit after a review and before the label, the person who adds the label may not see the commit, and the labeled run checks out the pushed commit (GHSL-2025-077); whether such a push comes between the review and the label is decided when the workflow runs", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("dispatch-checkout"), Text: "a checkout whose ref or repository refers to an input of workflow_dispatch: no label approves a run of workflow_dispatch, as a label approves only a run of pull_request_target with the activity type labeled; the one who dispatches the workflow chooses the value of the input, and untrusted-checkout reports the input as input-dispatch", Disposition: lint.Limitation(lint.DeciderDispatcher)},
		{ID: lint.MustUndetectedFormID("approval-none"), Text: "a job that no one approves: untrusted-checkout reports it", Disposition: lint.OtherRule(UntrustedCheckoutID)},
		{ID: lint.MustUndetectedFormID("comment-approval"), Text: "a job on issue_comment whose if reads the comment or its author as an approval: untrusted-checkout reports it", Disposition: lint.OtherRule(UntrustedCheckoutID)},
	}
	automaticLabelCheckoutLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("automatic-label-checkout"), Text: "a job on pull_request_target on labeled with no environment, whose run starts by " + labelerAddedLabel + ", where the attacker chooses the files of the pull request freely: no person approves the run; this rule does not report the checkout of such a job, and untrusted-checkout reports the checkout", Disposition: lint.OtherRule(UntrustedCheckoutID)}
)
