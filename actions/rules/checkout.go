package rules

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// What untrusted-checkout and untrusted-checkout-toctou share: both read
// the checkouts of actions/prcode, so they have the same privileged events,
// the same guard of actions/checkout and the same forms of no added gain.

// split is evs split into those the guard of actions/checkout covers
// (pull_request_target, workflow_run) and the rest.
func split(evs []analysis.EventActivity) (guarded, open []analysis.EventActivity) {
	for _, e := range evs {
		if analysis.Guarded(e) {
			guarded = append(guarded, e)
		} else {
			open = append(open, e)
		}
	}
	return guarded, open
}

// guarded are the events of a checkout on which a finding may hold, of its
// privileged events, with the guard of its release: on
// pull_request_target and workflow_run a release with the guard refuses
// the fork's code, so a finding holds there only for a release without
// it, or for a commit sha that has none of the guard's commits (cond). The
// other events hold whatever the release. ok is false when none may hold.
func guarded(events []analysis.EventActivity, guard analysis.Guard, sha facts.SHA) (evs []analysis.EventActivity, cond *lint.Condition, ok bool) {
	g, open := split(events)
	switch guard {
	case analysis.GuardNone:
		return events, nil, true
	case analysis.GuardStatic:
		return open, nil, len(open) > 0
	}
	if len(open) > 0 || len(g) == 0 {
		return open, nil, len(open) > 0 // one finding, on the events that hold whatever the commit
	}
	var leaves []lint.Condition
	for _, commit := range ir.GuardCommits() {
		l, err := lint.FactEq(facts.GitCommitContains{Repo: ir.CheckoutRepo, SHA: sha, Commit: commit}, false)
		if err != nil {
			panic(err) // false fits the boolean of the kind
		}
		leaves = append(leaves, l)
	}
	all := lint.All(leaves...)
	return g, &all, true
}

// allOf is the conjunction of conds, nil when there is none.
func allOf(conds ...*lint.Condition) *lint.Condition {
	var cs []lint.Condition
	for _, c := range conds {
		if c != nil {
			cs = append(cs, *c)
		}
	}
	switch len(cs) {
	case 0:
		return nil
	case 1:
		return &cs[0]
	}
	all := lint.All(cs...)
	return &all
}

// factCond is the leaf q = v.
func factCond(q facts.Query, v bool) *lint.Condition {
	c, err := lint.FactEq(q, v)
	if err != nil {
		panic(err) // v fits the boolean of every kind it is used for
	}
	return &c
}

// labelNameIf is the false positive form, of the kinds, of a job whose if
// compares the name of the label added with a string, on pull_request_target
// with labeled and another activity type: the payload of the other activity
// type has no label, so the if is false there.
func labelNameIf(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("label-name-if"), Text: "a job whose if compares github.event.label.name with == to a string that is not empty, in a workflow on pull_request_target whose types have labeled and an activity type whose payload has no label, such as types: [labeled, opened] (the payload of opened, synchronize and reopened has no label): on that activity type, github.event.label.name is an empty string, and the if is false, so the job runs only after a label is added; the rule does not read github.event.label.name as an empty string on that activity type, and reports the job as a job that runs on that activity type without an approval", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// executedQuery is the fact of whether a step after the checkout at step
// runs what it brings, and whether a fact can name the input (no backslash
// in its name).
func executedQuery(c *lint.RuleContext, step facts.StepPath) (facts.CheckoutExecuted, bool) {
	file, ok := c.Name().FactArgument()
	return facts.CheckoutExecuted{InputPath: file, Step: step}, ok
}

// checkoutRelated are the places of the finding of untrusted-checkout on
// the checkout whose refs name a pull request's code and after which runs
// run what it brings, other than the step of the checkout: the first ref,
// and the steps of runs.
func checkoutRelated(c *lint.RuleContext, refs []ir.CheckoutRef, runs []ir.CodeRunStep) []lint.Related {
	var out []lint.Related
	if len(refs) > 0 {
		out = append(out, lint.Related{Location: c.At(refs[0].At), Note: "names the code of the pull request (" + refs[0].Text + ")"})
	}
	return append(out, runEvidence(c, runs)...)
}

// runEvidence is where each step of runs runs what the checkout brings.
func runEvidence(c *lint.RuleContext, runs []ir.CodeRunStep) []lint.Related {
	var out []lint.Related
	for _, e := range runs {
		out = append(out, lint.Related{Location: c.At(e.At), Note: "runs what the checkout brings (" + e.Cite + ")"})
	}
	return out
}

func runNames(runs []ir.CodeRunStep) []string {
	var out []string
	for _, e := range runs {
		if len(out) == 0 || out[len(out)-1] != e.Name {
			out = append(out, e.Name)
		}
	}
	return out
}

// unexamined reports a checkout whose with the tables cannot tell: the
// values unknown, with a whole ${{ }} when dynamic, at the step, with the
// places of the finding the checkout of a pull request's code would give
// in related.
func unexamined(c *lint.RuleContext, dynamic bool, unknown []string, at ir.Handle, related []lint.Related) {
	kind := checkoutRefUnknown
	if dynamic {
		kind = checkoutWithDynamic
	}
	c.Inconclusive(lint.InconclusiveDraft{KindID: kind, Location: c.At(at), Related: related,
		Note: fmt.Sprintf("what this checkout brings is not known: %s", strings.Join(unknown, ", "))})
}

var (
	checkoutWithDynamic = lint.MustInconclusiveKindID("checkout-with-dynamic")
	checkoutRefUnknown  = lint.MustInconclusiveKindID("checkout-ref-unknown")

	checkoutGaps = []lint.InconclusiveKind{
		{ID: checkoutWithDynamic, Text: "a checkout whose with is a whole ${{ }}: its ref and repository are not known", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: checkoutRefUnknown, Text: "a checkout whose ref or repository has what a step or a job computes, an input other than one of workflow_dispatch (or an input of workflow_dispatch in a workflow that also has workflow_call, when a workflow on an event of a pull request calls the workflow), an env, a matrix or a variable: whether it names a pull request's code is not analyzed", Disposition: lint.Todo(lint.NeedSameFile)},
	}
)

var (
	observedCheckout = lint.MustDate("2026-09-28")

	pwnRequests = lint.MustCitation("https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/")
	checkoutV7  = lint.MustCitation("https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout")
	unit42      = lint.MustCitation("https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/")
	reRuns      = lint.MustCitation("https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs")

	privilegedEvent = lint.MustPreconditionID("privileged-event")
	prTree          = lint.MustPreconditionID("pr-tree")
	noGuard         = lint.MustPreconditionID("no-guard")
	spotbugs2024    = lint.MustIncidentID("spotbugs-2024")

	privilegedEventPre = lint.Precondition{
		ID:   privilegedEvent,
		Text: "the job runs on pull_request_target, workflow_run or issue_comment, which a pull request from a fork or a comment triggers, with the repository's secrets and a token that may write; not pull_request, pull_request_review or pull_request_review_comment: from a fork they run the pull request's own workflow, which its author can change, read-only unless a private repository sends them secrets or a token that writes; from a branch of the repository, the code checked out is of one who can write",
		Observed: []lint.Observation{
			{Date: observedCheckout, Runner: runner, What: "a pull request from a fork ran pull_request_target, workflow_run after its pull_request, and issue_comment on a comment, each with the repository's secret and a token that created a ref"},
		},
		Cites: []lint.Citation{prTarget},
	}
	prTreePre = lint.Precondition{
		ID:   prTree,
		Text: "the checkout brings the pull request's code: its head or merge commit, refs/pull/<n>/head or merge, or the fork as the repository; a branch's name with the base repository brings the base's branch of that name, if any",
		Observed: []lint.Observation{
			{Date: observedCheckout, Runner: runner, What: "a checkout of the fork's head SHA, refs/pull/<n>/head and refs/pull/<n>/merge from the base repository brought the fork's commit and the merge commit; one of head.ref with the base repository failed, as the base had no such branch"},
		},
		Cites: []lint.Citation{pwnRequests},
	}
	noGuardPre = lint.Precondition{
		ID:   noGuard,
		Text: "on pull_request_target and workflow_run, the release of actions/checkout does not refuse a fork's code: v1, a release before the guard (v2.8.0, v3.7.0, v4.4.0, v5.1.0, v6.1.0, v7.0.0), a commit pinned before it, or allow-unsafe-pr-checkout set; issue_comment is not guarded",
		Observed: []lint.Observation{
			{Date: observedCheckout, Runner: runner, What: "v7.0.1 and the major tag v4 refused the fork's head SHA and refs/pull/<n>/head on pull_request_target and workflow_run, and allowed them with allow-unsafe-pr-checkout; v4.2.2 pinned by its SHA fetched them; on issue_comment v7.0.1 fetched refs/pull/<n>/head"},
		},
		Cites: []lint.Citation{checkoutV7},
	}
)

// checkoutActors are those who get the job's gains by what a checkout
// brings.
func checkoutActors(via string, gains []lint.Gain) []lint.Actor {
	return []lint.Actor{
		{Attacker: lint.AttackerForkPRAuthor, Via: via,
			Events: forkPREvents, RunStarters: startedBy(forkPREvents), Gains: gains},
		{Attacker: lint.AttackerCommenter, Via: "comments on the pull request whose code a workflow on issue_comment checks out",
			Events: []workflow.EventName{workflow.EventNameIssueComment}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameIssueComment}), Gains: gains},
	}
}

// checkoutLimits are the forms both rules do not report.
var checkoutLimits = []lint.UndetectedForm{
	outsideCallerLimit,
	{ID: lint.MustUndetectedFormID("git-in-run"), Text: "the code of a pull request fetched by git or gh in a run (git fetch origin pull/<n>/head, gh pr checkout), not by actions/checkout", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("artifact"), Text: "the code of a pull request brought by the artifact of a run it drives: artifact-poisoning reports it", Disposition: lint.OtherRule(ArtifactPoisoningID)},
	{ID: lint.MustUndetectedFormID("cache"), Text: "the code of a pull request brought by a cache that another run or job wrote", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("remote-action"), Text: "a checkout in an action of another repository: the rule does not read the action", Disposition: lint.Todo(lint.NeedFact)},
	{ID: lint.MustUndetectedFormID("literal-ref"), Text: "a ref written out, such as a branch's name of the repository", Disposition: lint.NoAddedGain()},
	{ID: lint.MustUndetectedFormID("branch-name-ref"), Text: "the name of the pull request's branch as the ref with the base repository: from a fork, the base has no such branch, or its own; from the repository, the author can write to it", Disposition: lint.NoAddedGain()},
	pullRequestLimit,
	newActivityTypeLimit,
	{ID: lint.MustUndetectedFormID("not-privileged"), Text: "a job only on events that no attacker triggers (push, schedule), or on the events of a review (pull_request_review, pull_request_review_comment), where the code of the attacker reaches the checkout only in the run of a review of the pull request of the attacker, which runs the workflow of the merge commit of the pull request (refs/pull/<n>/merge), and the attacker can change that workflow in the pull request (a job on pull_request is the undetected form pull-request); on workflow_dispatch, a checkout with no input of workflow_dispatch in its ref and repository, and no value made from one, brings a branch or a tag of the repository, which only those who can write to the repository change (the one who dispatches the workflow chooses the branch or the tag); repository_dispatch, whose sender has write access to the permission Contents, which the credential premise assumes no attacker has", Disposition: lint.NoAddedGain()},
	{ID: lint.MustUndetectedFormID("guarded-checkout"), Text: "a checkout on pull_request_target or workflow_run by a release of actions/checkout that refuses a fork's code (a major tag from v2, or a release from the guard), without allow-unsafe-pr-checkout: the step fails before anything runs", Disposition: lint.NoAddedGain()},
	{ID: lint.MustUndetectedFormID("guard-gap"), Text: "a checkout the guard of actions/checkout lets through at run time that the rule takes as refused: a fork deleted since the pull request, whose repository is not in the event (refs/pull/<n>/head written with capitals, which its pattern does not match, is reported)", Disposition: lint.Limitation(lint.DeciderRunTime)},
}
