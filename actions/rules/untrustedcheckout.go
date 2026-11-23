package rules

import (
	"context"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// UntrustedCheckout is the rule untrusted-checkout (a pwn request): a
// privileged job that no one approves checks out the code of a pull
// request, which its author writes, and a step after it runs that code
// with the job's secrets and token. When no step is seen to run it, the
// finding holds if one does (checkout.executed, assumed true).
var UntrustedCheckout lint.Rule = withExamples(lint.WithView[ir.UntrustedCheckoutReader](untrustedCheckout{}, ir.UntrustedCheckoutView))

// UntrustedCheckoutID is the ID of untrusted-checkout, and BaseCheckoutID
// the kind of its fix.
var (
	UntrustedCheckoutID = lint.MustRuleID("untrusted-checkout")
	BaseCheckoutID      = lint.MustFixKindID(ir.FixBaseCheckout.String())
)

type untrustedCheckout struct{}

func (untrustedCheckout) Meta() lint.Meta { return untrustedCheckoutMeta }

func (untrustedCheckout) Check(_ context.Context, c *lint.RuleContext, v ir.UntrustedCheckoutReader) error {
	for _, s := range v.CheckoutSites() {
		// before the approval: a run of workflow_dispatch has no label
		if s.DispatchInput() && len(s.DispatchOn()) > 0 {
			c.Inconclusive(lint.InconclusiveDraft{KindID: inputDispatch, Location: c.At(s.At()), Related: runEvidence(c, s.CodeRunSteps()),
				Note: "the ref or the repository of " + s.UsesText() + " refers to an input of workflow_dispatch, whose value the one who dispatches the workflow chooses; the rule does not determine the code that the value names"})
		}
		if len(s.PRCodeOn()) == 0 {
			continue // only workflow_dispatch: the input is all
		}
		auto := s.AutomaticApproval()
		if s.Approval() == analysis.ApprovalLabel {
			// a label that the attacker gets freely approves nothing; one that
			// is not decided is inconclusive only where a free one gives a
			// finding, and untrusted-checkout-toctou reads the rest
			switch s.CheckoutCode() {
			case analysis.CodeBase:
				continue
			case analysis.CodeUnknown:
				if !freeLabel(c, auto) {
					continue
				}
			case analysis.CodePR:
				if _, _, ok := guarded(s.PRCodeOn(), s.Guard(), s.SHA()); !ok || !automaticLabelFree(c, auto, s.At(), stepRef(s.UsesText()), checkoutRelated(c, s.Refs(), s.CodeRunSteps())) {
					continue
				}
			}
		}
		switch s.CheckoutCode() {
		case analysis.CodeUnknown:
			related := runEvidence(c, s.CodeRunSteps())
			if s.Approval() == analysis.ApprovalLabel {
				related = append(related, automaticLabelRelated(c, auto)...)
			}
			unexamined(c, s.Dynamic(), s.InconclusiveValues(), s.At(), related) // the guard refuses only some values
			continue
		case analysis.CodeBase:
			continue
		}
		evs, guard, ok := guarded(s.PRCodeOn(), s.Guard(), s.SHA())
		if !ok {
			continue // the release refuses the fork's code
		}
		var approval *lint.Condition
		switch {
		case s.Approval() == analysis.ApprovalEnvironment:
			approval = environmentCond(c, analysis.ApprovalEnvironment, s.Environment())
		case s.Approval() == analysis.ApprovalLabel && auto.Environment != (facts.EnvironmentName{}) && !c.Barriers().Passes(analysis.BarrierLabelApproval):
			approval = environmentCond(c, analysis.ApprovalEnvironment, auto.Environment)
		}
		refs := s.Refs()
		f := lint.FindingDraft{Location: c.At(refs[0].At)}
		ref, uses := refs[0].Text, s.UsesText()
		if runs := s.CodeRunSteps(); len(runs) > 0 {
			f.Args = UntrustedCheckoutExecuted{Uses: uses, CheckoutRef: ref, PRCodeOn: eventsOf(evs), Runs: runNames(runs)}
			f.Evidence = runEvidence(c, runs)
			f.Condition = allOf(approval, guard)
		} else {
			// the fact names a step of the input: a step of a remote called
			// workflow, or of an input whose name no fact can hold, has none
			// to ask, and the finding holds as its assumed value
			// (checkout.executed is true)
			var executed *lint.Condition
			if q, ok := executedQuery(c, s.StepPath()); ok && !c.RemoteCalled() {
				executed = factCond(q, true)
			}
			f.Args = UntrustedCheckoutCheckout{Uses: uses, CheckoutRef: ref, PRCodeOn: eventsOf(evs)}
			f.Condition = allOf(approval, executed, guard)
		}
		if s.Approval() == analysis.ApprovalLabel {
			f.Related = automaticLabelRelated(c, auto)
		}
		f.Fix, f.NoFix = fixOf(s.BaseCheckout())
		c.Report(f)
	}
	return nil
}

// checkoutBase is the CVSS of untrusted-checkout: the attacker's code runs
// in the job, as code-injection's does.
var checkoutBase = lint.CVSS{
	AV: metric(lint.AttackVectorNetwork, "the attacker opens a pull request from a fork, or comments on one, over the network"),
	AC: metric(lint.AttackComplexityLow, "a change of a script, a build file or a package manifest of the pull request is all it takes"),
	AT: metric(lint.AttackRequirementsNone, "on a public repository anyone can fork it and open a pull request"),
	PR: metric(lint.PrivilegesRequiredNone, "nothing of the repository is needed"),
	UI: metric(lint.UserInteractionNone, "opening or updating the pull request triggers pull_request_target with nobody doing anything"),
	VC: metric(lint.ImpactHigh, "the code reads the job's secrets and GITHUB_TOKEN"),
	VI: metric(lint.ImpactHigh, "with the job's token the code can push, and write releases and packages"),
	VA: metric(lint.ImpactLow, "the code can fail or stop the job"),
	SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
	SI: metric(lint.ImpactHigh, "what the job publishes reaches those who use it; in the tj-actions incident a stolen token of this kind led to moved tags", unit42),
	SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
}

var (
	noApproval = lint.MustPreconditionID("no-approval")
	runsTree   = lint.MustPreconditionID("runs-tree")
)

var untrustedCheckoutMeta = lint.Meta{
	ID:       UntrustedCheckoutID,
	Problem:  "a privileged job that no one approves checks out the code of a pull request, which a step after it may run with the job's secrets and token",
	Expected: "a privileged job checks out only the base's code, or reads the pull request's code as data only",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessUntrustedCodeExecution}, AttackMeans: []lint.AttackMeans{lint.AttackMeansCode}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textUntrustedCheckoutExecuted,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerCommenter},
			Preconditions:   []lint.PreconditionID{privilegedEvent, prTree, noGuard, noApproval, runsTree, callersEvents, appStatusCheck},
			Incidents:       []lint.IncidentID{spotbugs2024},
			FactKinds:       []facts.Kind{facts.KindRepoEnvironmentProtected, facts.KindGitCommitContains},
			Fixes:           []lint.FixKindID{BaseCheckoutID},
			CVSS:            checkoutBase,
			ExploitMaturity: metric(lint.ExploitMaturityAttacked, "in 2024-12 a pull request to spotbugs/sonar-findbugs changed mvnw, which a pull_request_target workflow checked out and ran, and its token led to the compromise of tj-actions/changed-files", unit42),
		},
		{
			FindingText:     textUntrustedCheckoutCheckout,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerCommenter},
			Preconditions:   []lint.PreconditionID{privilegedEvent, prTree, noGuard, noApproval, runsTree, callersEvents, appStatusCheck},
			Incidents:       []lint.IncidentID{spotbugs2024},
			FactKinds:       []facts.Kind{facts.KindRepoEnvironmentProtected, facts.KindCheckoutExecuted, facts.KindGitCommitContains},
			Fixes:           []lint.FixKindID{BaseCheckoutID},
			CVSS:            checkoutBase,
			ExploitMaturity: metric(lint.ExploitMaturityAttacked, "the same as when a step is seen to run it: whether one does is what the condition asks", unit42),
		},
	},
	Threat: lint.Threat{
		Actors: checkoutActors("changes a script, a build file or a package manifest in a pull request from a fork", jobGains),
		Preconditions: []lint.Precondition{
			callersEventsPre,
			privilegedEventPre,
			appStatusCheckPre,
			prTreePre,
			noGuardPre,
			{
				ID:   noApproval,
				Text: "no one approves the run: either the job runs on at least one event other than pull_request_target with the activity type labeled, and a run on the other event starts with no label added, or no person adds the label that starts the run, as the label is " + labelerAddedLabel + "; and the job has no environment that has required reviewers (repo.environment-protected, assumed false: an environment is made with no protection rules)",
				Observed: []lint.Observation{
					{Date: observedCheckout, Runner: runner, What: "a push after the label ran no labeled run, and ran pull_request_target on synchronize"},
				},
			},
			{
				ID:    runsTree,
				Text:  "a step after the checkout runs what it brings: a program of the tree, an action of it, or a tool that reads its files (npm, pip, make, go test, cargo, mvn, gradle and the like); when none is seen, the finding holds if one does (checkout.executed, assumed true)",
				Cites: []lint.Citation{pwnRequests},
			},
		},
		Incidents: []lint.Incident{
			{ID: spotbugs2024, Date: lint.MustDate("2024-12-06"), Advisory: unit42,
				Compromised: repos("spotbugs/sonar-findbugs"),
				Downstream:  repos("tj-actions/changed-files"),
				Summary:     "a pull request changed mvnw, which a pull_request_target workflow checked out as refs/pull/<n>/merge and ran; its token was a maintainer's personal access token, the start of the tj-actions compromise"},
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee(append(append(append([]lint.UndetectedForm(nil), checkoutLimits...), automaticLabelForms...), deploymentStatusLimit, mergedPusherLimit, npmAbbreviation(kindUntrustedCheckoutExecuted), npmOptionValueCommand(kindUntrustedCheckoutExecuted),
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("approved"), Text: "a job a person approves (a job that runs only on pull_request_target with the activity type labeled, when no workflow of the same repository adds the label with actions/labeler to the pull request of an attacker, or a job with an environment that has required reviewers): this rule does not report the checkout of such a job, and untrusted-checkout-toctou reports the checkout", Disposition: lint.OtherRule(UntrustedCheckoutToctouID)}, insiderAssociationLimit, dispatchInputCallLimit, dispatchDerivedLimit,
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("converted-issue"), Text: "refs/pull/<the issue's number> on issue_comment pinned or unpinned, which the rule reads as naming no pull request, as GitHub pins no comment of one: an issue made a pull request after its comment was pinned (the issue of POST /repos/{owner}/{repo}/pulls) may have the attacker's head there; who may make one, and whether the pin and the unpin events then come, is not seen", Disposition: lint.Todo(lint.NeedFact)})),
	InconclusiveKinds: withRemoteCalleeUnknown(append(append(slices.Clone(checkoutGaps), automaticLabelKinds...),
		lint.InconclusiveKind{ID: inputDispatch, Text: "a checkout whose ref or repository has a ${{ }} that refers to an input of workflow_dispatch (inputs, github.event.inputs), alone or with other values: " + dispatcherChooses, Disposition: lint.Limitation(lint.DeciderDispatcher)})),
	FalsePositiveForms: withCallee(append([]lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("environment-expression"), Text: "an environment whose name is a ${{ }} and has required reviewers: which environment it is is known when the job runs, so it is read as approving nothing", FindingKinds: []lint.FindingKindID{kindUntrustedCheckoutExecuted, kindUntrustedCheckoutCheckout}, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustFalsePositiveFormID("not-executed"), Text: "a job that uses nothing of the tree it checks out as code or as the settings of a tool, and has no tool that follows a symlink of the tree to a file outside the checkout and puts the content of the file outside the checkout in the log or in an upload that the attacker can read (a job that reads a file of the tree as data is this form, except in the two cases below): no step runs a script, a build, a test or an action of the tree, no tool reads a file of the tree as settings that decide where a request goes or what command runs, and no tool follows a symlink of the tree to a file outside the checkout and puts the content of the file outside the checkout in the log or in an upload that the attacker can read, such as an artifact. A job whose tool reads settings that decide where a request goes or what command runs from the tree is not this form: SonarSource's scanner reads sonar.host.url from a project file of the tree and can send a secret to the host that the pull request names. A job whose tool follows a symlink of the tree to a file outside the checkout and puts the content of the file outside the checkout in the log or in an upload that the attacker can read is not this form either: a parse error of tmatens/compose-lint quotes a line of a file of credentials outside the checkout that a symlink of a pull request names (GHSA-whr6-fgpq-fpv9, GHSA-88f4-frh5-gmcr)", FindingKinds: []lint.FindingKindID{kindUntrustedCheckoutCheckout}, FactKinds: []facts.Kind{facts.KindCheckoutExecuted}},
		{ID: lint.MustFalsePositiveFormID("remote-not-executed"), Text: "a job of a reusable workflow of another repository that uses nothing of the tree it checks out in the ways that the form not-executed names: the fact checkout.executed names a step of the input and cannot name a step of a reusable workflow of another repository, so no answer of the fact removes the finding", FindingKinds: []lint.FindingKindID{kindUntrustedCheckoutCheckout}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("environment-protected"), Text: "a job whose environment has required reviewers, who approve it before it runs", FindingKinds: []lint.FindingKindID{kindUntrustedCheckoutExecuted, kindUntrustedCheckoutCheckout}, FactKinds: []facts.Kind{facts.KindRepoEnvironmentProtected}},
		labelNameIf(kindUntrustedCheckoutExecuted, kindUntrustedCheckoutCheckout),
		npmUnknownCommand(kindUntrustedCheckoutExecuted),
		npmOptionValueOperand(kindUntrustedCheckoutExecuted),
		cdOutOfTree(kindUntrustedCheckoutExecuted),
		ignoredPnpmfile(kindUntrustedCheckoutExecuted),
		absolutePathOutOfTree(kindUntrustedCheckoutExecuted),
		pytestPathOutOfTree(kindUntrustedCheckoutExecuted),
		toolDirectoryOutOfTree(kindUntrustedCheckoutExecuted),
	}, automaticLabelFalsePositives(kindUntrustedCheckoutExecuted, kindUntrustedCheckoutCheckout)...), kindUntrustedCheckoutExecuted, kindUntrustedCheckoutCheckout),
	FixKinds: []lint.FixKind{{
		ID:                  BaseCheckoutID,
		Title:               "check out the base's code: take out the inputs that name the pull request's (ref, and repository when it is the fork)",
		Safety:              lint.SafetyReview,
		PossibleSideEffects: []ir.SideEffect{ir.SideEffectPRCodeNotBuilt},
	}},
}
