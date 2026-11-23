package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// UnsoundContains is the rule unsound-contains: contains, startsWith or
// endsWith of a string and a reference in an if, which a part of the
// string passes, or of a reference and a string, which a value with the
// string as a part passes, where comparing whole values would keep the
// attacker out.
var UnsoundContains lint.Rule = withExamples(lint.WithView[ir.UnsoundContainsReader](unsoundContains{}, ir.UnsoundContainsView))

// UnsoundContainsID is the ID of unsound-contains, and ContainsArrayID
// and EqualityID those of its fixes.
var (
	UnsoundContainsID = lint.MustRuleID("unsound-contains")
	ContainsArrayID   = lint.MustFixKindID(ir.FixContainsArray.String())
	EqualityID        = lint.MustFixKindID(ir.FixEquality.String())
)

type unsoundContains struct{}

func (unsoundContains) Meta() lint.Meta { return unsoundContainsMeta }

func (unsoundContains) Check(_ context.Context, c *lint.RuleContext, v ir.UnsoundContainsReader) error {
	for _, s := range v.IfSites() {
		on := eventsOf(s.AttackerOn())
		for i, b := range s.SubstringBypasses() {
			f := lint.FindingDraft{Location: c.At(b.At)}
			if b.ReferenceFirst {
				f.Args = UnsoundContainsSuperstring{Func: b.Func, Literal: b.Literal, Path: b.Path, AttackerOn: on}
				f.Fix, f.NoFix = fixOf(s.Equality(i))
			} else {
				f.Args = UnsoundContainsSubstring{Func: b.Func, Literal: b.Literal, Path: b.Path, AttackerOn: on}
				f.Fix, f.NoFix = fixOf(s.ContainsArray(i))
			}
			c.Report(f)
		}
	}
	return nil
}

var (
	substringPre   = lint.MustPreconditionID("substring")
	loginPre       = lint.MustPreconditionID("chosen-login")
	expressionDocs = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#contains")
	zizmorContains = lint.MustCitation("https://github.com/zizmorcore/zizmor/blob/3c8c3f6aec1dbe9db2cf4bcb2b9216eb5b9c4b95/docs/audits.md#unsound-contains")
)

var unsoundContainsMeta = lint.Meta{
	ID:       UnsoundContainsID,
	Problem:  "an if compares a reference with a string by contains, startsWith or endsWith, which is true for a part of a value: with the string first, a value the attacker chooses, such as the attacker's login, passes when the value is only a part of a name in the string; with the reference first, a value of the attacker's that has the string as a part passes",
	Expected: "the if compares whole values: when the string is the first argument, contains(fromJSON('[\"alice\", \"bob\"]'), the reference); when the reference is the first argument, the reference == 'the string'",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessGateBypass}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{{
		FindingText:   textUnsoundContainsSubstring,
		Attackers:     exposureAttackers,
		Preconditions: []lint.PreconditionID{substringPre, loginPre, callersEvents},
		Fixes:         []lint.FixKindID{ContainsArrayID},
		CVSS: lint.CVSS{
			AV: metric(lint.AttackVectorNetwork, "the attacker opens an issue, a comment, a review or a pull request over the network"),
			AC: metric(lint.AttackComplexityLow, "the value is one the attacker chooses"),
			AT: metric(lint.AttackRequirementsPresent, "a login that is a part of the string has to be free to register, which the attacker does not decide"),
			PR: metric(lint.PrivilegesRequiredNone, "on a public repository anyone opens an issue or a pull request from a fork, or reviews a pull request"),
			UI: metric(lint.UserInteractionNone, "the event runs the job with nobody doing anything"),
			VC: metric(lint.ImpactHigh, "the job the if guards runs for the attacker with its secrets and token"),
			VI: metric(lint.ImpactHigh, "what such a job does for those it lets in, it does for the attacker"),
			VA: metric(lint.ImpactLow, "the job can cancel runs or delete what it may"),
			SC: metric(lint.ImpactHigh, "the secrets of the job open what is past it"),
			SI: metric(lint.ImpactHigh, "what it pushes or releases reaches those who use the repository"),
			SA: metric(lint.ImpactNone, "nothing past the repository is made unavailable by this as such"),
		},
		ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report of an attack on such an if was found"),
	}, {
		FindingText:   textUnsoundContainsSuperstring,
		Attackers:     exposureAttackers,
		Preconditions: []lint.PreconditionID{substringPre, loginPre, callersEvents},
		Fixes:         []lint.FixKindID{EqualityID},
		CVSS: lint.CVSS{
			AV: metric(lint.AttackVectorNetwork, "the attacker opens an issue, a comment, a review or a pull request over the network"),
			AC: metric(lint.AttackComplexityLow, "the value is one the attacker chooses"),
			AT: metric(lint.AttackRequirementsNone, "the attacker registers a login that has the string as a part and that no one has registered, by adding characters to the string"),
			PR: metric(lint.PrivilegesRequiredNone, "on a public repository anyone opens an issue or a pull request from a fork, or reviews a pull request"),
			UI: metric(lint.UserInteractionNone, "the event runs the job with nobody doing anything"),
			VC: metric(lint.ImpactHigh, "the job the if guards runs for the attacker with its secrets and token"),
			VI: metric(lint.ImpactHigh, "what such a job does for those it lets in, it does for the attacker"),
			VA: metric(lint.ImpactLow, "the job can cancel runs or delete what it may"),
			SC: metric(lint.ImpactHigh, "the secrets of the job open what is past it"),
			SI: metric(lint.ImpactHigh, "what it pushes or releases reaches those who use the repository"),
			SA: metric(lint.ImpactNone, "nothing past the repository is made unavailable by this as such"),
		},
		ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report of an attack on such an if was found"),
	}},
	Threat: lint.Threat{
		Actors: exposureActors,
		Preconditions: []lint.Precondition{
			callersEventsPre,
			{ID: substringPre, Text: "contains(search, item) is true when the item is a part of the first argument, startsWith(search, item) and endsWith(search, item) when the item is the start or the end of the first argument, all ignoring case: when the string is the first argument, a reference whose value is a part of the string passes; when the reference is the first argument, a reference whose value has the string as a part passes", Cites: []lint.Citation{expressionDocs}},
			{ID: loginPre, Text: "the attacker chooses the login they register, letters, digits and dashes, 39 at most, as long as no one has it. Besides the login, on pull_request_target on labeled, where a workflow of the same repository runs actions/labeler on the pull request of the attacker with a token other than the GITHUB_TOKEN, the attacker chooses which label of the configuration of actions/labeler the pull request gets, by the files that the pull request changes and by the name of the head branch", Cites: []lint.Citation{zizmorContains}},
		},
	},
	Citations:         []lint.Citation{cvss},
	Targets:           []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	InconclusiveKinds: withRemoteCalleeUnknown(nil),
	UndetectedForms: withRemoteCallee(append([]lint.UndetectedForm{
		npmAbbreviation(),
		npmOptionValueCommand(),
		{ID: lint.MustUndetectedFormID("caller-by-repository-name"), Text: "a comparison in a reusable workflow that a workflow of the same repository calls by the name owner/repo/.github/workflows/<file>@<ref> of the repository (the repository that --repo names) instead of the path ./.github/workflows/<file>: the rule does not resolve the call by the name to the file, so the rule reads the if on every event; the rule reports a comparison only when the compared value is the attacker's value in every run that the if lets in, and on push the login is empty, so the rule reports nothing", Disposition: lint.Todo(lint.NeedSameFile)},
		appCommitEventLimit,
		forkReviewLimit,
		{ID: lint.MustUndetectedFormID("undecided-label"), Text: "the name of a label compared with a string by contains, startsWith or endsWith, where the label of the run is " + labelerAddedLabel + ", and the configuration of actions/labeler adds the label only on a condition that the rule cannot decide (the paths of the files that the pull request changes, the name of the base branch, other labels of the same run of actions/labeler, the release or the configuration of actions/labeler): the rule reports no finding, even when the name of a label of the configuration is a part of the string, or has the string as a part", Disposition: lint.Todo(lint.NeedSameFile)},
		outsideCallerLimit,
		{ID: lint.MustUndetectedFormID("some-events-path"), Text: "a comparison of a value whose path one privileged event of the job has and another privileged event of the job does not have, such as github.event.comment.user.login, which issue_comment has and issues does not, in a job on issues and issue_comment: the rule reports no finding, even on the event that has the path", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("caller-value"), Text: "a value compared in an action through inputs.<name>, which a caller gives under with:, such as with: who: ${{ github.event.comment.user.login }}: the rule does not follow the value under with: into inputs.<name>", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("chosen-name"), Text: "a value that the attacker names in full (github.head_ref): a comparison of whole values is true for the value of the attacker too, so the flaw of the rule (a comparison of a part) adds nothing; the if is no approval, and the job runs for the attacker as if the job had no if", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("not-attacker-event"), Text: "a comparison in a workflow that runs on push and on no privileged event: only those who can write to the repository push, and the credential premise assumes that no attacker has a credential that pushes (a workflow on pull_request is the undetected form pull-request)", Disposition: lint.NoAddedGain()},
		pullRequestLimit,
		{ID: lint.MustUndetectedFormID("dispatch-actor"), Text: "a comparison of the actor in a workflow that runs on workflow_dispatch: the actor of a run of workflow_dispatch is the holder of the credential that dispatches the workflow, so whether the name of the actor is a part of a name in the string depends on the account whose credential dispatches the workflow; the inputs, whose whole value the one who dispatches the workflow chooses, and the ref, a branch or a tag of the repository, add nothing to a comparison of a part, as the undetected forms chosen-name and writer-value of this rule say", Disposition: lint.Limitation(lint.DeciderDispatcher)},
		{ID: lint.MustUndetectedFormID("writer-value"), Text: "a value only those who can write decide (github.ref on push)", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("base-branch-head"), Text: "the repository of the head of a pull request (github.event.pull_request.head.repo.full_name) compared with a string by contains, startsWith or endsWith: the if also runs for a pull request from a branch of the same repository, whose head is the repository itself and whose name the string may be, and the rule cannot tell such a run from a run of a fork", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("account-id"), Text: "the ID of an account compared with a string by contains, startsWith or endsWith (contains(github.event.comment.user.id, '4969'), contains('4969 1234', github.actor_id)): GitHub gives each account its number, and whether an attacker can get an account whose ID has the string as a part, or is a part of the string, is not known", Disposition: lint.Todo(lint.NeedFact)},
	}, automaticLabelForms...)),
	FalsePositiveForms: withCallee(append(automaticLabelFalsePositives(kindUnsoundContainsSubstring, kindUnsoundContainsSuperstring), forkFlagReview(kindUnsoundContainsSubstring)), kindUnsoundContainsSubstring, kindUnsoundContainsSuperstring),
	FixKinds: []lint.FixKind{{
		ID:                  ContainsArrayID,
		Title:               "compare whole values: contains(fromJSON('[...]'), the reference), the words of the string split by white space and commas",
		Safety:              lint.SafetyReview,
		PossibleSideEffects: []ir.SideEffect{ir.SideEffectSubstringNotMatched},
	}, {
		ID:                  EqualityID,
		Title:               "compare the whole value: contains(the reference, 'the string') becomes the reference == 'the string', when the string has the form of the value of the reference (a login, owner/name)",
		Safety:              lint.SafetyReview,
		PossibleSideEffects: []ir.SideEffect{ir.SideEffectSuperstringNotMatched},
	}},
}
