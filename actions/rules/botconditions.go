package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// BotConditions is the rule bot-conditions: an if that compares the actor
// with dependabot[bot] to let only Dependabot in, which the attacker passes
// by having Dependabot push to their pull request.
var BotConditions lint.Rule = withExamples(lint.WithView[ir.BotConditionsReader](botConditions{}, ir.BotConditionsView))

// BotConditionsID is the ID of bot-conditions, and AuthorContextID that of
// its fix.
var (
	BotConditionsID = lint.MustRuleID("bot-conditions")
	AuthorContextID = lint.MustFixKindID(ir.FixAuthorContext.String())
)

type botConditions struct{}

func (botConditions) Meta() lint.Meta { return botConditionsMeta }

var otherBot = lint.MustInconclusiveKindID("other-bot")

func (botConditions) Check(_ context.Context, c *lint.RuleContext, v ir.BotConditionsReader) error {
	for _, s := range v.IfSites() {
		on := eventsOf(s.AttackerOn())
		for i, b := range s.DependabotBypasses() {
			f := lint.FindingDraft{Location: c.At(b.At), Args: BotConditionsDependabot{Path: b.Path, Literal: b.Literal, AttackerOn: on}}
			f.Fix, f.NoFix = fixOf(s.AuthorContext(i))
			c.Report(f)
		}
		for _, o := range s.OtherBots() {
			c.Inconclusive(lint.InconclusiveDraft{KindID: otherBot, Location: c.At(o.At), Note: o.Text + " lets in a bot other than Dependabot; whether an attacker can have that bot act on their pull request is not known"})
		}
	}
	return nil
}

var (
	dependabotPush   = lint.MustPreconditionID("dependabot-push")
	actorComparedPre = lint.MustPreconditionID("actor-compared")

	synacktiv     = lint.MustCitation("https://www.synacktiv.com/publications/github-actions-exploitation-dependabot")
	zizmorBots    = lint.MustCitation("https://github.com/zizmorcore/zizmor/blob/3c8c3f6aec1dbe9db2cf4bcb2b9216eb5b9c4b95/docs/audits.md#bot-conditions")
	dependabotCmd = lint.MustCitation("https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-pull-request-comment-commands")
	contextsDocs  = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#github-context")
)

var botConditionsMeta = lint.Meta{
	ID:       BotConditionsID,
	Problem:  "an if lets only Dependabot in by comparing the actor of the run with dependabot[bot], but the actor is whoever made the latest change: an attacker has Dependabot push to their own pull request, and the run of that push passes the if",
	Expected: "the if compares the author of the pull request (github.event.pull_request.user.login), whom no push changes",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessGateBypass}, AttackMeans: []lint.AttackMeans{lint.AttackMeansOperation}},
	FindingKinds: []lint.FindingKind{{
		FindingText:   textBotConditionsDependabot,
		Attackers:     []lint.Attacker{lint.AttackerForkPRAuthor},
		Preconditions: []lint.PreconditionID{actorComparedPre, dependabotPush, callersEvents},
		Fixes:         []lint.FixKindID{AuthorContextID},
		CVSS: lint.CVSS{
			AV: metric(lint.AttackVectorNetwork, "the attacker forks the repository and opens a pull request over the network"),
			AC: metric(lint.AttackComplexityLow, "a comment @dependabot recreate on Dependabot's pull request in their fork makes the push"),
			AT: metric(lint.AttackRequirementsNone, "the attacker sets up all of it in their fork: Dependabot, a dependency it updates, and the pull request from its branch"),
			PR: metric(lint.PrivilegesRequiredNone, "on a public repository anyone opens a pull request from a fork"),
			UI: metric(lint.UserInteractionNone, "pull_request_target runs on the push with nobody doing anything"),
			VC: metric(lint.ImpactHigh, "the job the if guards runs on the attacker's pull request with its secrets and token: what it reads, they get when it runs their code"),
			VI: metric(lint.ImpactHigh, "such jobs approve and merge Dependabot's pull requests, so the attacker's is merged, or they write with the job's token"),
			VA: metric(lint.ImpactLow, "the job can cancel runs or delete what it may"),
			SC: metric(lint.ImpactHigh, "the secrets of the job open what is past it"),
			SI: metric(lint.ImpactHigh, "what is merged or released reaches those who use the repository"),
			SA: metric(lint.ImpactNone, "nothing past the repository is made unavailable by this as such"),
		},
		ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "Synacktiv passed the if of spring-projects/spring-security's merge-dependabot-pr.yml this way from a fork in 2024; spring-security and trpc then compared the author of the pull request", synacktiv),
	}},
	Threat: lint.Threat{
		Actors: []lint.Actor{{
			Attacker: lint.AttackerForkPRAuthor,
			Via:      "opens a pull request from the branch of Dependabot's pull request in their fork, then comments @dependabot recreate on Dependabot's pull request there; Dependabot's push runs pull_request_target on synchronize with the actor dependabot[bot]",
			Events:   []workflow.EventName{workflow.EventNamePullRequestTarget},
			// the attacker has Dependabot push, so the run follows an act of theirs
			RunStarters: startedBy([]workflow.EventName{workflow.EventNamePullRequestTarget}),
			Gains:       exposureGains,
		}},
		Preconditions: []lint.Precondition{
			callersEventsPre,
			{ID: actorComparedPre, Text: "github.actor, github.triggering_actor, github.actor_id or github.event.sender is the user that triggered the run: the one who pushed, for synchronize", Cites: []lint.Citation{contextsDocs, synacktiv}},
			{ID: dependabotPush, Text: "the owner of a fork may enable Dependabot there, and @dependabot recreate makes it push to the branch of its pull request; the deprecation of 2026-01-27 left recreate and rebase", Cites: []lint.Citation{dependabotCmd, synacktiv}},
		},
	},
	Citations: []lint.Citation{cvss, zizmorBots},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("caller-by-repository-name"), Text: "a comparison with a bot in a reusable workflow that a workflow of the same repository calls by the name owner/repo/.github/workflows/<file>@<ref> of the repository (the repository that --repo names) instead of the path ./.github/workflows/<file>: the rule does not resolve the call by the name to the file, so the rule reads the if on the events of the reusable workflow alone (workflow_call), which no attacker triggers", Disposition: lint.Todo(lint.NeedSameFile)},
		appCommitEventLimit,
		forkReviewLimit,
		{ID: lint.MustUndetectedFormID("caller-value"), Text: "an actor compared in an action through inputs.<name>, which a caller gives under with:, such as with: who: ${{ github.actor }}: the rule does not follow the value under with: into inputs.<name>", Disposition: lint.Todo(lint.NeedRepoFile)},
		outsideCallerLimit,
		{ID: lint.MustUndetectedFormID("not-attacker-event"), Text: "a comparison with a bot in a workflow that runs on no privileged event (not privileged events: push, schedule): no run of Dependabot's push to the attacker's pull request reaches it", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("actor-in-step-output"), Text: "the actor compared through the output of a step or an env", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("path-first"), Text: "the actor as the first argument of contains, startsWith or endsWith (endsWith(github.actor, '[bot]')), which the rule does not read as a comparison", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("workflow-run-actor"), Text: "github.actor compared with a bot in a job on workflow_run: whether the run of Dependabot's push makes the actor of workflow_run dependabot[bot] is not known", Disposition: lint.Todo(lint.NeedFact)},
	}),
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: otherBot, Text: "a comparison of the actor with a bot other than Dependabot (renovate[bot], github-actions[bot]): whether an attacker can have it act on their pull request is not known", Disposition: lint.Todo(lint.NeedFact)},
	}),
	FalsePositiveForms: withCallee(nil, kindBotConditionsDependabot),
	FixKinds: []lint.FixKind{{
		ID:                  AuthorContextID,
		Title:               "compare the author of the pull request in place of the actor: github.event.pull_request.user.login",
		Safety:              lint.SafetyReview,
		PossibleSideEffects: []ir.SideEffect{ir.SideEffectActorNotCompared},
	}},
}
