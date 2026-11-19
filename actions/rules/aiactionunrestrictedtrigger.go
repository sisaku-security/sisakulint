package rules

import (
	"context"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/labeler"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// AIActionUnrestrictedTrigger is the rule ai-action-unrestricted-trigger:
// a step of an action that runs an AI agent, which an attacker triggers
// themselves, as the actor, and whose action lets them start the agent:
// an input opens its check of the actor, or it has none.
var AIActionUnrestrictedTrigger lint.Rule = withExamples(lint.WithView[ir.AIActionUnrestrictedTriggerReader](aiActionUnrestrictedTrigger{}, ir.AIActionUnrestrictedTriggerView))

// AIActionUnrestrictedTriggerID is the ID of ai-action-unrestricted-trigger.
var AIActionUnrestrictedTriggerID = lint.MustRuleID("ai-action-unrestricted-trigger")

type aiActionUnrestrictedTrigger struct{}

func (aiActionUnrestrictedTrigger) Meta() lint.Meta { return aiActionUnrestrictedTriggerMeta }

var gateExpr = lint.MustInconclusiveKindID(analysis.InconclusiveAgentGate.String())

func (aiActionUnrestrictedTrigger) Check(_ context.Context, c *lint.RuleContext, v ir.AIActionUnrestrictedTriggerReader) error {
	for _, s := range v.AgentSteps() {
		if s.Substituted() {
			substitutedAgent(c, s.At(), s.Chain())
			continue
		}
		rp := agentPlace{c: c, at: s.At(), chain: s.Chain(), inner: s.InnerAt()}
		labelerTokenOwner(c, rp, s)
		if len(s.ActorOn()) == 0 {
			continue // no attacker triggers it: the gate keeps nobody out
		}
		opened := map[analysis.AgentInput]bool{}
		for _, g := range s.OpenGates() {
			if len(g.OpenOn) == 0 {
				continue
			}
			opened[g.Input] = true
			switch g.Gate {
			case analysis.AgentGateAnyUser:
				rp.Report(lint.FindingDraft{Location: rp.At(g.At), Args: AIActionUnrestrictedTriggerAnyUser{Action: s.Action(), Input: g.Input, GateValue: strings.TrimSpace(g.Text)}})
			case analysis.AgentGateAnyBot:
				rp.Report(lint.FindingDraft{Location: rp.At(g.At), Args: AIActionUnrestrictedTriggerAnyBot{Action: s.Action(), GateValue: strings.TrimSpace(g.Text)}, Condition: isPublic(c)})
			case analysis.AgentGateUnchecked:
				rp.Report(lint.FindingDraft{Location: rp.At(g.At), Args: AIActionUnrestrictedTriggerUnchecked{Action: s.Action()}})
			}
		}
		for _, g := range s.InconclusiveSettings() {
			if g.Kind == analysis.InconclusiveAgentGate && len(g.UndecidedOn) > 0 && !opened[g.Input] {
				rp.Inconclusive(lint.InconclusiveDraft{KindID: gateExpr, Location: rp.At(g.At), Note: g.Text + ": whom the step lets start the agent in a run the attacker triggers is not decided"})
			}
		}
	}
	unansweredAgents(c, v.CompositeCalls(), false)
	return nil
}

// labelerTokenOwner reports the labeled runs of s that a label of
// actions/labeler starts on an attacker's pull request: the actor of such a
// run is the account of the token of actions/labeler, which the check of
// the actor lets in as one who can write.
func labelerTokenOwner(c *lint.RuleContext, rp agentReporter, s ir.AIActionUnrestrictedTriggerOfAgentStep) {
	a := s.AutomaticApproval()
	open := slices.ContainsFunc(s.OpenGates(), func(g ir.OpenGate) bool {
		return len(g.OpenOn) > 0 && (g.Gate == analysis.AgentGateAnyUser || g.Gate == analysis.AgentGateUnchecked)
	})
	if open || len(a.AutomaticLabels) == 0 || !automaticLabelFree(c, a, s.At(), stepRef(s.UsesText()), nil) {
		return // an open gate lets the attacker start the agent anyway
	}
	switch a.Token {
	case labeler.TokenSourceAccount:
		rp.Report(lint.FindingDraft{Location: rp.At(s.At()), Anchor: "labeled", Args: AIActionUnrestrictedTriggerLabelerTokenOwner{Action: s.Action(), Labeler: a.At.InputName()}, Related: automaticLabelRelated(c, a)})
	case labeler.TokenSourceUnknown:
		rp.Inconclusive(lint.InconclusiveDraft{KindID: labelerUnknown, Location: rp.At(s.At()), Related: undecidedLabelerRelated(c, a),
			Note: s.UsesText() + " runs on pull_request_target on labeled, and actions/labeler in " + a.At.InputName() + " adds the label with a token whose source is not known, so the actor of the labeled run is not known"})
	}
}

var (
	labelerLabel = lint.MustPreconditionID("labeler-label")
	promptSteers = lint.MustPreconditionID("prompt-steers")
	actorEvent   = lint.MustPreconditionID("actor-event")
	appCreates   = lint.MustPreconditionID("app-creates")

	claudeSecurity = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/docs/security.md")
	claudePerms    = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/src/github/validation/permissions.ts")
	codexSecurity  = lint.MustCitation("https://github.com/openai/codex-action/blob/bdf19a4a223ec2549a3e2274a0cf61556bc07675/docs/security.md")
	baseReadme     = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/base-action/README.md")
	clinejection   = lint.MustCitation("https://adnanthekhan.com/posts/clinejection/")
	promptPwnd     = lint.MustCitation("https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents")
	flattAgent     = lint.MustCitation("https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/")
	restPulls      = lint.MustCitation("https://github.com/github/rest-api-description/blob/2a33d9cc5d1dc6ca603b908e0796454af88c1999/descriptions/api.github.com/api.github.com.json")
)

// promptSteersPre is that the agent follows what the attacker wrote: the
// rules of the AI agent actions share it.
var promptSteersPre = lint.Precondition{ID: promptSteers, Text: "the agent reads what the attacker wrote (in the prompt, or through its tools) and follows it over the workflow's prompt; the actions warn of it", Cites: []lint.Citation{claudeSecurity, codexSecurity, baseReadme}}

// agentActors are those who trigger an event of an issue, a comment, a
// review, a pull request from a fork or a fork, as its actor (attacker.Table.KeptActor),
// and start an agent past its gate: through their own account, or a
// GitHub App of theirs for any-bot.
var agentActors = []lint.Actor{
	{Attacker: lint.AttackerIssueAuthor, Via: "opens an issue or a discussion, from their account or a GitHub App of theirs, whose text is the agent's prompt or what it reads",
		Events: []workflow.EventName{workflow.EventNameIssues, workflow.EventNameDiscussion}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameIssues, workflow.EventNameDiscussion}), Gains: []lint.Gain{lint.GainWriteWithToken}},
	{Attacker: lint.AttackerCommenter, Via: "comments on an issue, a pull request or a discussion, or reviews a pull request from a branch of the repository or comments on the diff of the pull request, from their account or a GitHub App of theirs",
		Events: []workflow.EventName{workflow.EventNameIssueComment, workflow.EventNameDiscussionComment, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameIssueComment, workflow.EventNameDiscussionComment, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment}), Gains: []lint.Gain{lint.GainWriteWithToken}},
	{Attacker: lint.AttackerForkPRAuthor, Via: "opens or updates a pull request from a fork, with their account or with a GitHub App of theirs that is installed on the fork, and the pull request starts a run on pull_request_target",
		Events: []workflow.EventName{workflow.EventNamePullRequestTarget}, RunStarters: startedBy([]workflow.EventName{workflow.EventNamePullRequestTarget}), Gains: []lint.Gain{lint.GainWriteWithToken}},
	{Attacker: lint.AttackerAnyoneWhoForks, Via: "forks the repository",
		Events: []workflow.EventName{workflow.EventNameFork}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameFork}), Gains: []lint.Gain{lint.GainWriteWithToken}},
}

// the likelihood of the three kinds: an outsider writes an issue, a
// comment or a review, and the agent must follow it
var (
	agentAV = metric(lint.AttackVectorNetwork, "the attacker opens an issue, comments or reviews over the network")
	agentAC = metric(lint.AttackComplexityLow, "a prompt in what they write is all it takes")
	agentAT = metric(lint.AttackRequirementsPresent, "the agent must follow the attacker's text over the workflow's prompt (prompt injection), which depends on the model and the prompt")
	agentUI = metric(lint.UserInteractionNone, "the run starts when the issue, the comment or the review is written")
)

// agentImpact is what an agent the attacker starts holds: the run's token
// and the step's secrets, through the tools the step allows it (which the
// rule does not read; ai-action-excessive-tools reads them)
var agentImpact = lint.CVSS{
	VC: metric(lint.ImpactHigh, "the agent works with the run's token, the secrets given to the step and the repository, through the tools the step allows it"),
	VI: metric(lint.ImpactHigh, "with the token it writes what the job's permissions allow: comments, labels, branches"),
	VA: metric(lint.ImpactLow, "it can spend the run and the agent's quota"),
	SC: metric(lint.ImpactHigh, "the API key and the secrets open what is past the job"),
	SI: metric(lint.ImpactHigh, "what the agent writes reaches those who read and use the repository"),
	SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
}

func agentCVSS(pr lint.Metric[lint.PrivilegesRequired]) lint.CVSS {
	c := agentImpact
	c.AV, c.AC, c.AT, c.PR, c.UI = agentAV, agentAC, agentAT, pr, agentUI
	return c
}

var aiActionUnrestrictedTriggerMeta = lint.Meta{
	ID:       AIActionUnrestrictedTriggerID,
	Problem:  "a step of an action that runs an AI agent (claude-code-action, codex-action, claude-code's base-action, run-gemini-cli, ai-inference) lets an outsider who opens an issue, comments or reviews start the agent: an input opens the action's check of the actor, or the action has none",
	Expected: "the agent starts only for those who can write to the repository, or only on what no attacker wrote: the action's check of the actor, with the users and bots it lets in listed, or the step on events whose payload has nothing an attacker wrote, with a prompt that reads no input of workflow_dispatch",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessAgentHijack, lint.WeaknessGateBypass}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textAIActionUnrestrictedTriggerAnyUser,
			Attackers:       []lint.Attacker{lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerForkPRAuthor, lint.AttackerAnyoneWhoForks},
			Preconditions:   []lint.PreconditionID{actorEvent, promptSteers, callersEvents},
			CVSS:            agentCVSS(metric(lint.PrivilegesRequiredNone, "allowed_non_write_users or allow-users '*', or the run's actor, lets in anyone who triggers the event, who needs only an account on a public repository")),
			ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "in 2026 a researcher showed that an issue title steers the triage agent of cline/cline, whose claude-code-action had allowed_non_write_users '*', into running commands; an unauthorized publish of cline followed, which only others tie to the workflow", clinejection),
		},
		{
			FindingText:     textAIActionUnrestrictedTriggerLabelerTokenOwner,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor},
			Preconditions:   []lint.PreconditionID{labelerLabel, promptSteers, callersEvents},
			CVSS:            agentCVSS(metric(lint.PrivilegesRequiredNone, "the attacker needs only a pull request from a fork whose files match the configuration of actions/labeler")),
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "the authors of the rule found no report of an agent that a label of actions/labeler started on the pull request of an attacker"),
		},
		{
			FindingText:     textAIActionUnrestrictedTriggerAnyBot,
			Attackers:       []lint.Attacker{lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerForkPRAuthor},
			Preconditions:   []lint.PreconditionID{actorEvent, appCreates, promptSteers, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            agentCVSS(metric(lint.PrivilegesRequiredNone, "anyone makes a GitHub App, whose bot allowed_bots '*' or the run's actor lets in")),
			ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "in 2026 a researcher started claude-code-action's agent mode on anthropics/claude-code with an App of theirs, which the action let in as a bot; Anthropic fixed it", flattAgent),
		},
		{
			FindingText:     textAIActionUnrestrictedTriggerUnchecked,
			Attackers:       []lint.Attacker{lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerForkPRAuthor, lint.AttackerAnyoneWhoForks},
			Preconditions:   []lint.PreconditionID{actorEvent, promptSteers, callersEvents},
			CVSS:            agentCVSS(metric(lint.PrivilegesRequiredNone, "the action checks no actor: anyone who triggers the event starts it")),
			ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "in 2025 researchers showed on a fork that an issue steers the triage of google-gemini/gemini-cli, whose run-gemini-cli ran on issues opened, into printing its secrets; Google fixed it", promptPwnd),
		},
	},
	Threat: lint.Threat{
		Actors: agentActors,
		Preconditions: []lint.Precondition{
			callersEventsPre,
			{ID: actorEvent, Text: "the attacker triggers the event themselves, as its actor (an issue opened, a comment created, a review submitted, a comment on the diff created, a pull request from a fork), and the job's and the step's ifs let them in; claude-code-action checks the actor on the events of an issue, a pull request and workflow_run and fails on others but the three no outsider triggers", Cites: []lint.Citation{claudeSecurity, claudePerms}},
			promptSteersPre,
			{ID: labelerLabel, Text: "a workflow of the same repository runs actions/labeler on the pull request of the attacker with the token of an account, which is a token other than the GITHUB_TOKEN, and the configuration of actions/labeler adds the label that the job of the agent action waits for, from what the attacker writes (the files that the pull request changes, the name of the head branch); a label that a token other than the GITHUB_TOKEN adds starts a run of labeled, the actor of the run of labeled is the account of the token, and the account has write access to the repository", Cites: []lint.Citation{triggerWorkflow, labelerConfigs}},
			{ID: appCreates, Text: "a GitHub App that anyone makes opens an issue or a comment in a public repository that the App is not installed on, or opens a pull request in such a public repository from a branch of a fork that the App is installed on, and the actor of the run is the bot of the App: for issues and comments, claude-code-action's documents and a researcher's report say so; for pull requests, GitHub's REST API documents say that opening a pull request in a public repository needs write access to the head branch, which the installation of the App on the fork has", Cites: []lint.Citation{claudeSecurity, flattAgent, restPulls}},
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee(append([]lint.UndetectedForm{
		appCommitEventLimit,
		forkReviewLimit,
		{ID: lint.MustUndetectedFormID("labeler-app-bot"), Text: "a label that actions/labeler adds to the pull request of an attacker with the token of a GitHub App that a step of the run makes (actions/create-github-app-token, tibdex/github-app-token): the actor of the labeled run is the bot of the app, and the rule reports no labeled run whose label the token of an app adds, even on a step whose action lets the bot start the agent (allowed_bots that names the bot, or an action that checks no actor)", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("other-agent-action"), Text: "an action that runs an AI agent and is not in the linter's table of the actions that run an AI agent, such as a wrapper action in another repository", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("remote-composite"), Text: agentRemoteCompositeText, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("not-actor"), Text: "a run the attacker does not trigger as its actor, such as a maintainer's comment on the attacker's issue, other than a labeled run that a label of actions/labeler starts on the pull request of the attacker (the kind labeler-token-owner): the action checks the actor, and the actor is not the attacker", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("listed-users"), Text: "allowed_non_write_users or allow-users that lists users, or a ${{ }} whose value is not the login of an outsider, such as github.repository_owner: the action lets in only the users that the author of the workflow listed", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("bot-before-agent-check"), Text: "claude-code-action before v1.0.30, whose agent mode let any bot in without allowed_bots: the version is not read", Disposition: lint.Todo(lint.NeedFact)},
	}, automaticLabelForms...)),
	InconclusiveKinds: withRemoteCalleeUnknown(append([]lint.InconclusiveKind{
		{ID: remoteUnknown, Text: agentRemoteUnknownText, Disposition: lint.Todo(lint.NeedFact)},
		{ID: archiveSubstituted, Text: agentArchiveSubstitutedText, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: gateExpr, Text: "allowed_non_write_users, allowed_bots, allow-users or the whole with is a ${{ }} whose value, in a run the attacker triggers, is not decided", Disposition: lint.Todo(lint.NeedSameFile)},
	}, automaticLabelKinds...)),
	FalsePositiveForms: withNamedCaller(append([]lint.FalsePositiveForm{
		forkFlagReview(kindAIActionUnrestrictedTriggerAnyUser),
		{ID: lint.MustFalsePositiveFormID("app-token-secret"), Text: "a secret that actions/labeler uses as the input repo-token, where a workflow of the repository other than the workflow that runs actions/labeler keeps writing a new installation access token of a GitHub App to the secret, such as a workflow on schedule that makes the installation access token with actions/create-github-app-token and writes the installation access token to the secret with the GitHub REST API (gh secret set): the actor of the labeled run is the bot of the GitHub App, not the account of a person, and an agent action that checks the actor refuses the bot, such as claude-code-action whose input allowed_bots is not set or does not name the bot, so the agent action does not start the agent; the rule assumes that the secret that actions/labeler uses as the input repo-token holds the token of an account, and does not read the workflow that writes the secret", FindingKinds: []lint.FindingKindID{kindAIActionUnrestrictedTriggerLabelerTokenOwner}, Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustFalsePositiveFormID("old-version"), Text: "a version of the action without the input, which it ignores: claude-code-action before v1.0.6 has no allowed_non_write_users", FindingKinds: []lint.FindingKindID{kindAIActionUnrestrictedTriggerAnyUser}, Disposition: lint.Todo(lint.NeedFact)},
	}, automaticLabelFalsePositives(kindAIActionUnrestrictedTriggerLabelerTokenOwner)...), kindAIActionUnrestrictedTriggerAnyUser, kindAIActionUnrestrictedTriggerLabelerTokenOwner, kindAIActionUnrestrictedTriggerAnyBot, kindAIActionUnrestrictedTriggerUnchecked),
}
