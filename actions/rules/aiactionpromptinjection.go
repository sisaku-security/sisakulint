package rules

import (
	"context"
	"fmt"
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// AIActionPromptInjection is the rule ai-action-prompt-injection: a value
// an attacker writes that reaches an AI agent as text, through an input
// the action writes into its prompt or an env of its step that the agent
// reads.
// It counts the runs whose actor is the attacker only when the action's
// gate lets them in; a run of another's, such as a maintainer's label on
// their issue, gets past it.
var AIActionPromptInjection lint.Rule = withExamples(lint.WithView[ir.AIActionPromptInjectionReader](aiActionPromptInjection{}, ir.AIActionPromptInjectionView))

// AIActionPromptInjectionID is the ID of ai-action-prompt-injection.
var AIActionPromptInjectionID = lint.MustRuleID("ai-action-prompt-injection")

type aiActionPromptInjection struct{}

func (aiActionPromptInjection) Meta() lint.Meta { return aiActionPromptInjectionMeta }

var valueUnknown = lint.MustInconclusiveKindID("value-unknown")

func (aiActionPromptInjection) Check(_ context.Context, c *lint.RuleContext, v ir.AIActionPromptInjectionReader) error {
	// a value of the env of a job or of the workflow reaches each agent
	// step under it from one place: what each step gives it is joined there
	// and reported after all the steps (outerReports)
	outer := outerReports{}
	for _, s := range v.AgentSteps() {
		if s.Substituted() {
			substitutedAgent(c, s.At(), s.Chain())
			continue
		}
		rp := agentPlace{c: c, at: s.At(), chain: s.Chain(), inner: s.InnerAt()}
		gr := gateReachOf(c, s.Action(), s.ActorOn(), s.OpenGates(), s.InconclusiveSettings())
		seen := anchors{}
		outerSeen := map[string]anchors{} // by the key path of the value of the env
		for _, p := range s.PromptRefs() {
			r := p.Ref
			loc := rp.At(r.At)
			isOuter := p.Route == analysis.PromptRouteJobEnv || p.Route == analysis.PromptRouteWorkflowEnv
			var anchor string
			if isOuter {
				// each reference of one text of the value, whatever the
				// step gives it, so that every step counts it the same
				k := loc.KeyPath().String()
				if outerSeen[k] == nil {
					outerSeen[k] = anchors{}
				}
				anchor = outerSeen[k].next(r.Text, ir.FixPlan{})
			}
			report := func(f lint.FindingDraft) {
				if isOuter {
					outer.finding(rp, f)
					return
				}
				rp.Report(f)
			}
			inconclusive := func(d lint.InconclusiveDraft) {
				if isOuter {
					outer.inconclusive(rp, anchor, d)
					return
				}
				rp.Inconclusive(d)
			}
			switch r.Verdict {
			case analysis.Controlled:
				// the runs the attacker triggers as the actor reach it only
				// past an open gate; another's run gets past it, whose
				// payload has what the attacker wrote, or in which a variable
				// or a secret the attacker writes is theirs (EveryRunOn)
				own, others := within(notWiki(p.On), s.ActorOn()), append(notWiki(p.OthersOn), p.EveryRunOn...)
				var cond *lint.Condition
				evidence, related := valueEvidence(c, r, r.Text)
				switch {
				case len(others) > 0, len(within(own, gr.open)) > 0:
				case len(within(own, gr.bot)) > 0:
					cond = isPublic(c)
				case len(within(own, gr.undecided)) > 0:
					inconclusive(lint.InconclusiveDraft{KindID: gateExpr, Location: loc, Related: slices.Concat(evidence, related), Note: r.Text + " reaches the agent only in a run the attacker triggers, and whom the step lets start the agent then is not decided"})
					continue
				default:
					continue
				}
				// one value can have several: which one, and which of the same text
				if !isOuter {
					anchor = seen.next(r.Text, ir.FixPlan{})
				}
				f := lint.FindingDraft{Location: loc, Condition: cond, Evidence: evidence, Related: related, Anchor: anchor}
				if p.Route.InEnv() {
					f.Args = AIActionPromptInjectionEnv{Action: s.Action(), Env: p.Env.String(), ExprRef: r.Text}
				} else {
					f.Args = AIActionPromptInjectionPrompt{Action: s.Action(), Input: p.Input, ExprRef: r.Text}
				}
				report(f)
			case analysis.Inconclusive:
				if r.InconclusiveKind == analysis.InconclusiveRefInputDispatch && s.PromptDispatch() {
					// whether the gate lets the dispatcher in is the dispatcher's
					inconclusive(lint.InconclusiveDraft{KindID: inputDispatch, Location: loc,
						Note: r.Text + " reaches the agent as text and refers to an input of workflow_dispatch, whose value the one who dispatches the workflow chooses; the rule does not determine the text that the value gives the agent"})
					continue
				}
				if len(s.AttackerOn()) == 0 && len(s.WrittenValueOn()) == 0 {
					continue // no run has a value the attacker writes
				}
				inconclusive(lint.InconclusiveDraft{KindID: valueUnknown, Location: loc,
					Note: fmt.Sprintf("%s reaches the agent as text; whether an attacker controls it is not analyzed (%s)", r.Text, r.InconclusiveKind)})
			}
		}
	}
	outer.report()
	unansweredAgents(c, v.CompositeCalls(), false)
	return nil
}

// outerReports are what the agent steps give each reference of a value of
// the env of a job or of the workflow, by its place, in the order the
// places are first given: the finding with no condition of the steps that
// give one, else the one with the condition, the first of the steps of the
// file that gives it; and, but when the finding has no condition, each
// kind of inconclusive place the steps give it, once (where the condition
// is false, an inconclusive step may still let the attacker in).
type outerReports struct {
	order []string
	at    map[string]*outerReport
}

type outerReport struct {
	rp           agentPlace
	finding      *lint.FindingDraft
	inconclusive []lint.InconclusiveDraft
}

// of is what the steps give the reference at l whose anchor (of the
// references of one text in its value) is anchor.
func (o *outerReports) of(rp agentPlace, l lint.Location, anchor string) *outerReport {
	k := fmt.Sprintf("%s %s %s", l.File.Input, l.KeyPath(), anchor)
	if o.at == nil {
		o.at = map[string]*outerReport{}
	}
	r, ok := o.at[k]
	if !ok {
		r = &outerReport{rp: rp}
		o.at[k] = r
		o.order = append(o.order, k)
	}
	return r
}

func (o *outerReports) finding(rp agentPlace, f lint.FindingDraft) {
	r := o.of(rp, f.Location, f.Anchor)
	if r.finding == nil || r.finding.Condition != nil && f.Condition == nil {
		r.rp, r.finding = rp, &f
	}
}

func (o *outerReports) inconclusive(rp agentPlace, anchor string, d lint.InconclusiveDraft) {
	r := o.of(rp, d.Location, anchor)
	if !slices.ContainsFunc(r.inconclusive, func(e lint.InconclusiveDraft) bool { return e.KindID == d.KindID }) {
		r.inconclusive = append(r.inconclusive, d)
	}
}

func (o *outerReports) report() {
	for _, k := range o.order {
		r := o.at[k]
		if r.finding != nil {
			r.rp.Report(*r.finding)
			if r.finding.Condition == nil {
				continue
			}
		}
		for _, d := range r.inconclusive {
			r.rp.Inconclusive(d)
		}
	}
}

// gateReach are the events of a step's ActorOn on which its gates let the
// attacker in: as anyone (any-user, unchecked, or every event of actorOn
// when the attacker of the run gets past the gate of claude-code-action
// left closed, analysis.BarrierAgentGate) and as a bot (any-bot); and those
// on which whom a gate lets in is not decided (gate-expr).
type gateReach struct{ open, bot, undecided []analysis.EventActivity }

func gateReachOf(c *lint.RuleContext, action analysis.AgentAction, actorOn []analysis.EventActivity, gates []ir.OpenGate, settings []ir.InconclusiveSetting) gateReach {
	var r gateReach
	if action == analysis.AgentActionClaudeCode && c.Barriers().Passes(analysis.BarrierAgentGate) {
		r.open = append(r.open, actorOn...)
	}
	for _, g := range gates {
		switch g.Gate {
		case analysis.AgentGateAnyUser, analysis.AgentGateUnchecked:
			r.open = append(r.open, g.OpenOn...)
		case analysis.AgentGateAnyBot:
			r.bot = append(r.bot, g.OpenOn...)
		}
	}
	for _, g := range settings {
		if g.Kind == analysis.InconclusiveAgentGate {
			r.undecided = append(r.undecided, g.UndecidedOn...)
		}
	}
	return r
}

// within are the events of evs that are in of.
func within(evs, of []analysis.EventActivity) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range evs {
		if slices.Contains(of, e) {
			out = append(out, e)
		}
	}
	return out
}

// notWiki are the events of evs but gollum: a value an attacker writes
// only on gollum, a title of the wiki, is a form the rule leaves
// (UndetectedForm wiki-title).
func notWiki(evs []analysis.EventActivity) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range evs {
		if e.Name() != workflow.EventNameGollum {
			out = append(out, e)
		}
	}
	return out
}

var (
	textInPrompt   = lint.MustPreconditionID("text-in-prompt")
	agentReadsEnv  = lint.MustPreconditionID("agent-reads-env")
	actorNotAuthor = lint.MustPreconditionID("actor-not-author")

	claudeTagMode     = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/src/modes/tag/index.ts")
	claudeAgentMode   = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/src/modes/agent/index.ts")
	aiInferencePrompt = lint.MustCitation("https://github.com/actions/ai-inference/blob/2c43c91ae16266ca159d311430343c67a5ffa222/src/prompt.ts")
	geminiTriage      = lint.MustCitation("https://github.com/google-github-actions/run-gemini-cli/blob/f77273f4c914e4bf38440cf36a0369cb64a37489/.github/commands/gemini-triage.toml")
	runnerComposite   = lint.MustCitation("https://github.com/actions/runner/blob/197ca027b90de199464dee3bb9ff198a1db60967/src/Runner.Worker/Handlers/CompositeActionHandler.cs")
	codexActorCheck   = lint.MustCitation("https://github.com/openai/codex-action/blob/bdf19a4a223ec2549a3e2274a0cf61556bc07675/src/checkActorPermissions.ts")
)

// actorNotAuthorPre is that the actions check the actor of the run, not the
// author of what it reads: the rules of the AI agent actions share it.
var actorNotAuthorPre = lint.Precondition{ID: actorNotAuthor, Text: "the actions check the actor of the run, not the author of what it reads: a maintainer's label or comment on the attacker's issue gets past the check, and so does the attacker where an input of the action, such as allowed_non_write_users, lets the attacker in. A maintainer's review of a pull request that the attacker opened between two branches that others pushed to the repository gets past the check too: anyone with read access can open a pull request between two branches that the repository already has. That the run of such a review has the secrets and the token that the workflow asks for is inferred: the runs of reviews that the authors of the linter saw were of pull requests that the owner of the repository opened", Cites: []lint.Citation{claudePerms, codexActorCheck}}

// promptActors are those who write what the injection rules read, but the
// editor of a wiki and the author of a merged commit, and without the
// events of a commit status or a check run: the rule leaves a value written
// only on gollum, the events of a merge (push, merge_group) and the events
// of a commit status or a check run (app-commit-event), which the attacker
// run table has no rows of.
var promptActors = withoutAppCommitEvents(slices.DeleteFunc(injectionActors([]lint.Gain{lint.GainWriteWithToken}), func(a lint.Actor) bool {
	return a.Attacker == lint.AttackerWikiEditor || a.Attacker == lint.AttackerMergedCommitAuthor
}))

// promptCVSS is the CVSS of both kinds, in the worst case of the rule:
// where the gate is open or the action checks no actor, the attacker's own
// writing starts the run.
var promptCVSS = func() lint.CVSS {
	c := agentCVSS(metric(lint.PrivilegesRequiredNone, "anyone writes an issue, a comment or a review on a public repository, which the step's run reads"))
	c.UI = metric(lint.UserInteractionNone, "the worst case of the rule: where the action checks no actor or an input opens its check, the run starts when the attacker writes; past a closed check, a maintainer's label, comment, edit or deletion starts it")
	return c
}()

var aiActionPromptInjectionMeta = lint.Meta{
	ID:       AIActionPromptInjectionID,
	Problem:  "a value an attacker writes reaches an AI agent as text: a ${{ }} in an input the action writes into the agent's prompt, or a ${{ }} in the env of the step, in the env of the job or in the env of the workflow, which the agent reads, on a run that gets past the action's check of the actor",
	Expected: "what an attacker writes does not reach the agent: the step runs only on events whose payload holds only what those who can write wrote and inputs of workflow_dispatch that the prompt does not read, or the agent is given the number of an issue and not its text",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessAgentHijack}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textAIActionPromptInjectionPrompt,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerAnyoneWhoForks},
			Preconditions:   []lint.PreconditionID{attackerWrites, textInPrompt, actorNotAuthor, promptSteers, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            promptCVSS,
			ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "in 2026 a researcher showed that an issue title, written by ${{ }} into the prompt of cline/cline's triage agent, steered it into running commands; an unauthorized publish of cline followed, which only others tie to the workflow", clinejection),
		},
		{
			FindingText:     textAIActionPromptInjectionEnv,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerAnyoneWhoForks},
			Preconditions:   []lint.PreconditionID{attackerWrites, agentReadsEnv, actorNotAuthor, promptSteers, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            promptCVSS,
			ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "in 2025 researchers showed on a fork that an issue whose title and body google-gemini/gemini-cli's triage gave run-gemini-cli in env steered the agent into printing its secrets; Google fixed it", promptPwnd),
		},
	},
	Threat: lint.Threat{
		Actors: promptActors,
		Preconditions: []lint.Precondition{
			attackerWritesPre,
			promptSteersPre,
			{ID: textInPrompt, Text: "the action writes the input into the agent's prompt: claude-code-action's prompt in its agent mode, its base-action's, codex-action's and run-gemini-cli's prompt, ai-inference's prompt, system-prompt and the variables of input", Cites: []lint.Citation{claudeAgentMode, aiInferencePrompt}},
			{ID: agentReadsEnv, Text: "the env of the step, the env of the job and the env of the workflow reach the process of the agent, inside a composite action too, and the tools of the agent read the variables of the env of the step, of the job and of the workflow; a workflow puts a value in the env of the step, of the job or of the workflow for the agent, as the commands of run-gemini-cli read ISSUE_TITLE", Cites: []lint.Citation{runnerComposite, geminiTriage}},
			actorNotAuthorPre,
			callersEventsPre,
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		forkReviewLimit,
		repositoryDispatchLimit, appCommitEventLimit, dispatchRelayLimit, dispatchInputCallLimit, dispatchDerivedLimit,
		jobEnvComposite(false),
		windowsLabelOtherOS(false),
		{ID: lint.MustUndetectedFormID("action-fetches"), Text: "what the action fetches itself into the prompt: claude-code-action's tag mode (no prompt input) puts the title, the body and the comments of the issue or the pull request in it", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("agent-reads"), Text: "what the agent reads through its tools on its own, such as gh issue view: the prompt and the agent decide it", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("other-agent-action"), Text: "an action that runs an AI agent and is not in the linter's table of the actions that run an AI agent, such as a wrapper action in another repository", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("remote-composite"), Text: agentRemoteCompositeText, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("prompt-file"), Text: "an input that names a file of the prompt (prompt_file, prompt-file, system-prompt-file, file_input): what the file holds is not read", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("args-value"), Text: "a value an attacker writes in claude_args: the value of --system-prompt or --append-system-prompt is a prompt, and another flag it adds may allow tools; ai-action-excessive-tools reports it", Disposition: lint.OtherRule(AIActionExcessiveToolsID)},
		{ID: lint.MustUndetectedFormID("whole-with"), Text: "a with or an env of the step, or an env of the job or of the workflow, that is one whole ${{ }}, when no value that reaches the agent is outside that ${{ }}. The rule does not know which inputs the action gets and the values of those inputs, or the names and the values of the variables of the env that is one whole ${{ }}, so the rule does not know the values that reach the agent. An env that is one whole ${{ }} may also set a variable with the same name as a variable of an outer env (the env of the job and the env of the workflow are outer envs of an env of the step; the env of the workflow is the outer env of an env of the job), and the variable of the inner env replaces the variable of the outer env, so the rule does not count the values of the outer envs of an env that is one whole ${{ }} either. The form where a value outside the whole ${{ }} of the with, such as a value in an env of the step, reaches the agent, and the rule does not know whom the gate lets in, is gate-expr", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("merged-commit"), Text: "a value an attacker writes on push or merge_group, such as the message of their commit a maintainer merged: the run's actor is the maintainer, whom a check of the actor lets in, but the rule reads the events of the attacker run table, which has no rows of them", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("wiki-title"), Text: "a value an attacker writes only on gollum, the title of a wiki page", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("old-cli-env"), Text: "an env of run-gemini-cli whose name gemini-cli drops from its tools now, which an older version of the CLI, pinned by gemini_cli_version, passes", Disposition: lint.Todo(lint.NeedFact)},
		pullRequestLimit,
		mergedPusherLimit,
	}),
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: remoteUnknown, Text: agentRemoteUnknownText, Disposition: lint.Todo(lint.NeedFact)},
		{ID: archiveSubstituted, Text: agentArchiveSubstitutedText, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: valueUnknown, Text: "a value whose ${{ }} is not analyzed: the output of a step or a job, an input of a reusable workflow or a composite action, a matrix, an env the workflow does not set", Disposition: lint.Todo(lint.NeedSameFile, lint.NeedRepoFile, lint.NeedFact)},
		{ID: inputDispatch, Text: "a value that reaches the agent with a ${{ }} that refers to an input of workflow_dispatch (inputs, github.event.inputs), on a step that can run on workflow_dispatch: " + dispatcherChooses + ". The rule does not read the check of the actor for such a run: the one who dispatches the workflow uses a credential of the one who dispatches, the actor of the run is the holder of that credential, and the check of the actor admits the run when that holder passes the check", Disposition: lint.Limitation(lint.DeciderDispatcher)},
		{ID: gateExpr, Text: "a value that reaches the agent only in a run the attacker triggers, where allowed_non_write_users, allow-users or the whole with is a ${{ }} whose value in that run is not decided: the value that reaches the agent is known (when the whole with is a ${{ }}, that value is outside the with, such as in an env of the step), and whom the gate lets in is not known (whole-with is the form where no value that reaches the agent is outside the whole ${{ }})", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	FalsePositiveForms: withCallee([]lint.FalsePositiveForm{
		forkFlagReview(kindAIActionPromptInjectionPrompt),
		unknownOSCase(nil, kindAIActionPromptInjectionEnv),
		githubEnvWrite(nil, kindAIActionPromptInjectionEnv),
		{ID: lint.MustFalsePositiveFormID("no-env-tool"), Text: "an env of the step, of the job or of the workflow, where the agent of the step has no tool to read the env: ai-inference without copilot-allow-tools, claude-code-action's tag mode, which allows no shell but git", FindingKinds: []lint.FindingKindID{kindAIActionPromptInjectionEnv}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("indirect-value"), Text: "a value through an env or an input (${{ env.X }}, ${{ inputs.x }}) that is the attacker's only in their own run, such as the body of a comment, read as theirs in a maintainer's run too, past a closed gate", FindingKinds: []lint.FindingKindID{kindAIActionPromptInjectionPrompt, kindAIActionPromptInjectionEnv}, Disposition: lint.Todo(lint.NeedSameFile)},
		writerString(kindAIActionPromptInjectionPrompt, kindAIActionPromptInjectionEnv), ifUnnarrowedFalsePositive(kindAIActionPromptInjectionPrompt, kindAIActionPromptInjectionEnv),
	}, kindAIActionPromptInjectionPrompt, kindAIActionPromptInjectionEnv),
}
