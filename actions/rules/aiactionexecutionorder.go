package rules

import (
	"context"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// AIActionExecutionOrder is the rule ai-action-execution-order: a step of
// an action that runs an AI agent an attacker's text reaches, followed in
// its job by a step that runs what the agent may leave on the runner and
// holds more than the agent: the code it edits, or the secrets an agent
// that runs any code without sudo does not hold.
// It reads the reach as ai-action-excessive-tools does.
var AIActionExecutionOrder lint.Rule = withExamples(lint.WithView[ir.AIActionExecutionOrderReader](aiActionExecutionOrder{}, ir.AIActionExecutionOrderView))

// AIActionExecutionOrderID is the ID of ai-action-execution-order.
var AIActionExecutionOrderID = lint.MustRuleID("ai-action-execution-order")

type aiActionExecutionOrder struct{}

func (aiActionExecutionOrder) Meta() lint.Meta { return aiActionExecutionOrderMeta }

var (
	copilotGit       = lint.MustInconclusiveKindID("copilot-git")
	unprivilegedUser = lint.MustInconclusiveKindID("unprivileged-user")
)

// codexSandboxInputs are the inputs that decide what codex may write.
var codexSandboxInputs = []analysis.AgentInput{analysis.AgentInputSafetyStrategy, analysis.AgentInputSandbox, analysis.AgentInputPermissionProfile}

// verdict is what the rule says of a step of an agent action whose later
// steps it counts: a finding of args, or an inconclusive of kind; and what
// of a later step counts: the code of the workspace it runs, the git it
// starts, the secrets it holds that the agent does not.
type verdict struct {
	args               lint.FindingArgs
	kind               lint.InconclusiveKindID
	code, git, secrets bool
}

// counted are where the later step l holds or runs what vd counts.
func (vd verdict) counted(c *lint.RuleContext, l ir.LaterStep) []lint.Related {
	var out []lint.Related
	if vd.code {
		for _, r := range l.CodeRuns {
			out = append(out, lint.Related{Location: c.At(r.At), Note: l.Name + " runs " + r.Text + ", which the agent can edit"})
		}
	}
	if vd.git {
		for _, r := range l.GitRuns {
			out = append(out, lint.Related{Location: c.At(r.At), Note: l.Name + " runs " + r.Text + ", which runs the hooks and config of .git"})
		}
	}
	if vd.secrets {
		var held []string
		for _, n := range l.Secrets {
			held = append(held, "secrets."+n)
		}
		if l.Token {
			held = append(held, "the job's token")
		}
		if l.AllSecrets {
			held = append(held, "secrets it does not name")
		}
		if len(held) > 0 {
			out = append(out, lint.Related{Location: c.At(l.At), Note: l.Name + " holds " + strings.Join(held, ", ") + ", which the agent does not"})
		}
	}
	return out
}

func (aiActionExecutionOrder) Check(_ context.Context, c *lint.RuleContext, v ir.AIActionExecutionOrderReader) error {
	for _, s := range v.AgentSteps() {
		if s.Substituted() {
			substitutedAgent(c, s.At(), s.Chain())
			continue
		}
		rp := agentPlace{c: c, at: s.At(), chain: s.Chain(), inner: s.InnerAt()}
		vd, ok := verdictOf(s)
		if !ok {
			continue
		}
		gr := gateReachOf(c, s.Action(), s.ActorOn(), s.OpenGates(), s.InconclusiveSettings())
		own := within(s.AttackerOn(), s.ActorOn())
		// another's run: one whose payload has what the attacker wrote, or
		// one in which a variable or a secret the attacker writes reaches
		// the agent (EveryRunRefs)
		others := append(slices.Clone(s.OthersOn()), everyRunEvents(s.EveryRunRefs())...)
		stepReach, _ := reachOf(c, gr, own, others)
		// the events on which a run that has what the attacker wrote
		// reaches the agent, or past a gate not decided: a later step
		// counts when its if lets one of them through; when none does,
		// every later step counts
		var reachOn []analysis.EventActivity
		switch stepReach {
		case reached:
			reachOn = append(slices.Clone(others), within(own, append(slices.Clone(gr.open), gr.bot...))...)
		case reachGate:
			reachOn = within(own, gr.undecided)
		}
		var later []ir.LaterStep
		for _, l := range s.LaterSteps() {
			if stepReach == reachNone || len(within(l.On, reachOn)) > 0 {
				later = append(later, l)
			}
		}
		if vd.args != nil && vd.kind != (lint.InconclusiveKindID{}) {
			if slices.ContainsFunc(later, func(l ir.LaterStep) bool { return len(l.CodeRuns) > 0 }) {
				// a later step runs the workspace's code: the finding,
				// of what it counts
				vd = verdict{args: vd.args, code: true}
			} else {
				// what is counted holds only if the agent writes .git (the
				// Copilot CLI's) or starts in auto mode, which is not decided
				vd.args = nil
			}
		}
		var related []lint.Related
		var on []analysis.EventActivity // the events of the later steps counted
		for _, l := range later {
			if r := vd.counted(c, l); len(r) > 0 {
				related = append(related, r...)
				on = append(on, l.On...)
			}
		}
		if len(related) == 0 {
			continue
		}
		note := relatedNote(related)
		evidence := everyRunEvidence(c, s.Action(), s.EveryRunRefs(), on)
		switch {
		case stepReach == reachGate:
			rp.Inconclusive(lint.InconclusiveDraft{KindID: gateExpr, Location: rp.At(s.At()), Related: slices.Concat(evidence, related), Note: "steps after it run what its agent may leave, and what an attacker writes reaches it only in a run they trigger, past a gate not decided: " + note})
		case stepReach == reachNone:
			reachOrDispatch(rp, s.PromptDispatch(), s.At(), "steps after it run what its agent may leave: "+note, "steps after it run what its agent may leave, and the step runs on no event whose payload has what an attacker wrote past its check of the actor; whether the agent reads, through its tools, text that an attacker wrote elsewhere (in an issue, a pull request or a file) is not known: "+note, slices.Concat(evidence, related))
		case vd.args == nil:
			rp.Inconclusive(lint.InconclusiveDraft{KindID: vd.kind, Location: rp.At(s.At()), Note: note})
		default:
			// the condition of the runs that reach the later steps counted
			_, cond := reachOf(c, gr, within(own, on), within(others, on))
			rp.Report(lint.FindingDraft{Location: rp.At(s.At()), Args: vd.args, Condition: cond, Evidence: evidence, Related: related})
		}
	}
	unansweredAgents(c, v.CompositeCalls(), false)
	return nil
}

// verdictOf is what the rule says of s by what its agent may leave; false
// when it counts no later step.
func verdictOf(s ir.AIActionExecutionOrderOfAgentStep) (verdict, bool) {
	anyCode := slices.ContainsFunc(s.CapabilityGrants(), func(g ir.CapabilityGrant) bool { return g.Capability == analysis.AgentCapabilityRunsAnyCode }) ||
		slices.ContainsFunc(s.UnsafeSettings(), func(u ir.UnsafeSetting) bool { return u.Layer == analysis.SandboxLayerCommands }) ||
		s.AutoMode() == analysis.AgentAutoModeOn
	edits := slices.ContainsFunc(s.CapabilityGrants(), func(g ir.CapabilityGrant) bool { return g.Capability == analysis.AgentCapabilityEditsWorkspace })
	sudo := s.AgentUser() == analysis.AgentUserRunner && s.RunnerSudo()
	// a ${{ }} sets claude's mode or decides its subprocess env scrub
	undecided := s.AutoMode() == analysis.AgentAutoModeUndecided || s.ScrubDecides()
	switch {
	case s.Action() == analysis.AgentActionCodex && !edits && slices.ContainsFunc(s.InconclusiveSettings(), func(x ir.InconclusiveSetting) bool {
		return x.Kind == analysis.InconclusiveAgentSetting && slices.Contains(codexSandboxInputs, x.Input)
	}):
		// what codex may write is not decided (a profile decides it over a
		// sandbox that is a ${{ }}, and then codex edits)
		return verdict{kind: settingExpr, code: true, git: true, secrets: true}, true
	case anyCode && sudo:
		return verdict{}, false // it may read the job's secrets itself (sudo-agent, sudo-auto-mode, sudo-unsafe-setting)
	case anyCode && s.AgentUser() == analysis.AgentUserOther:
		return verdict{kind: unprivilegedUser, secrets: true}, true
	case anyCode:
		return verdict{args: AIActionExecutionOrderLaterSecrets{Action: s.Action()}, secrets: true}, true
	case edits && s.GitWrite() == analysis.AgentGitWriteYes:
		return verdict{args: AIActionExecutionOrderEditedCode{Action: s.Action()}, code: true, git: true}, true
	case edits && undecided:
		// its edits run in a step that runs the workspace's code; in auto
		// mode, which a ${{ }} may set, it also writes .git and runs any code
		return verdict{args: AIActionExecutionOrderEditedCode{Action: s.Action()}, kind: settingExpr, code: true, git: true, secrets: !s.RunnerSudo()}, true
	case undecided:
		// a ${{ }} may start it in auto mode or with its bypass, where it
		// runs any code and edits .git, or decide whether acceptEdits lets
		// it edit
		return verdict{kind: settingExpr, code: true, git: true, secrets: !s.RunnerSudo()}, true
	case edits && s.GitWrite() == analysis.AgentGitWriteUndecided:
		return verdict{args: AIActionExecutionOrderEditedCode{Action: s.Action()}, kind: copilotGit, code: true, git: true}, true
	case edits:
		return verdict{args: AIActionExecutionOrderEditedCode{Action: s.Action()}, code: true}, true
	}
	return verdict{}, false
}

// relatedNote is the notes of related, in one line.
func relatedNote(related []lint.Related) string {
	var notes []string
	for _, r := range related {
		notes = append(notes, r.Note)
	}
	return strings.Join(notes, "; ")
}

var (
	residueRuns = lint.MustPreconditionID("residue-runs")

	codexLastStep = lint.MustCitation("https://github.com/openai/codex-action/blob/bdf19a4a223ec2549a3e2274a0cf61556bc07675/docs/security.md")
	runnerCleanup = lint.MustCitation("https://github.com/actions/runner/blob/197ca027b90de199464dee3bb9ff198a1db60967/src/Runner.Worker/JobExtension.cs")
	runnerEnvFile = lint.MustCitation("https://github.com/actions/runner/blob/197ca027b90de199464dee3bb9ff198a1db60967/src/Runner.Worker/FileCommandManager.cs")
	runnerActions = lint.MustCitation("https://github.com/actions/runner/blob/197ca027b90de199464dee3bb9ff198a1db60967/src/Runner.Worker/ActionManager.cs")
	hostedSudo    = lint.MustCitation("https://github.com/github/docs/blob/ae648a1d328cb15fb173e80984aac748cf4b5af2/content/actions/reference/runners/github-hosted-runners.md")
)

var residueRunsPre = lint.Precondition{ID: residueRuns, Text: "a later step of the job runs what the agent leaves on the runner: the runner kills a step's processes only at the end of the job, applies the environment files (a BASH_ENV, a PATH) to every later step, and runs another action from the copy it downloaded at the start of the job; the workspace's scripts and builds, and git's hooks, are the agent's edits", Cites: []lint.Citation{codexLastStep, runnerCleanup, runnerEnvFile, runnerActions}}

var (
	editedCodeImpact = lint.CVSS{
		VC: metric(lint.ImpactHigh, "the later step runs the attacker's code with the job's env, the token actions/checkout leaves in .git/config and, on GitHub-hosted runners, sudo, with which it may read the job's secrets from the runner's memory", hostedSudo),
		VI: metric(lint.ImpactHigh, "with the token it pushes and writes what the job's permissions allow"),
		VA: metric(lint.ImpactLow, "it can stop the job"),
		SC: metric(lint.ImpactHigh, "it sends out the secrets that open what is past the job"),
		SI: metric(lint.ImpactHigh, "what the job publishes after it may carry what it changed"),
		SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
	}
	laterSecretsImpact = lint.CVSS{
		VC: metric(lint.ImpactHigh, "what the agent leaves reads the secrets the later step holds", runnerEnvFile),
		VI: metric(lint.ImpactHigh, "a secret of a publish or a deploy writes where the agent's step could not"),
		VA: metric(lint.ImpactLow, "it can stop the job"),
		SC: metric(lint.ImpactHigh, "the secrets open what is past the job"),
		SI: metric(lint.ImpactHigh, "what the later step publishes may carry what it changed"),
		SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
	}
	orderMaturity = metric(lint.ExploitMaturityUnreported, "no report of an agent's step whose leftovers a later step of its job ran was found (searched on 2026-10-14 for the agent actions with BASH_ENV, GITHUB_ENV, last step and later steps); codex-action's security notes warn of the forms")
)

var aiActionExecutionOrderMeta = lint.Meta{
	ID:       AIActionExecutionOrderID,
	Problem:  "a step of an action that runs an AI agent an attacker's text reaches is followed in its job by a step that runs what the agent may leave on the runner, and holds more than the agent: an agent that edits the workspace leaves code a later step runs; one that runs any code without sudo leaves a process, an environment file or another action's source that a later step with more secrets runs",
	Expected: "the agent runs as the last step of a job of its own, whose output a new job takes; no step after it runs the workspace's code or holds secrets the agent does not",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessAgentHijack}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textAIActionExecutionOrderEditedCode,
			Attackers:       toolsAttackers,
			Preconditions:   []lint.PreconditionID{textReaches, promptSteers, residueRuns, actorNotAuthor, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            toolsCVSS(agentAT, editedCodeImpact),
			ExploitMaturity: orderMaturity,
		},
		{
			FindingText:     textAIActionExecutionOrderLaterSecrets,
			Attackers:       toolsAttackers,
			Preconditions:   []lint.PreconditionID{textReaches, promptSteers, residueRuns, actorNotAuthor, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            toolsCVSS(agentAT, laterSecretsImpact),
			ExploitMaturity: orderMaturity,
		},
	},
	Threat: lint.Threat{
		Actors: toolActors,
		Preconditions: []lint.Precondition{
			textReachesPre,
			promptSteersPre,
			residueRunsPre,
			actorNotAuthorPre,
			callersEventsPre,
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		jobEnvComposite(true),
		wholeEnv,
		appCommitEventLimit,
		{ID: lint.MustUndetectedFormID("remote-composite"), Text: agentRemoteCompositeText, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("action-metadata"), Text: "an agent's step in an action metadata file: the steps of its caller's job after it, and the credentials its inputs pass to the steps after it, are not read", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("codex-environment-file"), Text: "codex's workspace-write sandbox writing the environment files ($GITHUB_ENV, $GITHUB_PATH): the rule holds that it cannot, as they are outside its writable roots, and reads it as an agent that only edits", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("codex-writable-roots"), Text: "a setting that adds writable roots to codex's sandbox (--add-dir and -c sandbox_workspace_write.writable_roots in codex-args, the config of codex-home and its profiles, which the rule reads as one that edits the workspace): with $RUNNER_TEMP among them, an agent that only edits writes the environment files", Disposition: lint.Todo(lint.NeedSameFile, lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("default-token-input"), Text: "a later step of a remote action that takes the job's token by the default of its input (actions/github-script's github-token): the workflow does not write the token, so the rule does not count it", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("git-running-action"), Text: "a later step of an action that runs git (actions/checkout, which leaves .git), after an agent that may write .git", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("kept-untracked"), Text: "a file the agent makes that git does not track (.npmrc with node-options), which a later checkout with clean false keeps, and a step after that runs: the rule takes every checkout of the workspace for one that takes the agent's edits away, as its --force puts back the tracked files", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("next-job"), Text: "what an agent leaves on a self-hosted runner, which later jobs on it run: self-hosted-runner reports the self-hosted runner of a public repository, not the jobs after the agent's", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("other-tool"), Text: "a later step that runs the workspace's code with a command or an action the table of prcode does not have (tox, docker build ., pre-commit/action), or git through bash -c, a function or gh, which the rule does not read for an agent that may write .git", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("post-step"), Text: "the post step of an action before the agent, which runs after every step of the job, the agent's last one too, from the source the agent may overwrite", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("published-edits"), Text: "a later step that publishes, pushes or uploads the workspace the agent edited without running it: the rule cannot tell it from a step that sends the edits to a person's review", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("scrubbed-env"), Text: "a secret of the job's env that claude-code-action's CLAUDE_CODE_SUBPROCESS_ENV_SCRUB keeps from the agent's commands: the rule holds that the agent holds it", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("sudo-agent"), Text: "an agent whose permissions let it run any code, as the runner's user on a GitHub-hosted Linux or macOS runner, followed by a step with more secrets: the rule holds that the agent may read the job's secrets from the memory of the runner's worker with sudo, where the runner keeps them from the start of the job; reading a secret's value was not tried", Disposition: lint.OtherRule(AIActionExcessiveToolsID)},
		{ID: lint.MustUndetectedFormID("sudo-auto-mode"), Text: "an agent in auto mode, as the runner's user on a GitHub-hosted Linux or macOS runner, followed by a step with more secrets: the rule holds, as for sudo-agent, that the agent may read the job's secrets with sudo; ai-action-excessive-tools reports the agent in auto mode", Disposition: lint.OtherRule(AIActionExcessiveToolsID)},
		{ID: lint.MustUndetectedFormID("sudo-unsafe-setting"), Text: "an agent with a setting that lets it run any code, as the runner's user on a GitHub-hosted Linux or macOS runner, followed by a step with more secrets: the rule holds, as for sudo-agent, that the agent may read the job's secrets with sudo", Disposition: lint.OtherRule(AIActionUnsafeSandboxID)},
		{ID: lint.MustUndetectedFormID("undecided-tools"), Text: "an agent whose permissions are not decided (a command the table does not know, a tool of an MCP server the step adds): ai-action-excessive-tools reports them inconclusive; this rule counts no step after it", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("withheld-input"), Text: "a secret in the with of an agent's step that the action does not pass on to the agent, but codex-action's key: the rule holds that the agent holds it", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("scrub-opt-out"), Text: "a step of claude-code-action with allowed_non_write_users whose subprocess env scrub an earlier step turns off by writing CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=0 to $GITHUB_ENV, or whose scrub the env of the caller of an action metadata file or the env key of the step's settings (the settings input, --settings) turns off: the rule holds that the scrub keeps the CLI in the default mode, and does not report the auto mode, nor the edits of acceptEdits, before the steps after the agent", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("old-cli"), Text: "a step that runs a Claude Code CLI older than the one of the action of now, by an older commit of the action or by path_to_claude_code_executable: a CLI before v2.1.302 starts in auto mode with no permission mode on a third-party provider or with telemetry off; a CLI older than the versions that keep the default mode under the subprocess env scrub may start under the scrub in the permission mode the step gives the CLI; the rule reads the start mode as the CLI of the action of now reads the start mode, and does not report the auto mode before the steps after the agent", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("workspace-hooks"), Text: "a directory of hooks in the workspace (core.hooksPath=.githooks) that is not one of claude's protected paths, which an agent that cannot write .git edits, and a later git commit runs", Disposition: lint.Todo(lint.NeedSameFile)},
		npmAbbreviation(kindAIActionExecutionOrderEditedCode),
		npmOptionValueCommand(kindAIActionExecutionOrderEditedCode),
	}),
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: remoteUnknown, Text: agentRemoteUnknownText, Disposition: lint.Todo(lint.NeedFact)},
		{ID: archiveSubstituted, Text: agentArchiveSubstitutedText, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: copilotGit, Text: "ai-inference's Copilot CLI with a permission to edit, followed only by steps that start git: whether its edits may write .git is not in its sources", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: gateExpr, Text: "an agent's step followed by steps that would count, that what an attacker writes reaches only in a run they trigger, where whom the gate lets in is not decided", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: reachUnknown, Text: "an agent's step followed by steps that would count, where no run that gets past the check of the actor of the agent's step has a payload with text that an attacker wrote: whether the agent reads, through its tools, text that an attacker wrote elsewhere (in an issue, a pull request or a file) is decided when it runs" + reachDispatch, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: inputDispatch, Text: promptDispatchText("an agent's step followed by steps that would count"), Disposition: lint.Limitation(lint.DeciderDispatcher)},
		{ID: settingExpr, Text: "codex-action's safety-strategy, sandbox or permission-profile, or the permission mode of claude-code-action (claude_args, settings, or allowed_non_write_users and the variable CLAUDE_CODE_SUBPROCESS_ENV_SCRUB of env, which decide the subprocess env scrub), is a ${{ }}, followed by steps that would count: what the agent may write is not decided", Disposition: lint.Todo(lint.NeedSameFile, lint.NeedRepoFile)},
		{ID: unprivilegedUser, Text: "codex-action's unprivileged-user with a sandbox that runs any code, followed by steps with more secrets: whether its user reaches the runner's user's files and processes is not known", Disposition: lint.Limitation(lint.DeciderRunTime)},
	}),
	FalsePositiveForms: withCallee([]lint.FalsePositiveForm{
		forkFlagReview(kindAIActionExecutionOrderEditedCode),
		unknownOSCase(valueAttackers, kindAIActionExecutionOrderEditedCode, kindAIActionExecutionOrderLaterSecrets),
		githubEnvUnreadWrite(valueAttackers, kindAIActionExecutionOrderEditedCode, kindAIActionExecutionOrderLaterSecrets),
		{ID: lint.MustFalsePositiveFormID("cleaned-workspace"), Text: "a step that is not a checkout of the workspace (git clean, git checkout -- ., a checkout of another path that puts back the code the later step runs) takes the agent's edits away before the later step", FindingKinds: []lint.FindingKindID{kindAIActionExecutionOrderEditedCode}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("earlier-file-secret"), Text: "a later step's secret that a step before the agent leaves on the runner (docker/login-action's config, an .npmrc, a line of $GITHUB_ENV), which the agent reads in its own step: the rule counts only the secrets of the env and the with of the agent's step, its job and its workflow", FindingKinds: []lint.FindingKindID{kindAIActionExecutionOrderLaterSecrets}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("scrub-opt-in"), Text: "a step of claude-code-action or its base-action whose subprocess env scrub an earlier step turns on by writing CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 to $GITHUB_ENV, or a container's env or the env key of the step's settings turns on: the CLI starts in the default mode whatever permission mode the step gives the CLI, and the rule, which does not read the scrub from $GITHUB_ENV, from a container's env or from the settings, reports the edits of acceptEdits and the auto mode before the steps after the agent", FindingKinds: []lint.FindingKindID{kindAIActionExecutionOrderEditedCode, kindAIActionExecutionOrderLaterSecrets}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("old-version"), Text: "a version of the action or its CLI that reads the input otherwise, as for ai-action-excessive-tools: the permissions are read with the grammar of the pinned versions", FindingKinds: []lint.FindingKindID{kindAIActionExecutionOrderEditedCode, kindAIActionExecutionOrderLaterSecrets}, Disposition: lint.Todo(lint.NeedFact)},
		npmUnknownCommand(kindAIActionExecutionOrderEditedCode),
		npmOptionValueOperand(kindAIActionExecutionOrderEditedCode),
		cdOutOfTree(kindAIActionExecutionOrderEditedCode),
		ignoredPnpmfile(kindAIActionExecutionOrderEditedCode),
		absolutePathOutOfTree(kindAIActionExecutionOrderEditedCode),
		pytestPathOutOfTree(kindAIActionExecutionOrderEditedCode),
		toolDirectoryOutOfTree(kindAIActionExecutionOrderEditedCode),
	}, kindAIActionExecutionOrderEditedCode, kindAIActionExecutionOrderLaterSecrets),
}
