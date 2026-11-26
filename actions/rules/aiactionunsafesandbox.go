package rules

import (
	"context"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// AIActionUnsafeSandbox is the rule ai-action-unsafe-sandbox: a setting
// of an action that runs an AI agent that takes a layer of its sandbox
// off, so that an agent text an attacker wrote steers is not held back.
// Whether the attacker's text reaches the agent is known only on a run
// whose payload has it; on another the agent may read it through its
// tools, which is inconclusive.
var AIActionUnsafeSandbox lint.Rule = withExamples(lint.WithView[ir.AIActionUnsafeSandboxReader](aiActionUnsafeSandbox{}, ir.AIActionUnsafeSandboxView))

// AIActionUnsafeSandboxID is the ID of ai-action-unsafe-sandbox.
var AIActionUnsafeSandboxID = lint.MustRuleID("ai-action-unsafe-sandbox")

type aiActionUnsafeSandbox struct{}

func (aiActionUnsafeSandbox) Meta() lint.Meta { return aiActionUnsafeSandboxMeta }

var (
	settingExpr  = lint.MustInconclusiveKindID(analysis.InconclusiveAgentSetting.String())
	reachUnknown = lint.MustInconclusiveKindID("reach-unknown")
)

// reachDispatch is what the texts of reach-unknown say of the two
// dispatches: on workflow_dispatch input-dispatch reports an input in the
// prompt, and the sender of repository_dispatch is outside the threat
// model.
const reachDispatch = ". On workflow_dispatch, the one who dispatches the workflow writes the inputs of the payload, and input-dispatch reports an input of workflow_dispatch in the prompt; the sender of repository_dispatch holds a credential with write access to the permission Contents, and the credential premise assumes that no attacker holds such a credential"

// promptDispatchText is the text of input-dispatch of the rules that read
// the reach of a step: of what, on a step whose prompt has an input of
// workflow_dispatch.
func promptDispatchText(what string) string {
	return what + ", of a step that can run on workflow_dispatch and whose prompt has a ${{ }} that refers to an input of workflow_dispatch (inputs, github.event.inputs): " + dispatcherChooses
}

// reachOrDispatch reports a place of a step that no attacker's text
// reaches past its check of the actor: input-dispatch when the prompt has an
// input of workflow_dispatch on a run of workflow_dispatch (promptDispatch),
// else reach-unknown with note. related are the places of the finding that
// the step would give were the text to reach the agent.
func reachOrDispatch(c agentReporter, promptDispatch bool, at ir.Handle, what, note string, related []lint.Related) {
	if promptDispatch {
		c.Inconclusive(lint.InconclusiveDraft{KindID: inputDispatch, Location: c.At(at), Related: related, Note: what + ": the prompt of the step refers to an input of workflow_dispatch, whose value the one who dispatches the workflow chooses; the rule does not determine the text that the value gives the agent"})
		return
	}
	c.Inconclusive(lint.InconclusiveDraft{KindID: reachUnknown, Location: c.At(at), Related: related, Note: note})
}

func (aiActionUnsafeSandbox) Check(_ context.Context, c *lint.RuleContext, v ir.AIActionUnsafeSandboxReader) error {
	for _, s := range v.AgentSteps() {
		if s.Substituted() {
			substitutedAgent(c, s.At(), s.Chain())
			continue
		}
		rp := agentPlace{c: c, at: s.At(), chain: s.Chain(), inner: s.InnerAt()}
		// what the attacker wrote reaches the agent: the payload of a run, or
		// a variable or a secret the attacker writes, in a run anyone starts
		reached := len(s.AttackerOn()) > 0 || len(s.EveryRunRefs()) > 0
		evidence := everyRunEvidence(c, s.Action(), s.EveryRunRefs(), everyRunEvents(s.EveryRunRefs()))
		for _, u := range s.UnsafeSettings() {
			if !reached {
				reachOrDispatch(rp, s.PromptDispatch(), u.At, u.Value+" in "+u.Input.String(), u.Value+" in "+u.Input.String()+": the step runs on no event whose payload has what an attacker wrote; whether the agent reads, through its tools, text that an attacker wrote elsewhere (in an issue, a pull request or a file) is not known", evidence)
				continue
			}
			var args lint.FindingArgs = AIActionUnsafeSandboxCommands{Action: s.Action(), Input: u.Input, Value: u.Value}
			if u.Layer == analysis.SandboxLayerPrivileges {
				args = AIActionUnsafeSandboxPrivileges{Action: s.Action(), Input: u.Input, Value: u.Value}
			}
			rp.Report(lint.FindingDraft{Location: rp.At(u.At), Args: args, Evidence: evidence})
		}
		for _, g := range s.InconclusiveSettings() {
			if g.Kind == analysis.InconclusiveAgentSetting {
				// on a step no attacker's run reaches too: as a literal it would be reach-unknown
				rp.Inconclusive(lint.InconclusiveDraft{KindID: settingExpr, Location: rp.At(g.At), Related: evidence, Note: g.Text + " is a ${{ }} or names a file; whether it takes a layer of the sandbox off is not known"})
			}
		}
	}
	unansweredAgents(c, v.CompositeCalls(), true)
	return nil
}

var (
	textReaches = lint.MustPreconditionID("text-reaches")

	codexAction  = lint.MustCitation("https://github.com/openai/codex-action/blob/bdf19a4a223ec2549a3e2274a0cf61556bc07675/action.yml")
	claudeCLI    = lint.MustCitation("https://code.claude.com/docs/en/cli-reference")
	codexSandbox = lint.MustCitation("https://developers.openai.com/codex/sandboxing")
)

// textReachesPre is that what the attacker wrote reaches the agent: the
// rules of the AI agent actions share it.
var textReachesPre = lint.Precondition{ID: textReaches, Text: "what the attacker wrote reaches the agent, in its prompt or what its tools read, and steers it; the actions warn of it", Cites: []lint.Citation{claudeSecurity, codexSecurity}}

// sandboxActors are those who write what a run's payload has: they trigger
// it, another comments on what they wrote, or an outside app makes a commit
// status or a check run for a commit that they write (of a pull request
// from a fork, or merged; withAppCommitEventsAdded, withMergedCommitAppEvents).
var sandboxActors = withMergedCommitAppEvents(withAppCommitEventsAdded(exposureActorsWith([]lint.Gain{lint.GainRunCode, lint.GainReadSecrets, lint.GainWriteWithToken, lint.GainWriteCache})))

var sandboxAT = metric(lint.AttackRequirementsPresent, "the attacker's text must reach the agent and steer it over the workflow's prompt (prompt injection)")

var aiActionUnsafeSandboxMeta = lint.Meta{
	ID:       AIActionUnsafeSandboxID,
	Problem:  "a setting of an action that runs an AI agent takes a layer of its sandbox off: the limits on the commands it runs (claude's bypassPermissions, codex's danger-full-access), or the privileges of its process (codex's safety-strategy unsafe), so that nothing holds back an agent an attacker's text steers",
	Expected: "the agent keeps its sandbox and its checks of permissions, and runs without sudo",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessAgentHijack}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:   textAIActionUnsafeSandboxCommands,
			Attackers:     []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerAnyoneWhoForks, lint.AttackerMergedCommitAuthor},
			Preconditions: []lint.PreconditionID{textReaches, callersEvents, appStatusCheck},
			CVSS: lint.CVSS{
				AV: agentAV, AC: agentAC, AT: sandboxAT, PR: metric(lint.PrivilegesRequiredNone, "anyone writes an issue, a comment or a review on a public repository, which the run's payload has"), UI: agentUI,
				VC: metric(lint.ImpactHigh, "any command reads the run's token, the secrets in the step's env and the files of the runner", codexSandbox, claudeCLI),
				VI: metric(lint.ImpactHigh, "with the token it pushes and writes what the job's permissions allow"),
				VA: metric(lint.ImpactLow, "it can stop the job"),
				SC: metric(lint.ImpactHigh, "it sends out over the network the secrets that open what is past the job"),
				SI: metric(lint.ImpactHigh, "what the job publishes after it may carry what it changed"),
				SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
			},
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of a sandbox taken off and used"),
		},
		{
			FindingText:   textAIActionUnsafeSandboxPrivileges,
			Attackers:     []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerAnyoneWhoForks, lint.AttackerMergedCommitAuthor},
			Preconditions: []lint.PreconditionID{textReaches, callersEvents, appStatusCheck},
			CVSS: lint.CVSS{
				AV: agentAV, AC: agentAC, AT: sandboxAT, PR: metric(lint.PrivilegesRequiredNone, "anyone writes an issue, a comment or a review on a public repository, which the run's payload has"), UI: agentUI,
				VC: metric(lint.ImpactHigh, "with sudo the agent reads the API key from the memory of the process that holds it, and prints it", codexAction),
				VI: metric(lint.ImpactLow, "the sandbox may still keep its commands from writing"),
				VA: metric(lint.ImpactLow, "it can stop the job"),
				SC: metric(lint.ImpactHigh, "the API key spends the owner's account, and the steps after it keep sudo"),
				SI: metric(lint.ImpactLow, "what it prints is in the run's output"),
				SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
			},
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of safety-strategy unsafe used"),
		},
	},
	Threat: lint.Threat{
		Actors: sandboxActors,
		Preconditions: []lint.Precondition{
			appStatusCheckPre,
			callersEventsPre,
			textReachesPre,
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		jobEnvComposite(true),
		wholeEnv,
		mergedCommitPush(),
		{ID: lint.MustUndetectedFormID("other-agent-action"), Text: "an action that runs an AI agent and is not in the linter's table of the actions that run an AI agent, such as a wrapper action in another repository", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("remote-composite"), Text: agentRemoteCompositeText, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("project-settings"), Text: "a setting in a file of the repository: codex's codex-home config, claude's .claude/settings.json", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("tool-capability"), Text: "what the tools an agent is allowed decide: run-gemini-cli always runs with --yolo, ai-inference's copilot-allow-tools; ai-action-excessive-tools reports them", Disposition: lint.OtherRule(AIActionExcessiveToolsID)},
		{ID: lint.MustUndetectedFormID("scrub-opt-out"), Text: "a step of claude-code-action with allowed_non_write_users whose subprocess env scrub an earlier step turns off by writing CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=0 to $GITHUB_ENV, or whose scrub the env of the caller of an action metadata file or the env key of the step's settings (the settings input, --settings) turns off: the rule holds that the scrub keeps the CLI in the default mode, and does not report claude's bypass", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: remoteUnknown, Text: agentRemoteUnknownText, Disposition: lint.Todo(lint.NeedFact)},
		{ID: archiveSubstituted, Text: agentArchiveSubstitutedText, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: settingExpr, Text: "claude_args, settings, safety-strategy, sandbox, permission-profile, codex-args or the whole with is a ${{ }}, settings names a file, or allowed_non_write_users or the variable CLAUDE_CODE_SUBPROCESS_ENV_SCRUB of env, which decide the subprocess env scrub, is a ${{ }} on a step with claude's bypass", Disposition: lint.Todo(lint.NeedSameFile, lint.NeedRepoFile)},
		{ID: reachUnknown, Text: "a setting that turns off a layer of the sandbox of the agent (the sandbox of the commands, or the limit of the privileges), of a step where no run has a payload with text that an attacker wrote: whether the agent reads, through its tools, text that an attacker wrote elsewhere (in an issue, a pull request or a file) is decided when it runs" + reachDispatch, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: inputDispatch, Text: promptDispatchText("a setting that turns off a layer of the sandbox of the agent (the sandbox of the commands, or the limit of the privileges)"), Disposition: lint.Limitation(lint.DeciderDispatcher)},
	}),
	FalsePositiveForms: withCallee([]lint.FalsePositiveForm{
		forkFlagReview(kindAIActionUnsafeSandboxPrivileges),
		unknownOSCase(valueAttackers, kindAIActionUnsafeSandboxCommands, kindAIActionUnsafeSandboxPrivileges),
		githubEnvWrite(valueAttackers, kindAIActionUnsafeSandboxCommands, kindAIActionUnsafeSandboxPrivileges),
		{ID: lint.MustFalsePositiveFormID("old-version"), Text: "a version of the action without the input, which it ignores: codex-action before v1.10 has no permission-profile", FindingKinds: []lint.FindingKindID{kindAIActionUnsafeSandboxCommands}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("scrub-opt-in"), Text: "a step of claude-code-action or its base-action whose subprocess env scrub an earlier step turns on by writing CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 to $GITHUB_ENV, or a container's env or the env key of the step's settings turns on: the CLI starts in the default mode whatever permission mode the step gives the CLI, and the rule, which does not read the scrub from $GITHUB_ENV, from a container's env or from the settings, reports claude's bypass", FindingKinds: []lint.FindingKindID{kindAIActionUnsafeSandboxCommands}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("tag-mode-settings"), Text: "the defaultMode of settings on a step of claude-code-action in its tag mode, whose --permission-mode acceptEdits wins over settings", FindingKinds: []lint.FindingKindID{kindAIActionUnsafeSandboxCommands}, Disposition: lint.Todo(lint.NeedSameFile)},
	}, kindAIActionUnsafeSandboxCommands, kindAIActionUnsafeSandboxPrivileges),
}
