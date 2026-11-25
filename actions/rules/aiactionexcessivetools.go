package rules

import (
	"context"
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// AIActionExcessiveTools is the rule ai-action-excessive-tools: a
// permission of a step of an action that runs an AI agent that gives an
// agent an attacker's text steers any code, a write with the token where it
// chooses, or a send to a host it chooses; and a value an attacker writes
// in an input the action splits into flags or reads as JSON.
// It reads the reach as ai-action-prompt-injection does: a run whose actor
// is the attacker counts only past an open gate.
var AIActionExcessiveTools lint.Rule = withExamples(lint.WithView[ir.AIActionExcessiveToolsReader](aiActionExcessiveTools{}, ir.AIActionExcessiveToolsView))

// AIActionExcessiveToolsID is the ID of ai-action-excessive-tools.
var AIActionExcessiveToolsID = lint.MustRuleID("ai-action-excessive-tools")

type aiActionExcessiveTools struct{}

func (aiActionExcessiveTools) Meta() lint.Meta { return aiActionExcessiveToolsMeta }

var (
	unknownCommand = lint.MustInconclusiveKindID(analysis.InconclusiveAgentCommand.String())
	customMCP      = lint.MustInconclusiveKindID(analysis.InconclusiveAgentMCP.String())
)

// undecidedKinds are the kinds of the inconclusive by why a permission is
// undecided.
var undecidedKinds = map[analysis.InconclusiveAgentKind]lint.InconclusiveKindID{
	analysis.InconclusiveAgentSetting: settingExpr,
	analysis.InconclusiveAgentCommand: unknownCommand,
	analysis.InconclusiveAgentMCP:     customMCP,
}

// reach is how what an attacker writes reaches a step.
type reach uint8

const (
	reachNone reach = iota // no run that has it gets past the step's check of the actor
	reachGate              // only a run they trigger, past a gate that is a ${{ }}
	reached
)

// reachOf: a run of another's that has what the attacker wrote (others)
// gets past the gate; one of theirs (own) past a gate open on its event,
// or past one that lets any bot in, on a public repository.
func reachOf(c *lint.RuleContext, gr gateReach, own, others []analysis.EventActivity) (reach, *lint.Condition) {
	switch {
	case len(others) > 0, len(within(own, gr.open)) > 0:
		return reached, nil
	case len(within(own, gr.bot)) > 0:
		return reached, isPublic(c)
	case len(within(own, gr.undecided)) > 0:
		return reachGate, nil
	}
	return reachNone, nil
}

func (aiActionExcessiveTools) Check(_ context.Context, c *lint.RuleContext, v ir.AIActionExcessiveToolsReader) error {
	for _, s := range v.AgentSteps() {
		if s.Substituted() {
			substitutedAgent(c, s.At(), s.Chain())
			continue
		}
		rp := agentPlace{c: c, at: s.At(), chain: s.Chain(), inner: s.InnerAt()}
		gr := gateReachOf(c, s.Action(), s.ActorOn(), s.OpenGates(), s.InconclusiveSettings())
		// another's run: one whose payload has what the attacker wrote, or
		// one in which a variable or a secret the attacker writes reaches
		// the agent (EveryRunRefs)
		everyRun := everyRunEvents(s.EveryRunRefs())
		others := append(slices.Clone(s.OthersOn()), everyRun...)
		stepReach, stepCond := reachOf(c, gr, within(s.AttackerOn(), s.ActorOn()), others)
		evidence := everyRunEvidence(c, s.Action(), s.EveryRunRefs(), everyRun)
		seen := anchors{}
		for _, g := range s.CapabilityGrants() {
			var args lint.FindingArgs
			switch g.Capability {
			case analysis.AgentCapabilityRunsAnyCode:
				args = AIActionExcessiveToolsRunCode{Action: s.Action(), Tool: g.Permission}
			case analysis.AgentCapabilityWritesChosenTarget:
				args = AIActionExcessiveToolsWriteToken{Action: s.Action(), Tool: g.Permission}
			case analysis.AgentCapabilitySendsChosenHost:
				args = AIActionExcessiveToolsSendNetwork{Action: s.Action(), Tool: g.Permission}
			default:
				continue // an edit: what it adds to is a grant of a command
			}
			var partner []lint.Related
			if g.Partner != "" {
				partner = []lint.Related{{Location: rp.At(g.PartnerAt), Note: g.Partner + " lets the agent change what " + g.Permission + " runs"}}
			}
			switch stepReach {
			case reached:
				rp.Report(lint.FindingDraft{Location: rp.At(g.At), Args: args, Condition: stepCond, Evidence: evidence, Related: partner, Anchor: seen.next(g.Permission, ir.FixPlan{})})
			case reachGate:
				rp.Inconclusive(lint.InconclusiveDraft{KindID: gateExpr, Location: rp.At(g.At), Related: slices.Concat(evidence, partner), Note: g.Permission + ": what an attacker writes reaches the step only in a run they trigger, and whom it lets start the agent then is not decided"})
			default:
				reachOrDispatch(rp, s.PromptDispatch(), g.At, g.Permission, g.Permission+": the step runs on no event whose payload has what an attacker wrote past its check of the actor; whether the agent reads, through its tools, text that an attacker wrote elsewhere (in an issue, a pull request or a file) is not known", slices.Concat(evidence, partner))
			}
		}
		valued := map[analysis.AgentInput]bool{}
		var unread []ir.SettingRef // a ${{ }} whose value is not analyzed, on a step an attacker's run reaches
		for _, p := range s.SettingRefs() {
			r := p.Ref
			if r.Verdict == analysis.Inconclusive && len(s.AttackerOn()) > 0 {
				unread = append(unread, p)
			}
			if r.Verdict != analysis.Controlled {
				continue
			}
			rch, cond := reachOf(c, gr, within(notWiki(p.On), s.ActorOn()), append(notWiki(p.OthersOn), p.EveryRunOn...))
			evidence, related := valueEvidence(c, r, r.Text)
			switch rch {
			case reached:
				rp.Report(lint.FindingDraft{Location: rp.At(r.At), Args: AIActionExcessiveToolsSettingValue{Action: s.Action(), Input: p.Input, ExprRef: r.Text}, Condition: cond, Evidence: evidence, Related: related, Anchor: seen.next(r.Text, ir.FixPlan{})})
				valued[p.Input] = true
			case reachGate:
				rp.Inconclusive(lint.InconclusiveDraft{KindID: gateExpr, Location: rp.At(r.At), Related: slices.Concat(evidence, related), Note: r.Text + " reaches the settings only in a run the attacker triggers, and whom the step lets start the agent then is not decided"})
			}
		}
		for _, p := range unread {
			if !valued[p.Input] {
				rp.Inconclusive(lint.InconclusiveDraft{KindID: settingExpr, Location: rp.At(p.Ref.At), Note: p.Ref.Text + " in " + p.Input.String() + ": whether an attacker controls it, and so the flags and keys it may add, is not analyzed (" + p.Ref.InconclusiveKind.String() + ")"})
			}
		}
		for _, u := range s.UndecidedPermissions() {
			if u.Kind == analysis.InconclusiveAgentSetting && valued[u.Input] {
				continue // the value an attacker writes there is reported
			}
			rp.Inconclusive(lint.InconclusiveDraft{KindID: undecidedKinds[u.Kind], Location: rp.At(u.At), Note: u.Permission + ": what it lets the agent do is not known (" + u.Kind.String() + ")"})
		}
		for _, m := range s.StartModes() {
			checkStartMode(c, rp, gr, s, m, others, seen)
		}
	}
	unansweredAgents(c, v.CompositeCalls(), false)
	return nil
}

// checkStartMode reports the mode claude starts in on the runs m holds,
// reached by the runs of another's on others (OthersOn and the events of
// EveryRunRefs): an
// auto or a plan mode, where a classifier decides what runs; with all of
// Bash denied too, as the agent may run code through a hook it writes, or
// through the git the tag mode runs after it. A mode a ${{ }} or a file
// may set, or one a ${{ }} of the subprocess env scrub leaves undecided,
// is the settings' inconclusive, once for the step.
func checkStartMode(c *lint.RuleContext, rp agentReporter, gr gateReach, s ir.AIActionExcessiveToolsOfAgentStep, m ir.StartMode, others []analysis.EventActivity, seen anchors) {
	rch, cond := reachOf(c, gr, within(within(s.AttackerOn(), s.ActorOn()), m.On), within(others, m.On))
	switch m.Mode {
	case analysis.ClaudeStartModeAuto, analysis.ClaudeStartModePlan:
		evidence := everyRunEvidence(c, s.Action(), s.EveryRunRefs(), m.On)
		switch rch {
		case reached:
			rp.Report(lint.FindingDraft{Location: rp.At(m.At), Args: AIActionExcessiveToolsAutoMode{Action: s.Action(), Source: m.Source}, Condition: cond, Evidence: evidence, Anchor: seen.next(m.Source, ir.FixPlan{})})
		case reachGate:
			rp.Inconclusive(lint.InconclusiveDraft{KindID: gateExpr, Location: rp.At(m.At), Related: evidence, Note: m.Source + ": what an attacker writes reaches the step only in a run they trigger, and whom it lets start the agent then is not decided"})
		default:
			reachOrDispatch(rp, s.PromptDispatch(), m.At, m.Source, m.Source+": the step runs on no event whose payload has what an attacker wrote past its check of the actor; whether the agent reads, through its tools, text that an attacker wrote elsewhere (in an issue, a pull request or a file) is not known", evidence)
		}
	case analysis.ClaudeStartModeUnread:
		if slices.ContainsFunc(s.UndecidedPermissions(), func(u ir.UndecidedPermission) bool { return u.Kind == analysis.InconclusiveAgentSetting }) {
			return // the input is the settings' inconclusive already
		}
		rp.Inconclusive(lint.InconclusiveDraft{KindID: settingExpr, Location: rp.At(m.At), Note: "a ${{ }} sets the mode the agent starts in, which settings the CLI reads, or whether the subprocess env scrub keeps the CLI in the default mode: whether it starts in auto mode is not known"})
	}
}

// observedScrub is when claude-code-action's subprocess env scrub was
// observed, on the runner scrubRunner.
var (
	observedScrub = lint.MustDate("2026-10-26")
	scrubRunner   = lint.MustVersion("2.338.0")
)

var (
	toolAllowed       = lint.MustPreconditionID("tool-allowed")
	settingParsed     = lint.MustPreconditionID("setting-parsed")
	classifierDecides = lint.MustPreconditionID("classifier-decides")

	claudePermissions     = lint.MustCitation("https://code.claude.com/docs/en/permissions")
	claudeTagTools        = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/src/modes/tag/index.ts")
	claudeGitPush         = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/scripts/git-push.sh")
	claudeArgsParse       = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/base-action/src/parse-sdk-options.ts")
	codexArgsParse        = lint.MustCitation("https://github.com/openai/codex-action/blob/bdf19a4a223ec2549a3e2274a0cf61556bc07675/src/main.ts")
	geminiPolicy          = lint.MustCitation("https://github.com/google-gemini/gemini-cli/blob/573846625af9e93b3b968e0e0b86bb093a4c9b16/packages/core/src/policy/utils.ts")
	copilotTools          = lint.MustCitation("https://github.com/github/docs/blob/be38ec5d78e24172587e61b3c6ff40ace1865c71/content/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools.md")
	githubMCPTools        = lint.MustCitation("https://github.com/github/github-mcp-server/blob/23fa0dd1a821d1346c1de2abafe7327d26981606/pkg/github/tools.go")
	nnUNetAdvisory        = lint.MustCitation("https://github.com/MIC-DKFZ/nnUNet/security/advisories/GHSA-63mx-j37w-gh59")
	claudePermissionModes = lint.MustCitation("https://code.claude.com/docs/en/permission-modes")
	claudeFlagFetch       = lint.MustCitation("https://code.claude.com/docs/en/env-vars")
	claudeScrubSet        = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/925afb53776cf1a2b738c6bdbed37b4d4000ef13/action.yml")
	claudeSettingsDoc     = lint.MustCitation("https://code.claude.com/docs/en/settings")
	claudeHooks           = lint.MustCitation("https://code.claude.com/docs/en/hooks")
	claudeBranchCleanup   = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/src/github/operations/branch-cleanup.ts")
)

// toolActors are those who write what the injection rules read, but the
// editor of a wiki and the author of a merged commit, and without the
// events of a commit status or a check run, as for
// ai-action-prompt-injection: what the agent's tools give is the job's.
var toolActors = withoutAppCommitEvents(slices.DeleteFunc(injectionActors([]lint.Gain{lint.GainRunCode, lint.GainReadSecrets, lint.GainWriteWithToken, lint.GainWriteCache}), func(a lint.Actor) bool {
	return a.Attacker == lint.AttackerWikiEditor || a.Attacker == lint.AttackerMergedCommitAuthor
}))

var (
	toolsPR = metric(lint.PrivilegesRequiredNone, "anyone writes an issue, a comment or a review on a public repository, which the step's run reads")
	toolsUI = metric(lint.UserInteractionNone, "the worst case of the rule: where the action checks no actor or an input opens its check, the run starts when the attacker writes; past a closed check, a maintainer's label or comment starts it")

	runCodeImpact = lint.CVSS{
		VC: metric(lint.ImpactHigh, "any command reads the run's token, the secrets in the step's env and the token actions/checkout leaves in .git/config; on GitHub-hosted Linux and macOS runners, whose user has passwordless sudo, it may read the job's secrets from the memory of the runner's worker, which keeps them from the start of the job", claudePermissions, hostedSudo),
		VI: metric(lint.ImpactHigh, "with the token it pushes and writes what the job's permissions allow"),
		VA: metric(lint.ImpactLow, "it can stop the job"),
		SC: metric(lint.ImpactHigh, "it sends out the secrets that open what is past the job"),
		SI: metric(lint.ImpactHigh, "what the job publishes after it may carry what it changed"),
		SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
	}
)

func toolsCVSS(at lint.Metric[lint.AttackRequirements], impact lint.CVSS) lint.CVSS {
	c := impact
	c.AV, c.AC, c.AT, c.PR, c.UI = agentAV, agentAC, at, toolsPR, toolsUI
	return c
}

var toolsAttackers = []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerAnyoneWhoForks}

var aiActionExcessiveToolsMeta = lint.Meta{
	ID:       AIActionExcessiveToolsID,
	Problem:  "a step of an action that runs an AI agent allows it tools that give an attacker whose text steers it more than the task needs: any code, writes with the token where the agent chooses, sending to a host it chooses; or a value an attacker writes is in an input the action splits into flags or reads as JSON, which adds tools or takes the sandbox off",
	Expected: "the agent is allowed only the tools the task needs, with their arguments and targets fixed, and the setting inputs hold no value an attacker writes",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessAgentHijack}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textAIActionExcessiveToolsAutoMode,
			Attackers:       toolsAttackers,
			Preconditions:   []lint.PreconditionID{textReaches, promptSteers, classifierDecides, actorNotAuthor, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            toolsCVSS(agentAT, runCodeImpact),
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report of an agent in auto mode in a workflow run that an attacker's text steered was found"),
		},
		{
			FindingText:     textAIActionExcessiveToolsRunCode,
			Attackers:       toolsAttackers,
			Preconditions:   []lint.PreconditionID{textReaches, promptSteers, toolAllowed, actorNotAuthor, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            toolsCVSS(agentAT, runCodeImpact),
			ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "in 2026 a researcher showed that cline/cline's triage agent, whose claude_args allowed Bash, ran the commands an issue title told it to; an unauthorized publish of cline followed, which only others tie to the workflow", clinejection),
		},
		{
			FindingText:   textAIActionExcessiveToolsWriteToken,
			Attackers:     toolsAttackers,
			Preconditions: []lint.PreconditionID{textReaches, promptSteers, toolAllowed, actorNotAuthor, callersEvents},
			FactKinds:     []facts.Kind{facts.KindRepoPublic},
			CVSS: toolsCVSS(agentAT, lint.CVSS{
				VC: metric(lint.ImpactLow, "it can post what the agent read where the attacker reads it"),
				VI: metric(lint.ImpactHigh, "with the token it comments, labels, pushes or merges wherever the token can write, not only on what it works on", githubMCPTools, claudeGitPush),
				VA: metric(lint.ImpactLow, "it can close issues and cancel runs"),
				SC: metric(lint.ImpactNone, "it reads no secret past what the agent holds"),
				SI: metric(lint.ImpactLow, "what it writes reaches those who read and use the repository"),
				SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
			}),
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "an advisory reports the form in nnUNet's triage, whose Bash(gh issue comment:*) and Bash(gh issue edit:*) let the agent comment and label as an issue tells it; its reporter did not try it on the live workflow, and no use is reported", nnUNetAdvisory),
		},
		{
			FindingText:   textAIActionExcessiveToolsSendNetwork,
			Attackers:     toolsAttackers,
			Preconditions: []lint.PreconditionID{textReaches, promptSteers, toolAllowed, actorNotAuthor, callersEvents},
			FactKinds:     []facts.Kind{facts.KindRepoPublic},
			CVSS: toolsCVSS(agentAT, lint.CVSS{
				VC: metric(lint.ImpactHigh, "the agent sends what it reads, the files of the workspace and of the runner, to the attacker's host", claudePermissions),
				VI: metric(lint.ImpactNone, "sending changes nothing"),
				VA: metric(lint.ImpactNone, "sending makes nothing unavailable"),
				SC: metric(lint.ImpactHigh, "the secrets among what it reads open what is past the job"),
				SI: metric(lint.ImpactNone, "sending changes nothing past the job"),
				SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
			}),
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an agent's fetch or network command used to send out what the agent read"),
		},
		{
			FindingText:     textAIActionExcessiveToolsSettingValue,
			Attackers:       toolsAttackers,
			Preconditions:   []lint.PreconditionID{attackerWrites, settingParsed, actorNotAuthor, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            toolsCVSS(metric(lint.AttackRequirementsNone, "the value adds its flags or keys when the step runs; the agent need not follow anything", claudeArgsParse), runCodeImpact),
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of a value an attacker wrote in claude_args, codex-args, settings or copilot-allow-tools"),
		},
	},
	Threat: lint.Threat{
		Actors: toolActors,
		Preconditions: []lint.Precondition{
			attackerWritesPre,
			textReachesPre,
			promptSteersPre,
			actorNotAuthorPre,
			{ID: toolAllowed, Text: "the agent runs what its permissions allow without asking, as no one answers a prompt in a workflow; a permission limits a command by its first words, and the agent chooses what comes after a *, after the words of gemini-cli's run_shell_command and of the Copilot CLI's shell", Cites: []lint.Citation{claudePermissions, geminiPolicy, copilotTools, claudeTagTools}},
			{ID: classifierDecides, Text: "in auto mode, and in plan mode for shell commands, a classifier decides each tool call no allow, ask or deny rule decides, and auto mode does not guarantee safety: an attacker's text in the prompt is a user message, which the classifier reads as the user's request, and one that tells it a blocked action is allowed as their approval; a command the agent makes from text it read through a tool, whose result the classifier does not see, is one the classifier may let run. Claude Code starts in auto mode only when a flag or a setting sets auto mode and the subprocess env scrub is off: claude-code-action turns the scrub on with allowed_non_write_users, and under the scrub the CLI starts in the default mode whatever permission mode the step gives the CLI; with no mode set, the CLI starts in the default mode from v2.1.302. Denying all of Bash does not keep the agent from running code: the classifier decides its writes to .claude and .git; Claude Code reloads the hooks of the project's .claude/settings.json in the running session and runs them in a -p session, outside the permissions of Bash (settings.md and hooks.md, fetched 2026-10-14, sha256 a8cc395af5e09386 and 0ccea55b53b6b616); and after the agent of the tag mode, claude-code-action runs git status and git commit in the same step when the agent left changes uncommitted, which run what the agent wrote in .git", Observed: []lint.Observation{{Date: observedScrub, Runner: scrubRunner, What: "claude-code-action 925afb53 (Claude Code 2.1.310) with allowed_non_write_users started the CLI in the default mode with --permission-mode auto, acceptEdits, bypassPermissions or --dangerously-skip-permissions, and denied a Write the tag mode's acceptEdits allows without the scrub; with CLAUDE_CODE_SUBPROCESS_ENV_SCRUB 0 in the env of the workflow, the job, the step or $GITHUB_ENV, the CLI started in auto mode"}}, Cites: []lint.Citation{claudePermissionModes, claudeFlagFetch, claudeScrubSet, claudeArgsParse, claudeSettingsDoc, claudeHooks, claudeBranchCleanup}},
			{ID: settingParsed, Text: "the action splits the input into words, or reads it as JSON, after GitHub writes the ${{ }} into it: a quote the value closes ends the word or the string, and what follows is a flag, a key or a tool", Cites: []lint.Citation{claudeArgsParse, codexArgsParse}},
			callersEventsPre,
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		npmAbbreviation(kindAIActionExcessiveToolsRunCode),
		npmOptionValueCommand(kindAIActionExcessiveToolsRunCode),
		appCommitEventLimit,
		ifComparedLimit,
		{ID: lint.MustUndetectedFormID("codex-rules"), Text: "codex-action's permissions of commands: execpolicy rules (prefix_rule) in the files of codex-home, whose allow runs a command outside the sandbox", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("project-settings"), Text: "a setting in a file of the repository the agent reads: the defaultMode of claude's .claude/settings.json (acceptEdits lets the agent edit what a command it is allowed runs), its hooks, codex's config in codex-home", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("other-mcp"), Text: "an MCP server the step adds from a file (--mcp-config with a path, the repository's .mcp.json), through claude-code-action's plugins, or in gemini-cli's settings (mcpServers): its tools are not read", Disposition: lint.Todo(lint.NeedRepoFile, lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("pr-workspace"), Text: "a command that runs the workspace's code, allowed without an edit, on a workspace with a pull request's code checked out: the attacker's code runs without the agent writing it", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("option-effects"), Text: "an option the table of commands does not declare that writes a file or runs a program, after a * (git log --output=.git/config writes a core.fsmonitor command into the git configuration, and git commit runs the command)", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("other-agent-action"), Text: "an action that runs an AI agent and is not in the linter's table of the actions that run an AI agent, such as a wrapper action in another repository", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("remote-composite"), Text: agentRemoteCompositeText, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("wiki-title"), Text: "a value an attacker writes only on gollum, the title of a wiki page, in a setting input", Disposition: lint.Todo(lint.NeedFact)},
		pullRequestLimit,
		{ID: lint.MustUndetectedFormID("scrub-opt-out"), Text: "a step of claude-code-action with allowed_non_write_users whose subprocess env scrub an earlier step turns off by writing CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=0 to $GITHUB_ENV, or whose scrub the env of the caller of an action metadata file or the env key of the step's settings (the settings input, --settings) turns off: the rule holds that the scrub keeps the CLI in the default mode, and does not report the auto mode, nor the command that the edits of acceptEdits change", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("old-cli"), Text: "a step that runs a Claude Code CLI older than the one of the action of now, by an older commit of the action or by path_to_claude_code_executable: a CLI before v2.1.302 starts in auto mode with no permission mode on a third-party provider or with telemetry off; a CLI older than the versions that keep the default mode under the subprocess env scrub may start under the scrub in the permission mode the step gives the CLI; the rule reads the start mode as the CLI of the action of now reads the start mode, and does not report the auto mode", Disposition: lint.Todo(lint.NeedFact)},
	}),
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: remoteUnknown, Text: agentRemoteUnknownText, Disposition: lint.Todo(lint.NeedFact)},
		{ID: archiveSubstituted, Text: agentArchiveSubstitutedText, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: reachUnknown, Text: "a permission, or a mode the agent starts in, of a step where no run that gets past the check of the actor of the step has a payload with text that an attacker wrote: whether the agent reads, through its tools, text that an attacker wrote elsewhere (in an issue, a pull request or a file) is decided when it runs" + reachDispatch, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: inputDispatch, Text: promptDispatchText("a permission, or a mode the agent starts in"), Disposition: lint.Limitation(lint.DeciderDispatcher)},
		{ID: settingExpr, Text: "an input of the permissions (claude_args, settings, copilot-allow-tools) or the whole with is a ${{ }} or names a file, a ${{ }} is where a flag, a permission or the permission mode is, a setting input has a ${{ }} whose value is not analyzed (the output of a step, an input), or allowed_non_write_users or the variable CLAUDE_CODE_SUBPROCESS_ENV_SCRUB of env, which decide the subprocess env scrub, is a ${{ }} on a step whose permission mode is auto, plan or acceptEdits", Disposition: lint.Todo(lint.NeedSameFile, lint.NeedRepoFile)},
		{ID: unknownCommand, Text: "a permission of a command the table of commands does not know, or with an option it does not declare", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: customMCP, Text: "a tool of an MCP server the step adds in claude_args' --mcp-config, or a server of the Copilot CLI: what its tools do is not known", Disposition: lint.Todo(lint.NeedFact)},
		{ID: gateExpr, Text: "a permission, a setting value or a mode the agent starts in that what an attacker writes reaches only in a run they trigger, where allowed_non_write_users, allow-users or the whole with is a ${{ }} whose value in that run is not decided", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	FalsePositiveForms: withCallee([]lint.FalsePositiveForm{
		forkFlagReview(kindAIActionExcessiveToolsWriteToken),
		npmUnknownCommand(kindAIActionExcessiveToolsRunCode),
		npmOptionValueOperand(kindAIActionExcessiveToolsRunCode),
		ignoredPnpmfile(kindAIActionExcessiveToolsRunCode),
		absolutePathOutOfTree(kindAIActionExcessiveToolsRunCode),
		pytestPathOutOfTree(kindAIActionExcessiveToolsRunCode),
		toolDirectoryOutOfTree(kindAIActionExcessiveToolsRunCode),
		{ID: lint.MustFalsePositiveFormID("read-only-token"), Text: "a permission to write with the token, in a job whose token cannot write there: the rule does not read the token's permissions, as an App's token or a PAT may be given", FindingKinds: []lint.FindingKindID{kindAIActionExcessiveToolsWriteToken}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("protected-branch"), Text: "claude-code-action's tag mode push to a branch the agent chooses, in a repository whose rules keep its branches from the run's token", FindingKinds: []lint.FindingKindID{kindAIActionExcessiveToolsWriteToken}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("old-version"), Text: "a version of the action or its CLI that reads the input otherwise: ai-inference before v2 has no copilot-allow-tools; a gemini-cli pinned by gemini_cli_version to one that reads a coreTools at the top of settings", FindingKinds: []lint.FindingKindID{kindAIActionExcessiveToolsRunCode, kindAIActionExcessiveToolsWriteToken, kindAIActionExcessiveToolsSendNetwork}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("auto-unavailable"), Text: "an auto or a plan mode the run does not start in: a model the provider does not support in auto mode, managed settings that set defaultMode or disableAutoMode, an organization whose policy withholds the auto default, auto mode turned off on the server, or a settings file the step names that sets disableAutoMode; the session starts in Manual, and plan mode without its classifier", FindingKinds: []lint.FindingKindID{kindAIActionExcessiveToolsAutoMode}, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustFalsePositiveFormID("project-mode"), Text: "claude-code-action whose workspace has a .claude/settings.json or .claude/settings.local.json that sets defaultMode or disableAutoMode, which wins over the settings input; auto there makes the CLI use its built-in default", FindingKinds: []lint.FindingKindID{kindAIActionExcessiveToolsAutoMode}, Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustFalsePositiveFormID("repo-settings"), Text: "run-gemini-cli without settings, on a workspace whose .gemini/settings.json, which gemini-cli reads then, limits the tools", FindingKinds: []lint.FindingKindID{kindAIActionExcessiveToolsRunCode, kindAIActionExcessiveToolsSendNetwork}, Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustFalsePositiveFormID("scrub-opt-in"), Text: "a step of claude-code-action or its base-action whose subprocess env scrub an earlier step turns on by writing CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 to $GITHUB_ENV, or a container's env or the env key of the step's settings turns on: the CLI starts in the default mode whatever permission mode the step gives the CLI, and the rule, which does not read the scrub from $GITHUB_ENV, from a container's env or from the settings, reports the auto mode, and a command that the edits of acceptEdits change", FindingKinds: []lint.FindingKindID{kindAIActionExcessiveToolsAutoMode, kindAIActionExcessiveToolsRunCode}, Disposition: lint.Todo(lint.NeedSameFile)},
		writerString(kindAIActionExcessiveToolsSettingValue), ifUnnarrowedFalsePositive(kindAIActionExcessiveToolsSettingValue),
	}, kindAIActionExcessiveToolsAutoMode, kindAIActionExcessiveToolsRunCode, kindAIActionExcessiveToolsWriteToken, kindAIActionExcessiveToolsSendNetwork, kindAIActionExcessiveToolsSettingValue),
}
