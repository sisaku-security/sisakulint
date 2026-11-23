package rules

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// EnvpathInjection is the rule envpath-injection: a value an attacker
// controls, written to $GITHUB_PATH, whose lines the runner puts before
// the PATH of the steps after it, each a directory; an executable of the
// attacker's there runs for a command those steps call by name, and as the
// shell of their run steps. No line
// break is needed, and no fix is given: no rewriting of the value keeps
// the directory from the attacker.
var EnvpathInjection lint.Rule = withExamples(lint.WithView[ir.FileCommandReader](fileCommand{
	file: analysis.EnvironmentFilePath, meta: &envpathInjectionMeta,
	controlled: func(ref string, evs []workflow.EventName) lint.FindingArgs {
		return EnvpathInjectionControlled{ExprRef: ref, ControlledOn: evs}
	},
	wiki: func(ref string) lint.FindingArgs { return EnvpathInjectionWiki{ExprRef: ref} },
}, ir.FileCommandView))

// EnvpathInjectionID is the ID of envpath-injection.
var EnvpathInjectionID = lint.MustRuleID("envpath-injection")

var (
	observedPath = lint.MustDate("2026-09-30")
	// what runs after the last step of a job: the post steps and the hooks
	observedAfter    = lint.MustDate("2026-10-22")
	runnerAfter      = lint.MustVersion("2.338.0")
	runnerHooks      = lint.MustCitation("https://github.com/actions/runner/blob/4c989f2f108bb6798e07ea5935bc8bc4aab7de2f/src/Runner.Worker/JobHookProvider.cs")
	runnerPrepend    = lint.MustCitation("https://github.com/actions/runner/blob/4c989f2f108bb6798e07ea5935bc8bc4aab7de2f/src/Runner.Worker/Handlers/Handler.cs")
	addingSystemPath = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#adding-a-system-path")
	addPathGHSA      = lint.MustCitation("https://github.com/advisories/GHSA-mfwh-5m23-j46w")

	runnerReadsPath    = lint.MustPreconditionID("runner-reads-path")
	pathLookup         = lint.MustPreconditionID("path-lookup")
	attackerExecutable = lint.MustPreconditionID("attacker-executable")

	runnerReadsPathPre = lint.Precondition{
		ID:   runnerReadsPath,
		Text: "the runner reads $GITHUB_PATH after the step by lines, and puts each line that is not empty, as it is, before the PATH of the steps after it; a relative one is looked up from where the command runs",
		Observed: []lint.Observation{
			{Date: observedPath, Runner: runner, What: "on ubuntu and macos, a line rel/bin written to $GITHUB_PATH made the next step run rel/bin/rel-cmd of the workspace, and not after it changed directory; \\r alone split a line in two, and an empty line was dropped"},
		},
		Cites: []lint.Citation{addingSystemPath},
	}
	pathLookupPre = lint.Precondition{
		ID:   pathLookup,
		Text: "the steps after it look up in that PATH the commands their scripts call by name, and the runner looks up in that PATH the shell a run step names (bash, sh); not the node of a JavaScript action, which is the runner's own. The post steps of the actions that the steps before the step that writes to $GITHUB_PATH use run after that step with that PATH too, and so do the hooks that a self-hosted runner runs after the job (a job completed hook, the hooks of a container); the runner looks up the shell of such a hook in that PATH",
		Observed: []lint.Observation{
			{Date: observedPath, Runner: runner, What: "on ubuntu and macos, an executable git in a directory written to $GITHUB_PATH ran for git in the next step, and that directory's bash and sh were the shell of the steps with no shell, with shell: bash and with shell: sh; actions/github-script ran on the runner's node"},
			{Date: observedAfter, Runner: runnerAfter, What: "on ubuntu-latest, the post step of actions/checkout, which a step before the last step used, ran the git and the sed of the directory that the last step wrote to $GITHUB_PATH; in a job whose last step wrote to $GITHUB_PATH and had no step with uses before the last step, nothing ran with that directory"},
		},
		Cites: []lint.Citation{runnerPrepend, runnerHooks},
	}
	attackerExecutablePre = lint.Precondition{
		ID:    attackerExecutable,
		Text:  "an executable of the attacker's is in the directory: the tree of a pull request checked out, an artifact, a cache; the rule does not look for it, and reports the write alone",
		Cites: []lint.Citation{prTarget},
	}
)

// pathBase is the CVSS of envpath-injection.controlled: code-injection's,
// but the attacker needs an executable of theirs in the directory, which
// the rule does not look for.
var pathBase = func() lint.CVSS {
	b := controlledBase
	b.AC = metric(lint.AttackComplexityLow, "a path in the text is all it takes; no line break is needed")
	b.AT = metric(lint.AttackRequirementsPresent, "an executable of the attacker's must be in the directory: the tree of a pull request checked out, an artifact or a cache, which the rule does not look for")
	return b
}()

// pathWikiBase is the CVSS of envpath-injection.wiki: the wiki's way in,
// with the executable still needed.
var pathWikiBase = func() lint.CVSS {
	b := wikiOf(pathBase, "the characters of a path")
	b.AT = metric(lint.AttackRequirementsPresent, "an executable of the attacker's must be in the directory, such as an artifact or a cache, which the rule does not look for")
	return b
}()

var envpathInjectionMeta = lint.Meta{
	ID:       EnvpathInjectionID,
	Problem:  "a value an attacker controls is written to $GITHUB_PATH, whose lines are directories put before the PATH of the steps after it",
	Expected: "no value an attacker controls is written to $GITHUB_PATH",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessEnvironmentFileInjection}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textEnvpathInjectionControlled,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerMergedCommitAuthor, lint.AttackerAnyoneWhoForks},
			Preconditions:   []lint.PreconditionID{runnerReadsPath, pathLookup, attackerExecutable, attackerWrites, attackerEvent, callersEvents, appStatusCheck},
			CVSS:            pathBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attack through a value written to $GITHUB_PATH; the nearest is GHSA-mfwh-5m23-j46w, on ::add-path:: in the log, which the runner has since stopped unless ACTIONS_ALLOW_UNSECURE_COMMANDS is set (add-path-command)", addPathGHSA),
		},
		{
			FindingText:     textEnvpathInjectionWiki,
			Attackers:       []lint.Attacker{lint.AttackerWikiEditor},
			Preconditions:   []lint.PreconditionID{runnerReadsPath, pathLookup, attackerExecutable, attackerEvent, callersEvents, wikiOpen},
			FactKinds:       []facts.Kind{facts.KindRepoWikiOpen},
			CVSS:            pathWikiBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attack through the title of a wiki page"),
		},
	},
	Threat: lint.Threat{
		Actors:        injectionActors([]lint.Gain{lint.GainSetPath, lint.GainRunCode, lint.GainReadSecrets, lint.GainWriteWithToken, lint.GainWriteCache}),
		Preconditions: []lint.Precondition{runnerReadsPathPre, pathLookupPre, attackerExecutablePre, attackerWritesPre, attackerEventPre, callersEventsPre, wikiOpenPre, appStatusCheckPre},
	},
	Citations:         []lint.Citation{cvss},
	Targets:           []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms:   withRemoteCallee(append(append(slices.Clone(envpathLimits), ifLimits...), splitEnvNameLimit, ifComparedLimit, forkReviewLimit, wikiSummaryLimit)),
	InconclusiveKinds: withRemoteCalleeUnknown(withCallBodyUnknown(fileGaps)),
	FalsePositiveForms: withCallee(append(injectionFalsePositives(kindEnvpathInjectionControlled, kindEnvpathInjectionWiki),
		branchNotRun(kindEnvpathInjectionControlled),
		reassignedEnvFalsePositive("$GITHUB_PATH", "X=\"$HOME/tools\"; echo \"$X\" >> \"$GITHUB_PATH\"", kindEnvpathInjectionControlled),
		backgroundWriteFalsePositive("$GITHUB_PATH", "(sleep 5; echo \"$X\" >> \"$GITHUB_PATH\") &", kindEnvpathInjectionControlled, kindEnvpathInjectionWiki),
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("no-attacker-executable"), Text: "a job where no file of the attacker's is on the runner to be found by the PATH: the rule holds this as the precondition of AT:P", FindingKinds: []lint.FindingKindID{kindEnvpathInjectionControlled, kindEnvpathInjectionWiki}, Disposition: lint.Limitation(lint.DeciderRunTime)},
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("nothing-after"), Text: "a job whose runs-on is ubuntu-latest alone (the string ubuntu-latest, or a list of that one label), with no container and no services, where no self-hosted runner that the repository can use has the label ubuntu-latest, and where the step that writes to $GITHUB_PATH is the last step of the job and no step with uses is before that step: nothing runs with that PATH after that step", FindingKinds: []lint.FindingKindID{kindEnvpathInjectionControlled, kindEnvpathInjectionWiki}, Disposition: lint.Todo(lint.NeedFact)},
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("fixed-parent"), Text: "a structured value under a fixed parent, such as $HOME/tools/ and a branch name, which git keeps from holding ..", FindingKinds: []lint.FindingKindID{kindEnvpathInjectionControlled}, Disposition: lint.Todo(lint.NeedSameFile)}), kindEnvpathInjectionControlled, kindEnvpathInjectionWiki),
}

// envpathLimits are the forms envpath-injection does not report.
var envpathLimits = []lint.UndetectedForm{
	outsideCallerLimit,
	pullRequestLimit, dispatchLimit, repositoryDispatchLimit, appWrittenLimit, deploymentStatusLimit, dispatchRelayLimit, dispatchInputCallLimit, notAttackerLimit, mergedPusherLimit, comparedLimit, newActivityTypeLimit,
	{ID: lint.MustUndetectedFormID("fixed"), Text: "a context whose form GitHub fixes: a SHA, a number, a date, the name of an account, what GitHub or the repository sets. At the head of a line one the attacker chooses or knows before (the number or the head SHA of a pull request, a login) is a relative path, to a directory they may put there in an artifact or a cache, or for a number or a login in the tree of the pull request; the rule cannot tell those from values no attacker chooses", Disposition: lint.Todo(lint.NeedSameFile)},
	scriptVarLimit,
	lastpipeLimit,
	nameNotLiteralLimit,
	recursiveUnsetLocalLimit,
	unsetCallerLocalLimit,
	fileContentLimit("$GITHUB_PATH"),
	nestedShellLimit,
	wrappedTeeLimit,
	otherShellLimit,
	caseArmLimit,
	{ID: lint.MustUndetectedFormID("github-script"), Text: "core.addPath of actions/github-script, which writes to $GITHUB_PATH what it is given: the rule does not read JavaScript", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("action-input"), Text: "an input of an action that puts it in PATH (a setup action and the like): what the action does with it is in its action.yml, which the rule does not read", Disposition: lint.Todo(lint.NeedFact)},
	{ID: lint.MustUndetectedFormID("add-path-command"), Text: "a value printed to the log of a job whose env sets ACTIONS_ALLOW_UNSECURE_COMMANDS to true, where the runner still reads ::add-path:: and puts the path in PATH", Disposition: lint.OtherRule(UnsecureCommandsID)},
	{ID: lint.MustUndetectedFormID("github-env"), Text: "a value written to $GITHUB_ENV", Disposition: lint.OtherRule(EnvvarInjectionID)},
	{ID: lint.MustUndetectedFormID("github-output"), Text: "a value written to $GITHUB_OUTPUT", Disposition: lint.OtherRule(OutputClobberingID)},
}
