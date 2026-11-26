package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// UnsecureCommands is the rule unsecure-commands: a value an attacker
// controls, printed to the log of a step whose env context has
// ACTIONS_ALLOW_UNSECURE_COMMANDS true, where the runner reads a line
// with ##[set-env name=NAME;] anywhere in it, or ::set-env at its head, as
// a command that sets the env of the steps after it; a set-env of BASH_ENV runs
// code in their bash, and add-path puts a directory before their PATH. No fix is
// given: removing the flag breaks the steps that use the commands.
var UnsecureCommands lint.Rule = withExamples(lint.WithView[ir.UnsecureCommandsReader](unsecureCommands{}, ir.UnsecureCommandsView))

// UnsecureCommandsID is the ID of unsecure-commands.
var UnsecureCommandsID = lint.MustRuleID("unsecure-commands")

type unsecureCommands struct{}

func (unsecureCommands) Meta() lint.Meta { return unsecureCommandsMeta }

var (
	flagExpressionKind  = lint.MustInconclusiveKindID("flag-expression")
	structuredValueKind = lint.MustInconclusiveKindID("structured-value")
)

func (unsecureCommands) Check(_ context.Context, c *lint.RuleContext, v ir.UnsecureCommandsReader) error {
	for _, s := range v.Sinks() {
		// set-env and add-path reach the steps after the step alone
		if s.UnsecureFlag() == analysis.UnsecureOff || !s.HasStepAfter() {
			continue
		}
		reportCallsNotRead(c, s.CallsNotRead())
		refs, seen := s.Refs(), anchors{}
		for _, w := range s.LogWrites() {
			ref := w.Var
			if w.RefIndex >= 0 {
				ref = refs[w.RefIndex]
			}
			at := c.At(w.At)
			anchor := seen.next(w.Path, ir.FixPlan{}) // every write of a text counts, whatever it gives
			switch {
			case s.UnsecureFlag() == analysis.UnsecureExpression && (ref.Verdict == analysis.Controlled || ref.Verdict == analysis.Inconclusive):
				c.Inconclusive(lint.InconclusiveDraft{KindID: flagExpressionKind, Location: at,
					Note: fmt.Sprintf("%s is printed to the log of a step whose ACTIONS_ALLOW_UNSECURE_COMMANDS is an expression; whether the runner reads set-env and add-path in the log is not known", w.Text)})
			case len(w.Commands) > 0 || len(w.PathCommands) > 0:
				// a name of a wiki page holds add-path, whatever the value
				// holds of the commands that take a property
				cmds := slices.Concat(w.Commands, w.PathCommands)
				on := eventsOf(cmds)
				slices.SortFunc(on, func(a, b workflow.EventName) int { return strings.Compare(a.String(), b.String()) })
				evidence, related := valueEvidence(c, ref, w.Text)
				f := lint.FindingDraft{Location: at, Anchor: anchor, Evidence: evidence, Related: related,
					Args: UnsecureCommandsControlled{ExprRef: w.Text, ControlledOn: on, Flag: s.UnsecureFlagPlace()}}
				if onlyGollum(cmds) {
					f.Args = UnsecureCommandsWiki{ExprRef: w.Text, Flag: s.UnsecureFlagPlace()}
					f.Condition = wikiOpenCond(c)
				}
				c.Report(f)
				if onlyGollum(cmds) && len(withoutGollum(w.CommandsUndecided)) > 0 {
					// the finding holds only where the wiki is open; another
					// event may still carry a command
					c.Inconclusive(lint.InconclusiveDraft{KindID: structuredValueKind, Location: at, Related: slices.Concat(evidence, related),
						Note: fmt.Sprintf("%s is printed to the log of a step whose ACTIONS_ALLOW_UNSECURE_COMMANDS is true; whether an attacker can write a workflow command in the value on an event other than gollum was not checked", w.Text)})
				}
			case len(w.CommandsUndecided) > 0:
				evidence, related := valueEvidence(c, ref, w.Text)
				c.Inconclusive(lint.InconclusiveDraft{KindID: structuredValueKind, Location: at, Related: slices.Concat(evidence, related),
					Note: fmt.Sprintf("%s is printed to the log of a step whose ACTIONS_ALLOW_UNSECURE_COMMANDS is true; whether an attacker can write a workflow command in the value was not checked", w.Text)})
			case ref.Verdict == analysis.Inconclusive:
				c.Inconclusive(lint.InconclusiveDraft{KindID: inconclusiveKind(ref.InconclusiveKind), Location: at,
					Note: fmt.Sprintf("%s is printed to the log of a step whose ACTIONS_ALLOW_UNSECURE_COMMANDS is true; whether an attacker controls the value is not analyzed (%s)", w.Text, ref.InconclusiveKind)})
			}
		}
	}
	return nil
}

var (
	runnerCommandParse = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Common/ActionCommand.cs")
	runnerOutput       = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/Handlers/OutputManager.cs")
	setEnvChangelog    = lint.MustCitation("https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/")

	unsecureFlag = lint.MustPreconditionID("unsecure-flag")

	// unsecureExecutablePre is attackerExecutablePre for a directory add-path
	// puts first in PATH.
	unsecureExecutablePre = lint.Precondition{
		ID:    attackerExecutable,
		Text:  "for add-path, an executable of the attacker's is in the directory the attacker puts first in PATH: the tree of a pull request checked out, an artifact, a cache; the rule does not look for the executable, and reports the value printed to the log alone; a set-env of BASH_ENV needs no executable",
		Cites: []lint.Citation{prTarget},
	}

	unsecureFlagPre = lint.Precondition{
		ID:   unsecureFlag,
		Text: "where the env context of a step has ACTIONS_ALLOW_UNSECURE_COMMANDS that bool.TryParse reads as true (true in upper, lower or mixed letters, with blanks around it or not), from the env of the workflow, the job or the step or from $GITHUB_ENV of a step before, the runner reads each line of the standard output and error of the step as a command: ::set-env and ::add-path:: at the head of the line after blanks, ##[set-env name=NAME;] and ##[add-path] anywhere in the line; set-env refuses NODE_OPTIONS alone, and the value sets the env of the steps after; ::stop-commands::TOKEN stops the reading up to ::TOKEN::, where TOKEN is a value the step chooses",
		Observed: []lint.Observation{
			{Date: observedSecretInLog, Runner: runner, What: "with the flag true in the env of the job, lines that printed ::set-env after blanks, ##[set-env name=NAME;] and ##[add-path] after other text, ::set-env on the standard error, ::SET-ENV, and ::set-env after a line break of a value set the env and the PATH of the next step; ::set-env name=BASH_ENV::$( ... ) made the next step run the command; NODE_OPTIONS was refused, and a line between ::stop-commands::TOKEN and ::TOKEN:: was not read. The flag TRUE and \" true \" turned the reading on, 1 did not; the flag in one step's env did so for that step alone, and the flag written to $GITHUB_ENV did so for the steps after. The email of a commit's author and committer, holding ##[set-env name=NAME;], set the env of the next step from github.event.head_commit"},
		},
		Cites: []lint.Citation{runnerCommandParse, runnerCommands, runnerOutput, setEnvChangelog, addPathGHSA},
	}
)

// unsecureWikiBase is the CVSS of unsecure-commands.wiki: the wiki's way
// in, and add-path alone, so the executable is still needed, as for
// envpath-injection.wiki.
var unsecureWikiBase = func() lint.CVSS {
	b := wikiOf(unsecureBase, "::add path:: and a directory")
	b.AT = metric(lint.AttackRequirementsPresent, "an executable of the attacker's must be in the directory, such as an artifact or a cache, which the rule does not look for; the name of a wiki page holds no set-env, which needs none")
	return b
}()

// unsecureActors are the actors of unsecure-commands: the editor of a wiki
// writes add-path but no set-env in the name of a wiki page, which holds no
// blank before a property.
var unsecureActors = func() []lint.Actor {
	actors := injectionActors([]lint.Gain{lint.GainSetEnv, lint.GainSetPath, lint.GainRunCode, lint.GainReadSecrets, lint.GainWriteWithToken, lint.GainWriteCache})
	for i, a := range actors {
		if a.Attacker == lint.AttackerWikiEditor {
			actors[i].Gains = slices.DeleteFunc(slices.Clone(a.Gains), func(g lint.Gain) bool { return g == lint.GainSetEnv })
		}
	}
	return actors
}()

// unsecureBase is the CVSS of unsecure-commands.controlled: envvar-injection's, but no line
// break is needed.
var unsecureBase = func() lint.CVSS {
	b := controlledBase
	b.AC = metric(lint.AttackComplexityLow, "##[set-env name=BASH_ENV;]$( ... ) anywhere in a printed line is enough; no line break is needed")
	return b
}()

var unsecureKinds = []lint.FindingKindID{kindUnsecureCommandsControlled, kindUnsecureCommandsWiki}

var unsecureCommandsMeta = lint.Meta{
	ID:       UnsecureCommandsID,
	Problem:  "a value an attacker controls is printed to the log of a step where ACTIONS_ALLOW_UNSECURE_COMMANDS is true, and the runner reads a set-env or add-path command in the log",
	Expected: "no step has ACTIONS_ALLOW_UNSECURE_COMMANDS true; environment variables are written to $GITHUB_ENV and paths to $GITHUB_PATH",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessWorkflowCommandInjection}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textUnsecureCommandsControlled,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerMergedCommitAuthor, lint.AttackerAnyoneWhoForks},
			Preconditions:   []lint.PreconditionID{unsecureFlag, bashEnv, pathLookup, attackerExecutable, attackerEvent, callersEvents, appStatusCheck},
			CVSS:            unsecureBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attack through a value printed with the flag on; GHSA-mfwh-5m23-j46w (CVE-2020-15228) is the advisory of the runner on the commands themselves: \"Workflows that log untrusted data to stdout may invoke these commands\"", addPathGHSA),
		},
		{
			FindingText:     textUnsecureCommandsWiki,
			Attackers:       []lint.Attacker{lint.AttackerWikiEditor},
			Preconditions:   []lint.PreconditionID{unsecureFlag, pathLookup, attackerExecutable, attackerEvent, callersEvents, wikiOpen},
			FactKinds:       []facts.Kind{facts.KindRepoWikiOpen},
			CVSS:            unsecureWikiBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attack through the name of a wiki page"),
		},
	},
	Threat: lint.Threat{
		Actors:        unsecureActors,
		Preconditions: []lint.Precondition{unsecureFlagPre, bashEnvPre, pathLookupPre, unsecureExecutablePre, attackerEventPre, callersEventsPre, wikiOpenPre, appStatusCheckPre},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee(append([]lint.UndetectedForm{
		wikiSummaryLimit,
		forkReviewLimit,
		ifComparedLimit,
		splitEnvNameLimit,
		outsideCallerLimit, pullRequestLimit, dispatchLimit, repositoryDispatchLimit, appWrittenLimit, deploymentStatusLimit, dispatchRelayLimit, dispatchInputCallLimit, notAttackerLimit, mergedPusherLimit, comparedLimit, newActivityTypeLimit, otherShellLimit,
		{ID: lint.MustUndetectedFormID("script-var"), Text: "a shell variable the script sets (from a file, an API, the value of env through an assignment) or a positional parameter of a function, printed to the log", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("decoded-escape"), Text: "the title of a wiki page printed by a command that decodes escapes in the value (printf with the value in its format, echo -e, printf %b): the attacker writes \\055 in the title, the command prints a - in its place, and the printed line can hold ##[set-env name=NAME;]value; the rule reads the title as holding no -", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("runner-environment"), Text: "ACTIONS_ALLOW_UNSECURE_COMMANDS in the environment of the process of a self-hosted runner, which the runner reads first: the workflow does not hold the variable", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("other-output"), Text: "a value an attacker controls that a command other than echo, printf, cat and tee prints: cat of a file of a pull request, git log, jq of $GITHUB_EVENT_PATH, the output of an action; also what a descriptor that exec points at the log (exec 3>&1) prints, and what goes to the log through a process substitution (exec > >(tee -a build.log))", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("background-step"), Text: "a value printed by a background step, where the step after the background step starts before the background step is done: whether the env of a step that starts after the printed line gets the value was not checked", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("caller-flag"), Text: "a value printed by a step of a composite action whose caller has ACTIONS_ALLOW_UNSECURE_COMMANDS true in the env of the job or the step: the rule reads the flag of the steps of the action alone; whether the steps of the action get the flag of the caller was not checked", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("post-step"), Text: "a value printed in the last step of a job, when the post step of an action the job uses runs after the last step: whether set-env and add-path reach a post step was not checked", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("caller-steps"), Text: "a value printed in the last step of a composite action: set-env and add-path reach the steps of the caller after the action, which the rule does not read", Disposition: lint.Todo(lint.NeedRepoFile)},
	}, ifLimits...)),
	InconclusiveKinds: withRemoteCalleeUnknown(withCallBodyUnknown(append([]lint.InconclusiveKind{
		{ID: flagExpressionKind, Text: "ACTIONS_ALLOW_UNSECURE_COMMANDS as a ${{ }}, or an env of the step that is all an expression, or written to $GITHUB_ENV with a value not in the run", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: structuredValueKind, Text: "a value where whether an attacker can write ##[ and ] in the value was not checked, such as a structured value (a URL, or github.event.forkee.description, which is the description of a fork; the account that makes the fork writes the description, and the description holds no line break): the email of a git commit is checked and reported, and the names of refs and repositories hold no [. The title of a wiki page is not of this kind: the title holds no -, so the title as written holds no command whose name has a -, and the rule reports nothing on the title (a command that decodes escapes can make a - of the title: decoded-escape)", Disposition: lint.Todo(lint.NeedFact)},
	}, valueGaps...))),
	FalsePositiveForms: withCallee(append([]lint.FalsePositiveForm{lastpipeFalsePositive(kindUnsecureCommandsControlled), nameNotLiteralFalsePositive(kindUnsecureCommandsControlled), forkFlagReview(unsecureKinds...), writerString(unsecureKinds...), ifUnnarrowedFalsePositive(unsecureKinds...)},
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("stopped-commands"), Text: "a value printed between ::stop-commands::TOKEN and ::TOKEN::, where TOKEN is a value the step chooses at random for each run, and the runner reads no command", FindingKinds: unsecureKinds, Disposition: lint.Todo(lint.NeedSameFile)}), kindUnsecureCommandsControlled, kindUnsecureCommandsWiki),
}
