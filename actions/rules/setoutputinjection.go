package rules

import (
	"context"
	"fmt"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// SetOutputInjection is the rule set-output-injection: a value an attacker
// controls, printed to the log of a step that has an id, where the runner
// reads a line with ##[set-output name=NAME;] anywhere in it, or
// ::set-output at its head, as a command that sets the output NAME of the
// step, with no ACTIONS_ALLOW_UNSECURE_COMMANDS. No fix is
// given: what removes the harm, not printing the value or printing it
// between stop-commands, is up to what the script means.
var SetOutputInjection lint.Rule = withExamples(lint.WithView[ir.SetOutputInjectionReader](setOutputInjection{}, ir.SetOutputInjectionView))

// SetOutputInjectionID is the ID of set-output-injection.
var SetOutputInjectionID = lint.MustRuleID("set-output-injection")

type setOutputInjection struct{}

func (setOutputInjection) Meta() lint.Meta { return setOutputInjectionMeta }

func (setOutputInjection) Check(_ context.Context, c *lint.RuleContext, v ir.SetOutputInjectionReader) error {
	for _, s := range v.Sinks() {
		// the runner sets the outputs of a step with an id alone
		if !s.HasStepID() {
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
			// the editor of a wiki is not an attacker of the rule: a value of
			// gollum gives an inconclusive place
			cmds := withoutGollum(w.Commands)
			evidence, related := valueEvidence(c, ref, w.Text)
			switch {
			case len(cmds) > 0:
				c.Report(lint.FindingDraft{Location: at, Anchor: seen.next(w.Path, ir.FixPlan{}), Evidence: evidence, Related: related,
					Args: SetOutputInjectionControlled{ExprRef: w.Text, ControlledOn: eventsOf(cmds)}})
			case len(w.Commands) > 0 || len(w.CommandsUndecided) > 0:
				c.Inconclusive(lint.InconclusiveDraft{KindID: structuredValueKind, Location: at, Related: slices.Concat(evidence, related),
					Note: fmt.Sprintf("%s is printed to the log of a step that has an id; whether an attacker can write a set-output command in the value was not checked", w.Text)})
			case ref.Verdict == analysis.Inconclusive:
				c.Inconclusive(lint.InconclusiveDraft{KindID: inconclusiveKind(ref.InconclusiveKind), Location: at,
					Note: fmt.Sprintf("%s is printed to the log of a step that has an id; whether an attacker controls the value is not analyzed (%s)", w.Text, ref.InconclusiveKind)})
			}
		}
	}
	return nil
}

var (
	observedLogSetOutput = lint.MustDate("2026-10-22")
	runnerLogSetOutput   = lint.MustVersion("2.338.0")
	runnerStepOutputs    = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/ExecutionContext.cs")
	setOutputChangelog   = lint.MustCitation("https://github.blog/changelog/2022-10-11-github-actions-deprecating-save-state-and-set-output-commands/")

	logSetOutput = lint.MustPreconditionID("log-set-output")

	logSetOutputPre = lint.Precondition{
		ID:   logSetOutput,
		Text: "with or without ACTIONS_ALLOW_UNSECURE_COMMANDS, the runner reads each line of the standard output and error of a step as a command: ##[set-output name=NAME;]value anywhere in the line, and ::set-output name=NAME::value at the head of the line after blanks; the command sets the output NAME of the step when the step has an id, and the outputs of a background step reach the steps after the wait for the background step; when the step also writes NAME to $GITHUB_OUTPUT, which the runner reads when the step is done, the value in $GITHUB_OUTPUT replaces the value from the log; ::stop-commands::TOKEN stops the reading up to ::TOKEN::",
		Observed: []lint.Observation{
			{Date: observedLogSetOutput, Runner: runnerLogSetOutput, What: "a commit message, an issue title, an issue body and a comment holding ##[set-output name=NAME;]value, echoed from env in a step with an id, set the output NAME of the step; a ::set-output line after a line break, the standard error and the trace of set -x did the same; a later step that wrote the output into its run script ran the $( ) in the output, the outputs of the job and of a composite action carried the value, and a background step's outputs were there after the wait; a step with no id was not in the steps context, a value in env not printed and a value printed between ::stop-commands:: and its token set nothing, and the value that the step wrote to $GITHUB_OUTPUT for the same name replaced the value from the log"},
		},
		Cites: []lint.Citation{runnerCommandParse, runnerCommands, runnerStepOutputs, setOutputChangelog},
	}
)

// setOutputBase is the CVSS of set-output-injection.controlled:
// output-clobbering's, but no line break is needed.
var setOutputBase = func() lint.CVSS {
	b := fileOutputBase
	b.AC = metric(lint.AttackComplexityLow, "##[set-output name=NAME;]value anywhere in a printed line is all it takes; no line break is needed")
	b.VA = metric(lint.ImpactLow, "a set-output command with no name fails the step (read in the source of the runner, not seen in a run)")
	return b
}()

var setOutputKinds = []lint.FindingKindID{kindSetOutputInjectionControlled}

var setOutputInjectionMeta = lint.Meta{
	ID:       SetOutputInjectionID,
	Problem:  "a step that has an id prints a value an attacker controls to the log of the step, and the runner reads a set-output command in the printed value as a command that sets an output of the step; the runner sets the outputs of a step only when the step has an id",
	Expected: "no value an attacker controls is printed to the log of a step that has an id, or such a value is printed only between ::stop-commands::TOKEN and ::TOKEN:: with a random TOKEN",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessWorkflowCommandInjection}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textSetOutputInjectionControlled,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerMergedCommitAuthor, lint.AttackerAnyoneWhoForks},
			Preconditions:   []lint.PreconditionID{logSetOutput, attackerEvent, callersEvents, appStatusCheck},
			CVSS:            setOutputBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attack through a value printed to the log of a step with an id, among the 56 advisories of the actions ecosystem of the GitHub Advisory Database (2026-10-22); GitHub added environment files in 2022 \"To avoid untrusted logged data to use save-stateand set-output workflow commands without the intention of the workflow author\"", setOutputChangelog),
		},
	},
	Threat: lint.Threat{
		Actors:        withoutWikiEditor(injectionActors([]lint.Gain{lint.GainSetOutputs})),
		Preconditions: []lint.Precondition{logSetOutputPre, attackerEventPre, callersEventsPre, appStatusCheckPre},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee(append([]lint.UndetectedForm{
		forkReviewLimit,
		ifComparedLimit,
		pullRequestLimit, dispatchLimit, repositoryDispatchLimit, appWrittenLimit, deploymentStatusLimit, dispatchRelayLimit, dispatchInputCallLimit, notAttackerLimit, mergedPusherLimit, comparedLimit, newActivityTypeLimit, outsideCallerLimit, splitEnvNameLimit, otherShellLimit,
		{ID: lint.MustUndetectedFormID("script-var"), Text: "a shell variable the script sets (from a file, an API, the value of env through an assignment) or a positional parameter of a function, printed to the log", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("other-output"), Text: "a value an attacker controls that a command of the run script other than echo, printf, cat and tee prints: cat of a file of a pull request, git log, jq of $GITHUB_EVENT_PATH; also what a descriptor that exec points at the log (exec 3>&1) prints, and what goes to the log through a process substitution (exec > >(tee -a build.log))", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("decoded-escape"), Text: "the title of a wiki page printed by a command that decodes escapes in the value (printf with the value in its format, echo -e, printf %b): the attacker writes \\055 in the title, the command prints a - in its place, and the printed line can hold ##[set-output name=NAME;]value; the rule reads the title as holding no -", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("action-output"), Text: "a value an attacker controls that an action prints to the log of the step that uses the action, where the step has an id: the rule reads only the run scripts of bash and sh, not the code of an action, such as the script of actions/github-script, a local action or an action of another repository", Disposition: lint.Todo(lint.NeedSameFile, lint.NeedRepoFile, lint.NeedFact)},
	}, ifLimits...)),
	InconclusiveKinds: withRemoteCalleeUnknown(withCallBodyUnknown(append([]lint.InconclusiveKind{
		{ID: structuredValueKind, Text: "a value where whether an attacker can write ##[ and ] in the value was not checked, such as a structured value (a URL, or github.event.forkee.description, which is the description of a fork; the account that makes the fork writes the description, and the description holds no line break). Two kinds of structured value are not of this kind: the email of a git commit, which was checked to hold ##[ and ] and is reported, and the names of refs and repositories, which hold no [ and are not reported. The name of a wiki page (page_name) is of this kind. For a page made on the web interface of GitHub, the page name holds no blank, because GitHub turns each blank of the title into a - after trimming the blanks at the head and the end of the title; a set-output command needs a blank between the word set-output and the property name=, so the page name holds no set-output command. For a page pushed by git, the page name keeps each blank and - of the file name of the page and can hold a set-output command, and a push by git from an account with the role read or triage was not tried (GitHub refused a push by git from an account with no role in the repository). The rule cannot tell from the value which way the page was made. Any other value that an attacker controls on gollum alone is of this kind too, such as github.event.pages[0][x] where x is an expression, or toJSON(github.event). The title of a wiki page is not of this kind: the title holds no -, so the title as written holds no command whose name has a -, and the rule reports nothing on the title (a command that decodes escapes can make a - of the title: decoded-escape)", Disposition: lint.Todo(lint.NeedFact)},
	}, valueGaps...))),
	FalsePositiveForms: withNamedCaller([]lint.FalsePositiveForm{
		lastpipeFalsePositive(kindSetOutputInjectionControlled),
		nameNotLiteralFalsePositive(kindSetOutputInjectionControlled),
		forkFlagReview(kindSetOutputInjectionControlled),
		calleeFalsePositive(setOutputKinds...),
		writerString(setOutputKinds...), ifUnnarrowedFalsePositive(setOutputKinds...),
		{ID: lint.MustFalsePositiveFormID("stopped-commands"), Text: "a value printed between ::stop-commands::TOKEN and ::TOKEN::, where TOKEN is a value the step chooses at random for each run, and the runner reads no command", FindingKinds: setOutputKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("file-output-wins"), Text: "a step that is not a background step, and whose run script also writes name=value to $GITHUB_OUTPUT for each output name that is read later, by the steps after the step, by the outputs of the job or by the outputs of the action. The run script writes each such name outside every if, case and ||, so that the write runs on every path of the script. The runner reads $GITHUB_OUTPUT when the step is done, and the value in $GITHUB_OUTPUT replaces the value from the log. A reference that does not name an output (toJSON(steps.<id>.outputs), toJSON(steps), steps[...]) reads every output name, the names that the attacker chooses among them, so a step whose outputs are read through such a reference is not of this form", FindingKinds: setOutputKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		unreadOutputs("", setOutputKinds...),
	}, kindSetOutputInjectionControlled),
}

// unreadOutputs is the false positive of a step whose outputs nothing
// reads: the harm of a gain set-outputs comes from what reads the outputs.
// also is a sentence more of the rule's.
func unreadOutputs(also string, kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	text := "a step whose outputs are not read: no step after the step, no output of the job and no output of the action has a reference to an output of the step (steps.<id>.outputs.NAME), or a reference that reads every output name (toJSON(steps.<id>.outputs), toJSON(steps), steps[...]). The harm comes from what the steps that read the outputs do with the outputs, and the outputs alone run nothing"
	if also != "" {
		text += ". " + also
	}
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("unread-outputs"), Text: text, FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile, lint.NeedRepoFile)}
}
