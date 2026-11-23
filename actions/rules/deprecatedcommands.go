package rules

import (
	"context"
	"strconv"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// DeprecatedCommands is the quality rule deprecated-commands: a workflow
// command whose name is in the text of a run and that the run prints to
// its log. set-output and
// save-state work, with a warning; set-env and add-path fail the step
// unless ACTIONS_ALLOW_UNSECURE_COMMANDS is true, which the YAML of a
// composite action does not decide. A value an attacker prints to the
// log of a step whose flag is true is unsecure-commands'.
var DeprecatedCommands lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.DeprecatedCommandsReader](deprecatedCommands{}, ir.DeprecatedCommandsView))

// DeprecatedCommandsID is the ID of deprecated-commands.
var DeprecatedCommandsID = lint.MustRuleID("deprecated-commands")

type deprecatedCommands struct{}

func (deprecatedCommands) QualityMeta() lint.QualityMeta { return deprecatedCommandsMeta }

func (deprecatedCommands) Check(_ context.Context, c *lint.RuleContext, v ir.DeprecatedCommandsReader) error {
	for _, s := range v.Sinks() {
		// the anchor tells the commands of one run apart without their
		// lines: the name and how many of the name came before it
		seen := map[analysis.AuthoredCommandName]int{}
		for _, a := range s.AuthoredCommands() {
			anchor := a.Command.Command() + "#" + strconv.Itoa(seen[a.Command])
			seen[a.Command]++
			switch a.Command {
			case analysis.AuthoredSetOutput, analysis.AuthoredSaveState:
				c.Report(lint.FindingDraft{Location: c.At(a.At), Anchor: anchor, Args: DeprecatedCommandsDeprecatedCommand{Command: a.Command}})
			case analysis.AuthoredSetEnv, analysis.AuthoredAddPath:
				c.Report(lint.FindingDraft{Location: c.At(a.At), Anchor: anchor, Args: DeprecatedCommandsDisabledCommand{Command: a.Command}})
			}
		}
	}
	return nil
}

var deprecatedCommandsMeta = lint.QualityMeta{
	ID:       DeprecatedCommandsID,
	Problem:  "the run script of a step prints to the log of the step, as ::name at the head of a line or ##[name anywhere in a line (such as ##[set-output name=x;]v), a workflow command that GitHub deprecated (set-output, save-state) or disabled (set-env, add-path)",
	Expected: "every run script that sets an output, state, an environment variable or the PATH writes to the environment files ($GITHUB_OUTPUT, $GITHUB_STATE, $GITHUB_ENV, $GITHUB_PATH) instead of printing a workflow command",
	Citations: []lint.Citation{
		lint.MustCitation("https://github.blog/changelog/2022-10-11-github-actions-deprecating-save-state-and-set-output-commands/"),
		lint.MustCitation("https://github.blog/changelog/2023-07-24-github-actions-update-on-save-state-and-set-output-commands/"),
		lint.MustCitation(githubDocs + "content/actions/reference/workflows-and-actions/workflow-commands.md"),
		lint.MustCitation(runnerValidity + "src/Runner.Worker/ActionCommandManager.cs"),
	},
	Targets: []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	FindingKinds: []lint.QualityFindingKind{
		{FindingText: textDeprecatedCommandsDeprecatedCommand},
		{FindingText: textDeprecatedCommandsDisabledCommand},
	},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("other-output"), Text: "a workflow command that a command other than echo, printf and cat prints, such as python -c in the run script or a script file of the repository, and a line that echo makes from an escape (echo -e with \\n) or from the output of a $( ) in its words: the rule reads the literal text that echo, printf and cat print", Disposition: lint.Todo(lint.NeedSameFile, lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("action-output"), Text: "a workflow command that the code of an action prints, such as setOutput of an old version of @actions/core: the rule reads the run scripts of bash and sh", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("dynamic-command"), Text: "a workflow command whose name comes from a variable or a ${{ }}: the rule reads a name written in the text of the run script", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("other-shell"), Text: "a workflow command that a run script of another shell than bash or sh prints, such as pwsh, and one of a run script whose shell the rule does not decide: a step without shell: on a runner that runs-on names by a label other than a label of a GitHub-hosted runner, a step whose shell: value is bash or sh with an option that the rule does not read, such as bash -v {0}, and a step whose shell: value names bash or sh by a path on a runner that the rule does not know to have the path", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("stopped-commands"), Text: "a workflow command printed after ::stop-commands:: and before the token that ends the stop: the runner reads no workflow command between the two", FindingKinds: []lint.FindingKindID{kindDeprecatedCommandsDeprecatedCommand, kindDeprecatedCommandsDisabledCommand}, Disposition: lint.Todo(lint.NeedSameFile)},
	},
}
