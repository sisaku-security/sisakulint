package rules

import (
	"context"

	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// EnvVarRule is the quality rule env-var: a key of env that does not set
// the variable it names. A key with =
// sets another variable to another value; a key the runner writes in every
// step, after env, never reaches the step. A name with a space or &, which
// upstream's rule reported, becomes the variable as written.
var EnvVarRule lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.EnvVarReader](envVar{}, ir.EnvVarView))

// EnvVarRuleID is the ID of env-var. (EnvVarID is the kind of the fix of the
// injection rules that moves a value to env.)
var EnvVarRuleID = lint.MustRuleID("env-var")

type envVar struct{}

func (envVar) QualityMeta() lint.QualityMeta { return envVarMeta }

func (envVar) Check(_ context.Context, c *lint.RuleContext, v ir.EnvVarReader) error {
	for _, k := range v.EnvKeys() {
		if k.Variable() != "" {
			c.Report(lint.FindingDraft{Location: c.At(k.At()), Args: EnvVarEqualsSign{Name: k.Name(), Variable: k.Variable()}})
		}
		if k.RunnerValue() != "" {
			c.Report(lint.FindingDraft{Location: c.At(k.At()), Args: EnvVarRunnerOverwritten{Name: k.Name(), RunnerValue: k.RunnerValue()}})
		}
	}
	return nil
}

var envVarMeta = lint.QualityMeta{
	ID:       EnvVarRuleID,
	Problem:  "a key of env has = in it, or names a variable that the runner writes in each step after the env of the step is set, with a value other than the value that the runner writes, so no step gets the variable with the name and the value as written",
	Expected: "every key of env is a name without =, and is a name that the runner does not write in each step, or is written with the value that the runner writes",
	Citations: []lint.Citation{
		lint.MustCitation(githubDocs + "content/actions/reference/workflows-and-actions/variables.md"),
		lint.MustCitation(runnerValidity + "src/Runner.Worker/GitHubContext.cs"),
		lint.MustCitation(runnerValidity + "src/Runner.Worker/RunnerContext.cs"),
		lint.MustCitation(runnerValidity + "src/Runner.Worker/Handlers/ScriptHandler.cs"),
		lint.MustCitation(runnerValidity + "src/Runner.Worker/Handlers/StepHost.cs"),
		lint.MustCitation(runnerValidity + "src/Runner.Sdk/ProcessInvoker.cs"),
	},
	Targets: []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	FindingKinds: []lint.QualityFindingKind{
		{FindingText: textEnvVarEqualsSign},
		{FindingText: textEnvVarRunnerOverwritten},
	},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("expression-name"), Text: "a key of env written with a ${{ }}, whose name is known when the workflow runs", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("expression-env"), Text: "an env written as one ${{ }}, whose keys are known when the workflow runs", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("unknown-os-case"), Text: "a key that names a variable the runner writes in another case (github_sha), in a job whose OS the runs-on does not decide, such as a ${{ }} of a matrix, or in runs.env or a step of an action.yml, whose caller decides the OS: on Windows the runner writes over the key, on Linux and macOS the key is another variable", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("empty-name"), Text: "a key of env that starts with =, such as =A: how the runner passes a key with an empty name before the = has not been tried", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
}
