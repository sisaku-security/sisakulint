package rules

import (
	"context"
	"strconv"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// ExpressionRule is the quality rule expression: a ${{ }} that GitHub
// accepts in the file, and that does not do what it says when the
// workflow runs: a value of a
// type its key does not take, a call of format(), case() or fromJSON()
// that fails, an object or an array written into a text, and a name of
// vars that no level of GitHub can define, which is the empty string in
// every run. The kinds of the first three are what happens, which depends on where GitHub or the runner reads the
// key; a ${{ }} that GitHub refuses when it reads the file is the
// model's Diagnostic (ExprSyntax).
var ExpressionRule lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.ExpressionReader](expressionRule{}, ir.ExpressionView))

// ExpressionRuleID is the ID of expression.
var ExpressionRuleID = lint.MustRuleID("expression")

type expressionRule struct{}

func (expressionRule) QualityMeta() lint.QualityMeta { return expressionMeta }

// expressionStages is the kind of each key: what happens when its ${{ }}
// fails.
var expressionStages = map[analysis.ExpressionKey]func(m ir.ExpressionOfExpressionMistake) lint.FindingArgs{}

func init() {
	unstarted := func(m ir.ExpressionOfExpressionMistake) lint.FindingArgs {
		return ExpressionUnstartedJob{Expression: m.Expression(), Key: m.ExpressionKey(), Error: m.Error(), ValueTypes: m.ValueTypes()}
	}
	failedJob := func(m ir.ExpressionOfExpressionMistake) lint.FindingArgs {
		return ExpressionFailedJob{Expression: m.Expression(), Key: m.ExpressionKey(), Error: m.Error(), ValueTypes: m.ValueTypes()}
	}
	failedStep := func(m ir.ExpressionOfExpressionMistake) lint.FindingArgs {
		return ExpressionFailedStep{Expression: m.Expression(), Key: m.ExpressionKey(), Error: m.Error(), ValueTypes: m.ValueTypes()}
	}
	ignored := func(m ir.ExpressionOfExpressionMistake) lint.FindingArgs {
		return ExpressionIgnoredSetting{Expression: m.Expression(), Key: m.ExpressionKey(), Error: m.Error(), ValueTypes: m.ValueTypes()}
	}
	for _, k := range []analysis.ExpressionKey{analysis.ExpressionKeyJobName, analysis.ExpressionKeyRunsOn, analysis.ExpressionKeyJobTimeoutMinutes, analysis.ExpressionKeyJobCancelTimeoutMinutes, analysis.ExpressionKeyJobContinueOnError, analysis.ExpressionKeyEnvironment, analysis.ExpressionKeyStrategyFailFast, analysis.ExpressionKeyStrategyMaxParallel, analysis.ExpressionKeyStrategyMatrix, analysis.ExpressionKeyJobConcurrency, analysis.ExpressionKeyJobIf, analysis.ExpressionKeyCallWith, analysis.ExpressionKeyRunName, analysis.ExpressionKeyWorkflowConcurrency} {
		expressionStages[k] = unstarted
	}
	for _, k := range []analysis.ExpressionKey{analysis.ExpressionKeyWorkflowEnv, analysis.ExpressionKeyJobEnv, analysis.ExpressionKeyContainer, analysis.ExpressionKeyServices, analysis.ExpressionKeyDefaultsRun, analysis.ExpressionKeyJobOutputs, analysis.ExpressionKeyEnvironmentURL, analysis.ExpressionKeyCallSecrets, analysis.ExpressionKeyWorkflowCallOutputs} {
		expressionStages[k] = failedJob
	}
	for _, k := range []analysis.ExpressionKey{analysis.ExpressionKeyStepEnv, analysis.ExpressionKeyStepWith, analysis.ExpressionKeyStepRun, analysis.ExpressionKeyStepWorkingDirectory, analysis.ExpressionKeyStepIf, analysis.ExpressionKeyActionOutputs} {
		expressionStages[k] = failedStep
	}
	for _, k := range []analysis.ExpressionKey{analysis.ExpressionKeyStepTimeoutMinutes, analysis.ExpressionKeyStepContinueOnError} {
		expressionStages[k] = ignored
	}
	expressionStages[analysis.ExpressionKeyInputDefault] = func(m ir.ExpressionOfExpressionMistake) lint.FindingArgs {
		return ExpressionUnstartedCaller{Expression: m.Expression(), ValueTypes: m.ValueTypes()}
	}
}

func (expressionRule) Check(_ context.Context, c *lint.RuleContext, v ir.ExpressionReader) error {
	// the anchor tells apart the mistakes at one place: the expression,
	// and how many of the same at that place came before
	seen := map[ir.Key]map[string]int{}
	for _, m := range v.ExpressionMistakes() {
		var args lint.FindingArgs
		if m.ObjectText() {
			args = ExpressionEmbeddedObject{Expression: m.Expression(), ValueTypes: m.ValueTypes()}
		} else if stage, ok := expressionStages[m.ExpressionKey()]; ok {
			args = stage(m)
		} else {
			continue
		}
		at := seen[m.Key()]
		if at == nil {
			at = map[string]int{}
			seen[m.Key()] = at
		}
		id := args.KindID().String() + " " + m.Expression()
		anchor := m.Expression() + "#" + strconv.Itoa(at[id])
		at[id]++
		c.Report(lint.FindingDraft{Location: c.At(m.At()), Anchor: anchor, Args: args})
	}
	// a name that no level can define is the empty string in every run,
	// whatever the configuration variables of the repository are
	for _, r := range v.ConfigurationVariableRefs() {
		if _, err := facts.ParseConfigurationVariableName(r.Name()); err == nil {
			continue
		}
		at := seen[r.Key()]
		if at == nil {
			at = map[string]int{}
			seen[r.Key()] = at
		}
		args := ExpressionUndefinableConfigurationVariable{Name: r.Name(), Expression: r.Expression()}
		id := args.KindID().String() + " " + r.Name()
		anchor := r.Name() + "#" + strconv.Itoa(at[id])
		at[id]++
		c.Report(lint.FindingDraft{Location: c.At(r.At()), Anchor: anchor, Args: args})
	}
	return nil
}

var expressionMeta = lint.QualityMeta{
	ID:       ExpressionRuleID,
	Problem:  "a ${{ }} that GitHub accepts in the file does not work when the workflow runs: the value of the ${{ }} has a type that the key of the ${{ }} does not take, a call of format(), case() or fromJSON() in the ${{ }} fails, the value of a ${{ }} in a text is an object or an array (the text of an if is the rule cond's, not this rule's), or the ${{ }} reads a configuration variable by a name that no level of GitHub can define",
	Expected: "every expression that is the whole value of a key (${{ x }} alone) gives a type that the key takes, every call of format(), case() and fromJSON() gets arguments that the function can use, and every expression written in a text (with other text, or with another ${{ }}, in the same value) gives a string, a number, a boolean or null; the whole text is a string, so the key of such a text takes a string; and every name read from vars is a name that GitHub lets a level define",
	Citations: []lint.Citation{
		lint.MustCitation(githubDocs + "content/actions/reference/workflows-and-actions/contexts.md"),
		lint.MustCitation(githubDocs + "content/actions/reference/workflows-and-actions/expressions.md"),
		lint.MustCitation(runnerValidity + "src/Sdk/DTObjectTemplating/ObjectTemplating/TemplateEvaluator.cs"),
		lint.MustCitation(runnerValidity + "src/Runner.Worker/StepsRunner.cs"),
		lint.MustCitation(runnerValidity + "src/Runner.Worker/ExecutionContext.cs"),
		lint.MustCitation(runnerValidity + "src/Sdk/DTExpressions2/Expressions2/EvaluationResult.cs"),
		lint.MustCitation(runnerValidity + "src/Sdk/DTExpressions2/Expressions2/Sdk/Functions/Format.cs"),
		lint.MustCitation(runnerValidity + "src/Sdk/DTExpressions2/Expressions2/Sdk/Functions/Case.cs"),
		lint.MustCitation(runnerValidity + "src/Sdk/DTExpressions2/Expressions2/Sdk/Functions/FromJson.cs"),
		lint.MustCitation(configurationVariableDocs + "data/reusables/actions/actions-secrets-and-variables-naming.md"),
	},
	Targets: []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	FindingKinds: []lint.QualityFindingKind{
		{FindingText: textExpressionEmbeddedObject},
		{FindingText: textExpressionFailedJob},
		{FindingText: textExpressionFailedStep},
		{FindingText: textExpressionIgnoredSetting},
		{FindingText: textExpressionUndefinableConfigurationVariable},
		{FindingText: textExpressionUnstartedCaller},
		{FindingText: textExpressionUnstartedJob},
	},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("unconfirmed-type"), Text: "a ${{ }} that reads an input of workflow_dispatch of the type choice or environment: the documentation of GitHub does not give the type of the value of such an input, and the authors of the rule did not try the type on GitHub", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("event-payload"), Text: "a ${{ }} that reads a property of github.event, whose type depends on the event, and github.event as the whole value of a key that takes a mapping of known properties, such as runs-on: ${{ github.event }}: the rule does not read the types of the payloads of the events", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("run-time-type"), Text: "a ${{ }} whose type is known only when the workflow runs: fromJSON() of a value that is not a literal, and a ${{ }} whose value may be of a type that the key takes or of a type that the key does not take, such as inputs.t || 30 for an input t of the type string", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("remote-call"), Text: "the with of a job that calls a reusable workflow of another repository when workflow.definition has no answer for the workflow (a run without --online and without the answer in --facts), or a reusable workflow of the repository whose file is not among the files given to the linter: the rule reads the types of the inputs of a called workflow only when the file of the called workflow is among the files given to the linter, or is the answer of workflow.definition", Disposition: lint.Todo(lint.NeedRepoFile, lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("default-call"), Text: "a call of format(), case() or fromJSON() that fails, in the default of an input of workflow_call: the rule reads the default for its type only, since what GitHub does with such a call in a default was not tried", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("text-value"), Text: "an expression written in a text (with other text, or with another ${{ }}, in the same value) in a key that takes a boolean, a number or a mapping, such as timeout-minutes: ${{ vars.BASE }}0: the value is a string, which such a key does not take, but the rule reads a text only for an object or an array in it, and what GitHub does with such a value was not tried", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("unread-key"), Text: "a ${{ }} of a key that the rule does not read: runs.env, runs.args and runs.entrypoint of a Docker container action, the default of an input of an action.yml, runs.pre-if and runs.post-if, snapshot of a job, the keys of the container and the services of a job other than image, credentials and env, such as ports and options, deployment of environment, group of a mapping of runs-on, and queue of concurrency", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("unevaluated-call"), Text: "a call of format(), case() or fromJSON() that no run evaluates, where the rule does not know so: after an operand of && that is false in every run of the workflow, or after a predicate of case() that is true in every run, such as github.event_name == 'pull_request' && fromJSON(github.event) in a workflow that runs on push only, where the comparison is false in every run. A call that is not evaluated does not fail", FindingKinds: []lint.FindingKindID{kindExpressionUnstartedJob, kindExpressionFailedJob, kindExpressionFailedStep, kindExpressionIgnoredSetting}, Disposition: lint.Todo(lint.NeedSameFile)},
	},
}
