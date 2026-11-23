package rules

import (
	"context"
	"slices"
	"strconv"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// UnsetConfigurationVariable is the quality rule
// unset-configuration-variable: a ${{ }} of a workflow that reads
// vars.<name> as a value, or gives vars.<name> to fromJSON(), where no
// level defines the name. GitHub gives the empty string for such a name
// and reports no error. The defined names are facts
// (repo.configuration-variables and
// repo.environment-configuration-variables), which --online answers only
// with a token that may read the Variables of the repository, so the rule
// runs only where the run has an answer (DefaultRunGivenFacts).
var UnsetConfigurationVariable lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.UnsetConfigurationVariableReader](unsetConfigurationVariable{}, ir.UnsetConfigurationVariableView))

// UnsetConfigurationVariableID is the ID of unset-configuration-variable.
var UnsetConfigurationVariableID = lint.MustRuleID("unset-configuration-variable")

type unsetConfigurationVariable struct{}

func (unsetConfigurationVariable) QualityMeta() lint.QualityMeta {
	return unsetConfigurationVariableMeta
}

func (unsetConfigurationVariable) Check(ctx context.Context, c *lint.RuleContext, v ir.UnsetConfigurationVariableReader) error {
	repoQuery := facts.RepoConfigurationVariables{Repo: c.Repo()}
	repoList := repoQuery.Ask(ctx, c.Resolver)
	if repoList.State != facts.StateFound {
		return nil // no answer (list-unknown) or absent: nothing to compare with
	}
	repoCond, err := lint.FactEq(repoQuery, repoList.Value)
	if err != nil {
		return err
	}
	seen := map[ir.Key]map[string]int{}
	for _, r := range v.ConfigurationVariableRefs() {
		if r.RemoteCallerOnly() || r.EnvironmentExpression() || r.Use() == analysis.ConfigurationVariableUseCompared {
			continue // remote-caller-only, environment-expression, compared
		}
		name, err := facts.ParseConfigurationVariableName(r.Name())
		if err != nil {
			continue // a name no level can define: expression.undefinable-configuration-variable
		}
		defined := slices.Contains(repoList.Value, name)
		conds := []lint.Condition{repoCond}
		known := true
		for _, e := range r.Environments() {
			q := facts.RepoEnvironmentConfigurationVariables{Repo: c.Repo(), Environment: e}
			a := q.Ask(ctx, c.Resolver)
			if a.State != facts.StateFound {
				known = false // environment-unknown
				break
			}
			cond, err := lint.FactEq(q, a.Value)
			if err != nil {
				return err
			}
			conds = append(conds, cond)
			defined = defined || slices.Contains(a.Value, name)
		}
		if !known || defined {
			continue
		}
		var args lint.FindingArgs = UnsetConfigurationVariableEmptyValue{Name: r.Name(), Expression: r.Expression()}
		if r.Use() == analysis.ConfigurationVariableUseFromJSON {
			args = UnsetConfigurationVariableFailedFromJSON{Name: r.Name(), Expression: r.Expression()}
		}
		at := seen[r.Key()]
		if at == nil {
			at = map[string]int{}
			seen[r.Key()] = at
		}
		id := args.KindID().String() + " " + name.String()
		anchor := name.String() + "#" + strconv.Itoa(at[id])
		at[id]++
		cond := lint.All(conds...)
		c.Report(lint.FindingDraft{Location: c.At(r.At()), Anchor: anchor, Args: args, Condition: &cond})
	}
	return nil
}

// configuration variables in the documentation of GitHub
const configurationVariableDocs = "https://github.com/github/docs/blob/6cbe6413ac7177bb692a78c171a74ae8be50d721/"

var (
	// the forms unset-configuration-variable declares
	variablesUnknown         = lint.MustUndetectedFormID("list-unknown")
	environmentUnknown       = lint.MustUndetectedFormID("environment-unknown")
	comparedVariable         = lint.MustUndetectedFormID("compared")
	dynamicVariableName      = lint.MustUndetectedFormID("dynamic-name")
	environmentExpression    = lint.MustUndetectedFormID("environment-expression")
	environmentBeforeStart   = lint.MustUndetectedFormID("environment-before-start")
	remoteCallerOnly         = lint.MustUndetectedFormID("remote-caller-only")
	variablesSizeLimit       = lint.MustUndetectedFormID("size-limit")
	otherJobEnvironment      = lint.MustUndetectedFormID("other-job-environment")
	unreadVariableKey        = lint.MustUndetectedFormID("unread-key")
	variablesForkPullRequest = lint.MustUndetectedFormID("fork-pull-request")
	scriptDefault            = lint.MustFalsePositiveFormID("script-default")
	actionEmptyInput         = lint.MustFalsePositiveFormID("action-empty-input")
	bothUnsetVariableKinds   = []lint.FindingKindID{kindUnsetConfigurationVariableEmptyValue, kindUnsetConfigurationVariableFailedFromJSON}
	unsetVariableFactKinds   = []facts.Kind{facts.KindRepoConfigurationVariables, facts.KindRepoEnvironmentConfigurationVariables}
)

var unsetConfigurationVariableMeta = lint.QualityMeta{
	ID:       UnsetConfigurationVariableID,
	Problem:  "a ${{ }} of a workflow reads a configuration variable (vars.<name>) as a value, or gives the configuration variable to fromJSON(), and no level (repository, organization, environment) defines the name: GitHub gives the empty string for the name and reports no error, so a misspelled name shows only in what the workflow run does",
	Expected: "every name that a ${{ }} reads from vars as a value, or gives to fromJSON(), is the name of a configuration variable defined at the repository level or the organization level (repo.configuration-variables), or defined at the environment level (repo.environment-configuration-variables) of an environment whose configuration variables the place of the ${{ }} reads",
	Citations: []lint.Citation{
		lint.MustCitation(configurationVariableDocs + "data/reusables/actions/actions-vars-context-example-usage.md"),
		lint.MustCitation(configurationVariableDocs + "content/actions/reference/workflows-and-actions/contexts.md"),
		lint.MustCitation(configurationVariableDocs + "content/actions/reference/workflows-and-actions/variables.md"),
	},
	Targets:    []lint.InputKind{lint.InputKindWorkflow},
	DefaultRun: lint.DefaultRunGivenFacts(facts.KindRepoConfigurationVariables, facts.KindRepoEnvironmentConfigurationVariables),
	FindingKinds: []lint.QualityFindingKind{
		{FindingText: textUnsetConfigurationVariableEmptyValue, FactKinds: unsetVariableFactKinds},
		{FindingText: textUnsetConfigurationVariableFailedFromJSON, FactKinds: unsetVariableFactKinds},
	},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: variablesUnknown, Text: "a run that names the rule with --rule but has no answer of repo.configuration-variables, or has the answer absent (without --rule, the rule does not run in such a run, and the report lists the rule among the skipped rules): the rule has no list of defined names to compare the names with, and reports nothing; also a run with --repo whose file of facts has repo.configuration-variables only in an entry without the argument repo: such an entry does not match the query of the rule, which has the argument repo", Disposition: lint.Todo(lint.NeedFact)},
		{ID: environmentUnknown, Text: "a reference whose place reads the configuration variables of an environment, when repo.environment-configuration-variables has no answer, or the answer absent, for the environment: in a key of a job, the environment of the job; in env, concurrency and on.workflow_call of the workflow, the environment of every job of the workflow (in a workflow run on GitHub, env of the workflow had the value of a name that only the environment level of the environment of the job defined; concurrency and on.workflow_call were not tried, and the rule takes the names of the environment of every job as defined for them, which can only miss a name). run-name of the workflow and the if and the name of a job read no environment. The rule does not know whether the environment level defines the name, and reports nothing for the reference", Disposition: lint.Todo(lint.NeedFact)},
		{ID: comparedVariable, Text: "a reference that the ${{ }} reads only as a boolean condition or in a comparison: an operand of || or && that is not the last, an operand of ! or of a comparison, an argument of contains(), startsWith() or endsWith(), a predicate of case(), or the whole of an if, such as if: vars.DEPOLY == 'true', where DEPOLY is a misspelling of the defined name DEPLOY. A workflow can leave a name undefined on purpose to turn a setting off, and the rule does not tell such a name from a misspelled one", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: dynamicVariableName, Text: "a reference whose name is not a literal, such as vars[matrix.name]: the rule does not compute the name", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: environmentExpression, Text: "a reference whose place reads the configuration variables of an environment whose name is written with a ${{ }}, such as environment: ${{ inputs.target }}: the rule does not compute the name of the environment, and reports nothing for the reference", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: environmentBeforeStart, Text: "a reference to a name that only the environment level defines, in a key that was not tried on GitHub: in runs-on, concurrency, strategy, timeout-minutes, continue-on-error, environment, container, services, defaults and outputs of a job, and in with and secrets of a job that calls a workflow, a name of the environment level of the environment of the job; in concurrency and on.workflow_call of the workflow, a name of the environment level of the environment of any job of the workflow. In a workflow run on GitHub, such a name was the empty string in run-name of the workflow and in the if and the name of the job, and had its value in env of the workflow and of the job and in the keys of the steps; in run-name and in the if and the name of a job, the rule does not take the names of the environment level as defined. In the keys that were not tried, the rule takes the names of the environment level as defined and reports nothing for the reference, though the name may be the empty string there", Disposition: lint.Todo(lint.NeedFact)},
		{ID: remoteCallerOnly, Text: "a reference in a workflow that runs on workflow_call only, when none of the files given to the linter calls the workflow with ./ or $/ (a path in the repository of the workflow): GitHub uses the configuration variables of the repository of the caller, and only workflows of other repositories call the workflow", Disposition: lint.Limitation(lint.DeciderRemoteCaller)},
		{ID: unreadVariableKey, Text: "a reference in a key that the rule does not read: a variable of strategy.matrix whose whole value is one ${{ }}, such as os: ${{ fromJSON(vars.OSES) }}, include or exclude of strategy.matrix whose whole value is one ${{ }}, a key of strategy.matrix written with a ${{ }}, the values of exclude of strategy.matrix, the options, ports and volumes of a container or a service, snapshot of a job, deployment of environment, group of a mapping of runs-on, and queue of concurrency. The rule reports nothing for such a reference. The rule reads the other values of strategy.matrix, such as the items of a list of a variable and the values of include", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: otherJobEnvironment, Text: "a reference in env, concurrency or on.workflow_call of the workflow to a name that only the environment level of the environment of some job of the workflow defines: a job without that environment reads the reference too, and gets the empty string; the rule takes the names of the environment level of every job of the workflow as defined for a key of the workflow, and reports nothing for the reference", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: variablesSizeLimit, Text: "a reference to a name that the repository level or the organization level defines, when the configuration variables of the two levels together are larger than the limit of a workflow run (256 KB on github.com): GitHub then gives the workflow run only the variables that fit, in the order of their names, and the empty string for the others. The rule does not read the sizes, takes the name as defined and reports nothing", Disposition: lint.Todo(lint.NeedFact)},
		{ID: variablesForkPullRequest, Text: "a reference to a defined name, which may be the empty string in a workflow run of a pull request from a fork: whether GitHub gives configuration variables to such a workflow run is not written in the documentation of GitHub, and the authors of the rule did not try such a workflow run. The rule takes the name as defined in such a workflow run as in other workflow runs, and reports nothing", Disposition: lint.Todo(lint.NeedFact)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: scriptDefault, Text: "a name that the workflow reads on purpose as an optional setting, whose empty value the script of a run step puts a default value in place of, such as env: {X: '${{ vars.X }}'} and ${X:-default} in the script: the empty string is what the workflow expects for a missing setting, and the rule does not read the script", FindingKinds: []lint.FindingKindID{kindUnsetConfigurationVariableEmptyValue}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: actionEmptyInput, Text: "a name that the workflow reads on purpose as an optional setting and gives to an input of an action under with, when the code of the action reads an empty input as an input not given and uses a default value: the runner gives the empty string to the action, since the key is under with, and the code of the action decides what the empty string means", FindingKinds: []lint.FindingKindID{kindUnsetConfigurationVariableEmptyValue}, Disposition: lint.Limitation(lint.DeciderRunTime)},
	},
}
