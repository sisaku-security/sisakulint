package rules

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// everyRunEvents are the events of the EveryRunOn of refs: those on which
// a variable or a secret that the attacker writes reaches the agent in a
// run anyone starts, in a run of the linter that adds variables-writer or
// secrets-writer.
func everyRunEvents(refs []ir.EveryRunRef) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, r := range refs {
		for _, e := range r.EveryRunOn {
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	return out
}

// everyRunEvidence is the evidence of a finding of a step of the agent
// action a on the events on: for each reference of refs that the attacker
// chooses on one of on, its place with its note (everyRunNote), and where
// its value comes from (valueEvidence).
func everyRunEvidence(c *lint.RuleContext, a analysis.AgentAction, refs []ir.EveryRunRef, on []analysis.EventActivity) []lint.Related {
	var out []lint.Related
	for _, r := range refs {
		if len(within(r.EveryRunOn, on)) == 0 {
			continue
		}
		// a secret by its source, or by the barrier of the run when the
		// value comes from no one reference of vars or secrets
		secret := r.SourceSecret
		if r.SourceName == "" {
			secret = !c.Barriers().Passes(analysis.BarrierVariableValue)
		}
		evidence, _ := valueEvidence(c, r.Ref, r.Ref.Text)
		out = append(out, lint.Related{Location: c.At(r.Ref.At), Note: everyRunNote(secret, a, r)})
		out = append(out, evidence...)
	}
	return out
}

// everyRunNote is the note of the reference r of a step of the agent
// action a, whose value comes from a secret (secret) or a variable: the
// route the reference reaches the agent through, and the attacker who
// chooses its value for every workflow run. For an input of a composite
// action of another repository, the note says too why the rule counts the
// input: a ${{ }} of the agent's step refers to it, and an input that
// reaches the agent only through another step is not counted.
func everyRunNote(secret bool, a analysis.AgentAction, r ir.EveryRunRef) string {
	kind, kinds := "variable", "variables"
	if secret {
		kind, kinds = "secret", "secrets"
	}
	var route, read string
	switch r.Route {
	case analysis.AgentValueRouteStepEnv:
		route = r.Ref.Text + " reaches the agent through the env " + r.Env.String() + " of the step"
	case analysis.AgentValueRouteJobEnv:
		route = r.Ref.Text + " reaches the agent through the variable " + r.Env.String() + " in the env of the job"
	case analysis.AgentValueRouteWorkflowEnv:
		route = r.Ref.Text + " reaches the agent through the variable " + r.Env.String() + " in the env of the workflow"
	case analysis.AgentValueRouteSettingInput:
		route = r.Ref.Text + " reaches the settings of the agent through the input " + r.Input.String() + " of " + textAgentAction(a)
	case analysis.AgentValueRouteCompositeInput:
		c := "the composite action " + r.Composite
		in := "the input " + r.CompositeInput.String()
		route = r.Ref.Text + " reaches " + in + " of " + c + " through the with of the step that uses " + c
		read = ". A ${{ }} in the with or the env of the step that runs the agent of " + textAgentAction(a) + " in " + c + " refers to " + in + ", so the rule counts " + in + " as a value that reaches the agent. The rule does not count an input of " + c + " that reaches the agent only through another step of " + c
	default:
		route = r.Ref.Text + " reaches the agent through the input " + r.Input.String() + " of " + textAgentAction(a)
	}
	const every = " for every workflow run, whoever starts the workflow run"
	switch {
	case r.SourceName != "" && r.Direct:
		return route + ", and an attacker who can write the " + kind + " " + r.SourceName + " chooses the value of " + r.Ref.Text + every + read
	case r.SourceName != "":
		return route + "; the value of " + r.Ref.Text + " comes from " + r.Source + ", and an attacker who can write the " + kind + " " + r.SourceName + " chooses the value of " + r.Source + every + read
	}
	return route + "; the value of " + r.Ref.Text + " comes from a " + kind + ", and an attacker who can write " + kinds + " chooses the value of the " + kind + every + read
}

// refusedActorRules are the rules of agent actions that read a run of
// another's as a run that the check of the actor of claude-code-action
// lets in, whatever actor the if of the job or the step lets in.
var refusedActorRules = []lint.RuleID{AIActionPromptInjectionID, AIActionExcessiveToolsID, AIActionExecutionOrderID, AIActionUnsafeSandboxID}

// claudeHumanActor is the check of claude-code-action that the actor of
// the run is a human, in every mode: a bot that allowed_bots does not list
// stops the action.
var claudeHumanActor = lint.MustCitation("https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/src/github/validation/actor.ts")

// withRefusedActor is m with refusedActor, for the rules of
// refusedActorRules.
func withRefusedActor(m lint.Meta) lint.Meta {
	if !slices.Contains(refusedActorRules, m.ID) {
		return m
	}
	var kinds []lint.FindingKindID
	for _, k := range m.FindingKinds {
		kinds = append(kinds, k.ID)
	}
	m.FalsePositiveForms = append(slices.Clone(m.FalsePositiveForms), refusedActor(kinds))
	return m
}

// refusedActor is the false positive form of refusedActorRules, of the
// kinds of the rule, in the run of the linter that adds no attacker.
func refusedActor(kinds []lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("refused-actor"),
		Text:         "a job or a step whose if lets in only the workflow runs whose actor is a bot (such as github.actor == 'dependabot[bot]'), where the step of claude-code-action has no input allowed_bots: the rule does not know the actor of a workflow run that an account other than the account of the attacker starts, such as the workflow run that starts when a maintainer adds a label to the issue of the attacker, so the rule reads the if as an if that may let in the workflow run that the account other than the account of the attacker starts, and reads the check of claude-code-action that the actor of the workflow run is a human as a check that lets in the workflow run that the account other than the account of the attacker starts. claude-code-action checks that the actor of each workflow run is a human, and claude-code-action stops in a workflow run whose actor is a bot that the input allowed_bots does not list (" + claudeHumanActor.String() + "), so the agent starts in no workflow run that the if lets in",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// refusedActorValueRun is the false positive form of refusedActorRules, of
// the kinds of the rule, in a run of the linter that adds variables-writer
// or secrets-writer.
func refusedActorValueRun(kinds []lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("refused-actor-value-run"),
		Text:         "in a run of the linter that adds variables-writer or secrets-writer, a job or a step in which a value of vars or secrets reaches the agent, and whose if lets in only the workflow runs whose actor is a bot (such as github.actor == 'dependabot[bot]'), where the step of claude-code-action has no input allowed_bots: claude-code-action stops in a workflow run whose actor is a bot that the input allowed_bots does not list (" + claudeHumanActor.String() + "). The rule evaluates the if with the values of github.event_name and github.event.action only, and reads every other value in the if as unknown; then the rule reads every workflow run of an event on which the if is not false by the values of github.event_name and github.event.action alone as a workflow run that an account with write access to the repository starts and that the checks of claude-code-action let in. On GitHub, the if lets in only the workflow runs whose actor is a bot, and claude-code-action stops in each of those workflow runs because the step that uses claude-code-action has no input allowed_bots, so the agent starts in no workflow run that the if lets in",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile), AddedAttackers: valueAttackers}
}

// unknownOSCase is the false positive form unknown-os-case of the rules of
// agent actions, of kinds: a value of the env of a job or of the workflow
// that an env of a nearer level hides only on Windows, in a job whose
// runs-on does not decide the OS. A rule that reads the env only in a run
// of the linter that adds an attacker who writes vars or secrets gives
// added (valueAttackers), and nil when it reads the env in every run.
func unknownOSCase(added []lint.AddedAttacker, kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	value, eg := "a value that an attacker writes", "body: fixed text in the env of the step, and BODY: ${{ github.event.issue.body }} in the env of the job"
	if added != nil {
		value, eg = "in a run of the linter that adds variables-writer or secrets-writer, a value of vars or secrets that the workflow writes", "guide: fixed text in the env of the step, and GUIDE: ${{ vars.GUIDE }} in the env of the job"
	}
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("unknown-os-case"),
		Text:         value + " in the env of the job or in the env of the workflow, in a job whose runs-on does not decide the OS of the runner (for example, a runs-on that is a ${{ }} of a matrix, or the labels of a self-hosted runner without the label windows), when the env of the step or the env of the job also has a variable whose name is the same as the name of the variable that holds the attacker's value except for upper and lower case (for example, " + eg + "). A Windows runner ignores upper and lower case when the Windows runner compares the names of variables, so on a Windows runner the variable in the env of the step replaces the variable in the env of the job, the variable in the env of the job replaces the variable in the env of the workflow, and the attacker's value does not reach the agent. A Linux runner and a macOS runner keep upper and lower case distinct, so on a Linux runner and on a macOS runner both variables reach the agent. The rule ignores upper and lower case only in a job whose runs-on decides a Windows runner",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile), AddedAttackers: added}
}

// jobEnvComposite is the undetected form job-env-composite of the rules of
// agent actions: the agent step of a composite action is read with the env
// of the step alone. A rule that reads the env only in a run of the linter
// that adds an attacker who writes vars or secrets gives valueRun.
func jobEnvComposite(valueRun bool) lint.UndetectedForm {
	value := "a value that an attacker writes, which the workflow puts"
	if valueRun {
		value = "in a run of the linter that adds variables-writer or secrets-writer, a value of vars or secrets, which the workflow puts"
	}
	return lint.UndetectedForm{ID: lint.MustUndetectedFormID("job-env-composite"),
		Text:        value + " in the env of the job or in the env of the workflow, where the job runs a composite action, in the same repository or in another repository, and a step of the composite action runs the agent: the process of the agent also gets the env of the job and the env of the workflow, but the rule reads only the env of the step of the composite action",
		Disposition: lint.Todo(lint.NeedSameFile)}
}

// wholeEnv is the undetected form whole-env of the rules of agent actions
// that read the env only in a run of the linter that adds an attacker who
// writes vars or secrets (ai-action-prompt-injection declares the form in
// whole-with): an env that is one whole ${{ }}, and its outer envs.
var wholeEnv = lint.UndetectedForm{ID: lint.MustUndetectedFormID("whole-env"),
	Text:        "in a run of the linter that adds variables-writer or secrets-writer, a value of vars or secrets in an env that is one whole ${{ }} (an env of the step, an env of the job or an env of the workflow), or in an outer env of an env that is one whole ${{ }} (the env of the job and the env of the workflow are outer envs of an env of the step; the env of the workflow is the outer env of an env of the job). The names and the values of the variables of an env that is one whole ${{ }} are not known, and the env that is one whole ${{ }} may set a variable with the same name as a variable of an outer env, and the variable that the env sets then replaces the variable of the outer env, so the rule counts neither the values of the whole ${{ }} nor the values of the outer envs as values that reach the agent",
	Disposition: lint.Todo(lint.NeedSameFile)}

// githubEnvWrite is the false positive form github-env-write of the rules
// of agent actions, of kinds: a variable of the env of the job or of the
// workflow that a step before replaces through $GITHUB_ENV, whose writes
// the rules do not read as replacing it. added is as for unknownOSCase.
func githubEnvWrite(added []lint.AddedAttacker, kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	value := "a value that an attacker writes"
	if added != nil {
		value = "in a run of the linter that adds variables-writer or secrets-writer, a value of vars or secrets that the workflow writes"
	}
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("github-env-write"),
		Text:         value + " in the env of the job or in the env of the workflow, when a step before the step of the agent writes to $GITHUB_ENV, in every run, a value that is not the attacker's value under the name of the variable that holds the attacker's value (on a Windows runner, also under a name that is the same except for upper and lower case). A variable that a step writes to $GITHUB_ENV replaces the variable of the same name in the env of the job and in the env of the workflow for the steps after the step that writes, so the attacker's value does not reach the agent. The rule does not read a write to $GITHUB_ENV as a write that replaces a variable of the env of the job or of the env of the workflow, because whether the write happens in every run depends on the if of the step, the branches of the run and the steps before, which the rule does not read in full",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile), AddedAttackers: added}
}
