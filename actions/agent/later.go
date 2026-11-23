package agent

import (
	"github.com/gh-intel/sisakulint/actions/attacker"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// LaterStep is a step of the job, or of the action, of a step of an agent
// action that may run after it has started, or beside it: the secrets it
// holds that the agent does not, and where it runs what the agent may
// leave in the workspace and in .git.
type LaterStep struct {
	Step     workflow.Step
	Name     string                   // its name, else steps[<n>]
	On       []analysis.EventActivity // of the agent's events (the attacker's, and those of everyRunOn), those its if lets through
	Secrets  job.Secrets              // what it reads that the agent does not hold
	CodeRuns []prcode.CodeRunStep     // where it runs the code of the agent's working directory
	GitRuns  []prcode.CodeRunStep     // where it starts git
}

// LaterSteps are the steps of steps (of the job j of w, of an action when j
// is nil, or of a composite action that a step of j runs) that may run
// after the step at, of the agent a, has started, or beside it, with what
// each holds more than the agent and runs of what it may leave; evs are the attacker's events of the agent's
// step, whose ifs t reads, and everyRunOn the events on which a variable or
// a secret the attacker writes reaches the agent in a run anyone starts,
// whose ifs are read by the event alone (taint.FilterEventOnly). The
// code of the working directory a later checkout cleans is not run after
// it; .git, which a checkout leaves, is. stepJob is the job whose steps
// steps are, j, or nil for the steps of an action, whose ifs do not read
// the needs context of j (attacker.StepIf).
func LaterSteps(t attacker.Table, w *workflow.Workflow, j, stepJob *workflow.Job, steps []workflow.Step, at int, a Step, evs, everyRunOn []analysis.EventActivity, m *shell.Memo) []LaterStep {
	order := workflow.OrderOf(steps)
	held := heldSecrets(w, j, steps, order, at, a)
	root, known := WorkingDirectory(a)
	code := prcode.WorkspaceRuns(w, j, steps, at, root, !known, m)
	git := prcode.GitRuns(w, j, steps, at, m)
	var out []LaterStep
	for k, x := range steps {
		if k == at || !order.MayRunAfter(at, k) {
			continue
		}
		vs := append(job.MapValues(x.Env), job.MapValues(x.With)...)
		if x.Name.Status == workflow.Present {
			vs = append(vs, x.Name.Value)
		}
		if x.Run.Status == workflow.Present {
			vs = append(vs, x.Run.Value)
		}
		p := attacker.StepIf(w, stepJob, x.If)
		on := taint.Filter(t, evs, p)
		for _, e := range taint.FilterEventOnly(everyRunOn, p) {
			if !slices.Contains(on, e) {
				on = append(on, e)
			}
		}
		l := LaterStep{Step: x, Name: prcode.StepName(x), On: on, Secrets: job.SecretsOf(vs...).Without(held)}
		for _, r := range code {
			if r.Step.Order == x.Order {
				l.CodeRuns = append(l.CodeRuns, r)
			}
		}
		for _, r := range git {
			if r.Step.Order == x.Order {
				l.GitRuns = append(l.GitRuns, r)
			}
		}
		out = append(out, l)
	}
	return out
}

// heldSecrets are what the agent of a, the step at, holds: the env of the
// workflow (but in a job that calls) and of the job, the env of the job's
// container, which the steps of the job that are not container actions
// run in (no agent action is one), its step's env, the with that reaches
// it, the token its action defaults to, and the token of each checkout
// done before it that persists its credentials in .git/config, which an
// agent that runs any code reads.
func heldSecrets(w *workflow.Workflow, j *workflow.Job, steps []workflow.Step, order workflow.StepOrder, at int, a Step) job.Secrets {
	var vs []workflow.String
	if w != nil && j != nil && j.Kind != workflow.JobCall {
		vs = append(vs, job.MapValues(w.Env)...)
	}
	if j != nil {
		vs = append(vs, job.MapValues(j.Env)...)
		if j.Container.Status == workflow.Present {
			vs = append(vs, job.MapValues(j.Container.Value.Env)...)
		}
	}
	vs = append(vs, job.MapValues(a.Step.Env)...)
	vs = append(vs, HeldInputs(a)...)
	jobToken := DefaultHeldToken(a)
	for k, x := range steps {
		if !order.DoneBefore(k, at) || x.Uses.Status != workflow.Present || !calls.IsCheckout(x.Uses.Value) {
			continue
		}
		if _, placed := prcode.CheckoutPlacement(j, steps, order, k); !placed {
			continue // the checkout fails on its path before it writes the token
		}
		token, persist, ok := checkoutCredentials(x)
		switch {
		case !ok || !persist:
		case token.Text() == "":
			jobToken = true // actions/checkout's token defaults to the job's
		default:
			vs = append(vs, token)
		}
	}
	s := job.SecretsOf(vs...)
	s.Token = s.Token || jobToken
	return s
}

// checkoutCredentials are the token of the checkout x as written (empty
// for the default, the job's) and whether it persists it: actions/checkout
// reads persist-credentials as true only for true in any case, and
// defaults it to true (its input-helper.ts); a ${{ }} is read as not, so
// that the agent is not taken to hold what it may not. ok is false for a
// with that is a ${{ }}.
func checkoutCredentials(x workflow.Step) (token workflow.String, persist, ok bool) {
	switch x.With.Status {
	case workflow.Dynamic:
		return workflow.String{}, false, false
	case workflow.Present:
	default:
		return workflow.String{}, true, true
	}
	if e, found := x.With.Value.Lookup("persist-credentials"); found &&
		(e.Value.Status != workflow.Present || e.Value.Value.Parts != nil || !strings.EqualFold(strings.TrimSpace(e.Value.Value.AsString()), "true")) {
		return workflow.String{}, false, true
	}
	if e, found := x.With.Value.Lookup("token"); found && e.Value.Status == workflow.Present {
		return e.Value.Value, true, true
	}
	return workflow.String{}, true, true
}
