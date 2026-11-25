package labeler

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// chain is one way an input runs on an attacker's events: evs are the
// events of the on of the workflow at its top, ifs the ifs of the jobs and
// steps of the calls that lead to the input, and via those calls, from the
// one that calls the input to the one in the workflow at the top. An input
// that its own on runs has a chain with no calls.
type chain struct {
	evs []analysis.EventActivity
	ifs []attacker.PlacedIf
	via []hop
}

// hop is a call, the input it calls and the file of its caller.
type hop struct {
	call   calls.Call
	called calls.File
	caller calls.File
}

// environment is whether a job of a call of c has an environment, whose
// required reviewers may approve the run before the label.
func (c chain) environment() bool {
	return slices.ContainsFunc(c.via, func(h hop) bool {
		return h.call.Job != nil && h.call.Job.Environment.Status != workflow.Absent
	})
}

// stepsBefore are the steps that run before the step of h in the job or
// the composite action of its caller, whose outputs a value of its with
// reads; none for a job that calls a workflow.
func (h hop) stepsBefore() []workflow.Step {
	if h.call.Step == nil {
		return nil
	}
	var steps []workflow.Step
	switch {
	case h.call.Job != nil && h.call.Job.Steps.Status == workflow.Present:
		steps = h.call.Job.Steps.Value.Items
	case h.call.Job == nil && h.caller.Action != nil && h.caller.Action.Runs.Status == workflow.Present && h.caller.Action.Runs.Value.Steps.Status == workflow.Present:
		steps = h.caller.Action.Runs.Value.Steps.Value.Items
	}
	for i, x := range steps {
		if x.Base.Node == h.call.Step.Base.Node {
			return steps[:i]
		}
	}
	return nil
}

// own is the chain of w on the events of its own on.
func own(w *workflow.Workflow) chain { return chain{evs: taint.EventsOn(w, attackerEvents)} }

// chainsOf are the chains of the input name in g: its own on, and each
// chain of each caller of the repository that calls it, through the ifs of
// the call. An input that no file of the repository calls has no chain of
// a caller: a caller in another repository labels the pull requests of
// its own. A call that comes back to an input read adds nothing.
func chainsOf(g *calls.Graph, name calls.Node, seen map[calls.Node]bool) []chain {
	f, ok := g.File(name)
	if !ok || seen[name] {
		return nil
	}
	var out []chain
	if f.Workflow != nil {
		if c := own(f.Workflow); len(c.evs) > 0 {
			out = append(out, c)
		}
	}
	seen[name] = true
	defer delete(seen, name)
	for _, call := range g.CallsOf(name) {
		cf, ok := g.File(call.Caller)
		if !ok {
			continue
		}
		ifs := callIfs(cf.Workflow, call)
		for _, up := range chainsOf(g, call.Caller, seen) {
			out = append(out, chain{
				evs: up.evs,
				ifs: append(slices.Clone(ifs), up.ifs...),
				via: append([]hop{{call, f, cf}}, up.via...),
			})
		}
	}
	return out
}

// callIfs are the ifs a run of call goes through in the workflow w of its
// caller (nil for a composite action): the ifs of its job
// (attacker.JobIfs) and the if of its step.
func callIfs(w *workflow.Workflow, call calls.Call) []attacker.PlacedIf {
	var out []attacker.PlacedIf
	if call.Job != nil {
		out = append(out, attacker.JobIfs(w, call.Job)...)
	}
	if call.Step != nil {
		if call.Job != nil {
			out = append(out, attacker.StepIf(w, call.Job, call.Step.If))
		} else {
			out = append(out, attacker.StepIf(nil, nil, call.Step.If))
		}
	}
	return out
}

// resolve is the value v, written in the input that c leads to after the
// steps before, as the workflow at the top of c gives it: inputs.<id> is
// the value that the call gives under with, else the default of the
// input, else empty; secrets.<id> of a reusable workflow is the secret
// that the calling job passes, the same secret under secrets: inherit,
// else empty. The steps returned are those before the step whose job or
// composite action writes the value, which steps.<id>.outputs of the value
// reads (tokenSource). ok is false for a value that the calls do not
// tell, such as an expression that reads more than one input.
func (c chain) resolve(v workflow.String, before []workflow.Step) (workflow.String, []workflow.Step, bool) {
	defaults := 0 // a default that reads another input is read again in the same input, a few times at most
	for k := 0; k < len(c.via); k++ {
		h := c.via[k]
		if v.Parts == nil {
			return v, before, true
		}
		n, ok := onlyTree(v)
		if !ok {
			return v, before, false
		}
		if taint.JobTokenRef(n) {
			return v, before, true
		}
		p, ok := expr.AccessPath(n)
		if !ok {
			return v, before, false
		}
		switch {
		case expr.HasPrefix(p, "steps"):
			return v, before, true // a step before, read by tokenSource
		case len(p) == 2 && expr.HasPrefix(p, "inputs"):
			id := expr.FoldName(p[1].Name)
			if w, ok := withValue(h.call.With, id); ok {
				v = w
			} else if d, ok := inputDefault(h.called, id); ok && defaults < len(c.via)+4 {
				v, defaults = d, defaults+1
				k-- // a default is read in the input, not in the caller
				continue
			} else {
				v = workflow.String{}
			}
		case len(p) == 2 && expr.HasPrefix(p, "secrets"):
			if h.call.Step != nil || h.call.Job.InheritSecrets {
				continue // a composite action, in the job of its step; or the same secret
			}
			id := expr.FoldName(p[1].Name)
			if w, ok := withValue(h.call.Job.Secrets, id); ok {
				v = w
			} else {
				v = workflow.String{}
			}
		default:
			return v, before, false
		}
		before = h.stepsBefore()
	}
	return v, before, true
}

// withValue is the value that with gives the key id, compared ignoring
// the case as GitHub does.
func withValue(with workflow.Field[workflow.Map[workflow.String]], id string) (workflow.String, bool) {
	if with.Status != workflow.Present {
		return workflow.String{}, false
	}
	for _, e := range with.Value.Entries {
		if expr.FoldName(e.Key.AsString()) != id {
			continue
		}
		switch e.Value.Status {
		case workflow.Present:
			return e.Value.Value, true
		case workflow.Dynamic:
			return workflow.String{Parts: []workflow.Part{{Expr: true}}}, true
		}
	}
	return workflow.String{}, false
}

// inputDefault is the default of the input id of f: of on.workflow_call
// in a workflow, of inputs in an action.
func inputDefault(f calls.File, id string) (workflow.String, bool) {
	if w := f.Workflow; w != nil && w.On.Status == workflow.Present {
		if ev, ok := w.On.Value.Event(workflow.EventNameWorkflowCall); ok && ev.Inputs.Status == workflow.Present {
			for _, e := range ev.Inputs.Value.Entries {
				if expr.FoldName(e.Key.AsString()) == id && e.Value.Status == workflow.Present && e.Value.Value.Default.Status == workflow.Present {
					return e.Value.Value.Default.Value, true
				}
			}
		}
	}
	if a := f.Action; a != nil && a.Inputs.Status == workflow.Present {
		for _, e := range a.Inputs.Value.Entries {
			if expr.FoldName(e.Key.AsString()) == id && e.Value.Status == workflow.Present && e.Value.Value.Default.Status == workflow.Present {
				return e.Value.Value.Default.Value, true
			}
		}
	}
	return workflow.String{}, false
}
