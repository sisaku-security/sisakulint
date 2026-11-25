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

// hop is a call and the input it calls.
type hop struct {
	call   calls.Call
	called calls.File
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
				via: append([]hop{{call, f}}, up.via...),
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

// resolve is the value v, written in the input that c leads to, as the
// workflow at the top of c gives it: inputs.<id> is the value that the
// call gives under with, else the default of the input, else empty;
// secrets.<id> of a reusable workflow is the secret that the calling job
// passes, the same secret under secrets: inherit, else empty. ok is false
// for a value that the calls do not tell, such as an expression that reads
// more than one input.
func (c chain) resolve(v workflow.String) (workflow.String, bool) {
	for k, h := range c.via {
		if v.Parts == nil {
			return v, true
		}
		n, ok := onlyTree(v)
		if !ok {
			return v, false
		}
		if taint.JobTokenRef(n) {
			return v, true
		}
		p, ok := expr.AccessPath(n)
		if !ok || len(p) != 2 && !(k == 0 && expr.HasPrefix(p, "steps")) {
			return v, false
		}
		switch {
		case expr.HasPrefix(p, "steps"):
			return v, true // a step of the input itself, before the step (tokenSource)
		case expr.HasPrefix(p, "inputs"):
			id := expr.FoldName(p[1].Name)
			if w, ok := withValue(h.call.With, id); ok {
				v = w
			} else if d, ok := inputDefault(h.called, id); ok {
				v = d
			} else {
				v = workflow.String{}
			}
		case expr.HasPrefix(p, "secrets"):
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
			return v, false
		}
	}
	return v, true
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
