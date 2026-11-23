package prcode

import (
	"github.com/sisaku-security/sisakulint/actions/attacker"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/job"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// checkoutDispatchInputs are the inputs of a checkout whose value, when an
// input of workflow_dispatch gives it, lets whoever dispatches the workflow
// choose what the checkout brings.
var checkoutDispatchInputs = []analysis.CheckoutInput{analysis.CheckoutInputRef, analysis.CheckoutInputRepository}

// dispatchOn is the runs of workflow_dispatch of w's own on that ifs let
// through: none for a remote called workflow (name), whose own
// workflow_dispatch starts runs in its repository.
func dispatchOn(t attacker.Table, name calls.Node, w *workflow.Workflow, ifs ...attacker.PlacedIf) []analysis.EventActivity {
	if _, remote := name.Remote(); w == nil || remote {
		return nil
	}
	return taint.Filter(t, taint.EventsOn(w, []workflow.EventName{workflow.EventNameWorkflowDispatch}), ifs...)
}

// checkoutDispatchInput is whether an input of checkoutDispatchInputs in
// with refers to an input of workflow_dispatch of w.
func checkoutDispatchInput(w *workflow.Workflow, with workflow.Field[workflow.Map[workflow.String]]) bool {
	if with.Status != workflow.Present {
		return false
	}
	return slices.ContainsFunc(checkoutDispatchInputs, func(in analysis.CheckoutInput) bool {
		e, ok := with.Value.Lookup(in.String())
		return ok && e.Value.Status == workflow.Present && job.DispatchInputs(w, e.Value.Value)
	})
}

// anyDispatchInput is whether an input in with refers to an input of
// workflow_dispatch of w: the inputs a download may read, of which
// markDispatch keeps those that its release reads.
func anyDispatchInput(w *workflow.Workflow, with workflow.Field[workflow.Map[workflow.String]]) bool {
	return with.Status == workflow.Present && slices.ContainsFunc(with.Value.Entries, func(e workflow.Entry[workflow.String]) bool {
		return e.Value.Status == workflow.Present && job.DispatchInputs(w, e.Value.Value)
	})
}

// callFromPR is whether the input a step reads is, besides the dispatcher's,
// the caller's on a call from an event of a pull request: w is also called
// (workflow_call) and the step runs on such an event.
func callFromPR(w *workflow.Workflow, input bool, prCodeOn []analysis.EventActivity) bool {
	if !input || len(prCodeOn) == 0 || w.On.Status != workflow.Present {
		return false
	}
	_, ok := w.On.Value.Event(workflow.EventNameWorkflowCall)
	return ok
}

// dispatcherChooses is whether the inputs of workflow_dispatch are the only
// references of f the tables cannot tell, and only the one who dispatches
// the workflow chooses them (CheckoutSite.dispatcherChooses).
func (s *DownloadSite) dispatcherChooses(f workflow.Field[workflow.String]) bool {
	if !s.DispatchInput || s.CallFromPR || f.Status != workflow.Present {
		return false
	}
	dispatch, other := false, false
	for _, p := range f.Value.Parts {
		if !p.Expr || p.Tree == nil {
			continue
		}
		taint.WrittenRefs(p.Tree, func(n expr.Node) {
			pth, _ := expr.AccessPath(n)
			switch {
			case isDispatchInput(pth):
				dispatch = true
			case len(pth) > 0 && !match(pth, []string{"github", "run_id"}) && !match(pth, []string{"github", "token"}) && !isBaseRepoPath(pth):
				other = true
			}
		})
	}
	return dispatch && !other
}

// isDispatchInput is whether pth is inputs.<name> or github.event.inputs.<name>.
func isDispatchInput(pth []expr.PathElem) bool {
	return expr.HasPrefix(pth, "inputs") || expr.HasPrefix(pth, "github", "event", "inputs")
}

// markDispatch records that read reads f, an input that chooses the run,
// when f refers to an input of workflow_dispatch (DispatchInput is then
// what read reads, not what the with has).
func (s *DownloadSite) markDispatch(f workflow.Field[workflow.String]) {
	if !s.DispatchInput || f.Status != workflow.Present {
		return
	}
	for _, p := range f.Value.Parts {
		if p.Expr && p.Tree != nil {
			taint.WrittenRefs(p.Tree, func(n expr.Node) {
				if pth, _ := expr.AccessPath(n); isDispatchInput(pth) {
					s.dispatchRead = true
				}
			})
		}
	}
}
