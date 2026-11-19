package job

import (
	"slices"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// DispatchInputs is whether a ${{ }} of s refers to an input of
// workflow_dispatch (inputs.<name>, github.event.inputs.<name>), anywhere in
// it, also where it is only compared: whoever dispatches the workflow then
// chooses the value. It is false unless w has workflow_dispatch; when w also has
// workflow_call, the inputs are still the dispatch's, as a run of
// workflow_dispatch takes any value (actions/taint reads them the same). A
// nil w has none.
func DispatchInputs(w *workflow.Workflow, s workflow.String) bool {
	if w == nil || w.On.Status != workflow.Present {
		return false
	}
	if _, ok := w.On.Value.Event(workflow.EventNameWorkflowDispatch); !ok {
		return false
	}
	for _, p := range s.Parts {
		if p.Expr && p.Tree != nil && refersToInputs(p.Tree) {
			return true
		}
	}
	return false
}

// refersToInputs is whether n has a reference to inputs or
// github.event.inputs, or one in the index of another reference.
func refersToInputs(n expr.Node) bool {
	if p, ok := expr.AccessPath(n); ok {
		if expr.HasPrefix(p, "inputs") || expr.HasPrefix(p, "github", "event", "inputs") {
			return true
		}
		return slices.ContainsFunc(p, func(e expr.PathElem) bool { return e.Dynamic != nil && refersToInputs(e.Dynamic) })
	}
	for _, c := range expr.Children(n) {
		if refersToInputs(c) {
			return true
		}
	}
	return false
}
