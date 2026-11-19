package attacker

import (
	"slices"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// StatusFunctions adds to seen the status functions n calls that seen does
// not have: GitHub evaluates an if that calls none as if success() && were
// written before the if, and an if that calls one as written (the runner's
// copy of the rule:
// https://github.com/actions/runner/blob/v2.337.0/src/Sdk/WorkflowParser/Conversion/WorkflowTemplateConverter.cs,
// ConvertToIfCondition).
func StatusFunctions(n expr.Node, seen []analysis.StatusFunction) []analysis.StatusFunction {
	if c, ok := n.(*expr.Call); ok {
		if f, ok := analysis.ParseStatusFunction(c.Name); ok && !slices.Contains(seen, f) {
			seen = append(seen, f)
		}
	}
	for _, c := range expr.Children(n) {
		seen = StatusFunctions(c, seen)
	}
	return seen
}

// IfTree is the expression GitHub evaluates for the if c, read in its
// syntax tree: the tree of an if of one expression (workflow.IfExpr,
// workflow.IfBare). An if of exactly ${{ 'always()' }} is already read as
// the expression always() by the model (workflow.If.Folded). A mixed if
// (workflow.IfMixed), an empty one, no if, and a syntax error have none.
func IfTree(c workflow.Field[workflow.If]) (expr.Node, bool) {
	if c.Status != workflow.Present || c.Value.Form == workflow.IfMixed || c.Value.Form == workflow.IfEmpty {
		return nil, false
	}
	if c.Value.Expr == nil || c.Value.Expr.Tree == nil {
		return nil, false
	}
	return c.Value.Expr.Tree, true
}

// HasStatusFunction is whether the if c calls a status function, read in
// its syntax trees: always () is always(), and a string that has always( is
// no call. A mixed if (workflow.IfMixed: text around its ${{ }}, or more
// than one) calls one when any of its ${{ }} does, as the template reader
// makes the whole if one expression of format(). Any other if calls one
// when its IfTree does. An if with a syntax error has none.
func HasStatusFunction(c workflow.Field[workflow.If]) bool {
	if c.Status == workflow.Present && c.Value.Form == workflow.IfMixed {
		for _, p := range c.Value.Parts {
			if p.Expr && p.Tree != nil && len(StatusFunctions(p.Tree, nil)) > 0 {
				return true
			}
		}
		return false
	}
	tree, ok := IfTree(c)
	return ok && len(StatusFunctions(tree, nil)) > 0
}

// TrueOnlyOnSuccess is whether the if c can be true only when success() is
// true: for the if of a job, when every job that the job depends on through
// needs succeeded; for the if of a step, when no step before failed. GitHub
// adds success() && to an if that calls no status function, so such an if
// is one. An if that calls a status function is one when the if is false
// with success() false, always() true, and failure(), cancelled() and every
// reference not known (success() && X, for one). A mixed if that calls a
// status function is not one. An if with a syntax error is one when
// HasStatusFunction finds no status function in it (GitHub does not accept
// the workflow).
func TrueOnlyOnSuccess(c workflow.Field[workflow.If]) bool {
	if !HasStatusFunction(c) {
		return true
	}
	tree, ok := IfTree(c)
	if !ok {
		return false
	}
	override := func(n expr.Node) (expr.Value, bool) {
		call, ok := n.(*expr.Call)
		if !ok || len(call.Args) != 0 {
			return expr.Value{}, false
		}
		switch f, _ := analysis.ParseStatusFunction(call.Name); f {
		case analysis.StatusFunctionSuccess:
			return expr.Bool(false), true
		case analysis.StatusFunctionAlways:
			return expr.Bool(true), true
		}
		return expr.Value{}, false
	}
	none := func([]expr.PathElem) (expr.Value, bool) { return expr.Value{}, false }
	return expr.PartialWith(tree, none, override).Truthy() == expr.TruthFalse
}
