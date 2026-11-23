package ir

import (
	"github.com/gh-intel/sisakulint/actions/agent"
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// place makes the handles on the elements of one file: of the input of x,
// or, when origin is set, of the file of an action of another repository
// (the value of action.definition) that a step of the input runs.
type place struct {
	x      *IR
	origin *composite.Origin
}

// inputPlace is the place of the input of x.
func (x *IR) inputPlace() place { return place{x: x} }

// handle is the handle on the element b.
func (p place) handle(b workflow.Base) Handle {
	if p.origin == nil {
		return p.x.handleOf(b)
	}
	return originHandle(*p.origin, b)
}

// span is the handle on the span sp of the value of v (workflow.String.Source).
func (p place) span(v workflow.String, sp expr.Span) Handle {
	if p.origin == nil {
		return p.x.spanOf(v, sp)
	}
	h := p.handle(v.Base)
	h.value, h.span, h.spanned = v.Value, sp, true
	h.src, h.exact = v.Source(sp)
	return h
}

// textAt is the handle on t.
func (p place) textAt(t agent.TextAt) Handle {
	if t.Spanned {
		return p.span(t.Value, t.Span)
	}
	return p.handle(t.Base)
}

// exprRef is x.exprRefOf with the env of r in the file of p.
func (p place) exprRef(r taint.ExprRef, t string, at Handle) ExprRef {
	if p.origin == nil {
		return p.x.exprRefOf(r, t, at)
	}
	// a composite action of another repository is read without callers:
	// its references have no with (taint.Callers), only the env of its step
	inner := r
	inner.Env = nil
	e := p.x.exprRefOf(inner, t, at)
	for _, v := range r.Env {
		e.Env = append(e.Env, p.envAt(v))
	}
	return e
}

// envAt is where the value of an env is: its first ${{ }}, or the whole value.
func (p place) envAt(v workflow.String) Handle {
	for _, pt := range v.Parts {
		if pt.Expr {
			return p.span(v, pt.Span)
		}
	}
	return p.handle(v.Base)
}

// codeRunSteps is x.codeRunSteps in the file of p.
func (p place) codeRunSteps(runs []prcode.CodeRunStep) []CodeRunStep {
	var out []CodeRunStep
	for _, e := range runs {
		at := p.handle(e.Step.Base)
		switch {
		case e.Step.Run.Status == workflow.Present && e.Span.End > e.Span.Start:
			at = p.span(e.Step.Run.Value, expr.Span{Start: e.Span.Start, End: e.Span.End})
		case e.Step.Uses.Status == workflow.Present:
			at = p.handle(e.Step.Uses.Value.Base)
		}
		out = append(out, CodeRunStep{Name: e.Name, Text: e.Text, Cite: e.Cite.String(), At: at})
	}
	return out
}
