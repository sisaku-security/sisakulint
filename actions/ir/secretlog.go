package ir

import (
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/taint"
)

// secretLeakOf is the projection of l, a leak of the run s.
func (x *IR) secretLeakOf(s taint.Sink, l taint.SecretLeak) SecretLeak {
	return SecretLeak{Secret: l.Secret.Name, Token: l.Secret.Token, Place: l.Place, Transform: l.Secret.Transform.String(),
		At: x.spanOf(s.Value, l.At), Command: x.spanOf(s.Value, l.Command)}
}

// logWriteOf is the projection of w, a reference the run s, whose text is
// text, prints to its log.
func (x *IR) logWriteOf(s taint.Sink, w taint.LogWrite, text string) LogWrite {
	o := LogWrite{Text: text[w.Span.Start:w.Span.End], RefIndex: w.RefIndex, At: x.spanOf(s.Value, w.Span)}
	r := w.Env
	if w.RefIndex >= 0 {
		r = s.Refs[w.RefIndex]
	} else {
		o.Var = x.exprRefOf(w.Env, o.Text, o.At)
	}
	o.Commands, o.CommandsUndecided, o.PathCommands = r.Commands, r.CommandsUndecided, r.PathCommands
	o.Path = expr.PathString(r.Source)
	if len(r.Source) == 0 {
		o.Path = expr.PathString(r.Path)
	}
	return o
}

func (x *IR) allPrintedOutputs() []*PrintedOutput {
	x.once(SummaryPrintedOutput, func() {
		var out []*PrintedOutput
		for _, p := range taint.PrintedOutputs(x.callersOf(), x.name, x.workflow, x.action) {
			part := p.Value.Parts[p.Part]
			out = append(out, &PrintedOutput{key: keyOf(x.paths, x.input, x.tree, p.Value.Base),
				alwaysSkipped: x.alwaysSkipped(p.Value.Base), at: x.spanOf(p.Value, part.Span),
				secret: p.Secret.Name, token: p.Secret.Token, transform: p.Secret.Transform.String(), text: p.Value.Text()[part.Span.Start:part.Span.End]})
		}
		x.printedOutputs = out
	})
	return x.printedOutputs
}
