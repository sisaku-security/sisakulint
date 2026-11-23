package taint

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
)

// VariableCode is a variable of env (or one the runner writes) whose value
// a run of bash reads as code (shell.VariableCodes): its name, where it is
// in the run, how the value is read, and what env gives it (Ref:
// Controlled or Inconclusive).
type VariableCode struct {
	Var     shell.VarName
	Span    expr.Span
	Reading analysis.CodeReading
	Ref     ExprRef
}

// codeReadings are the values of shell.CodeReading as analysis has them.
var codeReadings = map[shell.CodeReading]analysis.CodeReading{
	shell.CodeReadingCodeArgument:    analysis.CodeReadingCodeArgument,
	shell.CodeReadingCommandWord:     analysis.CodeReadingCommandWord,
	shell.CodeReadingCodeInput:       analysis.CodeReadingCodeInput,
	shell.CodeReadingArithmetic:      analysis.CodeReadingArithmetic,
	shell.CodeReadingPromptExpansion: analysis.CodeReadingPromptExpansion,
}

// variableCodes reads into s, a run of bash, the variables that env gives
// a value an attacker may control and that the run reads as code. A
// variable the script assigns before the place is not the value of env. As
// the command word and as arithmetic, the value runs only with blanks or a
// [ in it: there it counts on the events on which an attacker writes it
// freely (Lines).
func (c scope) variableCodes(s *Sink, f *secretFlow) {
	for _, v := range shell.VariableCodes(f.text, f.script) {
		name := v.Name.String()
		if f.assigned(name, v.Span.Start) { // also the name of for and select (shell.NameVisibility)
			continue
		}
		r, ok := c.varRef(name)
		if !ok || r.Verdict == analysis.NotControlled {
			continue
		}
		reading := codeReadings[v.Reading]
		if r.Verdict == analysis.Controlled && (reading == analysis.CodeReadingCommandWord || reading == analysis.CodeReadingArithmetic) {
			r.ControlledOn = slices.DeleteFunc(slices.Clone(r.ControlledOn), func(e analysis.EventActivity) bool { return !slices.Contains(r.Lines, e) })
			r.EveryRunOn = slices.DeleteFunc(slices.Clone(r.EveryRunOn), func(e analysis.EventActivity) bool { return !slices.Contains(r.Lines, e) })
			if len(r.ControlledOn) == 0 {
				continue
			}
		}
		s.VariableCodes = append(s.VariableCodes, VariableCode{Var: v.Name, Span: expr.Span{Start: v.Span.Start, End: v.Span.End}, Reading: reading, Ref: r})
	}
}
