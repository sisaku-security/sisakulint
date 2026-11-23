package taint

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// unsecureCommandsVar is the variable whose true lets the runner read the
// set-env and add-path commands in the log.
const unsecureCommandsVar = "ACTIONS_ALLOW_UNSECURE_COMMANDS"

// UnsecureFlag is ACTIONS_ALLOW_UNSECURE_COMMANDS in the env context of
// the step of a run: its state, and where it is set (Value, for the env of
// the workflow, the job or the step).
type UnsecureFlag struct {
	State analysis.UnsecureState
	Place analysis.FlagPlace
	Value workflow.String
}

// LogWrite is a reference an attacker may control that a run of bash or
// sh prints to its log: a ${{ }} (RefIndex, its index in Sink.Refs) or a
// variable of env (RefIndex -1: Var, and what env gives it, Env). Span is
// the reference in the value of the sink.
type LogWrite struct {
	RefIndex int
	Var      shell.VarName
	Env      ExprRef
	Span     expr.Span
}

// unsecureFlagOf is the flag of the step of c: the step's env, then what a
// step before wrote to $GITHUB_ENV, then the job's and the workflow's env.
func (c scope) unsecureFlagOf(f *secretFlow) UnsecureFlag {
	places := []analysis.FlagPlace{analysis.FlagPlaceStep, analysis.FlagPlaceJob, analysis.FlagPlaceWorkflow}
	for lvl, e := range c.envs {
		if lvl == 1 {
			if w, ok := f.crossWrite(unsecureCommandsVar); ok {
				if !w.literal {
					return UnsecureFlag{State: analysis.UnsecureExpression, Place: analysis.FlagPlaceGitHubEnv}
				}
				return UnsecureFlag{State: unsecureOf(w.value), Place: analysis.FlagPlaceGitHubEnv}.on()
			}
		}
		if e.Status == workflow.Dynamic {
			return UnsecureFlag{State: analysis.UnsecureExpression, Place: places[lvl]}
		}
		if e.Status != workflow.Present {
			continue
		}
		x, ok := e.Value.Lookup(unsecureCommandsVar)
		if !ok || x.Key.AsString() != unsecureCommandsVar || x.Value.Status != workflow.Present {
			continue
		}
		v := x.Value.Value
		if slices.ContainsFunc(v.Parts, func(p workflow.Part) bool { return p.Expr }) {
			return UnsecureFlag{State: analysis.UnsecureExpression, Place: places[lvl], Value: v}
		}
		return UnsecureFlag{State: unsecureOf(v.AsString()), Place: places[lvl], Value: v}.on()
	}
	if len(c.envs) == 1 { // an action.yml: $GITHUB_ENV is after the step's env
		if w, ok := f.crossWrite(unsecureCommandsVar); ok {
			if !w.literal {
				return UnsecureFlag{State: analysis.UnsecureExpression, Place: analysis.FlagPlaceGitHubEnv}
			}
			return UnsecureFlag{State: unsecureOf(w.value), Place: analysis.FlagPlaceGitHubEnv}.on()
		}
	}
	return UnsecureFlag{}
}

// on is f, with no place when it is off.
func (f UnsecureFlag) on() UnsecureFlag {
	if f.State == analysis.UnsecureOff {
		return UnsecureFlag{}
	}
	return f
}

// unsecureOf is how the runner reads the value v: bool.TryParse, which
// takes true in any case with blanks around it.
func unsecureOf(v string) analysis.UnsecureState {
	if strings.EqualFold(strings.TrimSpace(v), "true") {
		return analysis.UnsecureOn
	}
	return analysis.UnsecureOff
}

// crossWrite is the last write of name to $GITHUB_ENV of the steps done
// before the step of f.
func (f *secretFlow) crossWrite(name string) (secretFileWrite, bool) {
	c := f.c
	for i := len(c.before) - 1; i >= 0; i-- {
		if !c.order.DoneBefore(c.before[i].Order, len(c.before)) {
			continue
		}
		ws := c.writesOf(i)
		for j := len(ws) - 1; j >= 0; j-- {
			if ws[j].file == analysis.EnvironmentFileEnv && ws[j].name == name {
				return ws[j], true
			}
		}
	}
	return secretFileWrite{}, false
}

// unsecureCommands reads into s the flag of its step and, when the flag
// may be on and a step may run after it (set-env and add-path) or when the
// step has an id (set-output), the references an attacker may control that
// the run prints to its log, set -x included.
func (c scope) unsecureCommands(s *Sink, f *secretFlow) {
	s.UnsecureFlag = c.unsecureFlagOf(f)
	if (s.UnsecureFlag.State == analysis.UnsecureOff || !s.HasStepAfter) && !s.HasStepID {
		return
	}
	seen := map[expr.Span]bool{}
	add := func(w LogWrite) {
		if !seen[w.Span] {
			seen[w.Span] = true
			s.LogWrites = append(s.LogWrites, w)
		}
	}
	hole := func(i int) {
		for ri, r := range s.Refs {
			if r.Part == f.holes[i].part && r.Verdict != analysis.NotControlled {
				add(LogWrite{RefIndex: ri, Span: r.Span})
			}
		}
	}
	var param func(p *shell.Part)
	param = func(p *shell.Part) {
		if x := p.Param; x != nil {
			for _, w := range x.ValueWords() { // ${X:-$V}: $V when X is empty
				for i := range w.Parts {
					if q := &w.Parts[i]; q.Kind == shell.PartParam || q.Kind == shell.PartParamOp {
						param(q)
					}
				}
			}
		}
		name := p.Name.String()
		if e := expansionOf(*p); e.drop || e.opaque || f.assigned(name, p.Span.Start) {
			return // not the value of env: a length, or what the script assigns
		}
		if r, ok := c.varRef(name); ok && r.Verdict != analysis.NotControlled {
			add(LogWrite{RefIndex: -1, Var: p.Name, Env: r, Span: expr.Span{Start: p.Span.Start, End: p.Span.End}})
		}
	}
	parts := func(ps []shell.Part) {
		for i := range ps {
			p := &ps[i]
			switch p.Kind {
			case shell.PartParam, shell.PartParamOp:
				param(p)
			case shell.PartLiteral:
				for h, hs := range f.holes {
					if hs.span.Start >= p.Span.Start && hs.span.End <= p.Span.End {
						hole(h)
					}
				}
			}
		}
	}
	// what a command not read writes: the words and the input of the
	// commands in it whose output is printed and that write them as they
	// are (echo -e, a pipe to tee or cat, $(echo ...) in their words);
	// another command's output, and what a pipe gives to another command,
	// are not read (other-output)
	var commands func(cs []shell.Command)
	// printed reads the simple command c, whose output is printed
	var printed func(c *shell.Simple)
	printed = func(c *shell.Simple) {
		if len(c.Words) == 0 {
			return
		}
		if n, ok := shell.Literal(f.text, c.Words[0]); !ok || !identityCommands[n] {
			return
		}
		for _, w := range c.Words[1:] {
			parts(w.Parts)
			for _, p := range w.Parts {
				if p.Sub != nil {
					commands(p.Sub.List)
				}
			}
		}
		for _, r := range c.Redirects {
			switch {
			case r.Op == shell.RedirHereString:
				parts(r.Target.Parts)
			case r.Heredoc != nil && !r.Heredoc.Quoted:
				parts(r.Heredoc.Parts)
			}
		}
	}
	commands = func(cs []shell.Command) {
		shell.Walk(f.text, cs, shell.Enclosing{}, shell.Visitor{Descriptors: &shell.DescriptorReading{}, Command: func(c shell.Command, at shell.Enclosing) bool {
			if at.Env.Kind == shell.ExecutionEnvironmentCommandSubstitution || at.Env.Kind == shell.ExecutionEnvironmentProcessSubstitution {
				return false // read with the words that hold them
			}
			switch c := c.(type) {
			case *shell.Simple:
				if at.Stdout == shell.StdoutLog { // not a coproc's, nor one a redirect around takes (Walk)
					printed(c)
				}
				return false
			case *shell.Pipeline:
				// the last command prints; one before prints through the
				// commands after it when each writes its input as it is
				// (cat, tee: shell.PipePassageVerbatim)
				n := len(c.Commands)
				commands(c.Commands[n-1:])
				if x, ok := c.Commands[n-1].(*shell.Simple); ok && len(x.Words) > 0 && copiesInput(f.text, x) {
					for _, src := range shell.PipeSources(f.text, c, n-1) {
						if src.Passage == shell.PipePassageVerbatim {
							commands(c.Commands[src.Element : src.Element+1])
						}
					}
				}
				return false
			case *shell.FuncDef:
				return false
			}
			return true
		}})
	}
	for _, w := range f.logWrites() {
		for _, o := range w.Out {
			switch o.Kind {
			case shell.OutHole:
				hole(o.Hole)
			case shell.OutParam:
				param(o.Part)
			case shell.OutSubst:
				if o.Part.Sub != nil {
					commands(o.Part.Sub.List)
				}
			case shell.OutUnknown:
				commands([]shell.Command{o.Cmd})
			}
		}
	}
	for _, x := range f.traced() {
		for _, w := range shell.Words(x) {
			parts(w.Parts)
		}
	}
	slices.SortFunc(s.LogWrites, func(a, b LogWrite) int { return a.Span.Start - b.Span.Start })
}

// copiesInput is whether x writes its standard input as it is: cat and tee
// with no operand but tee's files.
func copiesInput(text string, x *shell.Simple) bool {
	n, ok := shell.Literal(text, x.Words[0])
	return ok && (n == "tee" || n == "cat" && len(x.Words) == 1)
}
