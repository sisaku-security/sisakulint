package taint

import (
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/shell"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// SecretLeak is a value the shell made from a secret, which the runner
// does not mask, where a run prints it to its log: At is the
// value in the run (Secret.Span), Command the command that prints or
// writes it.
type SecretLeak struct {
	Secret  CarriedSecret
	Place   analysis.LogPlace
	At      expr.Span
	Command expr.Span
}

// maskRegistration is an echo of ::add-mask:: and one variable: the runner
// masks the variable's value from then on in the job.
type maskRegistration struct {
	name string
	at   int
}

// registrations are the ::add-mask:: of the run, read once.
func (f *secretFlow) registrations() []maskRegistration {
	if f.regs != nil {
		return *f.regs
	}
	var out []maskRegistration
	for _, w := range f.logWrites() {
		if name, ok := maskedName(f.text, w.Out); ok {
			out = append(out, maskRegistration{name: name, at: w.At.Span().Start})
		}
	}
	f.regs = &out
	return out
}

// maskLine is the variable of a line of ::add-mask:: (after blanks the
// runner trims) and one variable: the runner reads the line as a command
// and does not print it.
func maskLine(out []shell.Out) (*shell.Part, bool) {
	var parts []shell.Out
	for _, o := range out {
		if o.Kind == shell.OutLit && o.Text == "\n" {
			continue
		}
		parts = append(parts, o)
	}
	if len(parts) != 2 || parts[0].Kind != shell.OutLit || strings.TrimLeft(parts[0].Text, " \t") != "::add-mask::" || parts[1].Kind != shell.OutParam {
		return nil, false
	}
	return parts[1].Part, true
}

// maskedName is the variable a line of ::add-mask:: registers: the
// variable as it is ($X, ${X}, or an operator that keeps the value), not a
// part or a length of it.
func maskedName(text string, out []shell.Out) (string, bool) {
	p, ok := maskLine(out)
	if !ok {
		return "", false
	}
	name := p.Name.String()
	if !wholeValue(*p) {
		return "", false
	}
	return name, true
}

// masked is whether the variable name, read at at, holds a value a
// ::add-mask:: of the run registered before at: the same assignment (or
// env) at the registration and at at.
func (f *secretFlow) masked(name string, at int) bool {
	for _, r := range f.registrations() {
		if r.name == name && r.at < at && f.sameValue(name, r.at, at) {
			return true
		}
	}
	return false
}

// maskedInStep is whether a ::add-mask:: of the run, before at or after it,
// registers the value the variable name holds at at: the runner masks the
// value in the steps after.
func (f *secretFlow) maskedInStep(name string, at int) bool {
	for _, r := range f.registrations() {
		if r.name == name && f.sameValue(name, r.at, at) {
			return true
		}
	}
	return false
}

// logWrites are what the run writes to its log, read once.
func (f *secretFlow) logWrites() []shell.Write {
	if f.logs != nil {
		return *f.logs
	}
	w := shell.Writes(f.text, f.script, shell.WriteOptions{
		Target:      func(shell.Word) bool { return false },
		Holes:       f.holeSpans(),
		EchoEscapes: f.s.Shell == ShellSh,
		Log:         true,
		Visibility:  f.vis,
		NotRead:     &f.s.CallsNotRead,
	})
	f.logs = &w
	return w
}

func (f *secretFlow) holeSpans() []shell.Span {
	var spans []shell.Span
	for _, h := range f.holes {
		spans = append(spans, h.span)
	}
	return spans
}

// leaked is whether c is a secret the runner does not mask where it is
// printed.
func leaked(c CarriedSecret) bool {
	return c.Form == analysis.SecretFormTransformed && !c.Masked && !c.Whole
}

// secretLeaks reads into s.SecretLeaks where the run of s prints a value
// the shell made from a secret.
func (c scope) secretLeaks(s *Sink, f *secretFlow) {
	add := func(cs []CarriedSecret, place analysis.LogPlace, cmd shell.Span) {
		for _, x := range cs {
			if !leaked(x) {
				continue
			}
			l := SecretLeak{Secret: x, Place: place, At: x.Span, Command: expr.Span{Start: cmd.Start, End: cmd.End}}
			if !slices.ContainsFunc(s.SecretLeaks, func(o SecretLeak) bool {
				return o.At == l.At && o.Place == l.Place && o.Secret.Name == x.Name && o.Secret.Token == x.Token
			}) {
				s.SecretLeaks = append(s.SecretLeaks, l)
			}
		}
	}
	defer func() {
		slices.SortStableFunc(s.SecretLeaks, func(a, b SecretLeak) int { return a.At.Start - b.At.Start })
	}()
	// the standard output and error, and the job summary
	for _, w := range f.logWrites() {
		if _, ok := maskLine(w.Out); ok {
			continue // the runner reads the line and does not print it
		}
		add(f.printedSecrets(w.Out), analysis.LogPlaceStandardOutputOrError, w.At.Span())
	}
	summary := shell.Writes(f.text, f.script, shell.WriteOptions{
		Target: func(w shell.Word) bool {
			return len(w.Parts) == 1 && w.Parts[0].Kind == shell.PartParam && w.Parts[0].Name.String() == "GITHUB_STEP_SUMMARY"
		},
		Holes:       f.holeSpans(),
		EchoEscapes: s.Shell == ShellSh,
		NotRead:     &s.CallsNotRead,
		Visibility:  f.vis,
	})
	for _, w := range summary {
		if !w.Exec {
			add(f.printedSecrets(w.Out), analysis.LogPlaceJobSummary, w.At.Span())
		}
	}
	// the message of ${NAME:?word}, which bash prints on the standard error
	// when NAME is empty, before the command runs
	for _, p := range shell.Params(f.script.List) {
		if x := p.Param; x != nil && x.Op == shell.ParamOpError && len(x.Words) == 1 {
			add(f.secretsInParts(x.Words[0].Parts, x.Words[0].Span.Start, p.Span.Start, 0), analysis.LogPlaceStandardOutputOrError, p.Span)
		}
	}
	// set -x
	for _, x := range f.traced() {
		var cs []CarriedSecret
		for _, w := range append(slices.Clone(x.Assigns), x.Words...) {
			cs = append(cs, f.secretsInParts(w.Parts, w.Span.Start, x.Span().Start, 0)...)
		}
		add(cs, analysis.LogPlaceXtrace, x.Span())
	}
	// $GITHUB_ENV, printed in the header of each step after
	if c.laterStep() {
		for _, w := range f.fileWrites() {
			if w.file == analysis.EnvironmentFileEnv {
				add(w.secrets, analysis.LogPlaceGitHubEnv, w.at)
			}
		}
	}
	// the ${{ }} of the run, printed in the header of the step
	for _, h := range f.holes {
		tree := s.Value.Parts[h.part].Tree
		if tree == nil {
			continue
		}
		add(f.exprSecrets(tree, expr.Span{Start: h.span.Start, End: h.span.End}, shell.VarName{}, 0), analysis.LogPlaceStepHeader, h.span)
	}
}

// printedSecrets are the secrets what a command prints carries: its
// variables, substitutions and pipelines. A ${{ }} is the step header's.
func (f *secretFlow) printedSecrets(out []shell.Out) []CarriedSecret {
	var cs []CarriedSecret
	for _, o := range out {
		switch o.Kind {
		case shell.OutParam:
			cs = append(cs, f.secretsInParts([]shell.Part{*o.Part}, o.Span.Start, o.Span.Start, 0)...)
		case shell.OutSubst:
			if o.Part.Sub != nil {
				for _, x := range f.substitutionSecrets(*o.Part, o.Span.Start, 0, nil) {
					x.Span = expr.Span{Start: o.Span.Start, End: o.Span.End}
					cs = append(cs, x)
				}
			}
		case shell.OutUnknown:
			cs = append(cs, f.writerSecrets(o)...)
		}
	}
	return cs
}

// writerSecrets are the secrets the piece o, not known, of what a command
// writes (shell.Writes) carries: what its command writes, read as it was
// before the readings of descriptors, every simple command of it (a call
// and the bodies of its functions) writing what it may write wherever its
// descriptors point (shell.OutputReading.BeginBlind); for a pipeline, what
// its last command writes wherever its own redirects point
// (shell.OutputReading.BeginPipeline). Reading the piece where its command
// runs, with the descriptors there, waits for a reading of the data flow of
// the shell's variables.
func (f *secretFlow) writerSecrets(o shell.Out) []CarriedSecret {
	if p, ok := o.Cmd.(*shell.Pipeline); ok && o.By == nil {
		return f.outputSecretsOf([]shell.Command{p}, nil, o.Span.Start, 0, func() *shell.DescriptorReading { return f.out.BeginPipeline(p) })
	}
	return f.outputSecretsOf([]shell.Command{o.Cmd}, nil, o.Span.Start, 0, f.out.BeginBlind)
}

// traced are the simple commands set -x traces: those of the items of
// the script's list from a set -x (-o xtrace) to a set +x (+o xtrace),
// and from the start of the script when the shell of the step starts with
// xtrace on (Sink.XTrace: a shell: with -x); in the body of a function,
// from a set -x in the body.
func (f *secretFlow) traced() []*shell.Simple {
	var out []*shell.Simple
	// on is the trace in each shell: a subshell, a command of a pipeline
	// and a substitution run in a child shell, which takes the state where
	// it starts and does not give it back; a function's body is read where
	// a call sees it, in the shell of the call (shell.NameVisibility), and a
	// body no call sees is read off, where it is defined
	on := map[*shell.ExecutionEnvironment]bool{}
	var saved []bool // the state before each function's body
	var state func(env *shell.ExecutionEnvironment) bool
	state = func(env *shell.ExecutionEnvironment) bool {
		if v, ok := on[env]; ok {
			return v
		}
		v := f.s.XTrace // the shell of the step starts as its shell: says
		if env.Parent != nil {
			v = state(env.Parent) // a shell starts with the state of its parent, seen or not
		}
		on[env] = v
		return v
	}
	calling := map[*shell.FuncDef]bool{}
	calls := 0 // the bodies read at calls, up to maxTracedCalls
	var walk func(cs []shell.Command, start shell.Enclosing)
	walk = func(cs []shell.Command, start shell.Enclosing) {
		shell.Walk(f.text, cs, start, shell.Visitor{
			Command: func(c shell.Command, at shell.Enclosing) bool {
				now := state(at.Env)
				switch c := c.(type) {
				case *shell.FuncDef:
					saved = append(saved, now)
					if len(f.vis.Calls(c)) > 0 {
						return false // read where it is called
					}
					on[at.Env] = false // a body no call sees: read off, where it is defined
				case *shell.Simple:
					if v, ok := f.xtraceSet(c); ok {
						if now && !v {
							out = append(out, c) // set +x is traced itself
						}
						on[at.Env] = v
						return false
					}
					if now {
						out = append(out, c)
					}
				}
				return true
			},
			Leave: func(c shell.Command, at shell.Enclosing) {
				switch c := c.(type) {
				case *shell.FuncDef:
					on[at.Env] = saved[len(saved)-1]
					saved = saved[:len(saved)-1]
				case *shell.Simple:
					// a function's body runs where it is called, in the shell
					// that calls it: with the trace there, and a set -x in it
					// stays after the call
					words := c.Words
					if len(words) == 0 {
						return
					}
					n, ok := shell.Literal(f.text, words[0])
					if !ok {
						return
					}
					defs, _ := f.vis.Functions(n, c.Span())
					for _, d := range defs {
						if calling[d] {
							continue
						}
						if calls >= maxTracedCalls {
							f.s.CallsNotRead.Add(c.Span())
							continue
						}
						calls++
						calling[d] = true
						body := at
						body.Func = d
						walk([]shell.Command{d.Body}, body)
						calling[d] = false
					}
				}
			},
		})
	}
	walk(f.script.List, shell.Enclosing{})
	// a body read at two calls gives its commands once
	seen := map[*shell.Simple]bool{}
	out = slices.DeleteFunc(out, func(x *shell.Simple) bool {
		if seen[x] {
			return true
		}
		seen[x] = true
		return false
	})
	return out
}

// maxTracedCalls is how many calls of functions traced reads the bodies
// of: functions that call others twice make the calls exponential.
const maxTracedCalls = 1 << 12

// xtraceSet is what a set command x does to the trace: on, off, or
// nothing (false).
func (f *secretFlow) xtraceSet(x *shell.Simple) (bool, bool) {
	if len(x.Words) < 2 {
		return false, false
	}
	if n, ok := shell.Literal(f.text, x.Words[0]); !ok || n != "set" {
		return false, false
	}
	set, changed := false, false
	for i := 1; i < len(x.Words); i++ {
		w, ok := shell.Literal(f.text, x.Words[i])
		if !ok {
			continue
		}
		if w == "--" || w == "-" {
			break // the words after are the parameters
		}
		if len(w) < 2 || w[0] != '-' && w[0] != '+' || strings.HasPrefix(w, "--") {
			continue
		}
		on := w[0] == '-'
		if strings.Contains(w[1:], "x") {
			set, changed = on, true
		}
		// -o, or a cluster that ends in o (-eo), takes the next word
		if strings.HasSuffix(w, "o") && i+1 < len(x.Words) {
			if v, ok := shell.Literal(f.text, x.Words[i+1]); ok && v == "xtrace" {
				set, changed = on, true
			}
			i++
		}
	}
	return set, changed
}

// laterStep is whether a step of the job (or the action) starts after
// the step of c is done: one of the same parallel group does not.
func (c scope) laterStep() bool {
	cur := len(c.before)
	for _, s := range c.all {
		if c.order.DoneBefore(cur, s.Order) {
			return true
		}
	}
	return false
}

// PrintedOutput is a ${{ }} of a step's env, with or name, or of a job's
// env, that reads an output (steps.<id>.outputs, needs.<job>.outputs)
// whose value the shell made from a secret: the runner prints the value,
// evaluated, in the header of the step, or of each step of the job. Part is
// the ${{ }}'s part of Value.
type PrintedOutput struct {
	Value  workflow.String
	Part   int
	Secret CarriedSecret
}

// PrintedOutputs are the PrintedOutputs of w, or of the composite steps of
// a, with what AnalyzeIn reads (cl, name).
func PrintedOutputs(cl *Callers, name calls.Node, w *workflow.Workflow, a *workflow.ActionMetadata) []PrintedOutput {
	var out []PrintedOutput
	jobs := map[*workflow.Job]bool{}
	walk(cl, name, w, a, nil, func(c scope, s workflow.Step) {
		var vals []workflow.String
		if c.job != nil && len(c.before) == 0 && !jobs[c.job] {
			jobs[c.job] = true
			vals = append(vals, mapValues(c.job.Env)...)
		}
		if s.Name.Status == workflow.Present {
			vals = append(vals, s.Name.Value)
		}
		vals = append(vals, mapValues(s.Env)...)
		vals = append(vals, mapValues(s.With)...)
		for _, v := range vals {
			for i, p := range v.Parts {
				if !p.Expr || p.Tree == nil {
					continue
				}
				for _, x := range c.outputCarried(p.Tree, 0) {
					if leaked(x) {
						out = append(out, PrintedOutput{Value: v, Part: i, Secret: x})
					}
				}
			}
		}
	})
	return out
}

// mapValues are the values of m that are there.
func mapValues(m workflow.Field[workflow.Map[workflow.String]]) []workflow.String {
	if m.Status != workflow.Present {
		return nil
	}
	var out []workflow.String
	for _, e := range m.Value.Entries {
		if e.Value.Status == workflow.Present {
			out = append(out, e.Value.Value)
		}
	}
	return out
}
