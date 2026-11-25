package ir

// The plan of the fix of each step whose run or script has what
// an attacker controls: one fix for the step, from the analysis of
// actions/taint alone, which every rule that reports in the step gives.
// ApplyFixes applies an edit that several findings have
// once, so the fixes of code-injection, envvar-injection and
// output-clobbering in one step apply together. What each place needs
// comes from where it is written, not from which rule asks: Data where a
// shell or JavaScript reads it (the expression moves to env and the
// variable is read), OneLine where the runner reads it as a line of a file
// command (its line breaks are taken out), a random delimiter for a
// name<<DELIM whose body an attacker writes, and no fix where the runner
// reads it as a directory of $GITHUB_PATH, which no rewriting keeps from
// the attacker.

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// stepPlan is the fixes of the steps of an analysis.
type stepPlan struct {
	exprs map[exprKey]FixPlan
	vars  map[varKey]FixPlan
}

type exprKey struct{ sink, part int }
type varKey struct{ sink, start int }

// expr is what the ${{ }} part of the sink gets.
func (p *stepPlan) expr(sink, part int) FixPlan { return p.exprs[exprKey{sink, part}] }

// variable is what a variable written to a file command gets, at start
// of the value of the sink.
func (p *stepPlan) variable(sink, start int) FixPlan { return p.vars[varKey{sink, start}] }

// need is what a place needs of the fix.
type need uint8

const (
	needData    need = 1 << iota // a shell or JavaScript reads it: it moves to env
	needOneLine                  // a line of a file command: its line breaks go
	needKey                      // before the = or << of a line: no fix
	needBody                     // the body of name<<DELIM of a form not rewritten: no fix
	needLine                     // anywhere on a line of $GITHUB_PATH: no fix
)

const (
	noteKey  = "the value is written before the = or << of a line of $GITHUB_ENV or $GITHUB_OUTPUT, where taking its line breaks out does not stop it from starting another name; write it after the = by hand"
	notePath = "the value is written to $GITHUB_PATH, where it is a directory the steps after it look for commands in; no rewriting of it keeps the attacker from choosing the directory: write a fixed path by hand, not one made of the value"
	noteBody = "the value is in the body of name<<DELIM whose delimiter an attacker can write; make the delimiter random by hand (the fix does it for echo \"name<<DELIM\" … echo DELIM alone)"
)

func noteOf(n need) string {
	switch {
	case n&needLine != 0:
		return notePath
	case n&needKey != 0:
		return noteKey
	}
	return noteBody
}

// makeStepPlan plans the fix of each step of sinks, reading their scripts
// with scripts.
func makeStepPlan(scripts *shell.Memo, sinks []taint.Sink) *stepPlan {
	p := &stepPlan{exprs: map[exprKey]FixPlan{}, vars: map[varKey]FixPlan{}}
	byStep := map[cst.Node][]int{}
	var order []cst.Node
	for i, s := range sinks {
		n := s.Step.Base.Node
		if _, ok := byStep[n]; !ok {
			order = append(order, n)
		}
		byStep[n] = append(byStep[n], i)
	}
	for _, n := range order {
		p.step(scripts, sinks, byStep[n])
	}
	return p
}

type partPlan struct {
	repl    string // what stands in its place
	name    shell.VarName
	value   string // the value of a new variable; "" when the variable is in env already
	noFix   *NoFix
	effects []SideEffect // what writing repl may change besides the finding
}

// varPlace is a variable written to a file command, and what it needs.
type varPlace struct {
	key varKey
	w   taint.EnvironmentFileWrite
	n   need
}

// refOf is what an attacker controls of the value of w.
func refOf(s taint.Sink, w taint.EnvironmentFileWrite) taint.ExprRef {
	if w.RefIndex >= 0 {
		return s.Refs[w.RefIndex]
	}
	return w.Env
}

// reached is whether an attacker who controls the value of w starts a name
// of their own with it.
func reached(s taint.Sink, w taint.EnvironmentFileWrite) bool {
	return len(taint.Reach(w.Side, refOf(s, w))) > 0
}

func (p *stepPlan) step(scripts *shell.Memo, sinks []taint.Sink, idx []int) {
	first := sinks[idx[0]]
	st := first.Step
	levels := first.Envs
	taken := map[string]bool{}
	for _, l := range levels {
		if l.Status == workflow.Present {
			for _, e := range l.Value.Entries {
				taken[expr.FoldName(e.Key.AsString())] = true
			}
		}
	}
	contexts := map[int]map[int]shell.Place{} // by sink: the place of each ${{ }}, the script read once
	for _, si := range idx {
		for _, name := range identifier.FindAllString(taint.Masked(sinks[si].Value), -1) {
			taken[expr.FoldName(name)] = true // a variable of the script: the new one must not shadow it
		}
		contexts[si] = placesOf(scripts, sinks[si].Value)
	}

	// what each place needs, from where it is written
	needs := map[exprKey]need{}
	firstRef := map[exprKey]taint.ExprRef{}
	var vars []varPlace
	var docs []*taint.DelimWrite
	docSink := map[*taint.DelimWrite]int{}
	for _, si := range idx {
		s := sinks[si]
		for _, r := range s.Refs {
			if r.Verdict == analysis.Controlled {
				k := exprKey{si, r.Part}
				if _, ok := firstRef[k]; !ok {
					firstRef[k] = r
				}
				needs[k] |= needData
			}
		}
		for _, w := range s.EnvironmentFileWrites {
			if !reached(s, w) {
				continue
			}
			var n need
			switch {
			case w.Side == analysis.SideLine:
				n = needLine
			case w.Side == analysis.SideValue:
				n = needOneLine
			case w.Side == analysis.SideKey:
				n = needKey
			case w.Heredoc != nil:
				if _, ok := docSink[w.Heredoc]; !ok {
					docSink[w.Heredoc] = si
					docs = append(docs, w.Heredoc)
				}
			default:
				n = needBody
			}
			if w.RefIndex >= 0 {
				needs[exprKey{si, s.Refs[w.RefIndex].Part}] |= n
			} else if i := slices.IndexFunc(vars, func(v varPlace) bool { return v.key == varKey{si, w.Span.Start} }); i >= 0 {
				vars[i].n |= n // written to both files (tee)
			} else {
				vars = append(vars, varPlace{varKey{si, w.Span.Start}, w, n})
			}
		}
	}

	var edits []edit.Edit
	oneLined, delimited := false, false
	var effects []SideEffect // of the replacements written, each once
	add := func(e SideEffect) {
		if !slices.Contains(effects, e) {
			effects = append(effects, e)
		}
	}

	// the delimiters made random
	stuck := map[*taint.DelimWrite]bool{}
	for _, d := range docs {
		s := sinks[docSink[d]]
		// dash's echo writes the delimiter's variable as a line the reading
		// does not know
		if sharedBase(s.Step.Base) || sharedBase(s.Value.Base) || s.Shell == taint.ShellSh {
			stuck[d] = true
			continue
		}
		name := freeName("GHA_DELIM", taken)
		ins, err1 := edit.Replace(s.Value.Value, d.Insert, d.Insert, taint.RandomDelim(name)+"; ")
		op, err2 := edit.Replace(s.Value.Value, d.Open.Start, d.Open.End, delimRef(name, d.OpenQuote))
		cl, err3 := edit.Replace(s.Value.Value, d.Close.Start, d.Close.End, delimRef(name, d.CloseQuote))
		if errors.Join(err1, err2, err3) != nil {
			stuck[d] = true
			continue
		}
		edits = append(edits, ins, op, cl)
		delimited = true
		add(SideEffectRandomDelimiter)
	}

	// the bodies of the heredocs whose delimiter the fix cannot make random
	if len(stuck) > 0 {
		for _, si := range idx {
			s := sinks[si]
			for _, w := range s.EnvironmentFileWrites {
				if w.Heredoc == nil || !stuck[w.Heredoc] || !reached(s, w) {
					continue
				}
				if w.RefIndex >= 0 {
					needs[exprKey{si, s.Refs[w.RefIndex].Part}] |= needBody
				}
			}
		}
		for i := range vars {
			if vars[i].w.Heredoc != nil && stuck[vars[i].w.Heredoc] {
				vars[i].n |= needBody
			}
		}
	}

	// the expressions, in the order of the sinks and of their parts
	keys := make([]exprKey, 0, len(needs))
	for k := range needs {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b exprKey) int {
		if a.sink != b.sink {
			return a.sink - b.sink
		}
		return a.part - b.part
	})
	byValue := map[string]string{} // the value of a new variable: its name
	var newVars edit.Map
	for _, k := range keys {
		n, s := needs[k], sinks[k.sink]
		if n&(needKey|needBody|needLine) != 0 {
			p.exprs[k] = FixPlan{NoFix: manual(noteOf(n))}
			continue
		}
		pp := planPart(s, firstRef[k], levels, taken, byValue, contexts[k.sink])
		if pp.noFix == nil && n&needOneLine != 0 {
			if s.Kind != analysis.SinkRun || (s.Shell != taint.ShellBash && s.Shell != taint.ShellSh) {
				pp.noFix = manual(noteOneLine)
			} else if oneLine(pp, contexts[k.sink][s.Value.Parts[k.part].Span.Start].Quoting); pp.noFix == nil {
				oneLined = true
			}
		}
		if pp.noFix == nil {
			text := s.Value.Text()
			sp := s.Value.Parts[k.part].Span
			if s.Kind == analysis.SinkScript && strings.HasPrefix(pp.repl, "process.env.") && quoted(text, sp) {
				sp = expr.Span{Start: sp.Start - 1, End: sp.End + 1}
			}
			e, err := edit.Replace(s.Value.Value, sp.Start, sp.End, pp.repl)
			if err != nil {
				pp.noFix = form("the expression cannot be written in place (" + err.Error() + "); move it to env by hand")
			} else {
				edits = append(edits, e)
				for _, x := range pp.effects {
					add(x)
				}
				if n&needOneLine != 0 {
					add(SideEffectLineBreaksRemoved)
				}
				if pp.value != "" && !hasPair(newVars, pp.name.String()) {
					newVars = append(newVars, edit.Pair{Key: pp.name.String(), Value: edit.Str(pp.value)})
				}
			}
		}
		p.exprs[k] = FixPlan{NoFix: pp.noFix}
	}

	// the variables written to a file command
	for _, v := range vars {
		s := sinks[v.key.sink]
		var o FixPlan
		switch {
		case v.n == 0: // in the body of a heredoc whose delimiter the fix makes random
		case v.n&(needKey|needBody|needLine) != 0:
			o.NoFix = manual(noteOf(v.n))
		case v.w.Nested:
			o.NoFix = manual("the variable is in the code after -c of another shell, inside single quotes, where the quotes of the fix would end that code; take its line breaks out by hand")
		case v.w.Op:
			o.NoFix = manual("the variable has an operator (${NAME:-x} and the like); take its line breaks out by hand")
		case sharedBase(s.Step.Base) || sharedBase(s.Value.Base):
			o.NoFix = form("the step is shared through an alias (or has an anchor): writing it changes every place it is used; fix it by hand")
		default:
			repl := `$(printf '%s' "${` + v.w.Var.String() + `}" | tr -d '\n')`
			if v.w.Quote == shell.QuoteNone && !v.w.InBody {
				repl = `"` + repl + `"`
			}
			e, err := edit.Replace(s.Value.Value, v.w.Span.Start, v.w.Span.End, repl)
			if err != nil {
				o.NoFix = form("the variable cannot be written in place (" + err.Error() + "); take its line breaks out by hand")
				break
			}
			edits = append(edits, e)
			oneLined = true
			add(SideEffectLineBreaksRemoved)
		}
		p.vars[v.key] = o
	}

	// the fix of the step, to every place without a reason for none
	if len(edits) == 0 {
		return
	}
	moved := len(newVars) > 0 || slices.ContainsFunc(keys, func(k exprKey) bool { return p.exprs[k].NoFix == nil })
	if len(newVars) > 0 {
		var e edit.Editor
		var ins edit.Edit
		var err error
		switch f := st.Env; {
		case f.Status == workflow.Present && !sharedBase(f.Value.Base):
			ins, err = e.Insert(f.Value.Base.Node, edit.Last(), newVars)
		case f.Status == workflow.Absent:
			ins, err = e.Insert(st.Base.Node, edit.Last(), edit.Map{{Key: "env", Value: newVars}})
		default:
			err = fmt.Errorf("the env of the step is not a mapping of its own")
		}
		if err != nil {
			no := form("the variables cannot be added to the env of the step (" + err.Error() + "); move the expressions to env by hand")
			p.each(idx, func(o *FixPlan) {
				if o.NoFix == nil {
					o.NoFix = no
				}
			})
			return
		}
		edits = append(edits, ins)
	}
	kind := FixEnvVar
	if len(effects) > 0 {
		kind = FixEnvVarReview
	}
	if moved {
		// whatever the place, the shell no longer reads the value as
		// part of the script: every fix that moves a value is to review
		add(SideEffectValueNotReadAsScript)
	}
	slices.Sort(effects)
	var what []string
	if moved {
		what = append(what, "move the expressions of the step an attacker controls into its env")
	}
	if oneLined {
		what = append(what, "take the line breaks out of what it writes to $GITHUB_ENV or $GITHUB_OUTPUT")
	}
	if delimited {
		what = append(what, "make the delimiter of name<<DELIM random")
	}
	fix := &Fix{Kind: kind, Title: fmt.Sprintf("%s (%d edits)", strings.Join(what, ", "), len(edits)), Edits: edits, SideEffects: effects}
	p.each(idx, func(o *FixPlan) {
		if o.NoFix == nil {
			o.Fix = fix
		}
	})
}

// each calls f with every outcome of the sinks idx.
func (p *stepPlan) each(idx []int, f func(*FixPlan)) {
	for k, o := range p.exprs {
		if slices.Contains(idx, k.sink) {
			f(&o)
			p.exprs[k] = o
		}
	}
	for k, o := range p.vars {
		if slices.Contains(idx, k.sink) {
			f(&o)
			p.vars[k] = o
		}
	}
}

// noteCollection is the note of an expression whose value may be an
// object or an array (taint.Sink.CollectionParts).
const noteCollection = "before the run, the rule cannot tell whether the value of the expression is a string, an object or an array; when the whole value of a variable of env is an object or an array, the runner fails the step before its script runs, so --fix does not rewrite this expression. To fix the step by hand, make the expression give a string (toJSON(...) for an object, join(...) for an array of strings), move that expression to env, and read the variable in the script"

const noteOneLine = "the value is written to $GITHUB_ENV or $GITHUB_OUTPUT where the rule cannot take its line breaks out (inside '...', a quoted heredoc, or what another program reads); take them out by hand"

// oneLine makes the replacement of p take the line breaks out of the
// value, for the place it is in.
func oneLine(p *partPlan, place shell.Quoting) {
	v := `$(printf '%s' "${` + p.name.String() + `}" | tr -d '\n')`
	switch place {
	case shell.DoubleQuoted, shell.Heredoc:
		p.repl = v
	case shell.Unquoted:
		p.repl = `"` + v + `"`
	default:
		p.noFix = manual(noteOneLine)
	}
}

// delimRef is the delimiter's variable, written inside the quotes q.
func delimRef(name string, q shell.Quote) string {
	switch q {
	case shell.QuoteDouble:
		return "${" + name + "}"
	case shell.QuoteSingle:
		return `'"${` + name + `}"'`
	}
	return `"${` + name + `}"`
}

func hasPair(m edit.Map, name string) bool {
	for _, p := range m {
		if p.Key == name {
			return true
		}
	}
	return false
}

// planPart decides what the ${{ }} of the reference r of the sink s
// becomes where a shell or JavaScript reads it.
func planPart(s taint.Sink, r taint.ExprRef, levels []workflow.Field[workflow.Map[workflow.String]], taken map[string]bool, byValue map[string]string, contexts map[int]shell.Place) *partPlan {
	p := &partPlan{}
	if sharedBase(s.Step.Base) || sharedBase(s.Value.Base) || s.Step.Env.Status == workflow.Present && sharedBase(s.Step.Env.Value.Base) {
		p.noFix = form("the step is shared through an alias (or has an anchor): writing it changes every place it is used; fix it by hand")
		return p
	}
	if slices.Contains(s.CollectionParts, r.Part) {
		p.noFix = manual(noteCollection)
		return p
	}
	pt := s.Value.Parts[r.Part]
	text := s.Value.Text()
	// the variable: one in env already when the expression is just env.<name>
	var name string
	if path, ok := expr.AccessPath(pt.Tree); ok && len(path) == 2 && expr.HasPrefix(path, "env") && path[1].Name != "" {
		for _, l := range levels {
			if l.Status != workflow.Present {
				continue
			}
			if e, ok := l.Value.Lookup(path[1].Name); ok {
				name = e.Key.AsString()
				break
			}
		}
	}
	if name == "" {
		if readsStepEnv(pt.Tree, levels[0]) {
			p.noFix = manual("the expression reads env of the step itself, which a value in the env of the step does not see; move it by hand")
			return p
		}
		p.value = "${{ " + strings.TrimSpace(text[pt.Inner.Start:pt.Inner.End]) + " }}"
		if n, ok := byValue[p.value]; ok {
			name = n
		} else {
			name = freeName(envVarName(r.Path), taken)
			byValue[p.value] = name
		}
	}
	v, ok := shell.NameOf(name)
	if !ok {
		p.noFix = manual("the variable " + name + " is not a name a shell reads; move the expression to env by hand")
		return p
	}
	p.name = v
	switch s.Kind {
	case analysis.SinkScript:
		p.effects = []SideEffect{SideEffectGitHubScriptUnchecked}
		if !quoted(text, pt.Span) {
			p.noFix = manual("the expression is inside JavaScript code, not the whole of a string; move it to env and read process.env by hand")
			return p
		}
		p.repl = "process.env." + p.name.String()
		return p
	}
	switch s.Shell {
	case taint.ShellBash, taint.ShellSh:
		switch contexts[pt.Span.Start].Quoting {
		case shell.Unquoted:
			// "${NAME}" is one word: ${{ }} was put in before bash read the
			// script, so a value with blanks was several words (inside [[ ]]
			// too, where bash refuses them), and in a pattern it is now matched
			// as it is
			p.effects = []SideEffect{SideEffectUnquotedOneWord}
			if contexts[pt.Span.Start].CondOperand == shell.CondOperandPattern {
				p.effects = append(p.effects, SideEffectPatternLiteral)
			}
			p.repl = `"${` + p.name.String() + `}"`
		case shell.DoubleQuoted, shell.Heredoc, shell.Comment:
			p.repl = "${" + p.name.String() + "}"
		case shell.SingleQuoted, shell.QuotedHeredoc:
			p.noFix = manual("the expression is inside '...' or a quoted heredoc, where a variable is not expanded; move it to env and change the quoting by hand")
		case shell.CommandString:
			p.noFix = manual("moving the expression to env does not stop the value of the expression from being read as code at this place: another program reads the value as code, directly or through a shell function that the script defines (sh -c, the code option of an interpreter, a heredoc given to such a program, or the input of a coproc running such a program); bash reads the value as code, directly or through a shell function that the script defines (eval, the command word, arithmetic, the subscript of an array); another program reads as code the output of a command substitution that holds the value; the value is an argument of a command whose name is decided only when the script runs; or the value is in the body of a heredoc or a here-string given to a file descriptor other than 0")
		default:
			p.noFix = manual("the rule cannot tell how the shell reads this place (for example: inside case, inside the ( ) of an array, inside $[ ], inside a <( ) whose output goes to a command that the rule does not know to run the output as code, in a pattern or a replacement of ${ }, or after the place where the rule stops following the script); move the expression to env by hand")
		}
	case taint.ShellPwsh:
		p.effects = []SideEffect{SideEffectPwshUnchecked}
		p.repl = "$env:" + p.name.String()
	default:
		p.noFix = manual("the shell is not known to be bash, sh or pwsh (set shell:, the runner is not one the rule knows, the shell: value has an option that the rule does not read, or the shell: value names bash or sh by a path on a runner where the rule does not know that the path exists); move the expression to env by hand")
	}
	return p
}

// readsStepEnv is whether n reads env.<name> of a name the env of the step
// has: a value in the env of the step does not see the others.
func readsStepEnv(n expr.Node, env workflow.Field[workflow.Map[workflow.String]]) bool {
	if env.Status != workflow.Present || n == nil {
		return false
	}
	if p, ok := expr.AccessPath(n); ok {
		if len(p) < 2 || !expr.HasPrefix(p, "env") {
			return false
		}
		if p[1].Name == "" {
			return true // env[x]: any of them
		}
		_, ok := env.Value.Lookup(p[1].Name)
		return ok
	}
	for _, c := range expr.Children(n) {
		if readsStepEnv(c, env) {
			return true
		}
	}
	return false
}

// placesOf is how bash or sh reads the script v at each of its ${{ }}, by
// where the ${{ }} starts, read with scripts.
func placesOf(scripts *shell.Memo, v workflow.String) map[int]shell.Place {
	var at []int
	for _, p := range v.Parts {
		if p.Expr {
			at = append(at, p.Span.Start)
		}
	}
	places := taint.ReadScript(scripts, v).Places
	out := make(map[int]shell.Place, len(at))
	for i, a := range at {
		out[a] = places[i]
	}
	return out
}

// quoted is whether the span sp of text is the whole of a JavaScript
// string: a quote just before it, and the same just after.
func quoted(text string, sp expr.Span) bool {
	if sp.Start == 0 || sp.End >= len(text) {
		return false
	}
	q := text[sp.Start-1]
	return (q == '\'' || q == '"' || q == '`') && text[sp.End] == q && (sp.Start < 2 || text[sp.Start-2] != '\\')
}

// sharedBase is whether writing b changes another place too: it is
// reached through an alias, or has an anchor.
func sharedBase(b workflow.Base) bool {
	_, anchored := b.Node.Anchor()
	return len(b.Via) > 0 || anchored
}

func (x *IR) allStepFixes() []*StepFix {
	x.once(SummaryStepFix, func() {
		x.allSinks()
		plan := makeStepPlan(x.scripts, x.analysis.Sinks)
		var out []*StepFix
		seen := map[Key]bool{}
		for _, s := range x.analysis.Sinks {
			k := keyOf(x.paths, x.input, x.tree, s.Step.Base)
			if !seen[k] {
				seen[k] = true
				out = append(out, &StepFix{key: k, at: x.handleOf(s.Step.Base), plan: plan})
			}
		}
		x.plan, x.fixes = plan, out
	})
	return x.fixes
}

func (s *Sink) refFix(q *RuleAccess, i int) FixPlan {
	q.ir.allStepFixes()
	return q.ir.plan.expr(q.ir.sinkIndex(s), s.refs[i].part)
}

func (s *Sink) writeFix(q *RuleAccess, i int) FixPlan {
	q.ir.allStepFixes()
	w, si := s.environmentFileWrites[i], q.ir.sinkIndex(s)
	if w.RefIndex >= 0 {
		return q.ir.plan.expr(si, s.refs[w.RefIndex].part)
	}
	return q.ir.plan.variable(si, w.start)
}

// sinkIndex is the index of s in the analysis, which the plan is keyed by.
func (x *IR) sinkIndex(s *Sink) int {
	for i, t := range x.sinks {
		if t == s {
			return i
		}
	}
	panic("a sink not of this IR")
}
