package taint

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// SecretRef is a secret a reference reads: by name, the job's token
// (secrets.GITHUB_TOKEN, github.token, the github context), or the whole
// secrets context (toJSON(secrets), secrets[x]).
type SecretRef struct {
	Name  string // the name as written, for a secret read by name but GITHUB_TOKEN
	Token bool
	Whole bool
}

// SecretRefs calls f with each secret n reads. A reference is not looked
// into, but for the expressions of its indexes: secrets.X is X, not all of
// them, and github.event.x is not the github context. secrets itself,
// secrets.* and secrets[x] whose x is not a string literal read the whole
// context. The github context has the token (the runner's
// ExecutionContext.cs: githubContext["token"]): github.token, github itself,
// github.* and github[x].
func SecretRefs(n expr.Node, f func(SecretRef)) {
	p, ok := expr.AccessPath(n)
	if !ok {
		for _, c := range expr.Children(n) {
			SecretRefs(c, f)
		}
		return
	}
	switch {
	case expr.EqualName(p[0].Name, "github") && (len(p) == 1 || p[1].Name == "" || expr.EqualName(p[1].Name, "token")):
		f(SecretRef{Token: true})
	case expr.EqualName(p[0].Name, "secrets") && (len(p) == 1 || p[1].Name == ""):
		f(SecretRef{Whole: true})
	case expr.EqualName(p[0].Name, "secrets") && expr.EqualName(p[1].Name, "GITHUB_TOKEN"):
		f(SecretRef{Token: true})
	case expr.EqualName(p[0].Name, "secrets"):
		f(SecretRef{Name: p[1].Name})
	}
	for _, e := range p {
		if e.Dynamic != nil {
			SecretRefs(e.Dynamic, f)
		}
	}
}

// JobTokenRef is whether n is a reference to the job's token and nothing
// more: github.token or secrets.GITHUB_TOKEN, in any spelling of the path
// (github['token'], secrets . GITHUB_TOKEN).
func JobTokenRef(n expr.Node) bool {
	return expr.IsPath(n, "github", "token") || expr.IsPath(n, "secrets", "GITHUB_TOKEN")
}

// CarriedSecret is a secret a word of a run carries:
// through a ${{ }} in the run, a variable of env, or a variable the script
// assigns before the word.
type CarriedSecret struct {
	Name      string        // as written; "" for the job's token
	Token     bool          // the job's token
	Whole     bool          // the whole secrets context: toJSON(secrets), secrets[x]
	Span      expr.Span     // in the run: the ${{ }}, the variable, or the $( )
	Var       shell.VarName // the variable it came through; the zero VarName for a ${{ }}
	Form      analysis.SecretForm
	Transform analysis.Transform // SecretFormTransformed: the last change the shell made
	Masked    bool               // a ::add-mask:: before registered the value: the runner masks it
}

// secretFlow reads, for the run of a sink, the secrets its words carry and
// the value of a destination.
type secretFlow struct {
	c       scope
	s       *Sink
	text    string // the run, its ${{ }} masked
	holes   []hole
	script  *shell.Script
	assigns []assignment // in the order of the script
	funcs   []function   // the functions the script defines
	vis     *shell.NameVisibility
	byAt    map[int]*assignment // the assignments by where they start
	regs    *[]maskRegistration
	logs    *[]shell.Write
	out     *shell.OutputReading // the readings of outputs, which nest at the $( ) of words
	// carried keeps the secrets of what is read once (memoized): a variable
	// at an assignment (an *assignment) or in env (an envLevel), a
	// parameter of a function (argKey), a $( ) (substKey); reading are the
	// keys being read, cuts how many reads the limit of depth cut short, and
	// loops how many met a key being read
	carried     map[any]memoEntry
	recursive   map[any][]*recursionAnswers // answers a recursion cut (memoized)
	reading     map[any]bool
	cuts, loops int
	// pass are, by an output of a reading of outputs open (its output, or a
	// pipe of a pipeline of it), what the commands of readings inside it
	// wrote there (shell.DescriptorReading.Outputs)
	pass map[shell.OutputPlace][]CarriedSecret
	// values keep what a variable holds at an assignment or in env: a
	// variable that doubles itself is read once per assignment
	values map[any][]seg
}

// memoEntry is an answer read once, with the cuts its read met, which a
// read of it from the memo counts again, and what its read wrote to the
// outputs of the readings around (by how far around, from the depth of the
// readings open then), which a read of it from the memo writes again.
type memoEntry struct {
	out  []CarriedSecret
	cuts cutCounts
	pass map[int][]CarriedSecret
	// defs are the definitions its read called
	defs []*shell.FuncDef
}

// recursionAnswers are the answers of a key that a recursion cut, whose
// reads called the definitions defs, by those of them being read then
// (shell.OutputReading.Reading): an answer holds where the same of them are
// being read.
type recursionAnswers struct {
	defs      []*shell.FuncDef
	byReading map[string]memoEntry
}

// cutCounts are the cuts reads met: calls whose bodies a reading of outputs
// did not read, of them those of a recursion, the limit of depth, and keys
// being read.
type cutCounts struct {
	calls, recursions, depth, loops int
}

func (f *secretFlow) cutsNow() cutCounts {
	all, rec := f.out.Cuts()
	return cutCounts{all, rec, f.cuts, f.loops}
}

// memoized is read() of the key k, read once: an answer is kept with the
// cuts its read met, what it wrote to the outputs of the readings around,
// and the definitions its read called, which a read of it from the memo
// counts, writes and calls again, so that what reads it keeps its own
// answer with them. An answer a recursion cut holds where those of the
// definitions it called that were being read are being read again. A key
// being read (a value that reaches itself) answers nothing, as a loop. The
// counts of the cuts other than recursions are kept as the reads met them;
// only a recursion makes the answer depend on where it is read.
func (f *secretFlow) memoized(k any, read func() []CarriedSecret) []CarriedSecret {
	if e, ok := f.carried[k]; ok {
		f.replay(e)
		return e.out
	}
	for _, rs := range f.recursive[k] {
		if e, ok := rs.byReading[f.out.Reading(rs.defs)]; ok {
			f.replay(e)
			return e.out
		}
	}
	if f.reading[k] {
		f.loops++
		return nil
	}
	f.reading[k] = true
	before := f.cutsNow()
	open := f.out.Depth()
	passed := map[shell.OutputPlace]int{}
	for p, cs := range f.pass {
		passed[p] = len(cs)
	}
	f.out.Watch()
	out := read()
	defs := f.out.Unwatch()
	var pass map[int][]CarriedSecret
	keep := true
	for p, cs := range f.pass {
		add := cs[passed[p]:]
		switch {
		case len(add) == 0, p.Depth > open:
		case p.Element != nil:
			keep = false // to a pipe of a pipeline of a reading around: what it reaches is where the read is
		default:
			if pass == nil {
				pass = map[int][]CarriedSecret{}
			}
			pass[open-p.Depth] = slices.Clone(add)
		}
	}
	delete(f.reading, k)
	if !keep {
		return out
	}
	now := f.cutsNow()
	d := cutCounts{now.calls - before.calls, now.recursions - before.recursions, now.depth - before.depth, now.loops - before.loops}
	e := memoEntry{out: out, cuts: d, pass: pass, defs: defs}
	if d.recursions > 0 {
		var rs *recursionAnswers
		for _, x := range f.recursive[k] {
			if slices.Equal(x.defs, defs) {
				rs = x
			}
		}
		if rs == nil {
			rs = &recursionAnswers{defs: defs, byReading: map[string]memoEntry{}}
			f.recursive[k] = append(f.recursive[k], rs)
		}
		rs.byReading[f.out.Reading(defs)] = e
		return out
	}
	f.carried[k] = e
	return out
}

func (f *secretFlow) replay(e memoEntry) {
	f.out.Called(e.defs)
	c := e.cuts
	f.out.Replay(c.calls, c.recursions)
	f.cuts += c.depth
	f.loops += c.loops
	open := f.out.Depth()
	for far, cs := range e.pass {
		p := shell.OutputPlace{Depth: open - far}
		f.pass[p] = append(f.pass[p], cs...)
	}
}

// envLevel is env.name read from the level lvl of the env the step sees.
type envLevel struct {
	name string
	lvl  int
}

// assignment is NAME=value in a run: by itself before a command word, or
// as a word of export, local, declare, readonly or typeset. fn is the
// function whose body it is in, nil for one outside them: the body's
// assignments count in the body alone.
type assignment struct {
	at    int
	name  string
	parts []shell.Part // the value's
	from  int          // where the value begins in the first part's span
	// cmd is the command an assignment before its words is for: it is in
	// the environment of the command, and the shell expands the words of
	// the command before it. nil for one that assigns in the shell.
	cmd *shell.Simple
	fn  *function
}

// function is a function the script defines: its name and its body.
type function struct {
	name string
	body shell.Span
	def  *shell.FuncDef
}

// argKey is a positional parameter of a function.
type argKey struct {
	body shell.Span
	name string
}

// declarers are the commands whose NAME=value words assign.
var declarers = map[string]bool{"export": true, "local": true, "declare": true, "readonly": true, "typeset": true}

func (c scope) secretFlowOf(s *Sink) *secretFlow {
	f := &secretFlow{c: c, s: s, text: Masked(s.Value), carried: map[any]memoEntry{}, recursive: map[any][]*recursionAnswers{}, values: map[any][]seg{}, reading: map[any]bool{}, pass: map[shell.OutputPlace][]CarriedSecret{}}
	for i, p := range s.Value.Parts {
		if p.Expr {
			f.holes = append(f.holes, hole{shell.Span{Start: p.Span.Start, End: p.Span.End}, i})
		}
	}
	f.script = ReadScript(c.scripts, s.Value).Script
	f.collect(f.script.List, nil)
	f.vis = c.scripts.Visibility(f.text, f.script)
	s.CallsNotRead.Join(f.vis.CallsNotRead())
	f.out = shell.NewOutputReading(f.text, f.script, f.vis, &s.CallsNotRead)
	f.byAt = map[int]*assignment{}
	for i := range f.assigns {
		f.byAt[f.assigns[i].at] = &f.assigns[i] // one before a call of a function reaches its body
	}
	return f
}

func (f *secretFlow) collect(cs []shell.Command, fn *function) {
	funcs := map[*shell.FuncDef]*function{}
	shell.Walk(f.text, cs, shell.Enclosing{}, shell.Visitor{Command: func(c shell.Command, e shell.Enclosing) bool {
		in := fn // the assignments of substitutions too: shell.NameVisibility reads them in their shells
		if e.Func != nil {
			in = funcs[e.Func]
		}
		switch c := c.(type) {
		case *shell.Simple:
			var cmd *shell.Simple
			as, words := c.Assigns, c.Words
			if len(words) > 0 {
				cmd = c
			}
			for _, w := range as {
				f.assign(w, cmd, in)
			}
			if len(words) > 0 {
				if name, ok := shell.Literal(f.text, words[0]); ok && declarers[name] {
					for _, w := range words[1:] {
						f.assign(w, nil, in)
					}
				}
			}
			return true // and the assignments in its substitutions
		case *shell.FuncDef:
			name, ok := shell.Literal(f.text, c.Name)
			if !ok {
				return false
			}
			g := &function{name: name, body: c.Body.Span(), def: c}
			f.funcs = append(f.funcs, *g)
			funcs[c] = g
		}
		return true
	}})
}

// funcAt is the innermost function whose body has at, or nil.
func (f *secretFlow) funcAt(at int) *function {
	var in *function
	for i := range f.funcs {
		if g := &f.funcs[i]; g.body.Start <= at && at < g.body.End && (in == nil || g.body.Start >= in.body.Start) {
			in = g
		}
	}
	return in
}

// assign adds w when it is NAME=value, or an element NAME[subscript]=value:
// a literal NAME at its head (shell.AssignedName).
func (f *secretFlow) assign(w shell.Word, cmd *shell.Simple, fn *function) {
	name, from, _, ok := shell.AssignedName(f.text, w)
	if !ok || f.holeIn(w.Span.Start, from) {
		return
	}
	f.assigns = append(f.assigns, assignment{at: w.Span.Start, name: name, parts: w.Parts, from: from, cmd: cmd, fn: fn})
}

func (f *secretFlow) holeIn(start, end int) bool {
	for _, h := range f.holes {
		if h.span.Start < end && start < h.span.End {
			return true
		}
	}
	return false
}

// reaching are the assignments of the run whose value the variable name,
// read at at, may have (shell.NameVisibility: on each path, the last;
// through a function, those before its calls), whether on some path none
// of the run reaches (the value is env's, or none), and whether one that
// reaches writes no value (read, unset, a declaration with no value).
func (f *secretFlow) reaching(name string, at int) (as []*assignment, before, valueless bool) {
	n, ok := shell.NameOf(name)
	if !ok {
		return nil, true, false // a positional or special parameter
	}
	rs := f.vis.Reaching(n, shell.Span{Start: at, End: at})
	if len(rs) == 0 {
		return nil, true, false
	}
	seen := map[int]bool{}
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if !r.Before {
			if seen[r.At.Start] {
				continue
			}
			seen[r.At.Start] = true
		}
		if r.Append {
			// NAME+=value: what it appends to is a part of its value too
			if bs := f.vis.Bases(r); len(bs) > 0 {
				rs = append(rs, bs...)
			} else {
				before = true
			}
		}
		a := f.byAt[r.At.Start]
		if a == nil && !r.Before && r.Value != nil {
			// an assignment the script's words do not hold: ${NAME:=value}
			a = &assignment{at: r.At.Start, name: r.Name.String(), parts: r.Value.Parts, from: r.Value.Span.Start, fn: f.funcAt(r.At.Start)}
			f.byAt[r.At.Start] = a
		}
		switch {
		case r.Before:
			before = true
		case r.Value == nil, a == nil || a.name != name:
			valueless = true
		default:
			as = append(as, a)
		}
	}
	return as, before, valueless
}

// assigned is whether every path to the read of name at at goes through
// an assignment of the run: its value is not env's.
func (f *secretFlow) assigned(name string, at int) bool {
	_, before, _ := f.reaching(name, at)
	return !before
}

// sameValue is whether name holds the same value at a and at b: the same
// assignments reach both.
func (f *secretFlow) sameValue(name string, a, b int) bool {
	x, xb, xv := f.reaching(name, a)
	y, yb, yv := f.reaching(name, b)
	return xb == yb && xv == yv && slices.Equal(x, y)
}

// callsOf are the simple commands that call the function fn.
func (f *secretFlow) callsOf(fn *function) []*shell.Simple {
	return f.vis.Calls(fn.def)
}

// argSecrets are the secrets the positional parameter name ($1, $@, $*)
// carries in the function fn: those of the words each call gives it.
func (f *secretFlow) argSecrets(fn *function, name string, depth int) []CarriedSecret {
	n, err := strconv.Atoi(name)
	all := name == "@" || name == "*"
	if err != nil && !all {
		return nil
	}
	return f.memoized(argKey{fn.body, name}, func() []CarriedSecret { // a call of the function in its body reads it again
		var out []CarriedSecret
		for _, x := range f.callsOf(fn) {
			for i, w := range x.Words[1:] {
				if all || i+1 == n {
					out = append(out, f.secretsInParts(w.Parts, w.Span.Start, x.Span().Start, depth+1)...)
				}
			}
		}
		return out
	})
}

// programAssign is the assignment of name the program x runs with: one
// before its words, or the last in the shell before it. nil when neither
// is; env may still give name.
func (f *secretFlow) programAssign(x *shell.Simple, name string) *assignment {
	for i := range f.assigns {
		if a := &f.assigns[i]; a.name == name && a.cmd == x {
			return a
		}
	}
	if as, before, valueless := f.reaching(name, x.Span().Start); len(as) == 1 && !before && !valueless {
		return as[0]
	}
	return nil
}

// secretsIn are the secrets the word w carries.
func (f *secretFlow) secretsIn(w shell.Word) []CarriedSecret {
	return f.secretsInParts(w.Parts, w.Span.Start, w.Span.Start, 0)
}

// secretsInParts are the secrets the parts carry from the byte from on, a
// variable read as the script has it at at.
func (f *secretFlow) secretsInParts(ps []shell.Part, from, at, depth int) []CarriedSecret {
	return f.secretsInWords(ps, from, at, depth, nil)
}

// secretsInWords is secretsInParts of the parts of a word of the command
// the walk d reads for gives (outputSecrets): a $( ) in them starts with the
// descriptors and the paths d has there (shell.OutputReading.Begin).
func (f *secretFlow) secretsInWords(ps []shell.Part, from, at, depth int, d *shell.DescriptorReading) []CarriedSecret {
	var out []CarriedSecret
	for _, p := range ps {
		if p.Span.End <= from && p.Span.Start < from {
			continue
		}
		switch p.Kind {
		case shell.PartLiteral:
			for _, h := range f.holes {
				if h.span.Start >= max(p.Span.Start, from) && h.span.End <= p.Span.End {
					out = append(out, f.exprSecrets(f.s.Value.Parts[h.part].Tree, expr.Span{Start: h.span.Start, End: h.span.End}, shell.VarName{}, depth)...)
				}
			}
		case shell.PartParam, shell.PartParamOp:
			if x := p.Param; x != nil {
				for _, w := range x.ValueWords() { // ${NAME:-word}: the word when NAME is empty
					out = append(out, f.secretsInWords(w.Parts, w.Span.Start, at, depth, d)...)
				}
			}
			e := expansionOf(p)
			if e.drop {
				continue
			}
			kept := !e.opaque && e.change == analysis.ExpansionChangeUnset
			for _, c := range f.varSecrets(p.Name.String(), p.Span.Start, depth) { // what reaches this read (shell.NameVisibility)
				c.Span, c.Var = expr.Span{Start: p.Span.Start, End: p.Span.End}, p.Name
				if kept && f.masked(p.Name.String(), at) {
					c.Masked = true
				}
				out = append(out, e.apply(c))
			}
		case shell.PartSubst, shell.PartProcIn:
			if p.Sub == nil {
				continue
			}
			for _, c := range f.substitutionSecrets(p, at, depth, d) {
				c.Span = expr.Span{Start: p.Span.Start, End: p.Span.End}
				out = append(out, c)
			}
		}
	}
	return out
}

// carriedOf are the secrets the expression n reads, at span through v.
func carriedOf(n expr.Node, span expr.Span, v shell.VarName) []CarriedSecret {
	var out []CarriedSecret
	if n == nil {
		return nil
	}
	SecretRefs(n, func(r SecretRef) {
		out = append(out, CarriedSecret{Name: r.Name, Token: r.Token, Whole: r.Whole, Span: span, Var: v, Form: analysis.SecretFormVerbatim})
	})
	return out
}

// varSecrets are the secrets the variable name carries at at: the value of
// its last assignment before at, or of env. Each secret is there once. An
// assignment reads the variables as they are before it, so that a chain of
// them ends.
func (f *secretFlow) varSecrets(name string, at, depth int) []CarriedSecret {
	if depth > 16 {
		f.cuts++
		return nil
	}
	as, before, _ := f.reaching(name, at)
	var out []CarriedSecret
	for _, a := range as {
		out = append(out, f.assignSecrets(a, depth)...)
	}
	if !before {
		return uniqueSecrets(out)
	}
	return uniqueSecrets(append(out, f.unassignedSecrets(name, at, depth)...))
}

// unassignedSecrets are the secrets name carries read at at where no
// assignment of the run reaches: a parameter of the function at is in, or
// env.
func (f *secretFlow) unassignedSecrets(name string, at, depth int) []CarriedSecret {
	if fn := f.funcAt(at); fn != nil && (name == "@" || name == "*" || strings.Trim(name, "0123456789") == "") {
		return uniqueSecrets(f.argSecrets(fn, name, depth))
	}
	if _, ok := f.c.runnerVariable(name); ok {
		return nil // the runner writes it over env and $GITHUB_ENV
	}
	// the step's own env, then what a step before wrote to $GITHUB_ENV,
	// then the job's and the workflow's env
	if _, ok := f.envAt(name, 0); !ok {
		if cs, ok := f.crossEnv(name); ok {
			return cs
		}
	}
	return f.envSecrets(name, 0, depth)
}

// assignSecrets are the secrets the value of a carries, each once.
func (f *secretFlow) assignSecrets(a *assignment, depth int) []CarriedSecret {
	return f.memoized(a, func() []CarriedSecret { // an assignment that reaches its own value (a loop) reads it again
		return uniqueSecrets(f.secretsInParts(a.parts, a.from, a.at, depth))
	})
}

// uniqueSecrets is cs with each secret once.
func uniqueSecrets(cs []CarriedSecret) []CarriedSecret {
	var out []CarriedSecret
	for _, c := range cs {
		if !slices.ContainsFunc(out, func(o CarriedSecret) bool {
			return o.Name == c.Name && o.Token == c.Token && o.Whole == c.Whole && o.Form == c.Form && o.Transform == c.Transform && o.Masked == c.Masked
		}) {
			out = append(out, c)
		}
	}
	return out
}

// envSecrets are the secrets env.name carries, read from the level from of
// the env the step sees: in the ${{ }} of its value, and through env.X in
// them, read from the level above.
func (f *secretFlow) envSecrets(name string, from, depth int) []CarriedSecret {
	return f.memoized(envLevel{name, from}, func() []CarriedSecret { return f.readEnvSecrets(name, from, depth) })
}

func (f *secretFlow) readEnvSecrets(name string, from, depth int) []CarriedSecret {
	var out []CarriedSecret
	for lvl := from; lvl < len(f.c.envs); lvl++ {
		v, ok := f.envAt(name, lvl)
		if !ok {
			continue
		}
		for _, p := range v.Parts {
			if !p.Expr || p.Tree == nil {
				continue
			}
			out = append(out, f.exprSecrets(p.Tree, expr.Span{}, shell.VarName{}, depth)...)
			envRefs(p.Tree, func(n string) {
				if depth < 16 {
					out = append(out, f.envSecrets(n, lvl+1, depth+1)...)
				} else {
					f.cuts++
				}
			})
		}
		break
	}
	return uniqueSecrets(out)
}

// envAt is the value of name in the level lvl of the env the step sees.
func (f *secretFlow) envAt(name string, lvl int) (workflow.String, bool) {
	e := f.c.envs[lvl]
	if e.Status != workflow.Present {
		return workflow.String{}, false
	}
	x, ok := e.Value.Lookup(name)
	if !ok || x.Key.AsString() != name || x.Value.Status != workflow.Present {
		return workflow.String{}, false
	}
	return x.Value.Value, true
}

// envRefs calls f with the name of each env.<name> in n.
func envRefs(n expr.Node, f func(string)) {
	if p, ok := expr.AccessPath(n); ok {
		if expr.EqualName(p[0].Name, "env") && len(p) > 1 && p[1].Name != "" {
			f(p[1].Name)
		}
		return
	}
	for _, c := range expr.Children(n) {
		envRefs(c, f)
	}
}

// segKind is what a piece of the value of a word is.
type segKind uint8

const (
	segLiteral segKind = iota
	segExpr            // a ${{ }}
	segGitHub          // a variable the runner sets to a URL of GitHub
	segUnknown         // a value not known: a variable the script and env do not give, a $( ), or more pieces than segLimit
)

// seg is a piece of the value of a word, read through the variables it
// expands.
type seg struct {
	kind segKind
	text string    // segLiteral
	tree expr.Node // segExpr; nil for one that does not parse
	hole int       // segExpr in the run: the index of its part of the run; -1 for one of env
	ref  ExprRef   // segExpr of env: the variable of the run read as a value an attacker may control
	// span is where in the run the piece comes from: the ${{ }}, the
	// variable, or the $( ); v is the variable of the run it comes
	// through, the zero VarName for a ${{ }} of the run.
	span    expr.Span
	v       shell.VarName
	secrets []CarriedSecret // segUnknown of a $( ): those in it
}

// segLimit is how many pieces a value is read to; what is after them is
// one segUnknown.
const segLimit = 64

// valueOf is the value of the parts ps from the byte from on, as pieces, a
// variable read as the script has it at at.
func (f *secretFlow) valueOf(ps []shell.Part, from, at, depth int) []seg {
	var out []seg
	for _, p := range ps {
		if p.Span.End <= from {
			continue
		}
		if len(out) >= segLimit {
			out = append(out, seg{kind: segUnknown})
			break
		}
		span := expr.Span{Start: p.Span.Start, End: p.Span.End}
		switch p.Kind {
		case shell.PartLiteral:
			out = append(out, f.literalSegs(max(p.Span.Start, from), p.Span.End)...)
		case shell.PartParam, shell.PartParamOp:
			for _, s := range f.varValue(p.Name.String(), p.Span.Start, depth) {
				s.span, s.v = span, p.Name
				out = append(out, s)
			}
		case shell.PartSubst, shell.PartProcIn:
			out = append(out, seg{kind: segUnknown, span: span, secrets: f.secretsInParts([]shell.Part{p}, p.Span.Start, at, depth)})
		default:
			out = append(out, seg{kind: segUnknown, span: span})
		}
	}
	if len(out) > segLimit {
		out = append(out[:segLimit:segLimit], seg{kind: segUnknown})
	}
	return out
}

// literalSegs are the pieces of the literal text of the run from start to
// end: the text, and the ${{ }} in it.
func (f *secretFlow) literalSegs(start, end int) []seg {
	var out []seg
	for start < end {
		next := -1
		for i, h := range f.holes {
			if h.span.Start >= start && h.span.Start < end && (next < 0 || h.span.Start < f.holes[next].span.Start) {
				next = i
			}
		}
		if next < 0 {
			return append(out, seg{kind: segLiteral, text: f.text[start:end]})
		}
		h := f.holes[next]
		if h.span.Start > start {
			out = append(out, seg{kind: segLiteral, text: f.text[start:h.span.Start]})
		}
		span := expr.Span{Start: h.span.Start, End: h.span.End}
		if h.span.End > end {
			return append(out, seg{kind: segUnknown, span: span}) // a ${{ }} across the parts of the word
		}
		tree := f.s.Value.Parts[h.part].Tree
		if name, ok := envName(tree); ok {
			if v, ok := f.envValue(name, 0, 0); ok {
				out = append(out, f.withRef(v, f.holeRef(h.part), span, shell.VarName{})...)
				start = h.span.End
				continue
			}
		}
		out = append(out, seg{kind: segExpr, tree: tree, hole: h.part, span: span})
		start = h.span.End
	}
	return out
}

// varValue is the value of the variable name at at: of its last assignment
// before at, of env, or the URL of GitHub the runner gives.
func (f *secretFlow) varValue(name string, at, depth int) []seg {
	if depth > 16 {
		return []seg{{kind: segUnknown}}
	}
	switch as, before, valueless := f.reaching(name, at); {
	case len(as) > 0:
		// more than one value reaches: the last of them in the run, as the
		// destination was read before the paths were (one value a host is
		// judged by)
		last := as[0]
		for _, a := range as[1:] {
			if a.at > last.at {
				last = a
			}
		}
		_ = before
		return f.assignValue(last, depth)
	case valueless:
		return []seg{{kind: segUnknown}} // a value not written
	}
	if v, ok := f.c.runnerVariable(name); ok {
		switch {
		case githubURLVars[name]:
			return []seg{{kind: segGitHub}}
		case v.Context == nil:
			return []seg{{kind: segLiteral, text: v.Fixed}}
		}
		tree, _ := expr.Parse(v.String())
		r, _ := f.c.varRef(name)
		return f.withRef([]seg{{kind: segExpr, tree: tree, hole: -1}}, r, expr.Span{}, shell.VarName{})
	}
	if v, ok := f.envValue(name, 0, depth); ok {
		r, _ := f.c.varRef(name)
		return f.withRef(v, r, expr.Span{}, shell.VarName{})
	}
	if githubURLVars[name] {
		return []seg{{kind: segGitHub}}
	}
	return []seg{{kind: segUnknown}}
}

// withRef is v, the value of env, with r given to the pieces whose ${{ }}
// read the reference r comes from (all of them when r names none), and,
// when span is not empty, the span in the run they come from. The other
// pieces keep the zero ExprRef: no attacker controls them.
func (f *secretFlow) withRef(v []seg, r ExprRef, span expr.Span, at shell.VarName) []seg {
	out := slices.Clone(v)
	for i := range out {
		if out[i].kind == segExpr && out[i].hole < 0 && (len(r.Source) == 0 || out[i].tree != nil && reads(out[i].tree, r.Source)) {
			out[i].ref = r
		}
		if span != (expr.Span{}) {
			out[i].span, out[i].v = span, at
		}
	}
	return out
}

// holeRef is the reference of the part i of the run.
func (f *secretFlow) holeRef(i int) ExprRef {
	for _, r := range f.s.Refs {
		if r.Part == i {
			return r
		}
	}
	return ExprRef{}
}

// envName is the name of env the expression n is, when n is env.<name>.
func envName(n expr.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	p, ok := expr.AccessPath(n)
	if !ok || len(p) != 2 || !expr.EqualName(p[0].Name, "env") || p[1].Name == "" {
		return "", false
	}
	return p[1].Name, true
}

// assignValue is the value of a.
func (f *secretFlow) assignValue(a *assignment, depth int) []seg {
	if v, ok := f.values[a]; ok {
		return v // read, or being read
	}
	f.values[a] = []seg{{kind: segUnknown}}
	v := f.valueOf(a.parts, a.from, a.at, depth)
	f.values[a] = v
	return v
}

// envValue is the value of env.name read from the level from, its env.X
// read from the level above.
func (f *secretFlow) envValue(name string, from, depth int) ([]seg, bool) {
	k := envLevel{name, from}
	if v, ok := f.values[k]; ok {
		return v, v != nil
	}
	for lvl := from; lvl < len(f.c.envs); lvl++ {
		v, ok := f.envAt(name, lvl)
		if !ok {
			continue
		}
		out := []seg{}
		if len(v.Parts) == 0 {
			out = append(out, seg{kind: segLiteral, text: v.Text()})
		}
		for _, p := range v.Parts {
			switch {
			case !p.Expr:
				out = append(out, seg{kind: segLiteral, text: v.Text()[p.Span.Start:p.Span.End]})
			case p.Tree == nil:
				out = append(out, seg{kind: segUnknown})
			default:
				if path, ok := expr.AccessPath(p.Tree); ok && expr.EqualName(path[0].Name, "env") && len(path) > 1 && path[1].Name != "" {
					if sub, ok := f.envValue(path[1].Name, lvl+1, depth+1); ok && depth < 16 {
						out = append(out, sub...)
					} else {
						out = append(out, seg{kind: segUnknown})
					}
					continue
				}
				out = append(out, seg{kind: segExpr, tree: p.Tree, hole: -1})
			}
		}
		f.values[k] = out
		return out, true
	}
	f.values[k] = nil
	return nil, false
}

// urlForm is how a value names where a request goes.
type urlForm uint8

const (
	urlFull     urlForm = iota // a URL, or a host and what follows it
	urlHostname                // a host alone (gh api --hostname, GH_HOST)
	urlAPIPath                 // a path of an API whose host is named elsewhere (gh api)
)

// urlLayout is where the host of a value is: the value with each piece not
// literal as one byte 0 (flat), where each piece begins in flat (at), the
// host (hostStart to hostEnd) and the end of the authority, before the
// path (authEnd).
type urlLayout struct {
	flat                        string
	at                          []int
	hostStart, hostEnd, authEnd int
}

func layoutOf(segs []seg, form urlForm) urlLayout {
	var b strings.Builder
	var l urlLayout
	for _, s := range segs {
		l.at = append(l.at, b.Len())
		if s.kind == segLiteral {
			b.WriteString(s.text)
		} else {
			b.WriteByte(0)
		}
	}
	l.flat = b.String()
	switch form {
	case urlHostname:
		l.hostEnd, l.authEnd = len(l.flat), len(l.flat)
		return l
	case urlAPIPath:
		return l
	}
	off := 0
	if m := urlScheme.FindStringIndex(l.flat); m != nil {
		off = m[1]
	} else if strings.HasPrefix(l.flat, "\x00://") {
		off = 4 // a scheme not known
	}
	l.authEnd = len(l.flat)
	if i := strings.IndexAny(l.flat[off:], "/?#"); i >= 0 {
		l.authEnd = off + i
	}
	l.hostStart = off
	if i := strings.LastIndexByte(l.flat[off:l.authEnd], '@'); i >= 0 {
		l.hostStart = off + i + 1
	}
	l.hostEnd = l.authEnd
	host := l.flat[l.hostStart:l.authEnd]
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i >= 0 {
			l.hostEnd = l.hostStart + i + 1
		}
	} else if i := strings.IndexByte(host, ':'); i >= 0 {
		l.hostEnd = l.hostStart + i
	}
	return l
}

// decidesHost is whether a value an attacker writes at the i-th piece
// decides the host: it is before the path, so that it can end the
// authority (with / or @) and write its own.
func (l urlLayout) decidesHost(i int) bool { return l.at[i] < l.authEnd }

// namesHost is whether the i-th piece is in the host: a secret there names
// the destination, and the request does not carry it.
func (l urlLayout) namesHost(i int) bool {
	return l.hostStart <= l.at[i] && l.at[i] < l.hostEnd
}

// urlAtHead is whether the endpoint of gh api whose value is segs holds a
// URL: :// in its literal head, or what is not known at its head (an
// attacker may write a URL there).
func urlAtHead(segs []seg) bool {
	for _, s := range segs {
		if s.kind != segLiteral {
			return true
		}
		if s.text != "" {
			return strings.Contains(s.text, "://")
		}
	}
	return false
}

// DestinationOrigin is where the host of a request comes from: written in
// the workflow, or a context's path, as the script and env have it.
type DestinationOrigin struct {
	Kind analysis.DestinationKind
	Host string          // Literal: the host, lower case, without the port
	Path []expr.PathElem // Named: the path, such as secrets.UPLOAD_API
	Ref  ExprRef         // Named: the path read as a value an attacker may control
}

func (o DestinationOrigin) String() string {
	switch o.Kind {
	case analysis.DestinationLiteral:
		return "literal " + o.Host
	case analysis.DestinationNamed:
		return "named " + expr.PathString(o.Path)
	case analysis.DestinationUnnamed:
		return "unnamed"
	case analysis.DestinationGitHub:
		return "github"
	}
	return "unset"
}

// githubURLVars are the variables the runner sets to the URLs of GitHub's
// API and server.
var githubURLVars = map[string]bool{"GITHUB_API_URL": true, "GITHUB_SERVER_URL": true}

// originOf is where the host of the URL the word w holds comes from.
func (f *secretFlow) originOf(w shell.Word) DestinationOrigin {
	segs := f.valueOf(w.Parts, w.Span.Start, w.Span.Start, 0)
	return f.originOfSegs(segs, layoutOf(segs, urlFull))
}

// originOfSegs is where the host of the value segs, laid out as l, comes
// from: written in the workflow, a ${{ }} at its head, or what is not
// known.
func (f *secretFlow) originOfSegs(segs []seg, l urlLayout) DestinationOrigin {
	unnamed := DestinationOrigin{Kind: analysis.DestinationUnnamed}
	host := l.flat[l.hostStart:l.hostEnd]
	switch {
	case host == "":
		return unnamed
	case host[0] == 0:
		i := slices.Index(l.at, l.hostStart)
		var o DestinationOrigin
		switch s := segs[i]; s.kind {
		case segExpr:
			o = f.exprOrigin(s) // https://${{ x }}/...
		case segGitHub:
			o = DestinationOrigin{Kind: analysis.DestinationGitHub}
		default:
			return unnamed
		}
		if o.Kind == analysis.DestinationGitHub && host != "\x00" {
			return unnamed // GitHub's URL and more host: ${GITHUB_API_URL}.example.com
		}
		return o
	case strings.IndexByte(host, 0) >= 0:
		return unnamed // the host goes on into what is not written
	}
	host = strings.TrimSuffix(host, ".") // the root of DNS: api.github.com. is api.github.com
	if host == "" {
		return unnamed
	}
	return DestinationOrigin{Kind: analysis.DestinationLiteral, Host: strings.ToLower(host)}
}

// exprOrigin is the origin of the ${{ }} of s.
func (f *secretFlow) exprOrigin(s seg) DestinationOrigin {
	if s.tree == nil {
		return DestinationOrigin{Kind: analysis.DestinationUnnamed}
	}
	path, ok := expr.AccessPath(s.tree)
	if !ok {
		return DestinationOrigin{Kind: analysis.DestinationUnnamed}
	}
	if isGitHubURL(path) {
		return DestinationOrigin{Kind: analysis.DestinationGitHub}
	}
	o := DestinationOrigin{Kind: analysis.DestinationNamed, Path: path, Ref: s.ref}
	if s.hole >= 0 {
		for _, r := range f.s.Refs {
			if r.Part == s.hole {
				o.Ref = r
				break
			}
		}
	}
	return o
}

func isGitHubURL(path []expr.PathElem) bool {
	return len(path) == 2 && expr.EqualName(path[0].Name, "github") && (expr.EqualName(path[1].Name, "api_url") || expr.EqualName(path[1].Name, "server_url"))
}

// urlScheme is the scheme at the head of a URL, with its ://.
var urlScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// expansion is what a parameter expansion does to the secrets of its
// variable: keeps them as they are, drops them (a length, an alternate
// value), or changes them.
type expansion struct {
	drop   bool
	opaque bool
	change analysis.ExpansionChange
}

// expansionOf is what the expansion p ($NAME or ${NAME...}) does to the
// secrets of its variable (shell.ParamExpansion.Value): the value and the
// value quoted (@Q @A @K @k) keep them, a length, the attributes and an
// alternate value drop them (the words that may become the value carry
// their own: ValueWords), the value of the variable the value names is
// what a command not known writes, and the others change them. A ${ } bash
// does not read changes them in a way not known.
func expansionOf(p shell.Part) expansion {
	x := p.Param
	switch {
	case p.Kind == shell.PartParam:
		return expansion{}
	case x == nil:
		return expansion{change: analysis.ExpansionChangeOther}
	}
	switch x.Value() {
	case shell.ParamValueWhole, shell.ParamValueQuoted:
		return expansion{}
	case shell.ParamValueNone:
		return expansion{drop: true}
	case shell.ParamValueIndirect:
		return expansion{opaque: true}
	}
	return expansion{change: expansionChanges[x.Change()]}
}

// expansionChanges are the values of shell.ParamChange as analysis has them.
var expansionChanges = map[shell.ParamChange]analysis.ExpansionChange{
	shell.ParamChangeSubstring:     analysis.ExpansionChangeSubstring,
	shell.ParamChangePrefixRemoval: analysis.ExpansionChangePrefixRemoval,
	shell.ParamChangeSuffixRemoval: analysis.ExpansionChangeSuffixRemoval,
	shell.ParamChangeReplacement:   analysis.ExpansionChangeReplacement,
	shell.ParamChangeCaseChange:    analysis.ExpansionChangeCaseChange,
	shell.ParamChangeOther:         analysis.ExpansionChangeOther,
}

// apply is c after the expansion.
func (e expansion) apply(c CarriedSecret) CarriedSecret {
	switch {
	case e.opaque:
		c.Form, c.Transform = analysis.SecretFormOpaque, analysis.Transform{}
	case e.change != analysis.ExpansionChangeUnset:
		c = transformed(c, analysis.TransformByExpansion(e.change))
	}
	return c
}

// transformed is c after the change t: a value made from it, unless it is
// what a command not known writes.
func transformed(c CarriedSecret, t analysis.Transform) CarriedSecret {
	if c.Form != analysis.SecretFormOpaque {
		c.Form, c.Transform, c.Masked = analysis.SecretFormTransformed, t, false // another value than the one registered
	}
	return c
}

// identityCommands write their words, or their input, as they are.
var identityCommands = map[string]bool{"echo": true, "printf": true, "cat": true, "tee": true}

// outputSecrets are the secrets what the commands cs write to their
// standard output carries, in carrying what comes to them on the standard
// input. An assignment's secrets are there as SecretFormOpaque, as a
// command after it in the substitution may write them. The walk reads the
// descriptors (shell.OutputReading): where each simple command's standard
// output goes, past exec, the redirects of compound commands and calls, |&,
// and the paths that return, exit, break and continue end; it gives the
// body of a function where each call runs it. from is the reading of the
// command the commands are a $( ) of a word of, which they start with the
// descriptors of; with no from, they start as a script does, their
// standard error going to the output too when err.
func (f *secretFlow) outputSecrets(cs []shell.Command, in []CarriedSecret, at, depth int, from *shell.DescriptorReading, err bool) []CarriedSecret {
	return f.outputSecretsOf(cs, in, at, depth, func() *shell.DescriptorReading { return f.out.Begin(from, err) })
}

// substitutionSecrets is outputSecrets of the $( ) or <( ) p, read with the
// reading d of the command whose word holds it, or, with no d, apart from
// that command (shell.OutputReading.BeginSubstitution).
func (f *secretFlow) substitutionSecrets(p shell.Part, at, depth int, d *shell.DescriptorReading) []CarriedSecret {
	key := substKey{part: p.Span.Start, at: at, start: f.out.Start(d, p.Span.Start)}
	if len(f.registrations()) == 0 {
		key.at = -1 // no ::add-mask:: in the run: the place it is read at masks nothing
	}
	return f.memoized(key, func() []CarriedSecret {
		var out []CarriedSecret
		if d != nil {
			out = f.outputSecrets(p.Sub.List, nil, at, depth, d, false)
		} else {
			out = f.outputSecretsOf(p.Sub.List, nil, at, depth, func() *shell.DescriptorReading { return f.out.BeginSubstitution(p.Span.Start) })
		}
		return uniqueSecrets(out) // the reader gives each the span of the $( ): the value of two $( ) of the same is no more
	})
}

// substKey is what the secrets of a $( ) depend on: where it is, the place
// at which its variables are read as masked or not (at), and what its
// reading starts from (shell.OutputReading.Start).
type substKey struct {
	part, at int
	start    string
}

// outputSecretsOf is outputSecrets with the reading begin begins.
func (f *secretFlow) outputSecretsOf(cs []shell.Command, in []CarriedSecret, at, depth int, begin func() *shell.DescriptorReading) []CarriedSecret {
	// frame is a command being read: what comes to it on the standard
	// input, what it writes, and for a pipeline, what each of its commands
	// writes
	type frame struct {
		in, out []CarriedSecret
		outs    [][]CarriedSecret
	}
	stack := []*frame{{in: in}}
	// calls are where what the body of a function a call runs writes goes:
	// where the call's own output went, and what comes to it on its input
	type call struct {
		in   []CarriedSecret
		into func([]CarriedSecret)
	}
	calls := map[*shell.Simple]*call{}
	d := begin()
	defer f.out.End(d)
	skipped := func(c shell.Command, e shell.Enclosing) bool {
		if e.Env.Kind == shell.ExecutionEnvironmentCommandSubstitution || e.Env.Kind == shell.ExecutionEnvironmentProcessSubstitution {
			return true // read with the words that hold them (secretsInParts)
		}
		if e.Call != nil && d.Blind() {
			return true // a blind reading does not read the bodies at calls (shell.OutputReading.BeginBlind)
		}
		if x, ok := c.(*shell.Compound); ok && x.Kind.PipesToShell() {
			return true // a coproc writes to the shell
		}
		_, def := c.(*shell.FuncDef) // a function writes where it is called
		return def
	}
	body := func(c shell.Command, e shell.Enclosing) *call {
		if e.Call != nil && e.Func != nil && e.Func.Body == c {
			return calls[e.Call]
		}
		return nil
	}
	shell.Walk(f.text, cs, shell.Enclosing{}, shell.Visitor{
		Descriptors: d,
		Command: func(c shell.Command, e shell.Enclosing) bool {
			if skipped(c, e) {
				return false
			}
			in := stack[len(stack)-1].in
			if k := body(c, e); k != nil {
				in = k.in
			}
			if e.Pipeline != nil && e.Element > 0 {
				// what the commands before it write through the pipe
				// (shell.PipeSources), when it reads the pipe
				in = nil
				readers, unread := shell.PipeReaders(f.text, c)
				if from := shell.PipeSources(f.text, e.Pipeline, e.Element); len(from) > 0 && from[0].Element == e.Element-1 && (len(readers) > 0 || unread) {
					in = stack[len(stack)-1].outs[e.Element-1]
				}
			}
			fr := &frame{in: in}
			if x, ok := c.(*shell.Pipeline); ok {
				fr.outs = make([][]CarriedSecret, len(x.Commands))
			}
			stack = append(stack, fr)
			x, ok := c.(*shell.Simple)
			if !ok {
				return true // the simple commands in it say where each writes
			}
			var called bool
			fr.out, called = f.simpleOutput(x, in, at, depth, d)
			if called {
				calls[x] = &call{in: f.inputOf(x, in, at, depth)}
			}
			f.out.Count(x)
			return false
		},
		Leave: func(c shell.Command, e shell.Enclosing) {
			if skipped(c, e) || len(stack) == 1 {
				return
			}
			fr := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			parent := stack[len(stack)-1]
			into := func(cs []CarriedSecret) { parent.out = append(parent.out, cs...) }
			if e.Pipeline != nil {
				i, last := e.Element, e.Element == len(e.Pipeline.Commands)-1
				into = func(cs []CarriedSecret) {
					parent.outs[i] = append(parent.outs[i], cs...)
					if last {
						parent.out = append(parent.out, cs...) // the last writes the pipeline's output
					}
				}
			}
			if k := body(c, e); k != nil && k.into != nil {
				into = k.into // the body writes where its call writes
			}
			if e.Env.Kind == shell.ExecutionEnvironmentPipelineElement {
				// what the commands of readings inside it wrote to the pipe
				// of its command of a pipeline: the next command reads it
				p := shell.OutputPlace{Depth: d.Depth(), Element: e.Env}
				fr.out = append(fr.out, f.pass[p]...)
				delete(f.pass, p)
			}
			into(fr.out)
			if x, ok := c.(*shell.Simple); ok && calls[x] != nil {
				calls[x].into = into // where the bodies Walk gives after it write
			}
		},
	})
	// what the commands of readings inside wrote to this one's output
	own := shell.OutputPlace{Depth: d.Depth()}
	out := append(stack[0].out, f.pass[own]...)
	delete(f.pass, own)
	return out
}

// inputOf is what comes to the simple command x on its standard input:
// in, and its here-strings and heredocs.
func (f *secretFlow) inputOf(x *shell.Simple, in []CarriedSecret, at, depth int) []CarriedSecret {
	stdin := slices.Clone(in)
	for _, r := range x.Redirects {
		switch {
		case r.Op == shell.RedirHereString:
			stdin = append(stdin, f.secretsInParts(r.Target.Parts, r.Target.Span.Start, at, depth)...)
		case r.Heredoc != nil && !r.Heredoc.Quoted:
			stdin = append(stdin, f.secretsInParts(r.Heredoc.Parts, r.Heredoc.Body.Start, at, depth)...)
		}
	}
	return stdin
}

// simpleOutput is outputSecrets of the simple command x, which the walk d
// reads for gives, and whether x calls a function, whose bodies the walk
// gives where x runs them (outputSecrets): what x writes counts where its
// standard output goes to the output read (DescriptorReading.Output).
func (f *secretFlow) simpleOutput(x *shell.Simple, in []CarriedSecret, at, depth int, d *shell.DescriptorReading) ([]CarriedSecret, bool) {
	var out []CarriedSecret
	for _, w := range x.Assigns {
		for _, c := range f.secretsInWords(w.Parts, w.Span.Start, at, depth, d) {
			c.Form, c.Transform = analysis.SecretFormOpaque, analysis.Transform{}
			out = append(out, c)
		}
	}
	if len(x.Words) == 0 {
		return out, false
	}
	var words []CarriedSecret
	for _, w := range x.Words[1:] {
		words = append(words, f.secretsInWords(w.Parts, w.Span.Start, at, depth, d)...)
	}
	own, around := d.Outputs(x)
	name, ok := shell.Literal(f.text, x.Words[0])
	if ok {
		if defs, _ := f.vis.Functions(name, x.Span()); len(defs) > 0 {
			return out, true // what the bodies print, the walk gives
		}
	}
	if !own && len(around) == 0 {
		return out, false // its own output goes elsewhere
	}
	wrote := f.wrote(x, name, ok, words, f.inputOf(x, in, at, depth))
	for _, p := range around {
		f.pass[p] = append(f.pass[p], wrote...) // to an output of a reading around, not to this one
	}
	if own {
		out = append(out, wrote...)
	}
	return out, false
}

// wrote are the secrets the simple command x, named name when literal (ok),
// writes to its standard output, from the secrets of its words and of its
// standard input.
func (f *secretFlow) wrote(x *shell.Simple, name string, ok bool, words, stdin []CarriedSecret) []CarriedSecret {
	switch {
	case ok && (name == "echo" || name == "printf"):
		return words
	case ok && (name == "cat" || name == "tee"):
		return stdin
	}
	var out []CarriedSecret
	all := append(words, stdin...)
	if m := shell.LookupCommand(shell.WordsOf(f.text, x)); m.Entry != nil {
		switch {
		case m.Entry.Has(shell.CommandTraitDigestsInput), f.silenced(m.Entry.Names[0], x):
			return nil
		case m.Entry.Has(shell.CommandTraitTransformsInput):
			// the words of a filter are its program, patterns and files: what
			// it writes is made from its input
			for _, c := range stdin {
				out = append(out, transformed(c, analysis.TransformByCommand(m.Entry.Names[0])))
			}
			all = words
		}
	}
	for _, c := range all {
		c.Form, c.Transform = analysis.SecretFormOpaque, analysis.Transform{}
		out = append(out, c)
	}
	return out
}

// silenced is whether the filter name, run as x, writes nothing of its
// input: grep that answers by its exit code or counts (-q, -c, -l, -L),
// sed that writes the file back (-i), base64 that writes a file (-o).
func (f *secretFlow) silenced(name string, x *shell.Simple) bool {
	var short, long string
	switch name {
	case "grep":
		short, long = "qclL", " --quiet --silent --count --files-with-matches --files-without-match "
	case "sed":
		short, long = "i", " --in-place "
	case "base64":
		// the base64 of macOS writes to the file of -o and --output
		// (https://github.com/apple-oss-distributions/text_cmds/blob/592aaf8a50aa5810ee8183df20f0ba48bb23aa7e/bintrans/bintrans.c);
		// GNU base64 has no -o and stops
		short, long = "o", " --output "
	default:
		return false
	}
	for _, w := range x.Words[1:] {
		t, ok := shell.Literal(f.text, w)
		switch {
		case !ok:
		case t == "--":
			return false
		case strings.HasPrefix(t, "--"):
			if strings.Contains(long, " "+strings.SplitN(t, "=", 2)[0]+" ") {
				return true
			}
		case strings.HasPrefix(t, "-") && len(t) > 1 && strings.ContainsAny(t[1:], short):
			return true // -ni and -in are in place too
		}
	}
	return false
}
