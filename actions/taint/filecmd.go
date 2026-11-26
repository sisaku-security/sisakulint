package taint

import (
	"github.com/gh-intel/sisakulint/actions/analysis"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// EnvironmentFileWrite is a reference an attacker may control, written to a file
// command by a run of bash or sh: a ${{ }} (Ref, its index in Sink.Refs)
// or a variable of env (Ref -1: Var, and what env gives it, Env). Span is
// the reference in the value of the sink: the ${{ }}'s reference, or the
// variable as written ($NAME, ${NAME}). Quote is the quotes of the
// variable, InBody whether it is in the body of a shell's heredoc, Op
// whether it has an operator (${NAME:-x}). Heredoc is, in SideBody, how to
// make the delimiter random, when the heredoc is of the form the fix
// rewrites.
type EnvironmentFileWrite struct {
	File     analysis.EnvironmentFile
	Side     analysis.Side
	Span     expr.Span
	RefIndex int
	Var      shell.VarName
	Op       bool
	Quote    shell.Quote
	InBody   bool
	Env      ExprRef
	Heredoc  *DelimWrite
	Nested   bool // in the code after -c of another shell (nested.go), inside single quotes
}

// DelimWrite is a name<<DELIM of the form the fix makes random:
// its first and last lines each written by echo of one word, the
// delimiter a literal. Insert is where the assignment of the delimiter
// goes, the start of the item of the script's list that writes it; Open and
// Close are the delimiter's bytes in the two words, and their quotes.
type DelimWrite struct {
	Insert                int
	Open, Close           expr.Span
	OpenQuote, CloseQuote shell.Quote
}

// InconclusiveWrite is a place of a write to an environment file whose
// analysis is inconclusive.
type InconclusiveWrite struct {
	File analysis.EnvironmentFile
	Kind analysis.InconclusiveWriteKind
	Span expr.Span
}

// Tainted is whether r may be what an attacker writes with line breaks:
// controlled with line breaks, or inconclusive.
func Tainted(r ExprRef) bool {
	return r.Verdict == analysis.Controlled && len(r.Lines) > 0 || r.Verdict == analysis.Inconclusive
}

// Reach are the events on which an attacker who controls r, written at
// side, writes what the runner reads as their own: a name, with a line
// break after the = or in a heredoc's body, with any value before the = (a
// branch name is enough); a directory, with any value on a line of
// $GITHUB_PATH.
func Reach(side analysis.Side, r ExprRef) []analysis.EventActivity {
	if r.Verdict != analysis.Controlled {
		return nil
	}
	if side == analysis.SideKey || side == analysis.SideLine {
		return r.ControlledOn
	}
	return r.Lines
}

// taintedFor is whether r may be what an attacker writes where any value
// counts (on $GITHUB_PATH, before the = of a line, or where the side is not
// known), or else what Tainted says.
func taintedFor(any bool, r ExprRef) bool {
	if any {
		return r.Verdict == analysis.Controlled || r.Verdict == analysis.Inconclusive
	}
	return Tainted(r)
}

// anyValue is whether any value an attacker controls counts written to file
// at side: on $GITHUB_PATH, a directory; before the = of a line, a name.
func anyValue(file analysis.EnvironmentFile, side analysis.Side) bool {
	return file == analysis.EnvironmentFilePath || side == analysis.SideKey
}

// counts is whether r written at side is an EnvironmentFileWrite: what an attacker may
// write there, or what is inconclusive.
func counts(side analysis.Side, r ExprRef) bool {
	return len(Reach(side, r)) > 0 || r.Verdict == analysis.Inconclusive
}

// RandomDelim is the assignment the fix writes before a name<<DELIM so that
// its delimiter is one an attacker cannot know: ghadelimiter_ and 16 bytes
// of /dev/urandom in hex. A delimiter is read as random only
// when it is a variable set by this assignment.
func RandomDelim(name string) string {
	return name + `="ghadelimiter_$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"`
}

var delimName = regexp.MustCompile(`^GHA_DELIM(_[0-9]+)?$`)

// fileNamed is the file of the variable name: $GITHUB_ENV, $GITHUB_OUTPUT
// or $GITHUB_PATH.
func fileNamed(name string) analysis.EnvironmentFile {
	switch name {
	case "GITHUB_ENV":
		return analysis.EnvironmentFileEnv
	case "GITHUB_OUTPUT":
		return analysis.EnvironmentFileOutput
	case "GITHUB_PATH":
		return analysis.EnvironmentFilePath
	}
	return analysis.EnvironmentFileUnset
}

// fileOf is the file the word w names: $GITHUB_ENV, $GITHUB_OUTPUT or
// $GITHUB_PATH alone, in braces or quotes or not, with an operator that
// keeps its value (${GITHUB_OUTPUT:?}), or a variable the script sets to
// one of them.
func (f *fileScan) fileOf(w shell.Word) analysis.EnvironmentFile {
	if len(w.Parts) != 1 {
		return analysis.EnvironmentFileUnset
	}
	p := w.Parts[0]
	switch {
	case p.Kind == shell.PartParam:
	case wholeValue(p):
	default:
		return analysis.EnvironmentFileUnset
	}
	if file := fileNamed(p.Name.String()); file != analysis.EnvironmentFileUnset {
		return file
	}
	if files, _ := f.aliasesAt(p); len(files) == 1 {
		for file := range files { // a path writes to the file (and others may not write)
			return file
		}
	}
	return analysis.EnvironmentFileUnset
}

// aliasesAt are the file commands the assignments that reach the read p
// set its variable to (out=$GITHUB_OUTPUT, export out=$GITHUB_OUTPUT), and
// whether another value may reach it too (another assignment, an unset, or
// the value from before the run).
func (f *fileScan) aliasesAt(p shell.Part) (map[analysis.EnvironmentFile]bool, bool) {
	files := map[analysis.EnvironmentFile]bool{}
	other := false
	rs := f.vis.Reaching(p.Name, p.Span)
	for _, r := range rs {
		file := analysis.EnvironmentFileUnset
		if r.Value != nil && !r.Append && len(r.Value.Parts) == 1 {
			// the value is $GITHUB_ENV, ${GITHUB_ENV} or one that keeps it
			if p := r.Value.Parts[0]; p.Kind == shell.PartParam || p.Kind == shell.PartParamOp && p.Param != nil && p.Param.Value() == shell.ParamValueWhole {
				file = fileNamed(p.Name.String())
			}
		}
		if file == analysis.EnvironmentFileUnset {
			other = true
			continue
		}
		files[file] = true
	}
	_ = other
	return files, len(files) > 1 // more than one file: which one a write goes to is not followed
}

// mixedOf is whether the word w is a variable the script sets to file and
// to another file: which one a write through it goes to is not followed.
func (f *fileScan) mixedOf(w shell.Word, file analysis.EnvironmentFile) bool {
	if len(w.Parts) != 1 || w.Parts[0].Kind != shell.PartParam {
		return false
	}
	files, mixed := f.aliasesAt(w.Parts[0])
	return files[file] && mixed
}

// wholeValue is whether the part p is the value of its variable when the
// variable is set, as the runner sets it: $NAME, or ${NAME...} whose
// ParamExpansion.Value is ParamValueWhole (no operator, :? ? :- - := =);
// not :+, %, / and the like, which give another value.
func wholeValue(p shell.Part) bool {
	return p.Kind == shell.PartParam || p.Kind == shell.PartParamOp && p.Param != nil && p.Param.Value() == shell.ParamValueWhole
}

// fileScan is the file commands of one run.
type fileScan struct {
	c        scope
	s        *Sink
	script   string
	holes    []shell.Span
	holePart []int // the part of s.Value of each hole
	vis      *shell.NameVisibility
}

// fileCommands reads what the run s writes to $GITHUB_ENV, $GITHUB_OUTPUT
// and $GITHUB_PATH into s.EnvironmentFileWrites and s.InconclusiveWrites.
func (c scope) fileCommands(s *Sink) {
	f := &fileScan{c: c, s: s, script: s.text()}
	for i, p := range s.Value.Parts {
		if p.Expr {
			f.holes = append(f.holes, shell.Span{Start: p.Span.Start, End: p.Span.End})
			f.holePart = append(f.holePart, i)
		}
	}
	sc := c.readSink(s).Script
	f.vis = c.scripts.Visibility(f.script, sc)
	s.CallsNotRead.Join(f.vis.CallsNotRead())
	writes := shell.Writes(f.script, sc, shell.WriteOptions{
		Target:      func(w shell.Word) bool { return f.fileOf(w) != analysis.EnvironmentFileUnset },
		Holes:       f.holes,
		EchoEscapes: s.Shell == ShellSh,
		NotRead:     &s.CallsNotRead,
		Visibility:  f.vis,
	})
	cases := casesOf(sc.List)
	for _, file := range []analysis.EnvironmentFile{analysis.EnvironmentFileEnv, analysis.EnvironmentFileOutput, analysis.EnvironmentFilePath} {
		r := &lineReader{f: f, file: file}
		for i := range writes {
			w := &writes[i]
			switch {
			case f.fileOf(w.Target) != file:
			case w.Exec:
				if f.taintedAfter(file == analysis.EnvironmentFilePath, sc, execFrom(sc, w.At)) {
					f.gap(file, analysis.InconclusiveWriteExecRedirect, w.At.Span())
				}
			case w.InFunc || f.nested(writes, i, file):
				// it runs where the function is called, or among the
				// lines of the write around it: read alone
				alone := &lineReader{f: f, file: file}
				alone.write(w)
				alone.end()
			default:
				r.write(w)
			}
		}
		r.end()
		read := map[shell.Command]bool{}
		for _, w := range writes {
			if f.fileOf(w.Target) == file {
				read[w.At] = true
			}
		}
		execFile := strings.Contains(f.script, "exec") && strings.Contains(f.script, file.String())
		opens := f.execOpens(sc.List, file)
		for _, t := range targets(f.script, sc.List) {
			// a file named in a way the rule does not read, as the file; a
			// descriptor that an exec of the file may have opened where the
			// command runs
			sp := t.cmd.Span()
			text := f.script[t.w.Span.Start:t.w.Span.End]
			named := strings.Contains(text, file.String()) && f.fileOf(t.w) == analysis.EnvironmentFileUnset
			fd := t.dup && execFile && strings.Trim(text, "0123456789") == "" && text != "0" && text != "1" && text != "2" && opens(text, t.cmd)
			// tee not in a pipeline, which what the writes read does not
			// follow: its input is a here-string or a heredoc
			tee := t.tee && f.fileOf(t.w) == file
			// a variable set to this file and to another, which is neither
			mixed := f.mixedOf(t.w, file)
			// the side of what they write is not known: any value counts
			any := file == analysis.EnvironmentFilePath || tee || mixed
			if (named || fd || tee || mixed) && !read[t.cmd] && (f.taintedText(any, sp) || f.taintedIn(any, sp, []shell.Command{t.cmd})) {
				f.gap(file, analysis.InconclusiveWriteWriterUnknown, sp)
			}
		}
		for _, c := range cases {
			// what case writes is not read
			sp := c.Span()
			if strings.Contains(f.script[sp.Start:sp.End], file.String()) && f.taintedText(file == analysis.EnvironmentFilePath, sp) {
				f.gap(file, analysis.InconclusiveWriteWriterUnknown, sp)
			}
		}
		if !sc.Complete && strings.Contains(f.script[sc.Stop:], file.String()) {
			f.gap(file, analysis.InconclusiveWriteAfterStop, shell.Span{Start: sc.Stop, End: len(f.script)})
		}
	}
}

// execOpens is whether an exec of file may have opened the descriptor fd
// where the command c runs: an exec with no command that points fd to
// file runs in the shell of c or in one c runs inside (a function's body
// runs where it is called), or no such exec is in the tree (it is where
// the tree does not follow, such as an arm of case). An exec in a subshell
// that does not hold c (a command of a pipeline, one ended by &) opens
// nothing for c.
func (f *fileScan) execOpens(cs []shell.Command, file analysis.EnvironmentFile) func(fd string, c shell.Command) bool {
	envs := map[shell.Command]*shell.ExecutionEnvironment{}
	execs := map[string][]*shell.ExecutionEnvironment{}
	shell.Walk(f.script, cs, shell.Enclosing{}, shell.Visitor{Command: func(c shell.Command, at shell.Enclosing) bool {
		envs[c] = at.Env
		x, ok := c.(*shell.Simple)
		if !ok || len(x.Words) != 1 {
			return true
		}
		if n, ok := shell.Literal(f.script, x.Words[0]); !ok || n != "exec" {
			return true
		}
		for _, r := range x.Redirects {
			if r.Fd >= 0 && f.fileOf(r.Target) == file {
				fd := strconv.Itoa(r.Fd)
				execs[fd] = append(execs[fd], at.Env)
			}
		}
		return true
	}})
	return func(fd string, c shell.Command) bool {
		if len(execs[fd]) == 0 {
			return true
		}
		for _, e := range execs[fd] {
			for in := envs[c]; in != nil; in = in.Parent {
				if in == e {
					return true
				}
			}
		}
		return false
	}
}

// nested is whether the write i to file is inside the command of another
// write to it, whose lines it runs among.
func (f *fileScan) nested(writes []shell.Write, i int, file analysis.EnvironmentFile) bool {
	sp := writes[i].At.Span()
	for j, w := range writes {
		o := w.At.Span()
		if j != i && f.fileOf(w.Target) == file && !w.Exec && o.Start <= sp.Start && sp.End <= o.End && o != sp {
			return true
		}
	}
	return false
}

// target is a word a command writes to: the target of a redirect of the
// output, or a file of tee.
type target struct {
	w   shell.Word
	cmd shell.Command
	dup bool // >&w
	tee bool // a file of tee
}

// targets are the words the commands cs write to, at any depth outside
// substitutions.
func targets(script string, cs []shell.Command) []target {
	var out []target
	redirects := func(c shell.Command, rs []shell.Redirect) {
		for _, r := range rs {
			switch r.Op {
			case shell.RedirOut, shell.RedirAppend, shell.RedirClobber, shell.RedirAll, shell.RedirAppendAll, shell.RedirDupOut:
				out = append(out, target{r.Target, c, r.Op == shell.RedirDupOut, false})
			}
		}
	}
	shell.Walk(script, cs, shell.Enclosing{}, shell.Visitor{
		Command: func(c shell.Command, at shell.Enclosing) bool {
			if substitution(at.Env) {
				return false
			}
			if x, ok := c.(*shell.Simple); ok {
				redirects(x, x.Redirects)
				if len(x.Words) > 1 {
					if p := x.Words[0].Parts; len(p) == 1 && p[0].Kind == shell.PartLiteral && script[p[0].Span.Start:p[0].Span.End] == "tee" {
						for _, a := range x.Words[1:] {
							out = append(out, target{a, x, false, true})
						}
					}
				}
				return false
			}
			return true
		},
		Leave: func(c shell.Command, at shell.Enclosing) {
			if x, ok := c.(*shell.Compound); ok && !substitution(at.Env) {
				redirects(x, x.Redirects) // after the targets of the commands in it
			}
		},
	})
	return out
}

// casesOf are the case commands of cs, at any depth outside substitutions.
func casesOf(cs []shell.Command) []shell.Command {
	var out []shell.Command
	shell.Walk("", cs, shell.Enclosing{}, shell.Visitor{Command: func(c shell.Command, at shell.Enclosing) bool {
		if substitution(at.Env) {
			return false
		}
		if x, ok := c.(*shell.Compound); ok && x.Kind == shell.CompoundCase {
			out = append(out, x)
		}
		return true
	}})
	return out
}

// substitution is whether a command Walk gives in env is the first of the
// script of a substitution.
func substitution(env *shell.ExecutionEnvironment) bool {
	return env.Kind == shell.ExecutionEnvironmentCommandSubstitution || env.Kind == shell.ExecutionEnvironmentProcessSubstitution
}

// taintedText is whether a ${{ }} inside sp, or a parameter of its bytes
// read as tokens of commands (shell.TextParams), may be what an attacker writes to
// file: for what the tree does not read.
func (f *fileScan) taintedText(any bool, sp shell.Span) bool {
	if f.taintedIn(any, sp, nil) {
		return true
	}
	for _, p := range shell.TextParams(f.script, sp) {
		if r, ok := f.varRef(p.Name.String()); ok && taintedFor(any, r) {
			return true
		}
	}
	return false
}

// taintedArith is whether the arithmetic expression a may write what an
// attacker controls: a parameter in it (what it gives is a number, with no
// line break, as any says), or, when bare, a name written without $ that
// it reads as the variable, which
// counts where any value does, on $GITHUB_PATH.
func (f *fileScan) taintedArith(any, bare bool, a *shell.Arithmetic) bool {
	if a == nil {
		return false
	}
	for _, p := range shell.PartParams(a.Parts) {
		if r, ok := f.varRef(p.Name.String()); ok && taintedFor(any, r) {
			return true
		}
	}
	for _, n := range a.Names {
		if r, ok := f.varRef(n.Name.String()); bare && !n.Assigned && ok && taintedFor(true, r) {
			return true
		}
	}
	return false
}

// random is whether the variable name is the fix's delimiter at at: every
// assignment that reaches at is the fix's (shell.NameVisibility; the name
// of a for or select assigns it a word of the loop, not the fix's).
func (f *fileScan) random(name string, at int) bool {
	n, ok := shell.NameOf(name)
	if !ok {
		return false
	}
	rs := f.vis.Reaching(n, shell.Span{Start: at, End: at})
	for _, r := range rs {
		if r.Before || r.Value == nil || f.script[r.At.Start:r.At.End] != RandomDelim(name) {
			return false
		}
	}
	return len(rs) > 0
}

// refsOfHole are the references of s.Refs in the ${{ }} of the hole h.
func (f *fileScan) refsOfHole(h int) []int {
	var out []int
	for i, r := range f.s.Refs {
		if r.Part == f.holePart[h] {
			out = append(out, i)
		}
	}
	return out
}

// varRef is what env gives the shell variable name (scope.varRef).
func (f *fileScan) varRef(name string) (ExprRef, bool) { return f.c.varRef(name) }

// varRef is what env gives the shell variable name: the env of a level
// whose key is name, with its case (a variable of Linux has its case). A
// variable the runner writes in every step (RunnerVariable) is its
// context, whatever env writes.
func (c scope) varRef(name string) (ExprRef, bool) {
	if v, ok := c.runnerVariable(name); ok {
		if v.Context == nil {
			return ExprRef{}, true // a fixed text, which no attacker controls
		}
		r := c.classify(v.Context, 0, writtenText)
		if r.Verdict == analysis.Controlled {
			r.Source = v.Context
		}
		return r, true
	}
	for lvl, e := range c.envs {
		if e.Status == workflow.Dynamic {
			return ExprRef{Verdict: analysis.Inconclusive, InconclusiveKind: analysis.InconclusiveRefEnvDynamic}, true
		}
		if e.Status != workflow.Present {
			continue
		}
		if x, ok := e.Value.Lookup(name); ok && x.Key.AsString() == name {
			if c.narrowed([]expr.PathElem{{Name: "env"}, {Name: name}}, 0) {
				return ExprRef{}, true // the value the step's if compares
			}
			return c.envFrom(name, lvl), true
		}
	}
	return ExprRef{}, false
}

// taintedIn is whether a ${{ }} inside sp, or a parameter of cmds, may be
// what an attacker writes to file.
func (f *fileScan) taintedIn(any bool, sp shell.Span, cmds []shell.Command) bool {
	for h, hs := range f.holes {
		if hs.Start >= sp.Start && hs.End <= sp.End {
			for _, ri := range f.refsOfHole(h) {
				if taintedFor(any, f.s.Refs[ri]) {
					return true
				}
			}
		}
	}
	for _, p := range f.paramsThrough(cmds) {
		if r, ok := f.varRef(p.Name.String()); ok && taintedFor(any, r) {
			return true
		}
	}
	return false
}

// paramsThrough are the parameters of cmds and of the bodies of the
// functions their calls may run (shell.NameVisibility), each body once: a
// command not known whose commands call a function writes what the body
// writes (f | cat >>"$GITHUB_ENV").
func (f *fileScan) paramsThrough(cmds []shell.Command) []*shell.Part {
	seen := map[*shell.FuncDef]bool{}
	var out []*shell.Part
	var add func(cs []shell.Command)
	add = func(cs []shell.Command) {
		out = append(out, shell.Params(cs)...)
		shell.WalkSimple(cs, func(x *shell.Simple) {
			if len(x.Words) == 0 {
				return
			}
			n, ok := shell.Literal(f.script, x.Words[0])
			if !ok {
				return
			}
			defs, _ := f.vis.Functions(n, x.Span())
			for _, d := range defs {
				if !seen[d] {
					seen[d] = true
					add([]shell.Command{d.Body})
				}
			}
		})
	}
	add(cmds)
	return out
}

// taintedAfter is whether what the script has from at on may be what an
// attacker writes to file.
func (f *fileScan) taintedAfter(any bool, sc *shell.Script, at int) bool {
	if f.taintedIn(any, shell.Span{Start: at, End: len(f.script)}, nil) {
		return true
	}
	for _, p := range shell.Params(sc.List) {
		if p.Span.Start < at {
			continue
		}
		if r, ok := f.varRef(p.Name.String()); ok && taintedFor(any, r) {
			return true
		}
	}
	return false
}

// execFrom is where what an exec c points a descriptor for starts: after
// it, or, for an exec in the body of a loop of the same shell, where the
// outermost such loop starts, whose next round runs the commands before
// the exec after it (for i in 1 2; do echo "$T"; exec >>"$GITHUB_ENV"; done).
func execFrom(sc *shell.Script, c shell.Command) int {
	at := c.Span().End
	type loop struct {
		c   *shell.Compound
		env *shell.ExecutionEnvironment
	}
	var loops []loop
	shell.Walk("", sc.List, shell.Enclosing{}, shell.Visitor{
		Command: func(x shell.Command, e shell.Enclosing) bool {
			if x == c {
				for _, l := range loops {
					if l.env == e.Env {
						at = l.c.Span().Start
						break
					}
				}
				return false
			}
			if y, ok := x.(*shell.Compound); ok && y.Kind.Loop() {
				loops = append(loops, loop{y, e.Env})
			}
			return true
		},
		Leave: func(x shell.Command, _ shell.Enclosing) {
			if y, ok := x.(*shell.Compound); ok && y.Kind.Loop() && len(loops) > 0 && loops[len(loops)-1].c == y {
				loops = loops[:len(loops)-1]
			}
		},
	})
	return at
}

func (f *fileScan) gap(file analysis.EnvironmentFile, g analysis.InconclusiveWriteKind, sp shell.Span) {
	x := InconclusiveWrite{File: file, Kind: g, Span: expr.Span{Start: sp.Start, End: sp.End}}
	for _, y := range f.s.InconclusiveWrites {
		if y == x {
			return
		}
	}
	f.s.InconclusiveWrites = append(f.s.InconclusiveWrites, x)
}

// frag is a piece of a line of a file command: an Out of a write, or the
// text of a literal Out from off on.
type frag struct {
	out    *shell.Out
	w      *shell.Write
	text   string
	off    int
	merged bool // the texts of literals next to each other, joined
}

// joined is line with the literals next to each other joined: the runner
// reads the line whole, so a << may be across two.
func joined(line []frag) []frag {
	var out []frag
	for _, x := range line {
		if n := len(out); n > 0 && x.lit() && out[n-1].lit() {
			out[n-1].text += x.text
			out[n-1].merged = true
			continue
		}
		out = append(out, x)
	}
	return out
}

func (x frag) lit() bool { return x.out.Kind == shell.OutLit }

// lineReader reads the writes to one file in order, as the runner reads
// the file.
type lineReader struct {
	f    *fileScan
	file analysis.EnvironmentFile
	line []frag
	doc  *openDoc
	// inParam: the pieces being read are in a word of a ${ } with an
	// operator (words), which the fix does not rewrite in place
	inParam int
}

// openDoc is a name<<DELIM whose body is being read.
type openDoc struct {
	delim  string        // a literal delimiter
	random shell.VarName // the variable of the fix's delimiter; zero when it is not one
	open   frag          // the literal the delimiter is in
	at     int           // where the delimiter starts in open.text
	single bool          // the first line is that literal alone
	openNL frag          // the line break that ends the first line
	bodies []int         // of s.EnvironmentFileWrites: the values of its body
}

func (r *lineReader) write(w *shell.Write) {
	for i := range w.Out {
		o := &w.Out[i]
		if o.Kind != shell.OutLit {
			r.line = append(r.line, frag{out: o, w: w})
			if o.Kind == shell.OutUnknown {
				r.eol(frag{}) // it writes whole lines
			}
			continue
		}
		t, off := o.Text, 0
		for {
			j := strings.IndexByte(t, '\n')
			if j < 0 {
				if t != "" {
					r.line = append(r.line, frag{out: o, w: w, text: t, off: off})
				}
				break
			}
			if j > 0 {
				r.line = append(r.line, frag{out: o, w: w, text: t[:j], off: off})
			}
			r.eol(frag{out: o, w: w, text: "\n", off: off + j})
			t, off = t[j+1:], off+j+1
		}
	}
}

func (r *lineReader) end() {
	if len(r.line) > 0 {
		r.eol(frag{})
	}
	r.doc = nil
}

func (r *lineReader) eol(nl frag) {
	line := joined(r.line)
	r.line = nil
	if r.doc != nil {
		r.bodyLine(line, nl)
		return
	}
	if r.file == analysis.EnvironmentFilePath {
		// the runner reads the line whole as a directory: no = or <<
		for _, x := range line {
			if !x.lit() {
				r.value(x, analysis.SideLine, nil)
			}
		}
		return
	}
	for k, x := range line {
		if !x.lit() {
			r.value(x, analysis.SideKey, nil)
			continue
		}
		e, h := strings.Index(x.text, "="), strings.Index(x.text, "<<")
		switch {
		case e >= 0 && (h < 0 || e < h):
			for _, y := range line[k+1:] {
				if !y.lit() {
					r.value(y, analysis.SideValue, nil)
				}
			}
			return
		case h >= 0:
			r.open(line, k, h, nl)
			return
		}
	}
}

// open reads the delimiter of name<<DELIM, << at h of line[k].
func (r *lineReader) open(line []frag, k, h int, nl frag) {
	d := &openDoc{open: line[k], at: h + 2, single: len(line) == 1, openNL: nl}
	tail, rest := line[k].text[h+2:], line[k+1:]
	var b strings.Builder
	b.WriteString(tail)
	lit := true
	for _, y := range rest {
		if !y.lit() {
			lit = false
			break
		}
		b.WriteString(y.text)
	}
	switch {
	case lit && b.Len() > 0:
		d.delim = b.String()
	case tail == "" && len(rest) == 1 && rest[0].out.Kind == shell.OutParam && rest[0].out.Part.Kind == shell.PartParam &&
		r.f.random(rest[0].out.Part.Name.String(), rest[0].out.Span.Start):
		d.random = rest[0].out.Part.Name
	default:
		for _, y := range rest {
			if !y.lit() {
				r.value(y, analysis.SideKey, nil) // the attacker writes the delimiter
			}
		}
	}
	r.doc = d
}

func (r *lineReader) bodyLine(line []frag, nl frag) {
	d := r.doc
	if d.closes(line) {
		r.doc = nil
		if d.delim != "" {
			if dw := r.delimWrite(d, line, nl); dw != nil {
				for _, i := range d.bodies {
					r.f.s.EnvironmentFileWrites[i].Heredoc = dw
				}
			}
		}
		return
	}
	if d.random != (shell.VarName{}) {
		return // no attacker writes the delimiter
	}
	for _, x := range line {
		if !x.lit() {
			r.value(x, analysis.SideBody, d)
		}
	}
}

func (d *openDoc) closes(line []frag) bool {
	if d.random != (shell.VarName{}) {
		return len(line) == 1 && line[0].out.Kind == shell.OutParam && line[0].out.Part.Kind == shell.PartParam && line[0].out.Part.Name == d.random
	}
	if d.delim == "" {
		return false // a delimiter not known: the body goes to the end
	}
	var b strings.Builder
	for _, x := range line {
		if !x.lit() {
			return false
		}
		b.WriteString(x.text)
	}
	return b.String() == d.delim
}

// delimWrite is how to make the delimiter of d random, when the fix can
// rewrite d so, or nil.
func (r *lineReader) delimWrite(d *openDoc, closeLine []frag, closeNL frag) *DelimWrite {
	one := func(x, nl frag) (*shell.Simple, bool) {
		o := x.out
		by := o.By
		return by, o.Kind == shell.OutLit && !x.merged && o.Exact && by != nil && o.Word == 1 && len(by.Words) == 2 &&
			nl.out != nil && nl.out.By == by && nl.out.Word == -1 && x.off+len(x.text) == len(o.Text) && isEcho(r.f.script, by)
	}
	if len(closeLine) != 1 {
		return nil
	}
	openBy, ok1 := one(d.open, d.openNL)
	closeBy, ok2 := one(closeLine[0], closeNL)
	if !ok1 || !ok2 || d.open.off != 0 || !d.single || d.at >= len(d.open.text) {
		return nil // the delimiter is not all in the one literal of the first line
	}
	ow, cw := d.open.w, closeLine[0].w
	switch {
	case ow == cw:
		// the first and the last lines are written whatever else runs: the
		// echos are commands of the braces themselves
		c, ok := ow.At.(*shell.Compound)
		if !ok || c.Kind != shell.CompoundBrace || ow.At != ow.Top || !slices.Contains(c.Body, shell.Command(openBy)) || !slices.Contains(c.Body, shell.Command(closeBy)) {
			return nil
		}
	case ow.At != ow.Top || cw.At != cw.Top || ow.At != shell.Command(openBy) || cw.At != shell.Command(closeBy):
		return nil
	}
	o, c := d.open.out, closeLine[0].out
	return &DelimWrite{
		Insert:     ow.Top.Span().Start,
		Open:       expr.Span{Start: o.Span.Start + d.at, End: o.Span.End},
		Close:      expr.Span{Start: c.Span.Start, End: c.Span.End},
		OpenQuote:  o.Quote,
		CloseQuote: c.Quote,
	}
}

func isEcho(script string, x *shell.Simple) bool {
	p := x.Words[0].Parts
	return len(p) == 1 && p[0].Kind == shell.PartLiteral && p[0].Quote == shell.QuoteNone && script[p[0].Span.Start:p[0].Span.End] == "echo"
}

// value reads the piece x of a line, at side: the references in it that
// an attacker may control, and what is inconclusive.
func (r *lineReader) value(x frag, side analysis.Side, d *openDoc) {
	o := x.out
	switch o.Kind {
	case shell.OutHole:
		for _, ri := range r.f.refsOfHole(o.Hole) {
			if ref := r.f.s.Refs[ri]; counts(side, ref) {
				r.add(EnvironmentFileWrite{File: r.file, Side: side, Span: ref.Span, RefIndex: ri}, d)
			}
		}
	case shell.OutParam:
		name := o.Part.Name.String()
		ref, ok := r.f.varRef(name)
		writes := ok && counts(side, ref) // the value of the variable is written
		if x := o.Part.Param; o.Part.Kind == shell.PartParamOp {
			switch {
			case x == nil:
				// a ${ } bash does not read: what its text names
				if r.f.taintedText(anyValue(r.file, side), o.Span) {
					r.f.gap(r.file, analysis.InconclusiveWriteSubstValue, o.Span)
				}
			case x.Value() == shell.ParamValueNone:
				writes = false // a length, the attributes, :+ (its word only)
			case x.Value() == shell.ParamValueIndirect:
				// the value of the variable the value names
				if ok && ref.Verdict != analysis.NotControlled {
					r.f.gap(r.file, analysis.InconclusiveWriteSubstValue, o.Span)
				}
				writes = false
			case x.Value() == shell.ParamValueQuoted && r.file != analysis.EnvironmentFilePath:
				writes = false // quoted as $'...': no line break; on $GITHUB_PATH the directory is still theirs
			case side == analysis.SideValue && r.file != analysis.EnvironmentFilePath && shell.LineFree(r.f.script, o.Part):
				writes = false // ${T%%[[:space:]]*}: no line break; before the = it still names a variable
			}
			if x != nil {
				for _, w := range x.ValueWords() {
					// ${x:-$V}: $V when x is empty. The fix rewrites $V in place,
					// but not when the ${ } is written too (the fix would change
					// the text of the finding of the ${ }), nor in the string of /,
					// where a & of the value stands for the match only outside
					// quotes (patsub_replacement)
					r.words(w, o, side, d, writes || x.Change() == shell.ParamChangeReplacement)
				}
			}
		}
		if !writes {
			return
		}
		r.add(EnvironmentFileWrite{File: r.file, Side: side, Span: expr.Span{Start: o.Span.Start, End: o.Span.End}, RefIndex: -1,
			Var: o.Part.Name, Op: o.Part.Kind == shell.PartParamOp || r.inParam > 0, Quote: o.Quote, InBody: o.InBody, Env: ref}, d)
	case shell.OutSubst, shell.OutOpaque:
		if o.Kind == shell.OutSubst && side == analysis.SideValue && shell.LineFree(r.f.script, o.Part) {
			return // without line breaks; before the = it still names a variable
		}
		var sub []shell.Command
		if o.Part != nil && o.Part.Sub != nil {
			sub = o.Part.Sub.List
		}
		// what $( ) and ` ` hold (their Sub), what $(( )) reads (its
		// Arithmetic), and, for a part the tree does not read, what its bytes
		// name
		any := anyValue(r.file, side)
		arith := o.Part != nil && o.Part.Kind == shell.PartArith
		if r.f.taintedIn(any, o.Span, sub) || arith && r.f.taintedArith(any, r.file == analysis.EnvironmentFilePath, o.Part.Arith) || o.Kind == shell.OutOpaque && !arith && r.f.taintedText(any, o.Span) {
			r.f.gap(r.file, analysis.InconclusiveWriteSubstValue, o.Span)
		}
	case shell.OutUnknown:
		if r.f.taintedIn(anyValue(r.file, side), o.Span, []shell.Command{o.Cmd}) {
			r.f.gap(r.file, analysis.InconclusiveWriteWriterUnknown, o.Span)
		}
	}
}

// words reads the word w of the ${ } of the piece o (ParamExpansion.ValueWords)
// as pieces of the line at side; outerWritten when the ${ } is written too, so
// that the fix does not rewrite the word inside it.
func (r *lineReader) words(w shell.Word, o *shell.Out, side analysis.Side, d *openDoc, outerWritten bool) {
	if outerWritten {
		r.inParam++
		defer func() { r.inParam-- }()
	}
	for i := range w.Parts {
		p := &w.Parts[i]
		out := shell.Out{Span: p.Span, Part: p, By: o.By, Word: o.Word, Quote: p.Quote, InBody: o.InBody}
		switch p.Kind {
		case shell.PartLiteral:
			for h, hs := range r.f.holes {
				if hs.Start >= p.Span.Start && hs.End <= p.Span.End {
					hole := out
					hole.Kind, hole.Span, hole.Hole = shell.OutHole, hs, h
					r.value(frag{out: &hole}, side, d)
				}
			}
			continue
		case shell.PartParam, shell.PartParamOp:
			out.Kind = shell.OutParam
		case shell.PartSubst:
			out.Kind = shell.OutSubst
		default:
			out.Kind = shell.OutOpaque
		}
		r.value(frag{out: &out}, side, d)
	}
}

func (r *lineReader) add(w EnvironmentFileWrite, d *openDoc) {
	for _, x := range r.f.s.EnvironmentFileWrites {
		if x.File == w.File && x.Side == w.Side && x.Span == w.Span && x.RefIndex == w.RefIndex {
			return // the same place written again, as a function called twice
		}
	}
	r.f.s.EnvironmentFileWrites = append(r.f.s.EnvironmentFileWrites, w)
	if d != nil && w.Side == analysis.SideBody {
		d.bodies = append(d.bodies, len(r.f.s.EnvironmentFileWrites)-1)
	}
}
