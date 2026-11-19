package shell

import (
	"maps"
	"slices"
	"strings"
)

// ExecutionEnvironmentKind is the kind of an ExecutionEnvironment: the
// shell that runs the script, or the subshell that one of the constructs
// bash runs in a subshell starts (bashref, "Command Execution
// Environment").
type ExecutionEnvironmentKind uint8

const (
	ExecutionEnvironmentUnset ExecutionEnvironmentKind = iota
	// ExecutionEnvironmentTop: the shell that runs the script.
	ExecutionEnvironmentTop
	// ExecutionEnvironmentSubshell: the commands of ( ... ).
	ExecutionEnvironmentSubshell
	// ExecutionEnvironmentCoproc: the command of a coproc.
	ExecutionEnvironmentCoproc
	// ExecutionEnvironmentPipelineElement: a command of a pipeline of two
	// or more commands.
	ExecutionEnvironmentPipelineElement
	// ExecutionEnvironmentAsynchronous: a command ended by &.
	ExecutionEnvironmentAsynchronous
	// ExecutionEnvironmentCommandSubstitution: the script of $( ) and of
	// ` `.
	ExecutionEnvironmentCommandSubstitution
	// ExecutionEnvironmentProcessSubstitution: the script of <( ) or >( ).
	ExecutionEnvironmentProcessSubstitution
)

var executionEnvironmentKindNames = [...]string{"ExecutionEnvironmentUnset", "ExecutionEnvironmentTop", "ExecutionEnvironmentSubshell", "ExecutionEnvironmentCoproc", "ExecutionEnvironmentPipelineElement", "ExecutionEnvironmentAsynchronous", "ExecutionEnvironmentCommandSubstitution", "ExecutionEnvironmentProcessSubstitution"}

func (k ExecutionEnvironmentKind) String() string { return executionEnvironmentKindNames[k] }

// ExecutionEnvironment is one shell that runs commands: what a command
// assigns, defines and opens in it stays in it and in the subshells it
// starts after, and does not reach its Parent. Start is the span of the
// node that starts it: the command, or the part of a substitution. The
// shell that runs the script has no Parent.
type ExecutionEnvironment struct {
	Kind   ExecutionEnvironmentKind
	Parent *ExecutionEnvironment
	Start  Span
}

// StdoutKind is where the standard output of a command goes before its own
// redirects.
type StdoutKind uint8

const (
	StdoutUnset StdoutKind = iota
	// StdoutLog: the step's log, the standard output or error the script
	// inherits.
	StdoutLog
	// StdoutPipe: a pipe: to the next command of a pipeline, to the shell
	// that starts a coproc, or to the command that reads a <( ).
	StdoutPipe
	// StdoutSubstitution: the value of a $( ).
	StdoutSubstitution
	// StdoutFile: anywhere else: a file, /dev/null, or a descriptor not
	// open.
	StdoutFile
)

var stdoutKindNames = [...]string{"StdoutUnset", "StdoutLog", "StdoutPipe", "StdoutSubstitution", "StdoutFile"}

func (k StdoutKind) String() string { return stdoutKindNames[k] }

// Enclosing is what Walk gives with a node: the ExecutionEnvironment that
// runs it, the function whose body it is in (nil outside one), the
// pipeline it is a command of and its index there (nil and -1 when it is
// not itself a command of a pipeline), and where its standard output goes.
type Enclosing struct {
	Env  *ExecutionEnvironment
	Func *FuncDef
	// Call: in the body of a function a reading of descriptors gives where
	// a call runs it (DescriptorReading), that call; nil elsewhere
	Call     *Simple
	Pipeline *Pipeline
	Element  int
	Stdout   StdoutKind
	sh       shellState // the state of Env where the node is; the zero one is that of a script's start
	mayNot   bool       // the node may not run where it is (after && or ||, in the body of if, while, until, for, select or case)
}

// Visitor is the functions Walk calls; a nil one is not called. Command
// gets each command before its words, redirects and the commands in it;
// when it returns false, Walk does not go into them. Leave gets each
// command Command got, after them, also when Command returned false. Part
// gets each part of a word, of a redirect's target and of a heredoc's
// body, before the script in its Sub; Redirect gets each redirect, before
// the parts of its target.
type Visitor struct {
	Command  func(c Command, at Enclosing) bool
	Leave    func(c Command, at Enclosing)
	Part     func(p *Part, at Enclosing)
	Redirect func(r *Redirect, at Enclosing)
	// Descriptors, when not nil, asks Walk to read the descriptors: then
	// Enclosing.Stdout is where the standard output of a command may go
	// on the paths that reach it, and, with a NameVisibility, the body of
	// a function a call sees is given where each call runs it.
	Descriptors *DescriptorReading
	// LeaveCall gets, in a walk that reads descriptors with a
	// NameVisibility, each simple command that calls a function, after the
	// bodies it runs (after Leave of the command), with whether it ran one:
	// a body is not run where a reading around it is reading it (a
	// recursion), past the limit of calls, and where a redirect of the call
	// fails on every path.
	LeaveCall func(x *Simple, at Enclosing, read bool)
}

// Walk gives the commands cs, and every command, word, part, redirect and
// heredoc's body in them and in the scripts of their substitutions, to v,
// in the order bash runs and expands them, each with the Enclosing it runs
// in. at is where cs are: a walk of the whole script gives the zero
// Enclosing, and Walk starts a shell of kind ExecutionEnvironmentTop. A
// function's body is walked where the function is defined.
//
// The order of a simple command is what bash 5.3 does: its words, then
// the values of its assignments, then its redirects, the target of each
// after the redirects before it. A compound command's redirects come before the commands in
// it; those of ( ... ) and of a coproc are in the subshell, where bash
// performs them. A heredoc's body is expanded where its redirect is.
//
// Walk follows, in each ExecutionEnvironment, whether a literal shopt has
// set lastpipe: the runner has no job control, so with lastpipe
// set bash runs the last command of a pipeline in the shell that runs the
// pipeline (bashref, "Pipelines").
func Walk(script string, cs []Command, at Enclosing, v Visitor) {
	if at.Env == nil {
		at.Env = &ExecutionEnvironment{Kind: ExecutionEnvironmentTop}
	}
	w := &walker{s: script, v: v}
	if d := v.Descriptors; d != nil {
		if d.reading == nil {
			d.reading = newFdReading(script)
		}
		w.r = d.reading
		if w.r.changing == nil {
			w.r.findChanges(cs)
		}
		if w.r.list == nil {
			w.r.list = cs
		}
	}
	w.list(cs, at)
}

// literalIn is literalOf, and not literal when s does not hold w (Walk
// given no script: WalkSimple, Params).
func literalIn(s string, w Word) (string, bool) {
	if w.Span.End > len(s) {
		return "", false
	}
	for _, p := range w.Parts {
		if p.Span.End > len(s) {
			return "", false
		}
	}
	return literalOf(s, w)
}

// shellState is what Walk follows in an ExecutionEnvironment: whether
// lastpipe is set (the descriptors, a reading of descriptors follows).
type shellState struct {
	lastpipe bool
}

// isExec is whether x is an exec with no command: its redirects stay in
// the shell.
//
// bash 5.3 keeps the redirects of exec, exec -- and command exec in the
// shell, and not those of builtin exec.
func isExec(s string, x *Simple) bool {
	var words []string
	for _, w := range x.Words {
		n, ok := literalIn(s, w)
		if !ok {
			return false
		}
		words = append(words, n)
	}
	if len(words) > 0 && words[0] == "command" {
		words = words[1:]
	}
	if len(words) > 1 && words[1] == "--" {
		words = append(words[:1], words[2:]...)
	}
	return len(words) == 1 && words[0] == "exec"
}

// movesFd is whether n, the target of >& or <&, moves a descriptor: a
// number and -, which duplicates the number and closes it.
func movesFd(n string) bool {
	d, ok := strings.CutSuffix(n, "-")
	return ok && d != "" && strings.Trim(d, "0123456789") == ""
}

// shopt is the lastpipe x sets or unsets when x is a literal shopt -s or
// -u that names lastpipe.
func shopt(s string, x *Simple) (set, ok bool) {
	if len(x.Words) < 2 {
		return false, false
	}
	var words []string
	for _, w := range x.Words {
		n, lit := literalIn(s, w)
		if !lit {
			return false, false
		}
		words = append(words, n)
	}
	if words[0] != "shopt" {
		return false, false
	}
	named := false
	on, off := false, false
	for _, a := range words[1:] {
		switch {
		case strings.HasPrefix(a, "-"):
			if strings.Contains(a, "o") {
				return false, false // the options of set -o
			}
			on = on || strings.Contains(a, "s")
			off = off || strings.Contains(a, "u")
		case a == "lastpipe":
			named = true
		}
	}
	if !named || on == off {
		return false, false
	}
	return on, true
}

type walker struct {
	s string
	v Visitor
	r *fdReading // the descriptors read, when Visitor.Descriptors asks for them
}

// child is the Enclosing of what runs in a new subshell of kind k that
// the node at sp starts.
func child(at Enclosing, k ExecutionEnvironmentKind, sp Span) Enclosing {
	return Enclosing{Env: &ExecutionEnvironment{Kind: k, Parent: at.Env, Start: sp}, Func: at.Func, Element: -1, sh: at.sh}
}

// inside is at for a node that is not itself a command of a pipeline.
func inside(at Enclosing) Enclosing {
	at.Pipeline, at.Element = nil, -1
	return at
}

func (w *walker) list(cs []Command, at Enclosing) shellState {
	at = inside(at)
	for _, c := range cs {
		at.sh = w.command(c, at)
	}
	return at.sh
}

// command walks c and is the state of at.Env after it.
func (w *walker) command(c Command, at Enclosing) shellState {
	at.Stdout = StdoutUnset
	if w.r != nil {
		ds, ok := w.r.pre(c, at)
		if !ok {
			return at.sh // past maxAhead: not read
		}
		at.Stdout = stdoutOf(ds)
		if w.r.rec != nil {
			w.r.flowEnter(c, at)
		}
	}
	sh := w.node(c, at)
	if w.r != nil {
		w.r.switchTo(at.Env) // back from the shells of its substitutions
		if w.r.rec != nil {
			w.r.flowLeave(c, at)
		}
	}
	if w.v.Leave != nil {
		w.v.Leave(c, at)
	}
	if w.r != nil && w.r.post(c, at) {
		if x, ok := c.(*Simple); ok {
			w.call(x, at)
		}
		w.r.done(c)
	}
	return sh
}

// stdoutOf is where the standard output that may point at the places ds
// goes: the log when one of them is, else a pipe, the value of a $( ), or
// a file, the first of those it may point at.
func stdoutOf(ds dests) StdoutKind {
	switch {
	case ds.log():
		return StdoutLog
	case slices.ContainsFunc(ds, func(d dest) bool { return d.pipe || d.input }):
		return StdoutPipe
	case slices.ContainsFunc(ds, func(d dest) bool { return d.substitution }):
		return StdoutSubstitution
	}
	return StdoutFile
}

// call gives, when the reading has a NameVisibility, the bodies of the
// definitions the simple command x calls, where x runs them: with the
// descriptors there and the redirects of x (bashref, "Shell Functions": a
// function runs in the shell that calls it).
func (w *walker) call(x *Simple, at Enclosing) {
	r := w.r
	name, defs := r.defsAt(x)
	if len(defs) == 0 || r.isExec(x) {
		return
	}
	read := false
	if w.v.LeaveCall != nil {
		defer func() { w.v.LeaveCall(x, at, read) }()
	}
	// a definition being read is not read again (a recursion); one its body
	// makes of the same name is (g() { g() { :; }; g; }; g)
	all := len(defs)
	if r.rec != nil {
		for _, d := range defs {
			if r.callingDefs[d] {
				r.flowRecursion(d) // the reading of d reads its body again from here
			}
		}
	}
	defs = slices.DeleteFunc(slices.Clone(defs), func(d *FuncDef) bool { return r.callingDefs[d] })
	if len(defs) < all {
		r.cuts++ // a recursion: a body not read here
	}
	if len(defs) == 0 {
		return
	}
	if r.calls >= maxCalls {
		r.cuts++
		r.notRead(x)
		return
	}
	saved := r.cmd
	r.cmd = x // its table joins 2 to 1 after |& (fdReading.joinErr), for its own redirects alone
	may, every := mayFail(r.table(x.Redirects))
	if every {
		r.cmd = saved
		return // bash does not run the call
	}
	r.calls++
	was := r.calling[name]
	r.calling[name] = true
	var skip []pathEnd
	if r.undefinedAt(x) {
		skip = append(skip, r.here()) // no definition reaches on some path: no body runs there
	}
	if may {
		skip = append(skip, r.here()) // bash does not run the body where a redirect of the call fails
	}
	sc := r.enter(x.Redirects)
	if r.joinErr[x] {
		sc.rs = append(slices.Clip(sc.rs), Redirect{Fd: 2, Op: RedirDupOut}) // what |& points, restored after the call
		r.scopes[len(r.scopes)-1] = sc
	}
	r.cmd = saved // not the commands of the body
	body := inside(at)
	body.Call = x
	from := r.here()
	var ends []pathEnd
	for i, d := range defs {
		if i > 0 {
			r.fds, r.ended = maps.Clone(from.fds), from.ended // each definition is read on a path of its own
			r.restoreVars(from)
		}
		if r.rec != nil {
			if out, ok := r.flowMemoed(d, x); ok {
				ends = append(ends, out...) // read before from the same state
				read = true
				continue
			}
		}
		in, cuts, framed := r.here(), r.cuts, r.framed
		entry := in
		var out []pathEnd
		for {
			ret := &paths{c: x, env: at.Env, scopes: len(r.scopes), loops: len(r.loops)}
			r.rets = append(r.rets, ret)
			if r.rec != nil {
				r.flowCall(d, x, at)
			}
			r.inFunc++
			r.callingDefs[d] = true
			r.callChain = append(r.callChain, x)
			body.Func = d
			w.command(d.Body, body)
			read = true
			r.callChain = r.callChain[:len(r.callChain)-1]
			r.callingDefs[d] = false
			r.inFunc--
			r.rets = r.rets[:len(r.rets)-1]
			out = append([]pathEnd{r.here()}, ret.ends...)
			if r.rec == nil {
				break
			}
			key := r.rec.chain[len(r.rec.chain)-1]
			r.flowReturn(out) // what the body made local is given back
			if r.cuts == cuts && r.framed == framed {
				r.flowKeep(d, x, in, key, out) // a body read whole: later calls from the same state end as it did
			}
			next, again := r.flowRecursed(d, entry, out)
			if !again {
				break
			}
			if r.calls >= maxCalls {
				delete(r.rec.recurOut, d)
				r.cuts++
				r.notRead(x) // each reading again is a call of the run
				break
			}
			r.calls++
			// the calls of d its body made, which were cut, run its body too:
			// read it again from what reaches them
			entry = next
			r.fds, r.ended = maps.Clone(entry.fds), entry.ended
			r.restoreVars(entry)
		}
		ends = append(ends, out...)
	}
	r.meet(ends...)
	r.leave(sc, x.Redirects)
	if len(skip) > 0 {
		r.meet(append(skip, r.here())...)
	}
	r.calling[name] = was
}

// node walks what is in c and is the state of at.Env after it.
func (w *walker) node(c Command, at Enclosing) shellState {
	in := inside(at)
	if w.v.Command != nil && !w.v.Command(c, at) {
		if x, ok := c.(*Simple); ok {
			return w.simpleState(x, in.sh, in.mayNot) // what it does to the shell, gone into or not
		}
		return at.sh
	}
	switch x := c.(type) {
	case *Simple:
		w.words(x.Words, in)
		w.words(x.Assigns, in)
		w.redirects(x.Redirects, in)
		return w.simpleState(x, in.sh, in.mayNot)
	case *Compound:
		w.words(Words(x), in) // a coproc's name, which the shell that starts the coproc expands
		switch x.Kind {
		case CompoundSubshell, CompoundCoproc:
			k := pick(x.Kind == CompoundSubshell, ExecutionEnvironmentSubshell, ExecutionEnvironmentCoproc)
			body := child(in, k, x.span)
			w.redirects(x.Redirects, body)
			w.list(x.Body, body)
			return in.sh
		}
		w.redirects(x.Redirects, in)
		if w.r != nil && w.r.never() {
			return in.sh // bash does not run its body
		}
		body := in
		switch x.Kind {
		case CompoundIf, CompoundWhile, CompoundUntil, CompoundFor, CompoundSelect, CompoundCase:
			body.mayNot = true
		}
		for _, a := range x.Arith {
			w.parts(a.Parts, body) // (( )) and for (( ; ; )): what they expand
		}
		return w.list(x.Body, body)
	case *FuncDef:
		if w.r != nil && !w.r.atDefinition(x) {
			return in.sh // a call sees it: the body is given where a call runs it
		}
		body := in
		body.Func = x
		body.Call = nil
		w.command(x.Body, body) // what the body does happens where the function is called
		return in.sh
	case *Pipeline:
		n := len(x.Commands)
		after := in.sh
		for i, y := range x.Commands {
			el := in
			if i < n-1 || !in.sh.lastpipe {
				el = child(in, ExecutionEnvironmentPipelineElement, y.Span())
			}
			el.Pipeline, el.Element = x, i
			sh := w.command(y, el)
			if el.Env == in.Env {
				after = sh
			}
		}
		return after
	case *AndOr:
		sh := w.command(x.Commands[0], in)
		rest := in
		rest.sh, rest.mayNot = sh, true
		for _, y := range x.Commands[1:] {
			rest.sh = w.command(y, rest)
		}
		return rest.sh
	case *Asynchronous:
		w.list([]Command{x.Command}, child(in, ExecutionEnvironmentAsynchronous, x.span))
		return in.sh
	}
	return in.sh
}

// simpleState is sh after the simple command x: a literal shopt sets or
// unsets lastpipe.
func (w *walker) simpleState(x *Simple, sh shellState, mayNot bool) shellState {
	if mayNot {
		return sh // what it does may not happen: the state is kept as if it does not run
	}
	if set, ok := shopt(w.s, x); ok {
		sh.lastpipe = set
	}
	return sh
}

func (w *walker) words(ws []Word, at Enclosing) {
	for i := range ws {
		w.parts(ws[i].Parts, at)
	}
}

// redirects walks the redirects rs in order: bash expands the target of
// each after the redirects before it are performed.
func (w *walker) redirects(rs []Redirect, at Enclosing) {
	var base fdMap
	if w.r != nil && len(w.r.frames) > 0 {
		// a reading of descriptors: the target of each redirect is expanded
		// with the descriptors before the command and the redirects before
		// it, where the substitutions of the target start; the command's
		// shell gets back what pre made of them after
		base = w.r.frames[len(w.r.frames)-1].base
		w.r.switchTo(at.Env)
		entered := w.r.fds
		defer func() {
			w.r.switchTo(at.Env)
			w.r.fds = entered
		}()
	}
	for i := range rs {
		if base != nil {
			w.r.switchTo(at.Env)
			w.r.fds = base
			w.r.fds = w.r.table(rs[:i]).flat()
		}
		r := &rs[i]
		if w.r != nil && w.r.rec != nil {
			w.r.flowRedirect(r, at)
		}
		if w.v.Redirect != nil {
			w.v.Redirect(r, at)
		}
		w.parts(r.Target.Parts, at)
		if r.Heredoc != nil {
			w.parts(r.Heredoc.Parts, at)
		}
	}
}

// paramWords walks the words of the ${ } x: its subscript, offset and
// length, and the words after its operator, which bash may expand.
func (w *walker) paramWords(x *ParamExpansion, at Enclosing) {
	for _, pw := range []*Word{x.Subscript, x.Offset, x.Length} {
		if pw != nil {
			w.parts(pw.Parts, at)
		}
	}
	for i := range x.Words {
		w.parts(x.Words[i].Parts, at)
	}
}

func (w *walker) parts(ps []Part, at Enclosing) {
	for i := range ps {
		p := &ps[i]
		if w.r != nil && w.r.rec != nil {
			w.r.flowPart(p, at)
		}
		if w.v.Part != nil {
			w.v.Part(p, at)
		}
		if x := p.Param; x != nil {
			w.paramWords(x, at)
		}
		if a := p.Arith; a != nil {
			w.parts(a.Parts, at) // $(( )): what it expands before it evaluates
		}
		if p.Sub == nil {
			continue
		}
		var sub Enclosing
		switch p.Kind {
		case PartProcIn, PartProcOut: // <( ), >( ): a pipe from or to the command (fdReading.stateOf)
			sub = child(at, ExecutionEnvironmentProcessSubstitution, p.Span)
		default:
			sub = child(at, ExecutionEnvironmentCommandSubstitution, p.Span)
		}
		w.list(p.Sub.List, sub)
	}
}
