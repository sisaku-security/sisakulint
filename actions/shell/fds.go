package shell

import (
	"maps"
	"slices"
	"strconv"
	"strings"
)

// dest is where a descriptor points: a file (w), which the caller names
// or not (file), or the log (the standard error the script inherits, or a
// device of the standard output or error).
type dest struct {
	w    Word
	file bool
	log  bool
	// call: the standard output a call's redirect points, inside the body:
	// what the body writes there is what the call writes (simple)
	call bool
	// name: for a file, the text of w in the script, which names the same
	// file wherever it is written ("$GITHUB_ENV")
	name string
	// closed: not open (closed with >&-, or never opened); failed: a
	// duplicate of a descriptor not open, which bash does not make, the
	// descriptor keeping where it pointed (an exec) or the command not
	// running
	closed, failed bool
	// pipe: a pipe (to the next command of a pipeline, to the shell that
	// starts a coproc, to or from a process substitution); substitution:
	// the value of a $( ); input: the pipe PipeReaders follows
	pipe, substitution, input bool
	// element: for the pipe a command of a pipeline writes to the next, the
	// shell of that command; the pipe of each command is a place of its own
	element *ExecutionEnvironment
	// output: for the output a reading of OutputReading reads, and for a
	// pipe of a pipeline of its commands, the reading (its depth, from 1):
	// what a $( ) read inside writes there is written to that output, not
	// to the value of the $( )
	output int
}

// same is whether d and e are the same place: a file by the text of the
// word of its redirect, and anywhere else by whether it is the log. The
// redirects of one file on many paths are one place, so that the places
// do not grow with the paths.
func (d dest) same(e dest) bool {
	return d.file == e.file && d.log == e.log && d.call == e.call && d.closed == e.closed && d.failed == e.failed && d.pipe == e.pipe && d.substitution == e.substitution && d.input == e.input && d.element == e.element && d.output == e.output && (!d.file || d.name == e.name)
}

// dests are the places a descriptor may point where a command runs, one
// for each path that reaches the command (the branches of if, the
// commands after && and ||, the rounds of a loop, the definitions a call
// may run, the places break, continue and return leave from), each place
// once, in the order they are met.
type dests []dest

// with is ds and the places es; ds itself is not changed.
func (ds dests) with(es ...dest) dests {
	out := ds
	for _, e := range es {
		if !slices.ContainsFunc(out, e.same) {
			out = append(slices.Clip(out), e)
		}
	}
	return out
}

// log is whether one of ds is the log.
func (ds dests) log() bool {
	return slices.ContainsFunc(ds, func(d dest) bool { return d.log })
}

// fdMap is where the descriptors may point: one not in it is the one the
// shell inherits (inherited).
type fdMap map[int]dests

// fdLook is a table of where the descriptors may point: an fdMap, or an
// fdTab.
type fdLook interface {
	get(fd int) (dests, bool)
	keys() []int
}

func (t fdMap) get(fd int) (dests, bool) {
	ds, ok := t[fd]
	return ds, ok
}

func (t fdMap) keys() []int { return slices.Sorted(maps.Keys(t)) }

// fdTab is the descriptors of base with what the redirects of a command
// change (table): it does not copy base, which keeps the descriptors
// {name} redirects opened and grows with them.
type fdTab struct {
	base, own fdMap
}

func (t *fdTab) get(fd int) (dests, bool) {
	if ds, ok := t.own[fd]; ok {
		return ds, ok
	}
	return t.base.get(fd)
}

func (t *fdTab) put(fd int, ds dests) {
	if t.own == nil {
		t.own = fdMap{}
	}
	t.own[fd] = ds
}

func (t *fdTab) keys() []int {
	out := t.base.keys()
	for fd := range t.own {
		if _, ok := t.base[fd]; !ok {
			out = append(out, fd)
		}
	}
	slices.Sort(out)
	return out
}

// flat is t as one fdMap of its own.
func (t *fdTab) flat() fdMap {
	out := maps.Clone(t.base)
	if out == nil {
		out = fdMap{}
	}
	maps.Copy(out, t.own)
	return out
}

// fdReading is where the descriptors of the shell being read point, on
// each path that reaches the command being read: what exec, the redirects
// of compound commands and calls, {name} redirects, and the paths of if,
// && and ||, loops, break, continue, return and exit do to them.
type fdReading struct {
	s      string
	target func(Word, fdLook) bool // whether a file is one the caller names, with the descriptors where it is opened
	fds    fdMap                   // the descriptors exec opened, other than the standard output
	ended  bool                    // all the paths that reach the command being read ended before it (jump)
	inFunc int                     // how deep in function bodies the command being read is
	vis    *NameVisibility         // which definitions a call sees
	named  map[string]bool         // the names literal commands of the script have
	// varFds are the descriptors of {name} redirects, by where each
	// redirect starts: a number of their own past any a script writes (varFd)
	varFds map[int]int
	// fd: fdValues of a variable at a place, and the places being read
	fd *fdState
	// ints: a variable of the script may have the integer attribute
	// (intVariables), whose v+=x adds
	ints bool
	// loops are the loops the command being read is in, and rets the calls
	// of functions: where break, continue and return leave their paths;
	// scopes are the commands with redirects it is in (enter)
	loops, rets []*paths
	scopes      []scope
	// changing are the loops whose rounds may change the descriptors
	// (findChanges); ahead, how many commands round has read ahead; dry,
	// how deep in rounds read ahead the command being read is
	changing map[*Compound]bool
	ahead    *aheadState
	dry      int
	// failable are the {name}>&m redirects, by where they start, that
	// duplicate a descriptor not open on some path: bash leaves name as
	// it was there (fdValues)
	failable map[int]bool
	// cmd is the simple command whose redirects table reads, if any
	cmd *Simple
	// env is the shell of the command being read, and envs the state of
	// the others; bodyFds, the descriptors the commands of a ( ... ) or a
	// coproc start with, by its span; pipeOuts, the commands of pipelines
	// but the last, whose standard output is the pipe
	env      *ExecutionEnvironment
	envs     map[*ExecutionEnvironment]fdEnv
	bodyFds  map[Span]fdMap
	pipeOuts map[*ExecutionEnvironment]bool
	pipeIns  map[*ExecutionEnvironment]bool
	// calls are the calls of functions followed, up to maxCalls; calling,
	// the functions being read where they are called; notReadCalls gets
	// the first call past maxCalls
	calls        int
	calling      map[string]bool
	callingDefs  map[*FuncDef]bool // the definitions being read where they are called
	notReadCalls *CallsNotRead
	// frames are what pre kept of the commands being read, for post
	frames []fdFrame
	// list is the script's commands, which copiesName reads; copies, its
	// answers by name
	list   []Command
	copies map[string]bool
	// notRun, when not nil, gets the commands whose redirects may fail
	// (walkNotRun), by where they start
	notRun map[int]bool
	// joinErr are the simple commands of pipelines followed by |&: their
	// table points 2 where 1 points after their redirects
	joinErr map[*Simple]bool
	// outFrom: the commands read are the script of a $( ) whose command is
	// in a loop (OutputReading.Begin): a break there ends them
	outFrom bool
	// writer: the command whose output is read wherever its redirects send
	// it (OutputReading.BeginPipeline); blind: what every simple command
	// writes is read, wherever it points (OutputReading.BeginBlind)
	writer *Simple
	blind  bool
	// depth: for a reading of OutputReading, its depth, from 1 (dest.output)
	depth int
	// rec, when not nil, makes the reading record the assignments and the
	// definitions of functions where each command runs (readFlow); vars is
	// what of them reaches the command being read
	rec  *flowRecorder
	vars reach
	// callChain: the calls whose bodies are being read, the outermost
	// first, whose context (NameVisibility.contextOf) fdValues reads in
	callChain []*Simple
	// cuts counts the calls whose bodies were not read (a recursion, past
	// maxCalls): a reading with one is not whole, and is not kept (flowKeep)
	cuts int
	// framed counts the unsets that took away a local of a calling function
	// (callerLocal): a reading with one depends on the calls around it, which
	// the state it starts from does not hold, and is not kept either
	framed int
}

// varFdBase is the first number varFd gives: past the numbers a script
// writes, which bash takes up to the limit of descriptors.
const varFdBase = 1 << 20

// varFd is the descriptor the {name} redirect at sp opens: bash opens one
// of 10 or more and assigns its number to name (bashref, "Redirections").
// Each redirect has a number of its own, so that the descriptors two
// redirects of a name open on different paths (exec {fd}>&2; c && { :; }
// {fd}>/dev/null) are both values of the name (fdValues).
func (w *fdReading) varFd(sp Span) int {
	if w.varFds == nil {
		w.varFds = map[int]int{}
	}
	if fd, ok := w.varFds[sp.Start]; ok {
		return fd
	}
	fd := varFdBase + len(w.varFds)
	w.varFds[sp.Start] = fd
	return fd
}

// namedFds are the descriptors the {name} redirect r points: the one it
// opens, or for {name}>&- and {name}<&-, those it may close (closedFds).
func (w *fdReading) namedFds(r *Redirect) []int {
	if !closesVar(w.s, r) {
		return []int{w.varFd(r.Span)}
	}
	fds, _ := w.closedFds(r)
	return fds
}

// closedFds are the descriptors {name}>&- or {name}<&- at r may close: the
// values of name that are numbers, from the assignments that reach r
// (fdValues), and whether it closes that descriptor on every path: one
// value, and no value not known. With more values, each descriptor is
// closed on the paths where name holds its number, and stays as it was
// on the others, where another name may hold its number (b=$fd; if c;
// then exec {fd}>/dev/null; fi; exec {fd}>&-; echo >&$b).
func (w *fdReading) closedFds(r *Redirect) ([]int, bool) {
	vals, known := w.fdValues(r.Var, r.Span)
	var fds []int
	for _, v := range vals {
		if isFdNumber(v) {
			fds = append(fds, atoi(v))
		}
	}
	if known && len(vals) == len(fds) && len(fds) > 0 && !w.copiesName(r.Var.String()) {
		ofRedirects := true // each a descriptor a {name} redirect opened (varFd)
		for _, fd := range fds {
			ofRedirects = ofRedirects && fd >= varFdBase
		}
		if ofRedirects {
			// on each path, name holds the descriptor its own redirect
			// opened, and no other name holds its number: closed on every
			// path
			return fds, true
		}
	}
	return fds, known && len(vals) == 1 && len(fds) == 1
}

// copiesName is whether the script may copy the value of the name n to
// another name, or name the number of a descriptor of a {n} redirect: a
// parameter $n but the target of >&$n, >&$n- and {n}>&-, n as a name in a
// literal of a word (b=n with declare -i, let b=n, [[ b=n -gt 0 ]], a
// subscript, declare -n b=n) or of an arithmetic expression, or a number
// of 10 or more after >& or <&, which bash gives {name} redirects. The
// literal is read as one token of the tree, by the bytes around n.
func (w *fdReading) copiesName(n string) bool {
	if c, ok := w.copies[n]; ok {
		return c
	}
	excluded := map[int]bool{} // the parameters of the targets of >&$n
	found := false
	Walk(w.s, w.list, Enclosing{}, Visitor{
		Redirect: func(r *Redirect, _ Enclosing) {
			if r.Op != RedirDupOut && r.Op != RedirDupIn {
				return
			}
			if t, ok := literalOf(w.s, r.Target); ok && isFdNumber(strings.TrimSuffix(t, "-")) && len(t) < 8 && atoi(strings.TrimSuffix(t, "-")) >= 10 {
				found = true
			}
			if ps := r.Target.Parts; len(ps) >= 1 && ps[0].Kind == PartParam && ps[0].Name.String() == n {
				excluded[ps[0].Span.Start] = true
			}
		},
		Part: func(p *Part, _ Enclosing) {
			switch p.Kind {
			case PartParam, PartParamOp:
				found = found || p.Name.String() == n && !excluded[p.Span.Start]
			case PartLiteral:
				found = found || namesIn(w.s[p.Span.Start:p.Span.End], n)
			}
		},
	})
	if w.copies == nil {
		w.copies = map[string]bool{}
	}
	w.copies[n] = found
	return found
}

// namesIn is whether the text of a literal holds the name n between bytes
// that are not of a name.
func namesIn(text, n string) bool {
	for i := strings.Index(text, n); i >= 0; {
		end := i + len(n)
		if (i == 0 || !isNameByte(text[i-1])) && (end == len(text) || !isNameByte(text[end])) {
			return true
		}
		j := strings.Index(text[i+1:], n)
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return false
}

// isFdNumber is whether v, the value of a variable, is the number of a
// descriptor: digits alone. bash reads >&$v whose value is N- as the file
// named N-, and - as closing (bash 5.3).
func isFdNumber(v string) bool {
	return v != "" && strings.Trim(v, "0123456789") == ""
}

// keptVarFds are the descriptors the {name} redirects of rs open, which
// persist beyond the command; what {name}>&- closes is restored after it
// (bash 5.3), as other redirects are.
func (w *fdReading) keptVarFds(rs []Redirect) []int {
	var fds []int
	for i := range rs {
		if r := &rs[i]; r.Var.String() != "" && !closesVar(w.s, r) {
			fds = append(fds, w.varFd(r.Span))
		}
	}
	return fds
}

// inherited is where the descriptor fd points when the shell has not
// changed it: the standard output and error, the log, or nowhere, for a
// descriptor not opened. A subshell whose standard output is a pipe or the
// value of a $( ) starts with it in its table (writer.stateOf).
func (w *fdReading) inherited(fd int) dest {
	switch fd {
	case 1:
		return dest{log: true}
	case 2:
		return dest{log: true}
	case 0:
		return dest{}
	}
	return dest{closed: true}
}

// at is where fd may point in t.
func (w *fdReading) at(t fdLook, fd int) dests {
	if ds, ok := t.get(fd); ok {
		return ds
	}
	return dests{w.inherited(fd)}
}

// join is where the descriptors may point where paths that leave with
// the tables ts meet: each descriptor at each place it has in one of them.
func (w *fdReading) join(ts ...fdMap) fdMap {
	u := fdMap{}
	for _, t := range ts {
		for fd := range t {
			if _, ok := u[fd]; ok {
				continue
			}
			var ds dests
			if same := sameDests(ts, fd); same != nil {
				ds = same // every table holds the same places: nothing to join
			} else {
				for _, t := range ts {
					ds = ds.with(w.at(t, fd)...)
				}
			}
			if !w.isInherited(fd, ds) {
				u[fd] = ds
			}
		}
	}
	return u
}

// sameDests is the places each table of ts holds for fd, when every table
// holds fd with the same slice, or nil.
func sameDests(ts []fdMap, fd int) dests {
	first, ok := ts[0][fd]
	if !ok || len(first) == 0 {
		return nil
	}
	for _, t := range ts[1:] {
		ds, ok := t[fd]
		if !ok || len(ds) != len(first) || &ds[0] != &first[0] {
			return nil
		}
	}
	return first
}

// set points fd at ds in the descriptors exec opened, or, when not ok,
// back at what the shell inherits. A descriptor that points where it
// would point inherited is left out, so that the descriptors {name}
// redirects opened and closed do not stay in the table.
func (w *fdReading) set(fd int, ds dests, ok bool) {
	if ok && !w.isInherited(fd, ds) {
		w.fds[fd] = ds
	} else {
		delete(w.fds, fd)
	}
}

// isInherited is whether ds is where fd points when the shell inherits
// it, for a descriptor that does not change with the command (not the
// standard output, which a subshell may start with elsewhere).
func (w *fdReading) isInherited(fd int, ds dests) bool {
	return fd >= 2 && len(ds) == 1 && ds[0].same(w.inherited(fd))
}

// pathEnd is where the descriptors may point on the paths that reach a
// place, and whether all of them ended before it (exit, return, break,
// continue).
type pathEnd struct {
	fds   fdMap
	ended bool
	vars  reach // what a reading that records (rec) carries of the variables and the definitions
}

// here is the pathEnd of the command being read.
func (w *fdReading) here() pathEnd {
	fds := maps.Clone(w.fds)
	if fds == nil {
		fds = fdMap{}
	}
	return pathEnd{fds, w.ended, w.carried()}
}

// joined is where the paths ps meet: those not ended, joined; ended when
// all are.
func (w *fdReading) joined(ps ...pathEnd) pathEnd {
	var live []fdMap
	var vars reach
	for _, p := range ps {
		if !p.ended {
			live = append(live, p.fds)
			if w.rec != nil {
				vars = w.rec.union(vars, p.vars, len(live) == 1)
			}
		}
	}
	if len(live) == 0 {
		return pathEnd{fdMap{}, true, reach{}}
	}
	return pathEnd{w.join(live...), false, vars}
}

// meet makes the command being read one that the paths ps reach.
func (w *fdReading) meet(ps ...pathEnd) {
	j := w.joined(ps...)
	if j.ended {
		w.ended = true // what follows runs on no path: its descriptors are kept as they are
		return
	}
	w.fds, w.ended = j.fds, false
	if w.rec != nil {
		w.vars = j.vars
	}
}

// paths is what walk keeps of a command whose parts run on some paths and
// not on others: an and-or list, if, a loop, or a call of a function
// (rets).
type paths struct {
	c   Command
	env *ExecutionEnvironment
	// scopes: how many of w.scopes are around c, its own included; loops,
	// for a call, how many of w.loops are around it, which a break in the
	// body does not leave
	scopes, loops int
	// ok, fail: for an and-or list, where the paths on which the commands
	// read so far succeed, and those on which they fail, are
	ok, fail pathEnd
	// start: for an and-or list, before the command being read; for if,
	// after the condition being read; for a loop, where each round starts
	start pathEnd
	// ends: where paths leave c: the commands after then, a condition of
	// while or until, break, return; conts: continue, which leaves a round
	// to the next round or out of the loop
	ends, conts []pathEnd
}

// branch is what the parts of p do where the command c in them starts:
// the commands after && or || may not run, the commands after then run
// after the condition, an elif or else starts where the commands after
// then end, and the condition of while or until may end the loop.
func (w *fdReading) branch(p *paths, c Command) {
	switch x := p.c.(type) {
	case *AndOr:
		// a command after && runs on the paths where the ones before
		// succeed, one after || where they fail
		if i := slices.Index(x.Commands, c); i > 0 {
			from := p.fail
			if x.Ops[i-1] == AndOrAnd {
				from = p.ok
			}
			w.fds, w.ended = maps.Clone(from.fds), from.ended
			w.restoreVars(from)
		}
	case *Compound:
		k := slices.Index(x.Body, c)
		i := slices.Index(x.lists, k)
		if k < 0 || i <= 0 {
			return
		}
		switch x.Kind {
		case CompoundIf:
			if i%2 == 1 {
				p.start = w.here()
				return
			}
			p.ends = append(p.ends, w.here())
			w.fds, w.ended = maps.Clone(p.start.fds), p.start.ended
			w.restoreVars(p.start)
		case CompoundWhile, CompoundUntil:
			p.ends = append(p.ends, w.here())
		}
	}
}

// after is what the parts of p do where the command c in them ends: in an
// and-or list, the paths on which the commands so far succeed and fail.
func (w *fdReading) after(p *paths, c Command) {
	x, ok := p.c.(*AndOr)
	if !ok {
		return
	}
	switch i := slices.Index(x.Commands, c); {
	case i == 0:
		p.ok, p.fail = w.here(), w.here()
	case i > 0 && x.Ops[i-1] == AndOrAnd:
		p.ok, p.fail = w.here(), w.joined(p.fail, w.here())
	case i > 0:
		p.ok, p.fail = w.joined(p.ok, w.here()), w.here()
	}
}

// leavePaths is where the paths of the if or the loop of p meet after it:
// where each leaves it, and for if without else, after the last
// condition; for for and select, also where a round starts (no round).
func (w *fdReading) leavePaths(p *paths) {
	x := p.c.(*Compound)
	ends := append(append(slices.Clone(p.ends), p.conts...), w.here())
	switch x.Kind {
	case CompoundIf:
		if !x.elseAt && p.start.fds != nil {
			ends = append(ends, p.start)
		}
	case CompoundFor, CompoundSelect:
		if !roundsOnce(w.s, x) {
			ends = append(ends, p.start)
		}
	}
	if x.Kind != CompoundIf {
		w.loops = w.loops[:len(w.loops)-1]
	}
	w.meet(ends...)
}

// aheadState is how many commands round has read ahead in one run of
// Writes, and how many it may read: maxAhead and aheadPerCommand for each
// command of the script. The rounds of loops nested in loops are read
// ahead in each round read ahead, which grows with the power of how deep
// the loops nest. Past the limit, a round read ahead reads no more
// commands, a loop is not read ahead, and a round starts with what the
// commands read ahead did, or with the descriptors before the loop alone:
// a write before an exec of the loop's body is then read with the
// descriptors before the exec alone.
type aheadState struct {
	n, max int
}

const (
	maxAhead        = 1 << 14
	aheadPerCommand = 8
)

// maxRounds is how many rounds of a loop enterLoop reads ahead, each from
// where the rounds before leave the descriptors: a round may point a
// descriptor where another pointed in the round before (exec 4>&3; exec
// 3>f).
const maxRounds = 8

// roundsOnce is whether the for x runs its body at least once: a word
// after in is a literal with no character of a pattern, which bash
// expands to one word (a pattern may expand to no word with nullglob).
func roundsOnce(s string, x *Compound) bool {
	if x.Kind != CompoundFor || !x.HasIn {
		return false
	}
	return slices.ContainsFunc(x.In, func(w Word) bool {
		if _, ok := literalOf(s, w); !ok {
			return false
		}
		return !slices.ContainsFunc(w.Parts, func(p Part) bool {
			return p.Quote == QuoteNone && strings.ContainsAny(s[p.Span.Start:p.Span.End], "*?[")
		})
	})
}

// sameFds is whether a and b point each descriptor at the same places.
func sameFds(a, b fdMap) bool {
	if len(a) != len(b) {
		return false
	}
	for fd, ds := range a {
		es, ok := b[fd]
		if !ok || len(ds) != len(es) {
			return false
		}
		for _, d := range ds {
			if !slices.ContainsFunc(es, d.same) {
				return false
			}
		}
	}
	return true
}

// jump is what the simple command x, run in env, does to the paths: break
// and continue leave the loops they name, return leaves the call of the
// function it is in, exit ends the shell; the paths that run x end there.
// A break, continue or return that bash takes as an error (outside a
// loop, outside a function) ends nothing.
func (w *fdReading) jump(x *Simple, env *ExecutionEnvironment) {
	k, n := jumpOf(w.s, x.Words)
	switch k {
	case jumpNone:
		return
	case jumpMay:
		w.mayJump(env) // what it runs may break, continue or return
		return
	case jumpExit:
	case jumpReturn:
		if w.inFunc == 0 {
			return
		}
		if r := len(w.rets); r > 0 && w.rets[r-1].env == env {
			w.rets[r-1].ends = append(w.rets[r-1].ends, w.leaving(w.rets[r-1].scopes))
		}
	case jumpBreak, jumpContinue:
		least := 0 // a break in a function's body does not leave a loop around the call (bash 5.3)
		if r := len(w.rets); r > 0 {
			least = w.rets[r-1].loops
		}
		var around []*paths // the loops it may leave, the innermost first
		for i := len(w.loops) - 1; i >= least; i-- {
			if w.loops[i].env == env {
				around = append(around, w.loops[i])
			}
		}
		if len(around) == 0 {
			if n != 0 && w.substitutionJump(env) {
				w.ended = true // bash ends the script of the $( ) (bash 5.3)
			}
			return
		}
		if n < 0 {
			n = len(around) // a number not known: the outermost
		}
		if n < 1 {
			return
		}
		if n > len(around) && w.substitutionJump(env) {
			w.ended = true // past the loops of the $( ): bash ends its script (bash 5.3)
			return
		}
		p := around[min(n, len(around))-1] // break N and continue N go to the Nth loop, or the outermost
		if k == jumpBreak {
			p.ends = append(p.ends, w.leaving(p.scopes))
		} else {
			p.conts = append(p.conts, w.leaving(p.scopes))
		}
	}
	w.ended = true
}

// substitutionJump is whether a break or continue run in env, with no loop
// of env around it, ends the script of a $( ) (bash 5.3): env is the shell
// of a $( ) whose command runs in a loop of the function the command being
// read is in, directly or through other $( ). One in ( ... ), or in the body
// of a function called in the loop, ends nothing.
func (w *fdReading) substitutionJump(env *ExecutionEnvironment) bool {
	if env.Parent == nil {
		return w.outFrom && len(w.rets) == 0 // the script of a reading begun at a $( ) (OutputReading.Begin), not the body of a function it calls
	}
	return env.Kind == ExecutionEnvironmentCommandSubstitution && w.loopAround(env.Parent)
}

// loopAround is whether a loop of the function the command being read is in
// runs in env, or env is the shell of a $( ) whose command is in such a
// loop, directly or through other $( ).
func (w *fdReading) loopAround(env *ExecutionEnvironment) bool {
	least := 0
	if r := len(w.rets); r > 0 {
		least = w.rets[r-1].loops
	}
	for e := env; e != nil; e = e.Parent {
		for _, p := range w.loops[least:] {
			if p.env == e {
				return true
			}
		}
		if e.Parent == nil {
			return w.outFrom && len(w.rets) == 0
		}
		if e.Kind != ExecutionEnvironmentCommandSubstitution {
			return false
		}
	}
	return false
}

// jumpKind is how a simple command leaves the paths that run it.
type jumpKind uint8

const (
	jumpNone     jumpKind = iota
	jumpBreak             // break
	jumpContinue          // continue
	jumpReturn            // return
	jumpExit              // exit
	// jumpMay: what it runs may break, continue or return, and the paths
	// go on too: eval, source, ., trap with an action that holds break,
	// continue or return (read where trap is), a command whose name is not
	// literal
	jumpMay
)

// jumpOf is how the simple command of the words ws of s leaves its paths,
// and, for break and continue, the loop it leaves (break N; 1 with no N,
// -1 for an N not known). command and builtin, with -p or --, run the
// builtin after them (bash 5.3); command -v does not run it.
func jumpOf(s string, ws []Word) (jumpKind, int) {
	if len(ws) == 0 {
		return jumpNone, 1
	}
	name, ok := literalOf(s, ws[0])
	for ok && (name == "command" || name == "builtin") && len(ws) > 1 {
		ws = ws[1:]
		name, ok = literalOf(s, ws[0])
		for ok && (name == "-p" || name == "--") && len(ws) > 1 {
			ws = ws[1:]
			name, ok = literalOf(s, ws[0])
		}
	}
	if !ok {
		return jumpMay, 1
	}
	switch name {
	case "eval", "source", ".":
		return jumpMay, 1
	case "trap":
		if len(ws) < 2 {
			return jumpNone, 1
		}
		action, ok := literalOf(s, ws[1])
		if !ok {
			return jumpMay, 1 // an action not known
		}
		// the action, read as a script where trap runs it
		k := jumpNone
		Walk(action, Parse(action).List, Enclosing{}, Visitor{Command: func(c Command, _ Enclosing) bool {
			if x, ok := c.(*Simple); ok {
				if j, _ := jumpOf(action, x.Words); j != jumpNone && j != jumpExit {
					k = jumpMay
				}
			}
			return k == jumpNone
		}})
		return k, 1
	case "exit":
		return jumpExit, 1
	case "return":
		return jumpReturn, 1
	case "break", "continue":
		n := 1
		if len(ws) > 1 {
			n = -1
			if a, ok := literalOf(s, ws[1]); ok && isFdNumber(a) && len(a) < 4 {
				n = atoi(a)
			}
		}
		return pick(name == "break", jumpBreak, jumpContinue), n
	}
	return jumpNone, 1
}

// mayJump is a command run in env that may break, continue or return
// (eval, source): the paths may leave each loop it is in, as a break or a
// continue, and the call of the function it is in, and go on.
func (w *fdReading) mayJump(env *ExecutionEnvironment) {
	least := 0
	if r := len(w.rets); r > 0 {
		least = w.rets[r-1].loops
		if w.rets[r-1].env == env {
			w.rets[r-1].ends = append(w.rets[r-1].ends, w.leaving(w.rets[r-1].scopes))
		}
	}
	for i := len(w.loops) - 1; i >= least; i-- {
		if p := w.loops[i]; p.env == env {
			p.ends = append(p.ends, w.leaving(p.scopes))
			p.conts = append(p.conts, w.leaving(p.scopes))
		}
	}
}

// findChanges finds the loops of cs whose rounds may change the
// descriptors: those with an exec, a {name} redirect or a call of a
// function in them.
func (w *fdReading) findChanges(cs []Command) {
	w.changing = map[*Compound]bool{}
	w.ahead = &aheadState{max: maxAhead}
	var loops []*Compound
	named := func(r Redirect) bool { return r.Var.String() != "" }
	Walk(w.s, cs, Enclosing{}, Visitor{
		Command: func(c Command, at Enclosing) bool {
			w.ahead.max += aheadPerCommand
			changes := w.rec != nil // a reading that records reads the rounds of every loop
			switch x := c.(type) {
			case *Compound:
				changes = changes || slices.ContainsFunc(x.Redirects, named)
				if x.Kind.Loop() {
					loops = append(loops, x)
				}
			case *Simple:
				_, defs := w.defsAt(x)
				changes = changes || w.isExec(x) || len(defs) > 0 || slices.ContainsFunc(x.Redirects, named)
			}
			for i := len(loops) - 1; changes && i >= 0 && !w.changing[loops[i]]; i-- {
				w.changing[loops[i]] = true // the loops around it are marked already when this one is
			}
			return true
		},
		Leave: func(c Command, at Enclosing) {
			if x, ok := c.(*Compound); ok && x.Kind.Loop() {
				loops = loops[:len(loops)-1]
			}
		},
	})
}

// scope is what enter saved: the descriptors before, and the redirects
// it applied.
type scope struct {
	fds fdMap
	rs  []Redirect
}

// enter makes the descriptors the redirects rs of a command point the
// ones of the commands inside it, until leave.
func (w *fdReading) enter(rs []Redirect) scope {
	sc := scope{w.fds, rs}
	w.scopes = append(w.scopes, sc)
	t := w.table(rs)
	w.fds = t.flat()
	if ds, ok := t.own[1]; ok {
		w.fds[1] = covered(ds) // what the commands inside write there is what the command writes
	}
	return sc
}

// covered is ds with each file marked as one an enclosing command's write
// already gives (dest.call): the standard output of a command whose own
// redirect points it at a file, or of an exec, for the commands inside or
// after it.
func covered(ds dests) dests {
	out := make(dests, len(ds))
	for i, d := range ds {
		d.call = d.call || d.file
		out[i] = d
	}
	return out
}

// leave restores, after the command of enter, what bash restores:
// the descriptors its redirects point.
func (w *fdReading) leave(sc scope, rs []Redirect) {
	w.scopes = w.scopes[:len(w.scopes)-1]
	w.fds = w.restored(w.fds, sc)
}

// restored is fds after the command of the scope sc ends: what exec did
// inside stays, as the compound runs in the shell itself, and so
// does what a {name} redirect of its redirects opens, which persists
// beyond the command (bashref, "Redirections"); the other descriptors its
// redirects point, and the standard output, point where they did before.
func (w *fdReading) restored(fds fdMap, sc scope) fdMap {
	kept := w.keptVarFds(sc.rs)
	own := slices.DeleteFunc(w.execFds(sc.rs), func(fd int) bool { return slices.Contains(kept, fd) })
	out := maps.Clone(fds)
	if out == nil {
		out = fdMap{}
	}
	for _, fd := range own {
		if ds, ok := sc.fds[fd]; ok {
			out[fd] = ds
		} else {
			delete(out, fd)
		}
	}
	return out
}

// leaving is where the descriptors point where a path jumps out of the
// commands whose scopes are past the first depth of w.scopes (break out
// of a loop, return out of a function): each of those commands restores
// what its redirects point.
func (w *fdReading) leaving(depth int) pathEnd {
	e := w.here()
	for i := len(w.scopes) - 1; i >= depth; i-- {
		e.fds = w.restored(e.fds, w.scopes[i])
	}
	return e
}

// findNames finds the names of the literal commands of cs.
func (w *fdReading) findNames(cs []Command) {
	w.named = map[string]bool{}
	Walk(w.s, cs, Enclosing{}, Visitor{Command: func(c Command, at Enclosing) bool {
		if x, ok := c.(*Simple); ok {
			if len(x.Words) > 0 {
				if n, ok := literalOf(w.s, x.Words[0]); ok {
					w.named[n] = true
				}
			}
		}
		return true
	}})
}

// defsAt are the definitions the simple command x calls (NameVisibility),
// past the assignments before its command word.
func (w *fdReading) defsAt(x *Simple) (string, []*FuncDef) {
	words := x.Words
	if len(words) == 0 || w.vis == nil {
		return "", nil
	}
	n, ok := literalOf(w.s, words[0])
	if !ok {
		return "", nil
	}
	if w.rec != nil {
		defs, _ := w.flowDefs(n)
		return n, defs
	}
	defs, _ := w.vis.Functions(n, x.Span())
	return n, defs
}

// undefinedAt is whether no definition the simple command x may call
// reaches it on some path, where x runs no body.
func (w *fdReading) undefinedAt(x *Simple) bool {
	if len(x.Words) == 0 || w.vis == nil {
		return false
	}
	n, ok := literalOf(w.s, x.Words[0])
	if !ok {
		return false
	}
	if w.rec != nil {
		_, undefined := w.flowDefs(n)
		return undefined
	}
	_, undefined := w.vis.Functions(n, x.Span())
	return undefined
}

// atDefinition is whether the body of d is read where d is defined: no
// call sees d, and no literal command names it (a command whose name is
// not literal, eval or source may call it). A body a call sees is read
// where it is called; one only calls before its definition name is not
// read (bash does not find it there).
func (w *fdReading) atDefinition(d *FuncDef) bool {
	if w.rec != nil {
		return false // a body never called is read after the script (readFlow)
	}
	n, ok := literalOf(w.s, d.Name)
	return w.vis == nil || len(w.vis.Calls(d)) == 0 && (!ok || !w.named[n])
}

// keepVarFds keeps the descriptors of the {name} redirects of x, which is
// no exec, for the rest of the shell: such a redirect persists beyond the
// command (bashref, "Redirections").
func (w *fdReading) keepVarFds(x *Simple) {
	kept := w.keptVarFds(x.Redirects)
	if len(kept) == 0 {
		return
	}
	t := w.table(x.Redirects)
	for _, fd := range kept {
		ds, ok := t.get(fd)
		w.set(fd, ds, ok)
	}
}

// logs is whether the standard output of a command with the redirects rs
// goes to the log.
func (w *fdReading) logs(rs []Redirect) bool {
	return w.at(w.table(rs), 1).log()
}

// deviceFd is the descriptor of the shell the file n names: /dev/stdin,
// /dev/stdout and /dev/stderr, /dev/fd/N and /proc/self/fd/N, which point
// where that descriptor points (the runner gives a step no terminal).
func deviceFd(n string) (int, bool) {
	switch n {
	case "/dev/stdin":
		return 0, true
	case "/dev/stdout":
		return 1, true
	case "/dev/stderr":
		return 2, true
	}
	for _, dir := range []string{"/dev/fd/", "/proc/self/fd/"} {
		if d := strings.TrimPrefix(n, dir); d != n && isFdNumber(d) && len(d) < 8 && (d == "0" || d[0] != '0') {
			return atoi(d), true
		}
	}
	return 0, false
}

// table is where the descriptors point after the redirects rs, applied in
// order from the descriptors exec opened: n>f, n>>f, n>|f, &>f and >&f (with
// f not a number) point n (or 1 and 2) to f; n>&m points n where m may point.
// A descriptor not in the table is the one the command inherits.
func (w *fdReading) table(rs []Redirect) *fdTab {
	t := &fdTab{base: w.fds}
	for i := range rs {
		r := &rs[i]
		fd := r.Fd
		named := r.Var.String() != ""
		switch {
		case named && closesVar(w.s, r):
			fds, every := w.closedFds(r)
			for _, n := range fds {
				if every {
					t.put(n, dests{{closed: true}})
				} else {
					t.put(n, w.at(t, n).with(dest{closed: true})) // closed on the paths where name holds n; a descriptor name may hold that is not known stays as it is
				}
			}
			continue
		case named:
			fd = w.varFd(r.Span)
		case fd < 0:
			fd = 1
		}
		to := dests{{w: r.Target, file: w.target(r.Target, t), name: w.s[r.Target.Span.Start:r.Target.Span.End]}}
		if n, ok := literalOf(w.s, r.Target); ok {
			if m, dev := deviceFd(n); dev {
				to = w.at(t, m)
			}
		}
		op := r.Op
		switch {
		case op == RedirDupIn && (r.Fd >= 1 || named):
			op = RedirDupOut // n<&m duplicates for output too
		case op == RedirReadWrite && (r.Fd >= 1 || named):
			op = RedirOut // n<>f opens f for output too
		}
		switch op {
		case RedirIn, RedirReadWrite, RedirHeredoc, RedirHeredocStrip, RedirHereString:
			// a descriptor opened to read a file, a heredoc or a here-string:
			// open, and not one a write reaches
			in := dests{{w: r.Target, name: w.s[r.Target.Span.Start:r.Target.Span.End]}}
			if !named && r.Fd > 0 {
				t.put(r.Fd, in)
			}
			if named {
				t.put(fd, in)
			}
			if r.Fd <= 0 && !named { // the standard input
				if n, ok := literalOf(w.s, r.Target); ok && (op == RedirIn || op == RedirReadWrite) {
					if m, dev := deviceFd(n); dev {
						in = w.at(t, m) // a file that names a descriptor: where it points
					}
				}
				t.put(0, in)
			}
		case RedirDupIn: // 0<&m, <&m
			switch n, isFd := w.dupTarget(r.Target); {
			case !isFd:
			case n == "-":
				t.put(0, dests{{closed: true}})
			case movesFd(n):
				m := atoi(strings.TrimSuffix(n, "-"))
				t.put(0, w.dupOf(t, 0, m))
				if m != 0 {
					t.put(m, dests{{closed: true}})
				}
			default:
				t.put(0, w.dupOf(t, 0, atoi(n)))
			}
		case RedirOut, RedirAppend, RedirClobber:
			t.put(fd, to)
		case RedirAll, RedirAppendAll:
			if !named {
				t.put(1, to)
				t.put(2, to)
			}
		case RedirDupOut:
			if named {
				defer w.markFailable(t, fd, r)
			}
			if v, at, ok := w.movedVar(r.Target); ok {
				w.moveVar(t, fd, v, at, to)
				continue
			}
			n, isFd := w.dupTarget(r.Target)
			switch {
			case movesFd(n):
				m := atoi(strings.TrimSuffix(n, "-"))
				t.put(fd, w.dupOf(t, fd, m))
				if m != fd { // 3>&3- leaves 3 open (bash 5.3)
					t.put(m, dests{{closed: true}})
				}
			case !isFd:
				fds, files := w.dupVar(t, fd, r.Target, to)
				switch {
				case r.Fd < 0 && !named && len(files) > 0 && len(fds) == 0:
					t.put(1, files)
					t.put(2, files)
				case r.Fd < 0 && !named && len(files) > 0:
					t.put(2, w.at(t, 2).with(files...)) // a file on some paths, a descriptor for 1 alone on others
					t.put(1, fds.with(files...))
				default:
					t.put(fd, fds.with(files...))
				}
			case n == "-":
				t.put(fd, dests{{closed: true}})
			default:
				if m := atoi(n); fd != 1 || m != 1 || hasFd(t, 1) {
					t.put(fd, w.dupOf(t, fd, m)) // 1>&1 of the inherited output changes nothing
				}
			}
		}
	}
	if w.cmd != nil && w.joinErr[w.cmd] {
		t.put(2, w.at(t, 1)) // |&: 2 to 1 after the redirects (bashref, "Pipelines")
	}
	return t
}

// markFailable keeps, for the {name}>&m redirect r, whether fd, which it
// opens, may be a duplicate bash does not make (failed) in t.
func (w *fdReading) markFailable(t *fdTab, fd int, r *Redirect) {
	if ds, ok := t.get(fd); ok && slices.ContainsFunc(ds, func(d dest) bool { return d.failed }) {
		if w.failable == nil {
			w.failable = map[int]bool{}
		}
		w.failable[r.Span.Start] = true
	}
}

// movedVar is the parameter of a target of >& that is a parameter alone
// followed by a - not quoted ($v-, "$v"-): bash reads the - as it reads
// the script, and moves the descriptor whose number the value is (bash
// 5.3; "$v-" names a file).
func (w *fdReading) movedVar(t Word) (VarName, Span, bool) {
	if w.vis == nil || len(t.Parts) != 2 {
		return VarName{}, Span{}, false
	}
	p, d := t.Parts[0], t.Parts[1]
	if p.Kind != PartParam || d.Kind != PartLiteral || d.Quote != QuoteNone || w.s[d.Span.Start:d.Span.End] != "-" {
		return VarName{}, Span{}, false
	}
	return p.Name, p.Span, true
}

// moveVar reads fd>&$v- with the table t: fd points where the descriptor
// of each value of v that is a number may point, and that descriptor is
// closed (on every path, for one value known); a value that is not a
// number names a file (to), and a value not known may be 1 or 2, the log,
// or a descriptor that points at a file the caller names.
func (w *fdReading) moveVar(t *fdTab, fd int, v VarName, at Span, to dests) {
	vals, known := w.fdValues(v, at)
	var into dests
	if !known || len(vals) == 0 {
		into = into.with(dest{log: true}).with(files(t)...)
	}
	var ms []int
	for _, val := range vals {
		if !isFdNumber(val) {
			into = into.with(to...)
			continue
		}
		m := atoi(val)
		ms = append(ms, m)
		into = into.with(w.dupOf(t, fd, m)...)
	}
	t.put(fd, into)
	for _, m := range ms {
		switch {
		case m == fd:
		case known && len(vals) == 1:
			t.put(m, dests{{closed: true}})
		default:
			t.put(m, w.at(t, m).with(dest{closed: true}))
		}
	}
}

// movedFds are the descriptors fd>&$v- (moveVar) may close: the values of
// v that are numbers.
func (w *fdReading) movedFds(t Word) []int {
	v, at, ok := w.movedVar(t)
	if !ok {
		return nil
	}
	vals, _ := w.fdValues(v, at)
	var fds []int
	for _, val := range vals {
		if isFdNumber(val) {
			fds = append(fds, atoi(val))
		}
	}
	return fds
}

// dupOf is where fd may point after fd>&m with the table t: where m may
// point. A descriptor not in t is the one the command inherits
// (inherited). A copy of the inherited standard output in another
// descriptor (exec 3>&1, exec {fd}>&1) keeps pointing there when the
// standard output moves after (exec >/dev/null). Where m is not open,
// bash does not make the duplicate (failed). A number of 10 and up not in
// t may be a descriptor a {name} redirect opened, which bash numbers from
// 10, or one bash keeps the descriptors a command's redirects point at
// while the command runs ({ echo >&10; } 2>/dev/null writes to the log;
// bash 5.3).
func (w *fdReading) dupOf(t fdLook, fd, m int) dests {
	var out dests
	from := w.at(t, m)
	if _, ok := t.get(m); !ok && m >= 10 && m < varFdBase {
		from = from.with(w.varFdDests(t)...).with(w.saved(t)...)
	}
	for _, d := range from {
		if d.closed {
			out = out.with(dest{failed: true})
			continue
		}
		d.call = d.call && fd == 1
		out = out.with(d)
	}
	return out
}

// keepsSaved is whether bash keeps, while the command whose redirects
// table reads runs, the descriptors its redirects point in 10 and up: a
// builtin, a function, or a compound command; a program bash runs after a
// fork gets its redirects in the child, which saves nothing (bash 5.3:
// echo and a function write to 10, cat and /bin/echo do not).
func (w *fdReading) keepsSaved() bool {
	x := w.cmd
	if x == nil || len(x.Words) == 0 {
		return true
	}
	n, ok := literalOf(w.s, x.Words[0])
	if !ok {
		return true
	}
	if _, defs := w.defsAt(x); len(defs) > 0 {
		return true
	}
	return builtins[n]
}

// builtins are the builtins of bash 5.3 (bashref, "Shell Builtin
// Commands").
var builtins = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`: . [ alias bg bind break builtin caller cd command compgen complete compopt continue declare dirs disown echo enable eval exec exit export false fc fg getopts hash help history jobs kill let local logout mapfile popd printf pushd pwd read readarray readonly return set shift shopt source suspend test times trap true type typeset ulimit umask unalias unset wait`) {
		builtins[n] = true
	}
}

// saved are the places the descriptors the redirects of the commands the
// command being read is in, and the redirects before in the table t,
// pointed at before them, which bash keeps in descriptors of 10 and up
// while those commands run.
func (w *fdReading) saved(t fdLook) dests {
	var out dests
	keep := func(ds dests) {
		for _, d := range ds {
			if !d.closed {
				out = out.with(d)
			}
		}
	}
	for _, sc := range w.scopes {
		for _, fd := range w.execFds(sc.rs) {
			keep(w.at(sc.fds, fd))
		}
	}
	if x, ok := t.(*fdTab); ok && w.keepsSaved() {
		// the redirects of the command before this one, which bash undoes
		// after the command (echo >&10 2>f... writes where 2 pointed)
		for _, fd := range slices.Sorted(maps.Keys(x.own)) {
			keep(w.at(x.base, fd))
		}
	}
	return out
}

// varFdDests are the places the descriptors {name} redirects opened may
// point in t.
func (w *fdReading) varFdDests(t fdLook) dests {
	var out dests
	for _, fd := range t.keys() {
		if ds, _ := t.get(fd); fd >= varFdBase {
			out = out.with(ds...)
		}
	}
	return out
}

// redirected is whether the standard output of a command with the
// redirects rs goes elsewhere than the output it inherits.
func (w *fdReading) redirected(rs []Redirect) bool {
	_, ok := w.table(rs).own[1]
	return ok
}

// targets are the words of the files the caller names that the output of
// a command with the redirects rs may go to, one for each place.
func (w *fdReading) targets(rs []Redirect) []Word {
	var out []Word
	for _, d := range w.table(rs).own[1] {
		if d.file && !d.call {
			out = append(out, d.w)
		}
	}
	return out
}

// exec keeps the descriptors other than the standard output that exec
// opens for the rest of the shell it runs in.
func (w *fdReading) exec(x *Simple) {
	w.fds = w.execResult(x)
}

// execResult is where the descriptors point after the exec x, which is
// not applied.
func (w *fdReading) execResult(x *Simple) fdMap {
	before := w.fds
	t := w.table(x.Redirects)
	fds := w.execFds(x.Redirects)
	failed := func(d dest) bool { return d.failed }
	may, fails := false, false // a redirect of it may fail, or fails on every path
	for _, fd := range fds {
		if ds, ok := t.get(fd); ok && slices.ContainsFunc(ds, failed) {
			may = true
			fails = fails || !slices.ContainsFunc(ds, func(d dest) bool { return !d.failed })
		}
	}
	if fails {
		return before // bash undoes the redirects of an exec one of which fails (bash 5.3)
	}
	w.fds = maps.Clone(before)
	if w.fds == nil {
		w.fds = fdMap{}
	}
	defer func() { w.fds = before }()
	for _, fd := range fds {
		ds, ok := t.get(fd)
		if may {
			// on the paths where a redirect fails, each descriptor points
			// where it pointed (exec 2>/dev/null 3>&4, 4 not open)
			ds = slices.DeleteFunc(slices.Clone(ds), failed).with(w.at(before, fd)...)
			ok = true
		}
		if fd == 1 && ok {
			ds = covered(ds) // what follows writes there: the exec's write gives it
		}
		w.set(fd, ds, ok) // not in the table: pointed at what it inherits
	}
	return w.fds
}

// execFds are the descriptors the redirects rs point: n of n>f, n>&m and
// n>&-, the standard output of >f, and both outputs of &>f and >&f.
func (w *fdReading) execFds(rs []Redirect) []int {
	var fds []int
	for _, r := range rs {
		n, isFd := w.dupTarget(r.Target)
		if isFd && (r.Op == RedirDupOut || r.Op == RedirDupIn) && movesFd(n) {
			fds = append(fds, atoi(strings.TrimSuffix(n, "-"))) // >&N- closes N
		}
		if r.Op == RedirDupOut || r.Op == RedirDupIn {
			fds = append(fds, w.movedFds(r.Target)...) // >&$v- closes the descriptor of $v
		}
		switch {
		case r.Var.String() != "":
			fds = append(fds, w.namedFds(&r)...)
		case r.Fd >= 0:
			fds = append(fds, r.Fd)
		case r.Op == RedirAll || r.Op == RedirAppendAll || r.Op == RedirDupOut && !isFd:
			fds = append(fds, 1, 2)
		case r.Op == RedirIn || r.Op == RedirReadWrite || r.Op == RedirDupIn || r.Op == RedirHeredoc || r.Op == RedirHeredocStrip || r.Op == RedirHereString:
			fds = append(fds, 0)
		default:
			fds = append(fds, 1)
		}
	}
	return fds
}

// isFdText is whether n, the target of >&, is a file descriptor: a number,
// N- to move it, or - to close.
func isFdText(n string) bool {
	if n == "-" {
		return true
	}
	n = strings.TrimSuffix(n, "-")
	return n != "" && strings.Trim(n, "0123456789") == ""
}

// dupVar reads fd>&t with the table tbl, where dupTarget does not resolve
// t to a descriptor: where fd may point on the paths where the value of t
// is a descriptor (fds), and where it may point on those where the value
// is a file (toFiles): to, the file t names, or, for a value that names the
// log (deviceFd: /dev/stderr), where that descriptor points. t that is
// not a parameter alone ($v, "$v") is a file. A value of $v is that of an
// assignment that reaches it (fdValues); a value not known (fd=$(echo 2),
// read -r fd, the value from before the script) may be 1 or 2, the log,
// or a file, or a descriptor that points at a file the caller names (a
// copy of a number, b=$fd).
func (w *fdReading) dupVar(tbl fdLook, fd int, t Word, to dests) (fds, toFiles dests) {
	if _, lit := literalOf(w.s, t); lit {
		return nil, to
	}
	if w.vis == nil {
		// no values read: a descriptor, which may be fd itself (kept as it
		// was, so that a pipe is not taken as cut), or a file
		return w.at(tbl, fd).with(dest{log: true}, dest{failed: true}).with(files(tbl)...), to
	}
	if len(t.Parts) != 1 || t.Parts[0].Kind != PartParam {
		// another word with expansions (${v:-2}, $((v)), $(echo 3)): what
		// it expands to is not known, but for a word with a literal
		// character that is not a digit ("$D/f"), which names a file
		for i, p := range t.Parts {
			if p.Kind != PartLiteral {
				continue
			}
			text, _ := unescape(w.s[p.Span.Start:p.Span.End], p.Quote, false)
			if i == len(t.Parts)-1 && p.Quote == QuoteNone {
				text = strings.TrimSuffix(text, "-")
			}
			if strings.Trim(text, "0123456789") != "" {
				return nil, to
			}
		}
		return dests{{log: true}}.with(files(tbl)...), to
	}
	vals, known := w.fdValues(t.Parts[0].Name, t.Parts[0].Span)
	if !known || len(vals) == 0 {
		// a value not known may also name a descriptor not open (failed)
		fds, toFiles = fds.with(dest{log: true}, dest{failed: true}).with(files(tbl)...), toFiles.with(to...)
	}
	for _, v := range vals {
		switch m, dev := deviceFd(v); {
		case isFdNumber(v):
			fds = fds.with(w.dupOf(tbl, fd, atoi(v))...)
		case dev:
			toFiles = toFiles.with(w.dupOf(tbl, m, m)...)
		default:
			toFiles = toFiles.with(to...)
		}
	}
	return fds, toFiles
}

// dupTarget is the target t of >& as a descriptor, and whether it is one:
// its text, or for a parameter alone ($v, "$v"), its value when each
// assignment that reaches it gives the same number (fdValues;
// bashref, "Duplicating File Descriptors": a word that does not expand to
// digits or - names a file).
func (w *fdReading) dupTarget(t Word) (string, bool) {
	if n, ok := literalOf(w.s, t); ok {
		return n, isFdText(n)
	}
	if w.vis == nil || len(t.Parts) != 1 || t.Parts[0].Kind != PartParam {
		return "", false
	}
	vals, known := w.fdValues(t.Parts[0].Name, t.Parts[0].Span)
	if !known || len(vals) == 0 {
		return "", false
	}
	v := vals[0]
	for _, x := range vals[1:] {
		if x != v {
			return "", false
		}
	}
	if v == "" || v == "-" || strings.HasSuffix(v, "-") || !isFdText(v) {
		return "", false
	}
	return v, true
}

// maxFdValues is how many values fdValues gives of a variable at a place;
// past it, the value is not known.
const maxFdValues = 16

// maxFdReads is how many places one read of fdValues (a >&$v or a
// {name}>&-) reads: a place whose read met a loop is read again for each
// read that reaches it, which grows with the power of how many v+=x a loop
// holds; past it, the values of that read are not known.
const maxFdReads = 1 << 10

type fdKey struct {
	name string
	at   int
	ctx  callContext
}

type fdResult struct {
	vals    []string
	known   bool
	reading bool // being read: a v+=x that reaches itself (a loop)
}

// fdState is what the reads of fdValues in one run of Writes share.
type fdState struct {
	memo  map[fdKey]fdResult
	depth int // how deep in fdValues the read is
	reads int // the places the read from depth 0 read, up to maxFdReads
	loops int // how many times a read met a place being read, or maxFdReads
}

// fdValues are the values the variable n may have at at, from the
// assignments that reach it (NameVisibility), and whether those are all
// of them: a literal; the number of the descriptor a {name} redirect
// opens (varFd); the value an assignment v+=x appends to, followed back
// to the assignments that reach v+=x. The values not known are not given:
// the value from before the script, one the script does not write as a
// literal, an element (v[0]=x), v+=x when the variable may have the
// integer attribute (v+=x adds) or when v+=x reaches itself (a loop), and
// all of them past maxFdValues or maxFdReads. Each place is read once
// (fdState), but a place whose read met a place being read: its values
// then lack those that place gives, and it is read again when it is reached
// from elsewhere.
func (w *fdReading) fdValues(n VarName, at Span) ([]string, bool) {
	if w.vis == nil {
		return nil, false // a reading with no values: not known
	}
	st := w.fd
	key := fdKey{n.String(), at.Start, w.context()}
	if r, ok := st.memo[key]; ok {
		if r.reading {
			st.loops++
		}
		return r.vals, r.known && !r.reading
	}
	if st.depth == 0 {
		st.reads = 0
	}
	if st.reads >= maxFdReads {
		st.loops++ // the places that met it lack values, as with a loop
		return nil, false
	}
	st.reads++
	st.depth++
	defer func() { st.depth-- }()
	loops := st.loops
	st.memo[key] = fdResult{reading: true}
	vals, known := w.readFdValues(n, at)
	if len(vals) > maxFdValues {
		vals, known = nil, false
	}
	if st.loops != loops && st.depth > 1 {
		delete(st.memo, key) // its values lack those of a place being read; the place a read starts from keeps its answer
	} else {
		st.memo[key] = fdResult{vals: vals, known: known}
	}
	return vals, known
}

func (w *fdReading) readFdValues(n VarName, at Span) ([]string, bool) {
	rs := w.vis.reachingIn(w.context(), n, at)
	if len(rs) == 0 {
		return nil, false // the value from before the script
	}
	var vals []string
	known := true
	add := func(v string) {
		if !slices.Contains(vals, v) {
			vals = append(vals, v)
		}
	}
	for _, r := range rs {
		if len(vals) > maxFdValues {
			return nil, false
		}
		switch {
		case r.Descriptor:
			add(strconv.Itoa(w.varFd(r.At)))
			if w.failable[r.At.Start] {
				// {name}>&m fails where m is not open, and bash leaves name
				// as it was (bash 5.3): the values before the redirect too
				before, all := w.fdValues(n, Span{r.At.Start, r.At.Start})
				known = known && all
				for _, v := range before {
					add(v)
				}
			}
			continue
		case r.Before || r.Value == nil:
			known = false
			continue
		}
		v, ok := literalOf(w.s, *r.Value)
		switch {
		case !ok:
			known = false
		case !r.Append:
			add(v)
		case !strings.HasPrefix(w.s[r.At.Start:], n.String()+"+=") || w.ints:
			known = false // an element, or a sum
		default:
			heads, all := w.fdValues(n, r.At)
			known = known && all
			for _, h := range heads {
				add(h + v)
			}
		}
	}
	return vals, known
}

func (w *fdReading) isExec(x *Simple) bool { return isExec(w.s, x) }

// context is the chain of calls the command being read runs in: the one
// being recorded, or the one NameVisibility read with the calls of
// callChain (-1 when it did not).
func (w *fdReading) context() callContext {
	switch {
	case w.rec != nil:
		return w.rec.ctx
	case len(w.callChain) == 0:
		return 0
	}
	return w.vis.contextOf(w.callChain)
}

// DescriptorReading asks Walk to read where the descriptors of each shell
// point on the paths that reach each command (Enclosing.Stdout), and, when
// it has a NameVisibility, to give the body of a function where each call
// of it runs (Enclosing.Call). Outside the package it is made empty.
type DescriptorReading struct {
	reading *fdReading
}

// fdEnv is what fdReading follows in one ExecutionEnvironment.
type fdEnv struct {
	fds   fdMap
	ended bool
	vars  reach
}

// fdFrame is what pre keeps of a command for post.
type fdFrame struct {
	// failing: where the paths on which the command's redirects fail go
	// after it, which do not run its body
	failing *pathEnd
	// stdin: for the last command of a pipeline run in the shell
	// (lastpipe), its standard input before
	stdin    dests
	lastpipe bool
	// base: the descriptors before its redirects; never: a redirect of it
	// fails on every path, and its body does not run
	base  fdMap
	never bool
	scope *scope
	fds   fdMap
	ended bool
	paths *paths
	skip  bool
}

// maxCalls is how many calls of functions a reading follows into their
// bodies: functions that call others twice make the calls exponential in how
// deep they nest. A call past it writes what is not known and opens nothing.
const maxCalls = 1 << 12

func newFdReading(s string) *fdReading {
	return &fdReading{s: s, fds: fdMap{}, varFds: map[int]int{}, fd: &fdState{memo: map[fdKey]fdResult{}}, envs: map[*ExecutionEnvironment]fdEnv{}, bodyFds: map[Span]fdMap{}, pipeOuts: map[*ExecutionEnvironment]bool{}, pipeIns: map[*ExecutionEnvironment]bool{}, joinErr: map[*Simple]bool{}, calling: map[string]bool{}, callingDefs: map[*FuncDef]bool{}, target: func(Word, fdLook) bool { return false }}
}

// notRead marks the call x, whose body is not read past maxCalls.
func (w *fdReading) notRead(x *Simple) {
	if w.notReadCalls != nil && w.dry == 0 { // a round read ahead is read again
		w.notReadCalls.Add(x.Span())
	}
}

// switchTo makes the state of env the reading's: what a subshell does stays
// in its state and does not reach its parent's.
func (w *fdReading) switchTo(env *ExecutionEnvironment) {
	if env == w.env {
		return
	}
	if w.env != nil {
		w.envs[w.env] = fdEnv{w.fds, w.ended, w.vars}
	}
	w.env = env
	st := w.stateOf(env)
	w.fds, w.ended, w.vars = st.fds, st.ended, st.vars
}

// stateOf is the state of env: kept, or, for a shell not seen yet, its
// parent's (seen or not) where it starts: a substitution's standard output
// is its value, a <( )'s and a command's of a pipeline but the last a pipe,
// and the commands of ( ... ) and of a coproc have the descriptors the
// compound's redirects point (bodyFds).
func (w *fdReading) stateOf(env *ExecutionEnvironment) fdEnv {
	if st, ok := w.envs[env]; ok {
		return st
	}
	st := fdEnv{w.fds, w.ended, w.vars}
	if env.Parent != nil {
		st = w.stateOf(env.Parent)
	}
	st.fds = maps.Clone(st.fds)
	if w.rec != nil {
		st.vars = st.vars.clone() // a subshell starts with what reaches where it starts
	}
	if st.fds == nil {
		st.fds = fdMap{}
	}
	switch env.Kind {
	case ExecutionEnvironmentCommandSubstitution:
		st.fds[1] = dests{{substitution: true}}
	case ExecutionEnvironmentProcessSubstitution:
		if w.s[env.Start.Start] == '<' {
			st.fds[1] = dests{{pipe: true}} // <( ): what it writes, the command reads
		} else {
			st.fds[0] = dests{{pipe: true}} // >( ): what the command writes, it reads
		}
	case ExecutionEnvironmentPipelineElement:
		if w.pipeOuts[env] {
			st.fds[1] = dests{{pipe: true, element: env, output: w.depth}}
		}
		if w.pipeIns[env] {
			st.fds[0] = dests{{pipe: true}}
		}
	case ExecutionEnvironmentSubshell, ExecutionEnvironmentCoproc:
		if t, ok := w.bodyFds[env.Start]; ok {
			st.fds = maps.Clone(t)
		}
	}
	w.envs[env] = st
	return st
}

// pre is what the command c, at, does to the paths and descriptors before
// what is in it is read, and where its standard output points before its
// own redirects; it is false for a command not read (past maxAhead).
func (w *fdReading) pre(c Command, at Enclosing) (dests, bool) {
	if w.dry > 0 {
		if w.ahead.n++; w.ahead.n > w.ahead.max {
			return nil, false // not read: no frame, and no post
		}
	}
	if at.Pipeline != nil && at.Env.Kind == ExecutionEnvironmentPipelineElement {
		if at.Element < len(at.Pipeline.Commands)-1 {
			w.pipeOuts[at.Env] = true // a command of a pipeline but the last: its standard output is the pipe
		}
		if at.Element > 0 {
			w.pipeIns[at.Env] = true // one but the first: its standard input
		}
	}
	w.switchTo(at.Env)
	lastpipe := at.Pipeline != nil && at.Element > 0 && at.Pipeline.Commands[at.Element] == c && at.Env.Kind != ExecutionEnvironmentPipelineElement
	var stdin dests
	if lastpipe {
		// the last command of a pipeline run in the shell (lastpipe): its
		// standard input is the pipe while it runs
		stdin = w.at(w.fds, 0)
		w.fds = maps.Clone(w.fds)
		w.fds[0] = dests{{pipe: true}}
	}
	if n := len(w.frames); n > 0 && w.frames[n-1].paths != nil {
		w.branch(w.frames[n-1].paths, c)
	}
	stdout := w.at(w.fds, 1)
	base := w.fds // before its redirects, which walker.redirects reads from
	joins := at.Pipeline != nil && at.Pipeline.Commands[at.Element] == c && at.Element < len(at.Pipeline.Stderr) && at.Pipeline.Stderr[at.Element]
	if x, ok := c.(*Simple); ok && joins {
		w.joinErr[x] = true // |&: 2 to 1 after its redirects (table)
	}
	var f fdFrame
	switch x := c.(type) {
	case *AndOr:
		f.paths = &paths{c: x, env: at.Env}
	case *Compound:
		if x.Kind == CompoundSubshell || x.Kind == CompoundCoproc {
			// the commands inside have the descriptors the redirects of the
			// compound point
			base := w.fds
			if x.Kind == CompoundCoproc {
				w.fds = maps.Clone(base)
				if w.fds == nil {
					w.fds = fdMap{}
				}
				w.fds[0], w.fds[1] = dests{{pipe: true}}, dests{{pipe: true}} // from and to the shell that starts it, before its redirects
			}
			t := w.table(x.Redirects)
			w.fds = base
			body := t.flat()
			if ds, ok := t.own[1]; ok {
				body[1] = covered(ds)
			}
			if joins {
				body[2] = w.at(body, 1)
			}
			w.bodyFds[x.span] = body
			break
		}
		if w.rec != nil {
			w.flowCompound(x, at)
		}
		may, every := mayFail(w.table(x.Redirects))
		if may {
			f.failing = &pathEnd{maps.Clone(w.fds), w.ended, w.carried()} // bash does not run the body where a redirect fails
			w.notRunAt(x.span.Start)
		}
		sc := w.enter(x.Redirects)
		if every {
			w.ended = true // on no path does the body run
			f.never = true
		}
		if joins {
			w.fds[2] = w.at(w.fds, 1) // |&: 2 to 1 after the redirects (bashref, "Pipelines")
			sc.rs = append(slices.Clip(sc.rs), Redirect{Fd: 2, Op: RedirDupOut})
		}
		f.scope = &sc
		switch x.Kind {
		case CompoundIf:
			f.paths = &paths{c: x, env: at.Env}
		case CompoundWhile, CompoundUntil, CompoundFor, CompoundSelect:
			f.paths = w.enterLoop(x, at)
		}
	case *FuncDef:
		// what exec opens in the body opens where the function is called,
		// not where it is defined
		f.fds, f.ended = maps.Clone(w.fds), w.ended
		w.inFunc++
	}
	f.stdin, f.lastpipe, f.base = stdin, lastpipe, base
	w.frames = append(w.frames, f)
	return stdout, true
}

// post is what the command c, at, does to the paths and descriptors after
// what is in it is read: an exec keeps its redirects, a {name} redirect
// its descriptor, break, continue, return and exit leave their paths, a
// compound command restores what its redirects point, and a function's
// definition what its body did.
func (w *fdReading) post(c Command, at Enclosing) bool {
	f := w.frames[len(w.frames)-1]
	w.frames = w.frames[:len(w.frames)-1]
	if f.skip {
		return false
	}
	w.switchTo(at.Env)
	switch x := c.(type) {
	case *Simple:
		saved := w.cmd
		w.cmd = x
		if w.isExec(x) {
			w.exec(x)
		} else {
			may, every := mayFail(w.table(x.Redirects))
			if may {
				w.notRunAt(x.span.Start)
			}
			if !every { // bash does not run a command whose redirect fails
				w.keepVarFds(x)
				var st pathEnd
				if may {
					st = w.here() // where the redirect fails, the path goes on from here
				}
				w.jump(x, at.Env)
				if may && w.ended {
					w.fds, w.ended = st.fds, st.ended // where the redirect fails, the path goes on
					w.restoreVars(st)
				}
			}
		}
		w.cmd = saved
	case *Compound:
		if f.scope != nil {
			if f.paths != nil {
				w.leavePaths(f.paths)
			}
			w.leave(*f.scope, x.Redirects)
			if f.failing != nil {
				w.meet(w.here(), *f.failing)
			}
		}
	case *AndOr:
		if f.paths != nil {
			w.meet(f.paths.ok, f.paths.fail) // after the list, the paths that succeed and those that fail
		}
	case *FuncDef:
		w.inFunc--
		w.fds, w.ended = f.fds, f.ended
		if w.rec != nil {
			w.flowDefine(x, at)
		}
	}
	if f.lastpipe {
		w.fds = maps.Clone(w.fds)
		w.fds[0] = f.stdin
	}
	return true
}

// done is what the command c ends in the paths of the command it is in: a
// command after && or || may not have run.
func (w *fdReading) done(c Command) {
	if n := len(w.frames); n > 0 && w.frames[n-1].paths != nil {
		w.after(w.frames[n-1].paths, c)
	}
}

// enterLoop is the paths of the loop x at: each round starts with the
// descriptors before the loop, or after rounds (round).
func (w *fdReading) enterLoop(x *Compound, at Enclosing) *paths {
	p := &paths{c: x, env: at.Env, scopes: len(w.scopes)}
	if start, ok := w.flowLoopMemoed(x, at); ok {
		w.fds, w.ended = maps.Clone(start.fds), start.ended
		w.restoreVars(start) // reached from the same state before: its rounds start where they did
		p.start = w.here()
		w.loops = append(w.loops, p)
		return p
	}
	in, whole := w.here(), true
	cuts, framed := w.cuts, w.framed
	// a reading that records reads the rounds until a round adds nothing,
	// up to the commands it may read ahead in the run (aheadState)
	for i := 0; (i < maxRounds || w.rec != nil) && w.changing[x]; i++ {
		r, ok := w.round(x, at)
		if !ok {
			whole = false
			break
		}
		before := w.here()
		w.meet(before, r)
		if sameFds(before.fds, w.fds) && (w.rec == nil || before.vars.same(w.vars)) {
			break // a round more adds nothing
		}
	}
	if w.rec != nil && whole && w.ahead.n < w.ahead.max && w.cuts == cuts && w.framed == framed {
		w.flowLoopKeep(x, at, in, w.here())
	}
	p.start = w.here()
	w.loops = append(w.loops, p)
	return p
}

// round reads ahead a round of the loop x at, with no Visitor, and is where
// it leaves the descriptors: what a later round starts with.
func (w *fdReading) round(x *Compound, at Enclosing) (pathEnd, bool) {
	if w.ahead == nil || w.ahead.n >= w.ahead.max {
		return pathEnd{}, false
	}
	st, calls := fdEnv{maps.Clone(w.fds), w.ended, w.carried()}, w.calls
	dry := &paths{c: x, env: at.Env, scopes: len(w.scopes)}
	w.loops = append(w.loops, dry)
	w.dry++
	body := inside(at)
	body.mayNot = true
	if w.rec != nil {
		w.flowLoopVar(x, at)
	}
	(&walker{s: w.s, r: w}).list(x.Body, body)
	w.dry--
	w.loops = w.loops[:len(w.loops)-1]
	end := w.joined(append(dry.conts, w.here())...) // a break leaves the loop, not to a round
	w.switchTo(at.Env)
	w.fds, w.ended = st.fds, st.ended
	if w.rec != nil {
		w.vars = st.vars
	}
	w.calls = calls // the calls read ahead are counted by ahead
	return end, true
}

// mayFail is whether a redirect of the table t may fail, a duplicate of a
// descriptor not open on some path (dest.failed), and whether it fails on
// every path. bash does not run a command one of whose redirects fails.
func mayFail(t *fdTab) (may, every bool) {
	failed := func(d dest) bool { return d.failed }
	for _, ds := range t.own {
		if slices.ContainsFunc(ds, failed) {
			may = true
			every = every || !slices.ContainsFunc(ds, func(d dest) bool { return !d.failed })
		}
	}
	return may, every
}

// notRunAt keeps, for walkNotRun, that the command at start may not run.
func (w *fdReading) notRunAt(start int) {
	if w.notRun != nil && w.dry == 0 {
		w.notRun[start] = true
	}
}

// failsAlways is whether a redirect of rs, the redirects of the command being
// read, fails on every path: bash does not run the command, which writes
// nothing. For a compound command, the table is read from the descriptors
// before its redirects.
func (w *fdReading) failsAlways(rs []Redirect) bool {
	if len(w.frames) > 0 {
		saved := w.fds
		w.fds = w.frames[len(w.frames)-1].base
		defer func() { w.fds = saved }()
	}
	_, every := mayFail(w.table(rs))
	return every
}

// never is whether the command being read, the last pre took, does not
// run its body: a redirect of it fails on every path.
func (w *fdReading) never() bool {
	return len(w.frames) > 0 && w.frames[len(w.frames)-1].never
}
