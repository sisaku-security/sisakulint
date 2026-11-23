package shell

// The reading NewNameVisibility made before the flow reading (readFlow):
// its own walk of the paths (and-or lists, if, loops read in rounds,
// break, continue, return, calls), read again with the commands whose
// redirects may fail (walkNotRun). The tests compare the flow reading with
// it (TestNameVisibility, TestFlowWithBash).

import (
	"maps"
	"slices"
	"strings"
)

// walkNotRun are the commands of sc, by where they start, whose redirects
// may fail, which bash may not run (mayFail): the compound commands, the
// calls of functions and the other simple commands but exec, read with the
// values and the definitions of v.
func walkNotRun(script string, sc *Script, v *NameVisibility) map[int]bool {
	r := newFdReading(script)
	r.vis = v
	r.findNames(sc.List)
	r.notRun = map[int]bool{}
	Walk(script, sc.List, Enclosing{}, Visitor{Descriptors: &DescriptorReading{reading: r}})
	return r.notRun
}

// maxNameCalls is how many calls of functions NewNameVisibility reads the
// bodies of, as Writes does (maxCalls).
const maxNameCalls = 1 << 12

// frame is a call of a function being read.
type callFrame struct {
	def   *FuncDef
	env   *ExecutionEnvironment    // the shell of the call: a return there ends the body
	saved map[string][]*Assignment // the names it made local, as they were before
	// loops: how many of visibility.loops are around the call, which a
	// break in the body does not leave; returns, the paths return leaves
	loops   int
	returns []reach
}

type visibility struct {
	canon  map[assignKey]*Assignment // one Assignment for one assignment, however often it is read
	s      string
	v      *NameVisibility
	scopes map[*ExecutionEnvironment]*reach
	frames []*callFrame
	loops  []*vloop // the loops being read, the innermost last
	// notRun are the commands, by where they start, whose redirects may
	// fail (walkNotRun): bash may not run them
	notRun map[int]bool
	quiet  int // reading a loop's body ahead: nothing is recorded
	nCalls int
	defs   []defined
	merged map[int]bool // the records of cmds made for more than one visit, which no reach keeps
	early  map[int]bool // the parameters of the words of for and select, read before the loop (loopWords)
	// ahead are the loops read ahead in rounds, by the loop and its shell:
	// what reached each, and what reached after it (memoLoop)
	ahead map[loopKey][]loopRun
}

// loopKey is a loop in a shell.
type loopKey struct {
	c   *Compound
	env *ExecutionEnvironment
}

// loopRun is what reached a loop read ahead, and what reached after it.
type loopRun struct {
	in, out reach
}

// memoLoop reads the loop c at, in sc, by read, when read ahead in rounds:
// a loop reached again with what reached it before ends as it did then,
// so that loops nested in loops are read a few times each, not to the
// power of their depth.
func (x *visibility) memoLoop(c *Compound, at Enclosing, sc *reach, read func()) {
	if x.quiet == 0 {
		read()
		return
	}
	k := loopKey{c, at.Env}
	for _, r := range x.ahead[k] {
		if r.in.same(*sc) {
			*sc = r.out.clone()
			return
		}
	}
	in := sc.clone()
	read()
	if x.ahead == nil {
		x.ahead = map[loopKey][]loopRun{}
	}
	x.ahead[k] = append(x.ahead[k], loopRun{in, sc.clone()})
}

// mk is the one Assignment of what a describes.
func (x *visibility) mk(a Assignment) *Assignment {
	k := assignKey{a.At, a.Name.String(), a.Local, a.Unset, a.Value != nil}
	if c, ok := x.canon[k]; ok {
		return c
	}
	c := &a
	x.canon[k] = c
	return c
}

// oldNameVisibility is the reading NewNameVisibility made before the flow
// reading: its own walk of the paths, read again with the commands whose
// redirects may fail (walkNotRun). The tests compare the two.
func oldNameVisibility(script string, sc *Script) *NameVisibility {
	v := readVisibility(script, sc, nil)
	if !dupRedirects(sc) {
		return v
	}
	// a command whose redirect may fail may not run: read again with those
	// (walkNotRun, from the values and definitions read), until no more are
	// found
	seen := map[int]bool{}
	for i := 0; ; i++ {
		notRun := walkNotRun(script, sc, v)
		maps.Copy(notRun, seen) // only grows, so the readings end
		if len(notRun) == 0 || maps.Equal(notRun, seen) {
			return v
		}
		if i == maxNotRunReads {
			// past the limit, each command with a duplicating redirect may not
			// run
			for _, c := range dupRedirectCommands(sc) {
				notRun[c] = true
			}
		}
		seen = notRun
		v = readVisibility(script, sc, notRun)
		if i == maxNotRunReads {
			return v
		}
	}
}

// maxNotRunReads is how many times NewNameVisibility reads a script again
// with the commands that may not run; each reading reads the whole script,
// and each may add the commands whose values the one before added.
const maxNotRunReads = 3

// dupRedirectCommands are where the commands of sc with a redirect that
// duplicates a descriptor start.
func dupRedirectCommands(sc *Script) []int {
	var out []int
	Walk("", sc.List, Enclosing{}, Visitor{Command: func(c Command, _ Enclosing) bool {
		var rs []Redirect
		switch x := c.(type) {
		case *Simple:
			rs = x.Redirects
		case *Compound:
			rs = x.Redirects
		}
		if slices.ContainsFunc(rs, func(r Redirect) bool { return r.Op == RedirDupOut || r.Op == RedirDupIn }) {
			out = append(out, c.Span().Start)
		}
		return true
	}})
	return out
}

// dupRedirects is whether a command of sc has a redirect that duplicates a
// descriptor (n>&m, n<&m), which may fail.
func dupRedirects(sc *Script) bool {
	found := false
	Walk("", sc.List, Enclosing{}, Visitor{Redirect: func(r *Redirect, _ Enclosing) {
		found = found || r.Op == RedirDupOut || r.Op == RedirDupIn
	}})
	return found
}

// readVisibility reads sc once, with the commands notRun, which may not run.
func readVisibility(script string, sc *Script, notRun map[int]bool) *NameVisibility {
	v := &NameVisibility{reads: map[int]map[string][]*Assignment{}, cmds: map[int]map[string][]*Assignment{}, funcs: map[int]map[string][]*FuncDef{}, calls: map[*FuncDef][]*Simple{}}
	x := &visibility{s: script, v: v, scopes: map[*ExecutionEnvironment]*reach{}, canon: map[assignKey]*Assignment{}, merged: map[int]bool{}, notRun: notRun}
	x.walk(sc.List, Enclosing{})
	for _, d := range x.defs {
		if len(v.calls[d.def]) > 0 {
			continue
		}
		// a body never called is read where it is defined, giving nothing back
		saved := x.scopeOf(d.at.Env).clone()
		*x.scopeOf(d.at.Env) = d.sc.clone()
		x.call(d.def, d.at, nil)
		*x.scopeOf(d.at.Env) = saved
	}
	return v
}

// scopeOf is the scope of env: a shell not seen yet starts with what
// reaches in its parent where it starts.
func (x *visibility) scopeOf(env *ExecutionEnvironment) *reach {
	if s, ok := x.scopes[env]; ok {
		return s
	}
	s := reach{vars: map[string][]*Assignment{}, funcs: map[string][]*FuncDef{}}
	if env.Parent != nil {
		s = x.scopeOf(env.Parent).clone()
	}
	x.scopes[env] = &s
	return &s
}

func (x *visibility) walk(cs []Command, at Enclosing) {
	type mark struct {
		before reach
		union  bool   // after it, the union of before and after
		loop   *vloop // the loop it reads, whose breaks and continues meet after it
	}
	var stack []Command
	var marks []mark
	// assigning: a command of assignment words alone, and how many of them
	// are done: a word reads the words before it (a=1 b=$a)
	type assigning struct {
		c    *Simple
		as   []Word
		done int
	}
	var words []assigning
	// pending: the assignments of ${NAME:=value} whose words are being read,
	// made at the first part after the ${ } or when the command is left
	type pendingAssign struct {
		a   *Assignment
		end int
	}
	var pending []pendingAssign
	// applied: how many redirects of a simple command being read are done:
	// bash performs each before it expands the target of the next, so a
	// {name} of a redirect is assigned before the targets after it are read
	applied := map[*Simple]int{}
	flush := func(at int) {
		slices.SortStableFunc(pending, func(a, b pendingAssign) int { return a.end - b.end }) // an inner ${ } first
		for len(pending) > 0 && pending[0].end <= at {
			x.appendTo(x.scopeOf(pending[0].a.Env), pending[0].a)
			pending = pending[1:]
		}
	}
	Walk(x.s, cs, at, Visitor{
		Command: func(c Command, at Enclosing) bool {
			parent := Command(nil)
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, c)
			m := mark{}
			sc := x.scopeOf(at.Env)
			if sc.ended {
				marks = append(marks, m)
				return false
			}
			if a, ok := parent.(*AndOr); ok && a.Commands[0] != c {
				m = mark{before: sc.clone(), union: true} // after && or ||: it may not run
			}
			switch c := c.(type) {
			case *AndOr:
				x.andOr(c, at, sc)
				marks = append(marks, m)
				return false
			case *Simple:
				if x.quiet == 0 {
					x.record(c.span.Start, sc)
				}
				if len(c.Words) == 0 {
					words = append(words, assigning{c: c, as: c.Assigns})
				}
			case *FuncDef:
				if n, ok := literalOf(x.s, c.Name); ok {
					sc.funcs[n] = []*FuncDef{c}
					if x.quiet == 0 { // a round read ahead is read again, recording
						x.defs = append(x.defs, defined{def: c, at: at, sc: sc.clone()})
					}
				}
				marks = append(marks, m)
				return false // read where it is called
			case *Compound:
				if x.notRun[c.span.Start] && !m.union {
					m = mark{before: sc.clone(), union: true} // its redirect may fail: the body may not run
				}
				if c.Kind != CompoundSubshell && c.Kind != CompoundCoproc {
					// bash applies the redirects of a compound command in the
					// shell that runs it before its body, and a {name} of them
					// stays after it; those of ( ... ) and a coproc are the
					// subshell's
					x.descriptors(sc, c.Redirects, nil, at)
				}
				switch c.Kind {
				case CompoundIf:
					if len(c.lists) > 0 {
						x.ifBranches(c, at, sc)
						marks = append(marks, m)
						return false
					}
					if !m.union {
						m = mark{before: sc.clone(), union: true}
					}
				case CompoundCase:
					if !m.union {
						m = mark{before: sc.clone(), union: true}
					}
				case CompoundWhile, CompoundUntil:
					if len(c.lists) == 2 {
						x.memoLoop(c, at, sc, func() { x.whileLoop(c, at, sc) })
						marks = append(marks, m)
						return false
					}
					fallthrough
				case CompoundFor, CompoundSelect:
					inner := at
					inner.mayNot = true // a return there may not run
					x.loopWords(c, sc)
					x.memoLoop(c, at, sc, func() {
						x.rounds(sc, at.Env, func() {
							x.loopVar(sc, c, at)
							x.walk(c.Body, inner)
						})
					})
					if x.quiet > 0 {
						// a round more adds nothing, and records nothing
						marks = append(marks, m)
						return false
					}
					if !m.union && !roundsOnce(x.s, c) {
						// the loop ends where a round would start; a for whose
						// words make one at least runs a round
						m = mark{before: sc.clone(), union: true}
					}
					x.loopVar(sc, c, at)
					m.loop = &vloop{env: at.Env}
					x.loops = append(x.loops, m.loop)
				}
			}
			marks = append(marks, m)
			return true
		},
		Leave: func(c Command, at Enclosing) {
			stack = stack[:len(stack)-1]
			m := marks[len(marks)-1]
			marks = marks[:len(marks)-1]
			sc := x.scopeOf(at.Env)
			if m.loop != nil {
				x.loops = x.loops[:len(x.loops)-1]
				for _, j := range append(m.loop.breaks, m.loop.conts...) {
					*sc = sc.union(j) // the paths that leave a round meet after the loop
				}
			}
			if !sc.ended {
				flush(c.Span().End)
			}
			if sc.ended {
				if m.union {
					*sc = m.before.union(*sc)
				}
				return
			}
			switch c := c.(type) {
			case *Simple:
				done := 0
				if len(c.Words) == 0 {
					done = words[len(words)-1].done
					words = words[:len(words)-1]
				}
				x.simple(c, at, done, applied[c])
				delete(applied, c)
			case *Compound:
				if c.Kind == CompoundCoproc {
					name := "COPROC"
					if c.Name != nil {
						if n, ok := literalOf(x.s, *c.Name); ok {
							name = n
						} else {
							name = ""
						}
					}
					if name != "" {
						x.assign(sc, &Assignment{Name: VarName{name}, At: c.span, Env: at.Env, Func: at.Func})
						x.assign(sc, &Assignment{Name: VarName{name + "_PID"}, At: c.span, Env: at.Env, Func: at.Func})
					}
				}
			}
			if m.union {
				*sc = m.before.union(*sc)
			}
		},
		Redirect: func(r *Redirect, at Enclosing) {
			sc := x.scopeOf(at.Env)
			if sc.ended || len(stack) == 0 {
				return
			}
			if k, ok := stack[len(stack)-1].(*Compound); ok {
				if (k.Kind == CompoundSubshell || k.Kind == CompoundCoproc) && len(k.Redirects) > 0 && r == &k.Redirects[0] {
					x.descriptors(sc, k.Redirects, nil, at) // the subshell's own, before its body (at is in the subshell)
				}
				return // another compound command's {name} is assigned before its body (Command)
			}
			c, ok := stack[len(stack)-1].(*Simple)
			if !ok {
				return
			}
			for i := range c.Redirects {
				if &c.Redirects[i] == r && i > applied[c] {
					x.descriptors(sc, c.Redirects[applied[c]:i], c, at)
					applied[c] = i
				}
			}
		},
		Part: func(p *Part, at Enclosing) {
			sc := x.scopeOf(at.Env)
			if sc.ended {
				return
			}
			flush(p.Span.Start)
			if n := len(words); n > 0 {
				w := &words[n-1]
				for w.done < len(w.as) && w.as[w.done].Span.End <= p.Span.Start {
					x.assignWord(sc, &w.as[w.done], w.c, at, false)
					w.done++
				}
			}
			if p.Kind != PartParam && p.Kind != PartParamOp {
				return
			}
			n := p.Name.String()
			if x.quiet == 0 && !x.early[p.Span.Start] {
				if x.v.reads[p.Span.Start] == nil {
					x.v.reads[p.Span.Start] = map[string][]*Assignment{}
				}
				x.v.reads[p.Span.Start][n] = unionAssign(x.v.reads[p.Span.Start][n], sc.vars[n])
			}
			if e := p.Param; e != nil && e.Op == ParamOpAssign && e.Prefix == ParamPrefixNone && e.All == ParamAllNone && isName(e.Name.String()) {
				// ${NAME:=value}, ${a[i]:=value}: the name keeps its value when it
				// has one; bash expands the word before it assigns, so the
				// assignment is made after the parts of the word are read
				var by *Simple
				if len(stack) > 0 {
					by, _ = stack[len(stack)-1].(*Simple)
				}
				pending = append(pending, pendingAssign{a: &Assignment{Name: e.Name, At: p.Span, Value: &e.Words[0], Append: e.Subscript != nil, Func: at.Func, Env: at.Env, By: by}, end: p.Span.End})
			}
		},
	})
}

// record keeps what reaches the simple command at start: the map of sc,
// which sc copies before its next change, at the first visit; after it,
// the union of the visits.
func (x *visibility) record(start int, sc *reach) {
	old, ok := x.v.cmds[start]
	switch {
	case !ok:
		x.v.cmds[start], sc.kept = sc.vars, true
	case x.merged[start]:
		x.v.cmds[start] = mergeVars(old, sc.vars)
	default:
		x.v.cmds[start] = mergeVars(maps.Clone(old), sc.vars)
		x.merged[start] = true
	}
}

func mergeVars(m map[string][]*Assignment, vars map[string][]*Assignment) map[string][]*Assignment {
	if m == nil {
		m = map[string][]*Assignment{}
	}
	for k, v := range vars {
		m[k] = unionAssign(m[k], v)
	}
	return m
}

// assign makes a the one assignment of its name that reaches.
func (x *visibility) assign(sc *reach, a *Assignment) {
	sc.setVar(a.Name.String(), []*Assignment{x.mk(*a)})
}

// appendTo adds a to what reaches its name (NAME+=value): the value is
// what reached with a's value after it.
func (x *visibility) appendTo(sc *reach, a *Assignment) {
	n := a.Name.String()
	old, ok := sc.vars[n]
	if !ok {
		old = withBefore(nil, n)
	}
	sc.setVar(n, unionAssign(old, []*Assignment{x.mk(*a)}))
}

// local makes the name n local to the function being read: its value
// before is given back when the function returns.
func (x *visibility) local(sc *reach, n string, env *ExecutionEnvironment) {
	if len(x.frames) == 0 || x.frames[len(x.frames)-1].env != env {
		return // a subshell's own: it ends with the subshell
	}
	f := x.frames[len(x.frames)-1]
	if _, ok := f.saved[n]; !ok {
		f.saved[n] = sc.vars[n]
	}
}

// descriptors assigns the names of the {name} redirects rs of the command
// by (nil for a compound command): {name} opens a descriptor and assigns
// its number to name, which stays after the command (bashref,
// "Redirections"); >&- and <&- close the one name holds. For a compound
// command, whose redirects are all done here before the walk reads their
// targets, the parameters of each target are read here, before the
// redirects after it (bash expands each target after the redirects before
// it).
func (x *visibility) descriptors(sc *reach, rs []Redirect, by *Simple, at Enclosing) {
	for i := range rs {
		r := &rs[i]
		if by == nil && x.quiet == 0 {
			for _, p := range PartParams(r.Target.Parts) {
				pn := p.Name.String()
				if x.v.reads[p.Span.Start] == nil {
					x.v.reads[p.Span.Start] = map[string][]*Assignment{}
				}
				x.v.reads[p.Span.Start][pn] = unionAssign(x.v.reads[p.Span.Start][pn], sc.vars[pn])
				if x.early == nil {
					x.early = map[int]bool{}
				}
				x.early[p.Span.Start] = true
			}
		}
		n := r.Var.String()
		if n == "" {
			continue
		}
		if x.quiet == 0 {
			// what reaches the redirect, before it assigns: the descriptor
			// {name}>&- closes is the one name holds there (bash applies the
			// redirects of a compound command before its body)
			if x.v.reads[r.Span.Start] == nil {
				x.v.reads[r.Span.Start] = map[string][]*Assignment{}
			}
			x.v.reads[r.Span.Start][n] = unionAssign(x.v.reads[r.Span.Start][n], sc.vars[n])
		}
		if !closesVar(x.s, r) {
			x.assign(sc, &Assignment{Name: r.Var, At: r.Span, Func: at.Func, Env: at.Env, By: by, Descriptor: true})
		}
	}
}

// simple does what the simple command c assigns, defines and calls, after
// its words are read, and the {name} of its redirects past the first
// redirectsDone, which the walk did before the targets after them.
func (x *visibility) simple(c *Simple, at Enclosing, done, redirectsDone int) {
	sc := x.scopeOf(at.Env)
	x.descriptors(sc, c.Redirects[redirectsDone:], c, at)
	var words []string
	as, wordsAt := c.Assigns, c.Words
	for _, w := range wordsAt {
		n, _ := literalOf(x.s, w)
		words = append(words, n) // "" where not literal
	}
	prefixed := false
	for len(words) > 1 && (words[0] == "builtin" || words[0] == "command") && !strings.HasPrefix(words[1], "-") {
		words, wordsAt, prefixed = words[1:], wordsAt[1:], true // the builtin or the program it runs, never a function
	}
	if x.quiet == 0 && len(words) > 0 && words[0] != "" {
		if x.v.funcs[c.span.Start] == nil {
			x.v.funcs[c.span.Start] = map[string][]*FuncDef{}
		}
		x.v.funcs[c.span.Start][words[0]] = unionOf(x.v.funcs[c.span.Start][words[0]], sc.funcs[words[0]])
	}
	if len(wordsAt) == 0 {
		for i := range as {
			// those a later word's read did not do already; with no command,
			// bash assigns after the redirects, so an assignment of a name a
			// {name} redirect assigns is done again (fd=3 {fd}>f leaves fd=3)
			if n, _ := assignedName(x.s, as[i]); i >= done || n != "" && slices.ContainsFunc(c.Redirects, func(r Redirect) bool { return r.Var.String() == n && !closesVar(x.s, &r) }) {
				x.assignWord(sc, &as[i], c, at, false)
			}
		}
		return
	}
	if x.notRun[c.span.Start] {
		// its redirect may fail, and bash then runs neither the builtin nor
		// the function (an assignment alone, above, it makes)
		before := sc.clone()
		defer func() { *sc = before.union(*sc) }()
	}
	if k, n := jumpOf(x.s, c.Words); k != jumpNone {
		x.jump(k, n, sc, at.Env)
		if k != jumpMay {
			return
		}
	}
	if len(words) == 0 || words[0] == "" {
		return
	}
	if defs := sc.funcs[words[0]]; len(defs) > 0 && !prefixed {
		x.callAll(defs, c, at)
		return
	}
	inFunc := len(x.frames) > 0
	switch words[0] {
	case "export", "readonly", "declare", "typeset", "local":
		if words[0] == "local" && !inFunc {
			return // an error to bash: it assigns nothing
		}
		global := false
		for _, w := range words[1:] {
			if strings.HasPrefix(w, "-") && strings.Contains(w, "g") {
				global = true
			}
			if strings.HasPrefix(w, "-") && strings.ContainsAny(w, "pfF") {
				return // prints, or names functions: no variable is declared
			}
		}
		isLocal := inFunc && !global && (words[0] == "local" || words[0] == "declare" || words[0] == "typeset")
		for i := 1; i < len(wordsAt); i++ {
			if strings.HasPrefix(words[i], "-") {
				continue
			}
			if strings.Contains(x.s[wordsAt[i].Span.Start:wordsAt[i].Span.End], "=") {
				if isLocal {
					if n, ok := assignedName(x.s, wordsAt[i]); ok {
						x.local(sc, n, at.Env)
					}
				}
				x.assignWord(sc, &wordsAt[i], c, at, isLocal)
				continue
			}
			if isLocal && words[i] != "" && isName(words[i]) {
				x.local(sc, words[i], at.Env)
				x.assign(sc, &Assignment{Name: VarName{words[i]}, At: wordsAt[i].Span, Func: at.Func, Local: true, Env: at.Env, By: c})
			}
		}
	case "read", "mapfile", "readarray", "printf":
		for _, n := range readNames(words) {
			x.assign(sc, &Assignment{Name: VarName{n}, At: c.span, Func: at.Func, Env: at.Env, By: c})
		}
	case "unset":
		fn := false
		for _, w := range words[1:] {
			switch {
			case w == "-f":
				fn = true
			case w == "-v":
				fn = false
			case strings.HasPrefix(w, "-"):
			case fn:
				delete(sc.funcs, w)
			case isName(w):
				x.assign(sc, &Assignment{Name: VarName{w}, At: c.span, Unset: true, Func: at.Func, Env: at.Env, By: c})
			}
		}
	}
}

// andOr reads the and-or list c in sc: a command after && runs on the
// paths where the one before succeeds, one after || where it fails; after
// the list, the union of the two.
func (x *visibility) andOr(c *AndOr, at Enclosing, sc *reach) {
	inner := at
	inner.mayNot = true
	run := func(cmd Command, st reach, at Enclosing) reach {
		*sc = st.clone() // st may be shared by both paths
		x.walk([]Command{cmd}, at)
		return sc.clone()
	}
	r := run(c.Commands[0], sc.clone(), at)
	ok, fail := r, r
	for i, op := range c.Ops {
		switch op {
		case AndOrAnd:
			r = run(c.Commands[i+1], ok, inner)
			ok, fail = r, fail.union(r)
		default:
			r = run(c.Commands[i+1], fail, inner)
			ok, fail = ok.union(r), r
		}
	}
	*sc = ok.union(fail)
}

// whileLoop reads the while or until c in sc: the condition runs at least
// once; a round of the body goes back to the condition; the loop ends
// after the condition.
func (x *visibility) whileLoop(c *Compound, at Enclosing, sc *reach) {
	inner := at
	inner.mayNot = true
	cond, body := c.Body[:c.lists[1]], c.Body[c.lists[1]:]
	// the start of the condition: first, or after a round
	x.rounds(sc, at.Env, func() {
		x.walk(cond, inner)
		x.walk(body, inner)
	})
	l := &vloop{env: at.Env}
	x.loops = append(x.loops, l)
	defer func() { x.loops = x.loops[:len(x.loops)-1] }()
	x.walk(cond, inner)
	if x.quiet > 0 {
		return // a round more adds nothing, and records nothing
	}
	afterCond := sc.clone()
	x.walk(body, inner)
	*sc = afterCond
	for _, j := range append(l.breaks, l.conts...) {
		*sc = sc.union(j) // a continue goes back to the condition, which may end the loop
	}
}

// rounds makes sc what reaches the start of a round of a loop, read by
// round from sc without recording: what reaches the loop, and the end of
// each round, until a round adds nothing (a function a round defines may
// define another that a later round calls). A loop inside reached with
// what its rounds add already ends after one round, so nested loops take
// a few rounds each, not two to the power of their depth.
func (x *visibility) rounds(sc *reach, env *ExecutionEnvironment, round func()) {
	start := sc.clone()
	x.quiet++
	for {
		l := &vloop{env: env}
		x.loops = append(x.loops, l)
		round()
		x.loops = x.loops[:len(x.loops)-1]
		next := start.union(*sc)
		for _, j := range l.conts {
			next = next.union(j) // a continue starts the next round
		}
		if next.same(start) {
			break
		}
		start = next
		*sc = start.clone()
	}
	x.quiet--
	*sc = start
}

// ifBranches reads the if c in sc: each condition, the commands after
// then on the path where it holds, and the next condition or else on the
// path where it does not; after the if, the union of the ends of the
// paths.
func (x *visibility) ifBranches(c *Compound, at Enclosing, sc *reach) {
	seg := func(i int) []Command {
		end := len(c.Body)
		if i+1 < len(c.lists) {
			end = c.lists[i+1]
		}
		return c.Body[c.lists[i]:end]
	}
	inner := at
	inner.mayNot = true
	pairs := len(c.lists) / 2
	if c.elseAt {
		pairs = (len(c.lists) - 1) / 2
	}
	var ends []reach
	for i := 0; i < pairs; i++ {
		cond := inner
		if i == 0 {
			cond = at // the first condition runs whenever the if does
		}
		x.walk(seg(2*i), cond)
		afterCond := sc.clone()
		x.walk(seg(2*i+1), inner)
		ends = append(ends, sc.clone())
		*sc = afterCond
	}
	if c.elseAt {
		x.walk(seg(len(c.lists)-1), inner)
	}
	out := sc.clone()
	for _, e := range ends {
		out = out.union(e)
	}
	*sc = out
}

func (x *visibility) assignWord(sc *reach, w *Word, c *Simple, at Enclosing, local bool) {
	n, value, element, ok := AssignedName(x.s, *w)
	if !ok {
		return
	}
	a := &Assignment{Name: VarName{n}, At: w.Span, Value: valueWord(*w, value), Append: element || x.s[value-2] == '+', Func: at.Func, Local: local, Env: at.Env, By: c}
	if element {
		x.appendTo(sc, a) // an element leaves the others as they were
		return
	}
	// NAME+=value too: its value is what reached and value after it; what
	// reached is read through Bases, not as a value of NAME after it
	x.assign(sc, a)
}

// loopWords records what reaches the parameters of the words after in of
// the for or select c, which bash expands once before the loop, before the
// rounds of its body are read ahead: Walk gives the parts after that.
func (x *visibility) loopWords(c *Compound, sc *reach) {
	for i := range c.In {
		for _, p := range PartParams(c.In[i].Parts) {
			if x.quiet == 0 {
				n := p.Name.String()
				if x.v.reads[p.Span.Start] == nil {
					x.v.reads[p.Span.Start] = map[string][]*Assignment{}
				}
				x.v.reads[p.Span.Start][n] = unionAssign(x.v.reads[p.Span.Start][n], sc.vars[n])
			}
			if x.early == nil {
				x.early = map[int]bool{}
			}
			x.early[p.Span.Start] = true
		}
	}
}

// loopVar assigns the name of the for or select c at the start of a
// round: one of the words after in, or, with no in, a value the script
// does not write ("$@"). With an in and no words, the body does not run.
func (x *visibility) loopVar(sc *reach, c *Compound, at Enclosing) {
	if c.Var == nil {
		return
	}
	n, ok := literalOf(x.s, *c.Var)
	if !ok || !isName(n) {
		return
	}
	var as []*Assignment
	if !c.HasIn {
		as = append(as, x.mk(Assignment{Name: VarName{n}, At: c.Var.Span, Func: at.Func, Env: at.Env}))
	}
	for i := range c.In {
		as = append(as, x.mk(Assignment{Name: VarName{n}, At: c.In[i].Span, Value: &c.In[i], Func: at.Func, Env: at.Env}))
	}
	if len(as) > 0 {
		sc.setVar(n, as)
	}
}

// callAll reads the call c of the definitions defs: the commands after it
// get the union of what each leaves.
func (x *visibility) callAll(defs []*FuncDef, c *Simple, at Enclosing) {
	sc := x.scopeOf(at.Env)
	before := sc.clone()
	var after *reach
	for _, d := range defs {
		*sc = before.clone()
		if d != nil { // nil: a path where no definition reaches, which runs no body
			x.call(d, at, c)
		}
		if after == nil {
			cp := sc.clone()
			after = &cp
		} else {
			u := after.union(*sc)
			after = &u
		}
	}
	if after != nil {
		*sc = *after
	}
}

// call reads the body of d where c calls it (c is nil for a body never
// called), with what reaches the call: the assignments before the command
// word of c are seen by the body only, and what the body makes local is
// given back when it returns.
func (x *visibility) call(d *FuncDef, at Enclosing, c *Simple) {
	for _, f := range x.frames {
		if f.def == d {
			return // a recursion: read once
		}
	}
	if x.nCalls >= maxNameCalls {
		switch {
		case c != nil:
			x.v.notRead.Add(c.span)
		case !x.v.notRead.OK:
			// a body never called, read after the calls: its definition,
			// when no call was left unread
			x.v.notRead.Add(d.Span())
		}
		return
	}
	x.nCalls++
	if c != nil && x.quiet == 0 {
		x.v.calls[d] = unionOf(x.v.calls[d], []*Simple{c})
	}
	sc := x.scopeOf(at.Env)
	f := &callFrame{def: d, env: at.Env, saved: map[string][]*Assignment{}, loops: len(x.loops)}
	x.frames = append(x.frames, f)
	if c != nil {
		as := c.Assigns
		for i := range as {
			// bash refuses an element of an array before a command word
			// (a[0]: not a valid identifier) and runs the command
			if n, _, element, ok := AssignedName(x.s, as[i]); ok && !element {
				x.local(sc, n, at.Env)
				x.assignWord(sc, &as[i], c, at, false)
			}
		}
	}
	body := at
	body.Func = d
	x.walk([]Command{d.Body}, body)
	x.frames = x.frames[:len(x.frames)-1]
	for _, r := range f.returns {
		*sc = sc.union(r) // the paths return leaves meet after the call
	}
	for n, v := range f.saved {
		sc.setVar(n, v)
	}
}

// vloop is a loop being read: the paths its breaks and continues leave.
type vloop struct {
	env           *ExecutionEnvironment
	breaks, conts []reach
}

// jump is what a simple command of kind k (jumpOf), run in env, does to
// the paths: break N and continue N leave the Nth loop of env around it
// in the function being read, return the call, exit the script; what the
// command runs (jumpMay) may leave each of them, and the path goes on.
func (x *visibility) jump(k jumpKind, n int, sc *reach, env *ExecutionEnvironment) {
	least := 0
	var fr *callFrame
	if len(x.frames) > 0 {
		fr = x.frames[len(x.frames)-1]
		least = fr.loops // a break in a function's body leaves no loop around the call (bash 5.3)
	}
	var around []*vloop // the innermost first
	for i := len(x.loops) - 1; i >= least; i-- {
		if x.loops[i].env == env {
			around = append(around, x.loops[i])
		}
	}
	switch k {
	case jumpMay:
		for _, l := range around {
			l.breaks = append(l.breaks, sc.clone())
			l.conts = append(l.conts, sc.clone())
		}
		if fr != nil && fr.env == env {
			fr.returns = append(fr.returns, sc.clone())
		}
	case jumpReturn:
		if fr == nil || fr.env != env {
			return // an error to bash outside a function, and a subshell's own
		}
		fr.returns = append(fr.returns, sc.clone())
		sc.ended = true
	case jumpBreak, jumpContinue:
		if n < 0 {
			n = len(around) // a number not known: the outermost
		}
		if len(around) == 0 || n < 1 {
			return // an error to bash: the path goes on
		}
		l := around[min(n, len(around))-1]
		if k == jumpBreak {
			l.breaks = append(l.breaks, sc.clone())
		} else {
			l.conts = append(l.conts, sc.clone())
		}
		sc.ended = true
	case jumpExit:
		sc.ended = true
	}
}
