package shell

import (
	"maps"
	"slices"
	"strconv"
	"strings"
)

// readFlow reads sc, the tree of script, once with the reading of
// descriptors, carrying with the descriptors what reaches each command of
// the variables and the definitions of functions (reach), and records
// where each is read: the paths are those the descriptors are read on
// (if, && and ||, the rounds of loops, break, continue, return and exit,
// a redirect that fails, the shells of subshells, and the bodies of
// functions where each call runs them), so that the values and the
// descriptors are read on the same paths. A body never called is read
// where it is defined, after the script, giving nothing back.
func readFlow(script string, sc *Script) *NameVisibility {
	return readFlowOf(script, sc, true)
}

// readFlowOf is readFlow; with vars false, it records the definitions each
// call may run (Functions, Calls) and not what reaches the reads of
// variables, which takes a copy of the variables at each command.
func readFlowOf(script string, sc *Script, vars bool) *NameVisibility {
	v := &NameVisibility{reads: map[int]map[string][]*Assignment{}, cmds: map[int]map[string][]*Assignment{}, funcs: map[int]map[string][]*FuncDef{}, calls: map[*FuncDef][]*Simple{}}
	r := newFdReading(script)
	r.rec = &flowRecorder{v: v, canon: map[assignKey]*Assignment{}, early: map[int]bool{}, applied: map[*Simple]int{}, memo: map[*FuncDef][]flowMemo{}, noVars: !vars, unreachedReads: map[unreachedKey]bool{}, loops: map[loopRoundsKey][]loopRounds{}, recurIn: map[*FuncDef]pathEnd{}, recurOut: map[*FuncDef]pathEnd{}}
	v.contexts = map[string]callContext{"": 0}
	v.aliases = map[string]string{}
	v.ctxReads = map[callContext]map[int]map[string][]*Assignment{}
	r.vis = v
	r.vars = reach{vars: map[string][]*Assignment{}, funcs: map[string][]*FuncDef{}}
	r.notReadCalls = &v.notRead
	Walk(script, sc.List, Enclosing{}, Visitor{Descriptors: &DescriptorReading{reading: r}})
	for _, d := range r.rec.defs {
		if len(v.calls[d.def]) == 0 {
			r.flowAtDefinition(d)
		}
	}
	return v
}

// flowRecorder is what a reading that records (fdReading.rec) keeps: the
// record, and where the reading is in the commands that assign.
type flowRecorder struct {
	v      *NameVisibility
	noVars bool                      // what reaches the reads of variables is not recorded (readFlowOf)
	canon  map[assignKey]*Assignment // one Assignment for one assignment, however often it is read
	early  map[int]bool              // the parameters of the words of for and select, and of the targets of a compound command's redirects, read before it
	stack  []Command                 // the commands being read, the innermost last
	// words: the commands of assignment words alone being read, and how
	// many of their words are done (a=1 b=$a)
	words []flowWords
	// pending: the assignments of ${NAME:=value} whose words are being read
	pending []flowPending
	// applied: how many redirects of a simple command being read are done:
	// bash performs each before it expands the target of the next
	applied map[*Simple]int
	// locals: the calls of functions being read, with the names their
	// bodies made local, as they were before
	locals []flowLocal
	defs   []defined // the definitions, where they are made, for the bodies never called
	// chain: the calls whose bodies are being read, the innermost last, by
	// their keys (contextKey); ctx, the context of the innermost
	chain []string
	ctx   callContext
	// memo: for each definition, the states its bodies were read from
	// and where they left them, and the context of that reading
	memo map[*FuncDef][]flowMemo
	// unreachedReads are the reads recorded where no path reached them, which
	// a later visit replaces
	unreachedReads map[unreachedKey]bool
	// loops: for each loop and its shell, the states its rounds were read
	// from and where the rounds start after them (flowLoopKeep)
	loops map[loopRoundsKey][]loopRounds
	// recurIn: for each definition being read, what reaches its calls that
	// its body made and that were cut (a recursion); recurOut, where its
	// body left the paths when read last
	recurIn  map[*FuncDef]pathEnd
	recurOut map[*FuncDef]pathEnd
}

// loopRoundsKey is a loop in a shell.
type loopRoundsKey struct {
	c   *Compound
	env *ExecutionEnvironment
}

// loopRounds is a state a loop was reached in, and where its rounds start
// after they were read from it.
type loopRounds struct{ in, start pathEnd }

// flowMemo is a body read from in, which left the paths out, in the
// context ctx under the key key.
type flowMemo struct {
	call *Simple // the call, when it assigns before its command word
	// recorded: the body was read where the reading records (not in a
	// round read ahead), so its reads are in the record
	recorded bool
	in       pathEnd
	out      []pathEnd
	key      string
}

// callContext is a chain of calls whose bodies a reading read, the first
// the outermost: 0 is the script itself.
type callContext int

// contextKey is the key of the call x inside the chain whose key is
// outer.
func contextKey(outer string, x *Simple) string {
	return outer + "," + strconv.Itoa(x.Span().Start)
}

// contextOf is the context of the chain of calls, the outermost first, or
// -1 when the reading did not read it.
func (v *NameVisibility) contextOf(chain []*Simple) callContext {
	k := ""
	for _, x := range chain {
		k = contextKey(k, x)
		if a, ok := v.aliases[k]; ok {
			k = a
		}
	}
	if c, ok := v.contexts[k]; ok {
		return c
	}
	return -1
}

// reachingIn is Reaching for the read at at in the context ctx: what
// reaches it where the calls of ctx run it, or, when that is not known,
// Reaching.
func (v *NameVisibility) reachingIn(ctx callContext, n VarName, at Span) []Assignment {
	if set, ok := v.ctxReads[ctx][at.Start][n.String()]; ok && ctx > 0 {
		out := make([]Assignment, 0, len(set))
		for _, a := range set {
			out = append(out, *a)
		}
		return out
	}
	return v.Reaching(n, at)
}

type flowWords struct {
	c    *Simple
	as   []Word
	done int
	at   Enclosing
}

type flowPending struct {
	a   *Assignment
	end int
}

type flowLocal struct {
	env   *ExecutionEnvironment
	saved map[string][]*Assignment // the values the names had before the body made them local, on the paths that did
	outer map[string]bool          // the names the call's caller had made local (reach.locals)
}

// carried is what of the variables and the definitions reaches the command
// being read, for a path end: a copy, or nothing when the reading does not
// record.
func (w *fdReading) carried() reach {
	if w.rec == nil {
		return reach{}
	}
	return w.vars.clone()
}

// restoreVars makes what reaches the command being read that of the path
// end p, when the reading records.
func (w *fdReading) restoreVars(p pathEnd) {
	if w.rec != nil {
		w.vars = p.vars.clone()
	}
}

// union is acc with what v has too; v alone when first.
func (r *flowRecorder) union(acc, v reach, first bool) reach {
	if first {
		return v.clone()
	}
	return acc.union(v)
}

// flowDefs are the definitions the name n may call where the command being
// read is, and whether no definition reaches it on some path.
func (w *fdReading) flowDefs(n string) (defs []*FuncDef, undefined bool) {
	for _, d := range w.vars.funcs[n] {
		if d == nil {
			undefined = true
		} else {
			defs = append(defs, d)
		}
	}
	return defs, undefined && len(defs) > 0
}

// updateVars changes, by f, what reaches the shell env: the command being
// read's, or the one kept for env.
func (w *fdReading) updateVars(env *ExecutionEnvironment, f func(*reach)) {
	if env == w.env {
		f(&w.vars)
		return
	}
	st := w.stateOf(env)
	f(&st.vars)
	w.envs[env] = st
}

// record keeps what reaches the simple command at start: the map of sc,
// which sc copies before its next change, at the first visit; after it,
// the union of the visits.
func (r *flowRecorder) record(start int, sc *reach) {
	if r.noVars {
		return
	}
	if _, ok := r.v.cmds[start]; !ok {
		r.v.cmds[start], sc.kept = sc.vars, true
		return
	}
	if r.v.cmdsMore == nil {
		r.v.cmdsMore = map[int][]map[string][]*Assignment{}
	}
	r.v.cmdsMore[start], sc.kept = append(r.v.cmdsMore[start], sc.vars), true // joined when read (Reaching)
}

// read keeps that the parameter at start reads n where sc reaches, for
// every context and for the context being read.
func (r *flowRecorder) read(start int, n string, sc *reach) {
	if r.noVars {
		return
	}
	if r.v.reads[start] == nil {
		r.v.reads[start] = map[string][]*Assignment{}
	}
	r.v.reads[start][n] = r.visit(r.v.reads[start], start, n, sc.vars[n], 0)
	if r.ctx > 0 {
		m := r.ctxReads()
		if m[start] == nil {
			m[start] = map[string][]*Assignment{}
		}
		m[start][n] = r.visit(m[start], start, n, sc.vars[n], r.ctx)
	}
}

// visit is what reaches the read of n at start, in the reads m of the
// context ctx, with the visit as: the first visit's, or the union of the
// visits (unionBefore), a visit where only no path reached giving nothing.
func (r *flowRecorder) visit(m map[string][]*Assignment, start int, n string, as []*Assignment, ctx callContext) []*Assignment {
	cur, seen := m[n]
	k := unreachedKey{start, n, ctx}
	if r.unreachedReads[k] {
		seen = false
		delete(r.unreachedReads, k)
	}
	if !seen {
		return as
	}
	return unionBefore(cur, as, n)
}

// unreachedKey is a read of n at start in the context ctx.
type unreachedKey struct {
	start int
	n     string
	ctx   callContext
}

// ctxReads are the reads of the context being read.
func (r *flowRecorder) ctxReads() map[int]map[string][]*Assignment {
	m := r.v.ctxReads[r.ctx]
	if m == nil {
		m = map[int]map[string][]*Assignment{}
		r.v.ctxReads[r.ctx] = m
	}
	return m
}

// unreached keeps that the parameter at start reads n where no path
// reaches, so that Reaching does not take what reaches a command before it.
func (r *flowRecorder) unreached(start int, n string) {
	if r.v.reads[start] == nil {
		r.v.reads[start] = map[string][]*Assignment{}
	}
	if _, ok := r.v.reads[start][n]; !ok {
		r.v.reads[start][n] = nil
		r.unreachedReads[unreachedKey{start, n, 0}] = true
	}
	if r.ctx > 0 {
		m := r.ctxReads()
		if m[start] == nil {
			m[start] = map[string][]*Assignment{}
		}
		if _, ok := m[start][n]; !ok {
			m[start][n] = nil
			r.unreachedReads[unreachedKey{start, n, r.ctx}] = true
		}
	}
}

// mk is the one Assignment of what a describes.
func (r *flowRecorder) mk(a Assignment) *Assignment {
	k := assignKey{a.At, a.Name.String(), a.Local, a.Unset, a.Value != nil}
	if c, ok := r.canon[k]; ok {
		return c
	}
	c := &a
	r.canon[k] = c
	return c
}

func (w *fdReading) assign(sc *reach, a *Assignment) {
	sc.setVar(a.Name.String(), []*Assignment{w.rec.mk(*a)})
}

// appendTo adds a to what reaches its name: an element of an array, whose
// other elements stay, or ${NAME:=value}, which keeps a value the name has.
func (w *fdReading) appendTo(sc *reach, a *Assignment) {
	n := a.Name.String()
	old, ok := sc.vars[n]
	if !ok {
		old = withBefore(nil, n)
	}
	sc.setVar(n, unionAssign(old, []*Assignment{w.rec.mk(*a)}))
}

// local makes the name n local to the function being read in env: its
// value before is given back when the call returns.
func (w *fdReading) local(sc *reach, n string, env *ExecutionEnvironment) {
	l := w.rec.locals
	if len(l) == 0 || l[len(l)-1].env != env {
		return // a subshell's own: it ends with the subshell
	}
	f := &l[len(l)-1]
	if all, ok := sc.locals[n]; ok && all {
		return // made local on this path already: the value before it is saved
	}
	if old, ok := f.saved[n]; ok {
		f.saved[n] = unionBefore(old, sc.vars[n], n)
	} else {
		f.saved[n] = sc.vars[n]
	}
	if sc.locals == nil {
		sc.locals = map[string]bool{}
	}
	sc.locals[n] = true
}

func (w *fdReading) assignWord(sc *reach, wd *Word, c *Simple, at Enclosing, local bool) {
	n, value, element, ok := AssignedName(w.s, *wd)
	if !ok {
		return
	}
	a := &Assignment{Name: VarName{n}, At: wd.Span, Value: valueWord(*wd, value), Append: element || w.s[value-2] == '+', Func: at.Func, Local: local, Env: at.Env, By: c}
	if element {
		w.appendTo(sc, a) // an element leaves the others as they were
		return
	}
	// NAME+=value too: its value is what reached and value after it; what
	// reached is read through Bases, not as a value of NAME after it
	w.assign(sc, a)
}

// flowDescriptors assigns the names of the {name} redirects rs of the
// command by (nil for a compound command, whose redirects are done before
// its body and whose targets' parameters are read here); >&- and <&- close
// the descriptor the name holds and assign nothing.
func (w *fdReading) flowDescriptors(sc *reach, rs []Redirect, by *Simple, at Enclosing) {
	rec := w.rec
	for i := range rs {
		r := &rs[i]
		if by == nil && w.dry == 0 {
			for _, p := range PartParams(r.Target.Parts) {
				rec.read(p.Span.Start, p.Name.String(), sc)
				rec.early[p.Span.Start] = true
			}
		}
		n := r.Var.String()
		if n == "" {
			continue
		}
		if w.dry == 0 {
			// what reaches the redirect, before it assigns: the descriptor
			// {name}>&- closes is the one name holds there
			rec.read(r.Span.Start, n, sc)
		}
		if !closesVar(w.s, r) {
			w.assign(sc, &Assignment{Name: r.Var, At: r.Span, Func: at.Func, Env: at.Env, By: by, Descriptor: true})
		}
	}
}

// flowFlush makes the assignments of ${NAME:=value} whose words end at or
// before at, an inner ${ } first.
func (w *fdReading) flowFlush(at int) {
	r := w.rec
	slices.SortStableFunc(r.pending, func(a, b flowPending) int { return a.end - b.end })
	for len(r.pending) > 0 && r.pending[0].end <= at {
		a := r.pending[0].a
		w.updateVars(a.Env, func(sc *reach) { w.appendTo(sc, a) })
		r.pending = r.pending[1:]
	}
}

// flowEnter is what the reading records of the command c, at, before what
// is in it is read.
func (w *fdReading) flowEnter(c Command, at Enclosing) {
	r := w.rec
	r.stack = append(r.stack, c)
	switch x := c.(type) {
	case *Simple:
		if !w.ended && w.dry == 0 {
			r.record(x.span.Start, &w.vars)
		}
		if len(x.Words) == 0 {
			r.words = append(r.words, flowWords{c: x, as: x.Assigns, at: at})
		}
	case *Compound:
		if !w.ended && (x.Kind == CompoundFor || x.Kind == CompoundSelect) {
			w.flowLoopVar(x, at) // the round read, after the rounds read ahead
		}
	}
}

// flowCompound reads, before the compound command x at and the rounds of a
// loop read ahead, the {name} of its redirects and the words of for and
// select, which bash expands before the body.
func (w *fdReading) flowCompound(x *Compound, at Enclosing) {
	if w.ended {
		return
	}
	w.flowDescriptors(&w.vars, x.Redirects, nil, at)
	if x.Kind != CompoundFor && x.Kind != CompoundSelect {
		return
	}
	for i := range x.In {
		for _, p := range PartParams(x.In[i].Parts) {
			if w.dry == 0 {
				w.rec.read(p.Span.Start, p.Name.String(), &w.vars)
			}
			w.rec.early[p.Span.Start] = true
		}
	}
}

// flowLoopVar assigns the name of the for or select x at the start of a
// round: one of the words after in, or, with no in, a value the script
// does not write ("$@").
func (w *fdReading) flowLoopVar(x *Compound, at Enclosing) {
	if x.Var == nil || x.Kind != CompoundFor && x.Kind != CompoundSelect {
		return
	}
	n, ok := literalOf(w.s, *x.Var)
	if !ok || !isName(n) {
		return
	}
	var as []*Assignment
	if !x.HasIn {
		as = append(as, w.rec.mk(Assignment{Name: VarName{n}, At: x.Var.Span, Func: at.Func, Env: at.Env}))
	}
	for i := range x.In {
		as = append(as, w.rec.mk(Assignment{Name: VarName{n}, At: x.In[i].Span, Value: &x.In[i], Func: at.Func, Env: at.Env}))
	}
	if len(as) > 0 {
		w.vars.setVar(n, as)
	}
}

// flowDefine makes the definition x, at, the one its name calls, and keeps
// where it is made, for a body never called.
func (w *fdReading) flowDefine(x *FuncDef, at Enclosing) {
	if w.ended {
		return
	}
	n, ok := literalOf(w.s, x.Name)
	if !ok {
		return
	}
	w.vars.funcs[n] = []*FuncDef{x}
	if w.dry == 0 {
		w.rec.defs = append(w.rec.defs, defined{def: x, at: at, sc: w.vars.clone()})
	}
}

// flowRedirect is what the redirect r, at, assigns before the targets
// after it are read.
func (w *fdReading) flowRedirect(r *Redirect, at Enclosing) {
	w.switchTo(at.Env)
	rec := w.rec
	if w.ended || len(rec.stack) == 0 {
		return
	}
	if k, ok := rec.stack[len(rec.stack)-1].(*Compound); ok {
		if (k.Kind == CompoundSubshell || k.Kind == CompoundCoproc) && len(k.Redirects) > 0 && r == &k.Redirects[0] {
			w.flowDescriptors(&w.vars, k.Redirects, nil, at) // the subshell's own, before its body
		}
		return
	}
	c, ok := rec.stack[len(rec.stack)-1].(*Simple)
	if !ok {
		return
	}
	for i := range c.Redirects {
		if &c.Redirects[i] == r && i > rec.applied[c] {
			w.flowDescriptors(&w.vars, c.Redirects[rec.applied[c]:i], c, at)
			rec.applied[c] = i
		}
	}
}

// flowPart is what the part p, at, reads and assigns: the assignment words
// before it of a command of assignments alone, the parameter it reads, and
// a ${NAME:=value}, assigned after its words.
func (w *fdReading) flowPart(p *Part, at Enclosing) {
	w.switchTo(at.Env)
	r := w.rec
	if w.ended {
		if (p.Kind == PartParam || p.Kind == PartParamOp) && w.dry == 0 {
			r.unreached(p.Span.Start, p.Name.String()) // no path reaches it: nothing reaches the read
		}
		return
	}
	w.flowFlush(p.Span.Start)
	if n := len(r.words); n > 0 {
		fw := &r.words[n-1]
		for fw.done < len(fw.as) && fw.as[fw.done].Span.End <= p.Span.Start {
			wd := &fw.as[fw.done]
			w.updateVars(fw.at.Env, func(sc *reach) { w.assignWord(sc, wd, fw.c, fw.at, false) })
			fw.done++
		}
	}
	if p.Kind != PartParam && p.Kind != PartParamOp {
		return
	}
	if w.dry == 0 && !r.early[p.Span.Start] {
		r.read(p.Span.Start, p.Name.String(), &w.vars)
	}
	if e := p.Param; e != nil && e.Op == ParamOpAssign && e.Prefix == ParamPrefixNone && e.All == ParamAllNone && isName(e.Name.String()) {
		var by *Simple
		if len(r.stack) > 0 {
			by, _ = r.stack[len(r.stack)-1].(*Simple)
		}
		r.pending = append(r.pending, flowPending{a: &Assignment{Name: e.Name, At: p.Span, Value: &e.Words[0], Append: e.Subscript != nil, Func: at.Func, Env: at.Env, By: by}, end: p.Span.End})
	}
}

// flowLeave is what the command c, at, assigns after what is in it is read.
func (w *fdReading) flowLeave(c Command, at Enclosing) {
	r := w.rec
	r.stack = r.stack[:len(r.stack)-1]
	done := 0
	x, simple := c.(*Simple)
	if simple && len(x.Words) == 0 {
		done = r.words[len(r.words)-1].done
		r.words = r.words[:len(r.words)-1]
	}
	if w.ended {
		return
	}
	w.flowFlush(c.Span().End)
	switch y := c.(type) {
	case *Simple:
		w.flowSimple(y, at, done, r.applied[y])
		delete(r.applied, y)
	case *Compound:
		if y.Kind == CompoundCoproc {
			name := "COPROC"
			if y.Name != nil {
				if n, ok := literalOf(w.s, *y.Name); ok {
					name = n
				} else {
					name = ""
				}
			}
			if name != "" {
				w.assign(&w.vars, &Assignment{Name: VarName{name}, At: y.span, Env: at.Env, Func: at.Func})
				w.assign(&w.vars, &Assignment{Name: VarName{name + "_PID"}, At: y.span, Env: at.Env, Func: at.Func})
			}
		}
	}
}

// flowCall is what the call x of d, at, does before the body: the
// assignments before its command word, local to the body, and the record
// of the call.
func (w *fdReading) flowCall(d *FuncDef, x *Simple, at Enclosing) {
	r := w.rec
	if w.dry == 0 {
		r.v.calls[d] = unionOf(r.v.calls[d], []*Simple{x})
	}
	r.locals = append(r.locals, flowLocal{env: at.Env, saved: map[string][]*Assignment{}, outer: w.vars.locals})
	w.vars.locals = nil
	r.enter(x)
	for i := range x.Assigns {
		// bash refuses an element of an array before a command word
		if n, _, element, ok := AssignedName(w.s, x.Assigns[i]); ok && !element {
			w.local(&w.vars, n, at.Env)
			w.assignWord(&w.vars, &x.Assigns[i], x, at, false)
		}
	}
}

// flowReturn gives back, at the ends of a call's body, the names the body
// made local.
func (w *fdReading) flowReturn(ends []pathEnd) {
	r := w.rec
	l := r.locals[len(r.locals)-1]
	r.locals = r.locals[:len(r.locals)-1]
	r.leave()
	for i := range ends {
		e := &ends[i].vars
		for n, v := range l.saved {
			switch all, ok := e.locals[n]; {
			case !ok: // not made local on this path
			case all:
				e.setVar(n, v)
			default: // made local on some of the paths joined into this one
				e.setVar(n, unionBefore(e.vars[n], v, n))
			}
		}
		e.locals = maps.Clone(l.outer)
	}
}

// flowAtDefinition reads the body of a definition no call reads where it
// is defined, with what reached it there, giving nothing back.
func (w *fdReading) flowAtDefinition(d defined) {
	if w.calls >= maxCalls {
		if !w.rec.v.notRead.OK {
			w.rec.v.notRead.Add(d.def.Span())
		}
		return
	}
	w.calls++
	w.switchTo(d.at.Env)
	saved := fdEnv{w.fds, w.ended, w.vars}
	w.vars, w.ended = d.sc.clone(), false
	ret := &paths{env: d.at.Env, scopes: len(w.scopes), loops: len(w.loops)}
	w.rets = append(w.rets, ret)
	w.rec.locals = append(w.rec.locals, flowLocal{env: d.at.Env, saved: map[string][]*Assignment{}, outer: w.vars.locals})
	w.inFunc++
	w.callingDefs[d.def] = true
	body := inside(d.at)
	body.Func = d.def
	(&walker{s: w.s, r: w}).command(d.def.Body, body)
	w.callingDefs[d.def] = false
	w.inFunc--
	w.rec.locals = w.rec.locals[:len(w.rec.locals)-1]
	w.rets = w.rets[:len(w.rets)-1]
	w.switchTo(d.at.Env)
	w.fds, w.ended, w.vars = saved.fds, saved.ended, saved.vars
}

// flowSimple is what the simple command c, at, assigns and defines after
// its words are read, and the {name} of its redirects past the first
// redirectsDone; its call of a function is read by walker.call.
func (w *fdReading) flowSimple(c *Simple, at Enclosing, done, redirectsDone int) {
	r := w.rec
	w.flowDescriptors(&w.vars, c.Redirects[redirectsDone:], c, at)
	var words []string
	as, wordsAt := c.Assigns, c.Words
	for _, wd := range wordsAt {
		n, _ := literalOf(w.s, wd)
		words = append(words, n) // "" where not literal
	}
	prefixed := false
	for len(words) > 1 && (words[0] == "builtin" || words[0] == "command") && !strings.HasPrefix(words[1], "-") {
		words, wordsAt, prefixed = words[1:], wordsAt[1:], true // the builtin or the program it runs, never a function
	}
	if w.dry == 0 && len(words) > 0 && words[0] != "" {
		f := r.v.funcs[c.span.Start]
		if f == nil {
			f = map[string][]*FuncDef{}
			r.v.funcs[c.span.Start] = f
		}
		f[words[0]] = unionOf(f[words[0]], w.vars.funcs[words[0]])
	}
	if len(wordsAt) == 0 {
		for i := range as {
			// those a later word's read did not do already; with no command,
			// bash assigns after the redirects, so an assignment of a name a
			// {name} redirect assigns is done again (fd=3 {fd}>f leaves fd=3)
			if n, _ := assignedName(w.s, as[i]); i >= done || n != "" && slices.ContainsFunc(c.Redirects, func(rd Redirect) bool { return rd.Var.String() == n && !closesVar(w.s, &rd) }) {
				w.assignWord(&w.vars, &as[i], c, at, false)
			}
		}
		return
	}
	saved := w.cmd
	w.cmd = c
	may, every := mayFail(w.table(c.Redirects))
	w.cmd = saved
	if every {
		return // a redirect fails on every path: bash runs neither the builtin nor the function
	}
	if may {
		// on the paths where its redirect fails, bash runs neither
		before := w.vars.clone()
		defer func() { w.vars = before.union(w.vars) }()
	}
	if k, _ := jumpOf(w.s, c.Words); k != jumpNone && k != jumpMay {
		return
	}
	if len(words) == 0 || words[0] == "" {
		return
	}
	if defs := w.vars.funcs[words[0]]; len(defs) > 0 && !prefixed {
		return // a call: walker.call reads the bodies
	}
	inFunc := len(r.locals) > 0
	switch words[0] {
	case "export", "readonly", "declare", "typeset", "local":
		if words[0] == "local" && !inFunc {
			return // an error to bash: it assigns nothing
		}
		global := false
		for _, wd := range words[1:] {
			if strings.HasPrefix(wd, "-") && strings.Contains(wd, "g") {
				global = true
			}
			if strings.HasPrefix(wd, "-") && strings.ContainsAny(wd, "pfF") {
				return // prints, or names functions: no variable is declared
			}
		}
		isLocal := inFunc && !global && (words[0] == "local" || words[0] == "declare" || words[0] == "typeset")
		for i := 1; i < len(wordsAt); i++ {
			if strings.HasPrefix(words[i], "-") {
				continue
			}
			if strings.Contains(w.s[wordsAt[i].Span.Start:wordsAt[i].Span.End], "=") {
				if isLocal {
					if n, ok := assignedName(w.s, wordsAt[i]); ok {
						w.local(&w.vars, n, at.Env)
					}
				}
				if n, value, ok := nameParam(w.s, wordsAt[i]); ok {
					// declare "$n=value": an assignment to the name n holds,
					// when n holds one literal name on every path
					if name, ok := literalName(w.s, w.vars.vars[n]); ok {
						if isLocal {
							w.local(&w.vars, name, at.Env)
						}
						w.assign(&w.vars, &Assignment{Name: VarName{name}, At: wordsAt[i].Span, Value: valueWord(wordsAt[i], value), Func: at.Func, Local: isLocal, Env: at.Env, By: c})
					}
					continue
				}
				w.assignWord(&w.vars, &wordsAt[i], c, at, isLocal)
				continue
			}
			if isLocal && words[i] != "" && isName(words[i]) {
				w.local(&w.vars, words[i], at.Env)
				w.assign(&w.vars, &Assignment{Name: VarName{words[i]}, At: wordsAt[i].Span, Func: at.Func, Local: true, Env: at.Env, By: c})
			}
		}
	case "read", "mapfile", "readarray", "printf":
		for _, n := range readNames(words) {
			w.assign(&w.vars, &Assignment{Name: VarName{n}, At: c.span, Func: at.Func, Env: at.Env, By: c})
		}
	case "unset":
		fn := false
		for _, wd := range words[1:] {
			switch {
			case wd == "-f":
				fn = true
			case wd == "-v":
				fn = false
			case strings.HasPrefix(wd, "-"):
			case fn:
				delete(w.vars.funcs, wd)
			case isName(wd):
				un := &Assignment{Name: VarName{wd}, At: c.span, Unset: true, Func: at.Func, Env: at.Env, By: c}
				if v, all, ok := w.callerLocal(wd); ok {
					// a local of a calling function: unset takes it away, and
					// the name holds the value from before that function made
					// it local (bash 5.3.15 and 5.2.37)
					if !all {
						v = unionBefore(v, []*Assignment{w.rec.mk(*un)}, wd)
					}
					w.vars.setVar(wd, v)
					w.framed++
					continue
				}
				w.assign(&w.vars, un)
			}
		}
	}
}

// enter makes the call x the innermost of the chain being read.
func (r *flowRecorder) enter(x *Simple) {
	outer := ""
	if len(r.chain) > 0 {
		outer = r.chain[len(r.chain)-1]
	}
	k := contextKey(outer, x)
	if a, ok := r.v.aliases[k]; ok {
		k = a
	}
	c, ok := r.v.contexts[k]
	if !ok {
		c = callContext(len(r.v.contexts))
		r.v.contexts[k] = c
	}
	r.chain = append(r.chain, k)
	r.ctx = c
}

// leave ends the innermost call of the chain.
func (r *flowRecorder) leave() {
	r.chain = r.chain[:len(r.chain)-1]
	r.ctx = 0
	if n := len(r.chain); n > 0 {
		r.ctx = r.v.contexts[r.chain[n-1]]
	}
}

// flowMemoed is where the paths go after the call x of d, at, when a body
// of d was read from the same state before: that reading's ends, with the
// context of x the context of that reading.
func (w *fdReading) flowMemoed(d *FuncDef, x *Simple) ([]pathEnd, bool) {
	r := w.rec
	in := w.here()
	for _, m := range r.memo[d] {
		if (m.call != nil || len(x.Assigns) > 0) && m.call != x || !m.recorded && w.dry == 0 {
			continue
		}
		if m.in.ended != in.ended || !samePlaces(m.in.fds, in.fds) || !m.in.vars.same(in.vars) {
			continue
		}
		outer := ""
		if len(r.chain) > 0 {
			outer = r.chain[len(r.chain)-1]
		}
		if k := contextKey(outer, x); k != m.key {
			r.v.aliases[k] = m.key
		}
		if w.dry == 0 {
			r.v.calls[d] = unionOf(r.v.calls[d], []*Simple{x})
		}
		pipes := pipesOf(m.in.fds, in.fds)
		out := make([]pathEnd, len(m.out))
		for i, e := range m.out {
			out[i] = pathEnd{pipes.remap(e.fds), e.ended, e.vars.clone()}
		}
		return out, true
	}
	return nil, false
}

// flowKeep keeps, for later calls of d from in, where the body read in the
// context key left the paths.
func (w *fdReading) flowKeep(d *FuncDef, x *Simple, in pathEnd, key string, out []pathEnd) {
	m := flowMemo{in: in, key: key, recorded: w.dry == 0}
	if len(x.Assigns) > 0 {
		m.call = x
	}
	for _, e := range out {
		m.out = append(m.out, pathEnd{maps.Clone(e.fds), e.ended, e.vars.clone()})
	}
	w.rec.memo[d] = append(w.rec.memo[d], m)
}

// samePlaces is sameFds, with the pipe of a command of a pipeline and the
// output of a reading of OutputReading the same place whichever command or
// reading they are of: the body of a function called in each command of
// many pipelines is read once (flowMemoed).
func samePlaces(a, b fdMap) bool {
	if len(a) != len(b) {
		return false
	}
	for fd, ds := range a {
		es, ok := b[fd]
		if !ok || len(ds) != len(es) {
			return false
		}
		for i := range ds {
			d, e := ds[i], es[i]
			d.element, d.output, e.element, e.output = nil, 0, nil, 0
			if !d.same(e) {
				return false
			}
		}
	}
	return true
}

// pipeMap gives the pipes of one reading of a body the commands and the
// readings of another (samePlaces).
type pipeMap struct {
	elements map[*ExecutionEnvironment]*ExecutionEnvironment
	outputs  map[int]int
}

// pipesOf maps the pipes of from to those at the same places of to.
func pipesOf(from, to fdMap) pipeMap {
	m := pipeMap{elements: map[*ExecutionEnvironment]*ExecutionEnvironment{}, outputs: map[int]int{}}
	for fd, ds := range from {
		es := to[fd]
		for i := range ds {
			if i < len(es) && ds[i].element != es[i].element {
				m.elements[ds[i].element] = es[i].element
			}
			if i < len(es) && ds[i].output != es[i].output {
				m.outputs[ds[i].output] = es[i].output
			}
		}
	}
	return m
}

// remap is t with the pipes of m's from as those of its to.
func (m pipeMap) remap(t fdMap) fdMap {
	out := maps.Clone(t)
	if len(m.elements) == 0 && len(m.outputs) == 0 {
		return out
	}
	for fd, ds := range out {
		var nd dests
		for _, d := range ds {
			if e, ok := m.elements[d.element]; ok {
				d.element = e
			}
			if o, ok := m.outputs[d.output]; ok {
				d.output = o
			}
			nd = append(nd, d)
		}
		out[fd] = nd
	}
	return out
}

// flowLoopMemoed is where the rounds of the loop x at start, when a reading
// that records read them before from the state it is reached in: loops
// nested in loops are read a few times each, not to the power of their
// depth, so that the commands the run may read ahead (aheadState) are not
// spent.
func (w *fdReading) flowLoopMemoed(x *Compound, at Enclosing) (pathEnd, bool) {
	if w.rec == nil {
		return pathEnd{}, false
	}
	in := w.here()
	for _, l := range w.rec.loops[loopRoundsKey{x, at.Env}] {
		if l.in.ended == in.ended && sameFds(l.in.fds, in.fds) && l.in.vars.same(in.vars) {
			return l.start, true
		}
	}
	return pathEnd{}, false
}

// flowLoopKeep keeps where the rounds of the loop x at start when read
// whole from in.
func (w *fdReading) flowLoopKeep(x *Compound, at Enclosing, in, start pathEnd) {
	k := loopRoundsKey{x, at.Env}
	w.rec.loops[k] = append(w.rec.loops[k], loopRounds{in, start})
}

// flowRecursion is a call of d, which is being read, that is cut: what
// reaches it reaches the body of d too, and the call may leave the paths
// where the body left them when read last.
func (w *fdReading) flowRecursion(d *FuncDef) {
	r := w.rec
	here := w.here()
	if old, ok := r.recurIn[d]; ok {
		r.recurIn[d] = w.joined(old, here)
	} else {
		r.recurIn[d] = here
	}
	if out, ok := r.recurOut[d]; ok {
		w.meet(here, out)
	}
}

// flowRecursed is, after the body of d was read from entry to the ends
// out, the state to read it from again and whether to: when the body cut
// calls of d, from entry with what reached them, until a reading adds
// nothing. The states only grow, so the readings end; each is a call of
// the run (maxCalls).
func (w *fdReading) flowRecursed(d *FuncDef, entry pathEnd, out []pathEnd) (pathEnd, bool) {
	r := w.rec
	rin, cut := r.recurIn[d]
	delete(r.recurIn, d)
	exit := w.joined(out...)
	prev, had := r.recurOut[d]
	r.recurOut[d] = exit
	if !cut {
		delete(r.recurOut, d)
		return pathEnd{}, false
	}
	next := w.joined(entry, rin)
	if samePlacesEnd(next, entry) && had && samePlacesEnd(prev, exit) {
		delete(r.recurOut, d)
		return pathEnd{}, false
	}
	return next, true
}

// samePlacesEnd is whether a and b are the same state but for the pipes
// of the commands of pipelines: each descriptor points at the same places.
// A recursion through a pipeline or a process substitution makes a pipe
// for each reading of the body, so that the states would grow without end.
func samePlacesEnd(a, b pathEnd) bool {
	return a.ended == b.ended && a.vars.same(b.vars) && placesIn(a.fds, b.fds) && placesIn(b.fds, a.fds)
}

// placesIn is whether each descriptor of a points at no place that it does
// not point at in b, the pipes of the commands of pipelines aside.
func placesIn(a, b fdMap) bool {
	if len(a) != len(b) {
		return false
	}
	for fd, ds := range a {
		es, ok := b[fd]
		if !ok {
			return false
		}
		for _, d := range ds {
			d.element, d.output = nil, 0
			if !slices.ContainsFunc(es, func(e dest) bool {
				e.element, e.output = nil, 0
				return d.same(e)
			}) {
				return false
			}
		}
	}
	return true
}

// sameEnd is whether a and b are the same state.
func sameEnd(a, b pathEnd) bool {
	return a.ended == b.ended && sameFds(a.fds, b.fds) && a.vars.same(b.vars)
}

// callerLocal is, for the name n that the function being read did not make
// local, the value n had before the nearest calling function made it local,
// whether that function made it local on every path, and whether one did.
func (w *fdReading) callerLocal(n string) ([]*Assignment, bool, bool) {
	l := w.rec.locals
	if len(l) == 0 {
		return nil, false, false
	}
	if _, own := w.vars.locals[n]; own {
		return nil, false, false
	}
	for j := len(l) - 1; j >= 1; j-- {
		if all, ok := l[j].outer[n]; ok {
			return l[j-1].saved[n], all, true // frame j's caller is frame j-1
		}
	}
	return nil, false, false
}
