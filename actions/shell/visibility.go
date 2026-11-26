package shell

import (
	"maps"
	"slices"
	"strings"
)

// Assignment is one assignment of a shell variable: its name, the span
// that assigns it (the word NAME=value, the ${NAME:=value}, or the
// command), the word of its value (the parts after the = of NAME=value, the
// word after := or =; nil when it has none the script writes: a value read
// from input (read, mapfile, printf -v, the name of a coproc), a variable a
// function declares with no value, and an unset), whether the value is
// added to the one before (NAME+=value, an element NAME[i]=value), the
// function whose body has it, whether it is local to that function,
// whether it unsets the variable, and the shell it runs in.
type Assignment struct {
	Name   VarName
	At     Span
	Value  *Word
	Append bool
	// Descriptor: the number of the descriptor a {name} redirect opens
	Descriptor bool
	Func       *FuncDef
	Local      bool
	Unset      bool
	Env        *ExecutionEnvironment
	By         *Simple
	// Before: no assignment of the script, on some path to the place: the
	// value the variable has before the script (the step's env, or none).
	Before bool
}

// NameVisibility tells, at a place of a script, which assignments a read
// of a variable may get its value from, and which definitions a command
// name may call (bashref, "Shell Functions": a variable's visibility). It
// answers reaching definitions: on each path to the place, the last
// assignment; at a place many paths reach, the union.
//
// The tree does not keep where the branches of if and case begin, so the
// body of if is read in order, and after it the assignments before it and
// all those of its body reach. A loop's body is read with what reaches
// its start and what the end of each round gives back to its start, until
// a round adds nothing. An element of an array (a[0]=x) adds to what
// reaches its array, whose other elements stay. A command after
// && or || may not run. A subshell (( ... ), a coproc, a command of a
// pipeline but the last with lastpipe, a command ended by &, a
// substitution) starts with what reaches where it starts, and gives
// nothing back. A function's body is read where it is called, with what
// reaches the call (dynamic reach): what it assigns, but to the names it
// declares local, reaches the commands after the call; the assignments
// before the command word of the call are seen by the body only. A body
// never called is read where it is defined, giving nothing back. The
// value of a variable is not read: if false; then s=x; fi reaches as any
// other if. Assignments and definitions whose names are not literal are
// not followed, but declare "$n=value" (and local, export, readonly) where
// n holds one literal name on every path: an assignment to that name.
type NameVisibility struct {
	reads map[int]map[string][]*Assignment // by where a parameter starts
	cmds  map[int]map[string][]*Assignment // by where a simple command starts: what reaches it
	// cmdsMore are, by where a simple command starts, what reached it on
	// the visits after the first (a flow reading keeps each, and Reaching
	// joins them)
	cmdsMore map[int][]map[string][]*Assignment
	funcs    map[int]map[string][]*FuncDef // by where a simple command starts
	calls    map[*FuncDef][]*Simple
	notRead  CallsNotRead
	// contexts are the chains of calls a flow reading (readFlow) read, by
	// their keys (contextKey), and aliases the keys of chains it did not
	// read again, as a call before from the same state was read; ctxReads,
	// for each context, what reaches the reads there
	contexts map[string]callContext
	aliases  map[string]string
	ctxReads map[callContext]map[int]map[string][]*Assignment
}

// Reaching are the assignments that may give its value to the variable n
// read at at: where a parameter at.Start reads it, or else what reaches
// the simple command that starts at at.Start or holds it.
func (v *NameVisibility) Reaching(n VarName, at Span) []Assignment {
	set, ok := v.reads[at.Start][n.String()]
	if !ok {
		best := -1
		for start := range v.cmds {
			if start <= at.Start && start > best {
				best = start
			}
		}
		if best >= 0 {
			set = v.cmds[best][n.String()]
			for _, m := range v.cmdsMore[best] {
				set = unionBefore(set, m[n.String()], n.String())
			}
		}
	}
	out := make([]Assignment, 0, len(set))
	for _, a := range set {
		out = append(out, *a)
	}
	return out
}

// Functions are the definitions a simple command that starts at at.Start
// and names name may call, and whether, with definitions, no definition
// reaches it on some path (if c; then f() { :; }; fi; f), where it runs
// no body.
func (v *NameVisibility) Functions(name string, at Span) (defs []*FuncDef, undefined bool) {
	for _, d := range v.funcs[at.Start][name] {
		if d == nil {
			undefined = true
		} else {
			defs = append(defs, d)
		}
	}
	return defs, undefined && len(defs) > 0
}

// Bases are the assignments that the assignment a, NAME+=value, appends
// its value to: those that reach it (Reaching where it is). Reaching after
// a gives a, not those.
func (v *NameVisibility) Bases(a Assignment) []Assignment {
	if !a.Append {
		return nil
	}
	return v.Reaching(a.Name, a.At)
}

// Calls are the simple commands that call the definition d.
func (v *NameVisibility) Calls(d *FuncDef) []*Simple { return v.calls[d] }

// CallsNotRead is the first call, in the order of the script, whose body
// NameVisibility did not read because it had read the bodies of
// maxNameCalls calls (or, when every call was read, the definition of a
// body never called that it did not read). What
// the bodies not read assign and define does not reach the places after
// them.
func (v *NameVisibility) CallsNotRead() CallsNotRead { return v.notRead }

// CallsNotRead is, when OK, the first call (At), in the order of the
// script, whose body a reading of the script did not read because the
// reading had read the bodies of as many calls as its limit
// (maxNameCalls, maxCalls): functions that call others twice make the
// calls exponential in how deep they nest.
type CallsNotRead struct {
	At Span
	OK bool
}

// Add makes n the first of n and the call at.
func (n *CallsNotRead) Add(at Span) {
	if !n.OK || at.Start < n.At.Start {
		n.At, n.OK = at, true
	}
}

// Join makes n the first of n and o.
func (n *CallsNotRead) Join(o CallsNotRead) {
	if o.OK {
		n.Add(o.At)
	}
}

// scope is what reaches, in one shell: by the name of each variable, and
// by the name of each function.
type reach struct {
	vars  map[string][]*Assignment
	funcs map[string][]*FuncDef
	ended bool // an exit ended the path
	// kept: a record (NameVisibility.cmds) keeps vars too; a change copies
	// vars first
	kept bool
	// locals: for a flow reading, the names the body of the call being
	// read made local on this path: true where it made them local on every
	// path joined into this one, false where on some
	locals map[string]bool
}

// setVar makes as what reaches the name n, or nothing when as is nil.
func (s *reach) setVar(n string, as []*Assignment) {
	if s.kept {
		s.vars, s.kept = maps.Clone(s.vars), false
	}
	if as == nil {
		delete(s.vars, n)
		return
	}
	s.vars[n] = as
}

func (s reach) clone() reach {
	c := reach{vars: make(map[string][]*Assignment, len(s.vars)), funcs: make(map[string][]*FuncDef, len(s.funcs)), ended: s.ended}
	for k, v := range s.vars {
		c.vars[k] = v
	}
	for k, v := range s.funcs {
		c.funcs[k] = v
	}
	c.locals = maps.Clone(s.locals)
	return c
}

// union is s with what t has too. A name one of them has no assignment
// of keeps, on that path, its value from before the script.
func (s reach) union(t reach) reach {
	switch {
	case s.ended:
		return t.clone() // the path of s goes no further
	case t.ended:
		return s.clone()
	}
	c := s.clone()
	for k, v := range t.vars {
		if _, ok := s.vars[k]; !ok {
			c.vars[k] = withBefore(c.vars[k], k)
		}
		c.vars[k] = unionAssign(c.vars[k], v)
	}
	for k := range s.vars {
		if _, ok := t.vars[k]; !ok {
			c.vars[k] = withBefore(c.vars[k], k)
		}
	}
	for k, v := range t.funcs {
		if _, ok := s.funcs[k]; !ok {
			c.funcs[k] = unionOf(c.funcs[k], []*FuncDef{nil}) // not defined on the path of s
		}
		c.funcs[k] = unionOf(c.funcs[k], v)
	}
	for k := range s.funcs {
		if _, ok := t.funcs[k]; !ok {
			c.funcs[k] = unionOf(c.funcs[k], []*FuncDef{nil})
		}
	}
	c.locals = joinLocals(s.locals, t.locals)
	return c
}

// joinLocals are the names made local on the paths of a and b: on every
// path where both make a name local on every path, else on some.
func joinLocals(a, b map[string]bool) map[string]bool {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := map[string]bool{}
	for k, all := range a {
		out[k] = all && b[k]
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out[k] = false
		}
	}
	return out
}

// unionBefore is the union of what reaches a name n on two visits, a and
// b: a visit no assignment reaches gives the value from before the script.
func unionBefore(a, b []*Assignment, n string) []*Assignment {
	switch {
	case len(a) == 0 && len(b) == 0:
		return nil
	case len(a) == 0:
		return withBefore(b, n)
	case len(b) == 0:
		return withBefore(a, n)
	}
	return unionAssign(a, b)
}

// withBefore is as with the value from before the script, once.
func withBefore(as []*Assignment, name string) []*Assignment {
	for _, a := range as {
		if a.Before {
			return as
		}
	}
	return append(append([]*Assignment(nil), as...), &Assignment{Name: VarName{name}, Before: true})
}

// unionOf is a with the elements of b it does not have, in order: a
// itself, clipped so that an append copies it, when it has them all. With
// many elements it looks them up in a set, so that the union of the
// assignments many paths give a name does not take the square of their
// number, nor copy them each time.
func unionOf[T comparable](a, b []T) []T {
	if len(b) == 0 || len(b) <= len(a) && &a[0] == &b[0] {
		return slices.Clip(a) // b is a, or the start of a: the paths share their assignments
	}
	var add []T
	if len(b) > 8 {
		seen := make(map[T]bool, len(a))
		for _, x := range a {
			seen[x] = true
		}
		for _, x := range b {
			if !seen[x] {
				seen[x] = true
				add = append(add, x)
			}
		}
	} else {
		for _, x := range b {
			// from the end: what is added last is met most
			found := false
			for i := len(a) - 1; i >= 0 && !found; i-- {
				found = a[i] == x
			}
			if !found && !slices.Contains(add, x) {
				add = append(add, x)
			}
		}
	}
	if len(add) == 0 {
		return slices.Clip(a)
	}
	return append(append(make([]T, 0, len(a)+len(add)), a...), add...)
}

// assignKey tells one assignment from another.
type assignKey struct {
	at                   Span
	name                 string
	local, unset, valued bool
}

// defined is a definition, where it is made, for a body never called.
type defined struct {
	def *FuncDef
	at  Enclosing
	sc  reach
}

// NewNameVisibility reads the script sc of script: the flow reading
// (readFlow), which reads the variables and the definitions on the paths
// the descriptors are read on.
func NewNameVisibility(script string, sc *Script) *NameVisibility {
	return readFlow(script, sc)
}

// unionAssign is the union of a and b, with the value from before the
// script once.
func unionAssign(a, b []*Assignment) []*Assignment {
	before := slices.ContainsFunc(a, func(x *Assignment) bool { return x.Before })
	if before && slices.ContainsFunc(b, func(x *Assignment) bool { return x.Before }) {
		b = slices.DeleteFunc(slices.Clone(b), func(x *Assignment) bool { return x.Before })
	}
	return unionOf(a, b)
}

// same is whether s and t have the same assignments and definitions.
func (s reach) same(t reach) bool {
	if s.ended != t.ended || len(s.vars) != len(t.vars) || len(s.funcs) != len(t.funcs) || !maps.Equal(s.locals, t.locals) {
		return false
	}
	for k, a := range s.vars {
		b, ok := t.vars[k]
		if !ok || !sameSet(a, b, func(a *Assignment) bool { return a.Before }) {
			return false
		}
	}
	for k, a := range s.funcs {
		b, ok := t.funcs[k]
		if !ok || !sameSet(a, b, func(*FuncDef) bool { return false }) {
			return false
		}
	}
	return true
}

// sameSet is whether a and b have the same elements, the ones before
// tells being one element. It takes time in the length of a and b: the
// rounds of a loop compare the assignments of every name.
func sameSet[T comparable](a, b []T, before func(T) bool) bool {
	set := func(xs []T) (map[T]bool, bool) {
		m := make(map[T]bool, len(xs))
		any := false
		for _, x := range xs {
			if before(x) {
				any = true
			} else {
				m[x] = true
			}
		}
		return m, any
	}
	ma, ba := set(a)
	mb, bb := set(b)
	if ba != bb || len(ma) != len(mb) {
		return false
	}
	for x := range ma {
		if !mb[x] {
			return false
		}
	}
	return true
}

// readNames are the names read, mapfile, readarray and printf -v assign.
func readNames(words []string) []string {
	var out []string
	switch words[0] {
	case "printf":
		for i := 1; i+1 < len(words); i++ {
			if words[i] == "-v" && isName(words[i+1]) {
				out = append(out, words[i+1])
			}
		}
	case "read":
		for i := 1; i < len(words); i++ {
			w := words[i]
			switch {
			case strings.HasPrefix(w, "-") && strings.HasSuffix(w, "a") && i+1 < len(words):
				out = append(out, words[i+1])
				i++
			case strings.HasPrefix(w, "-") && len(w) > 1 && strings.ContainsAny(w[len(w)-1:], "pdnNtui"):
				i++ // the option's value, also after others in one word (-rp prompt)
			case strings.HasPrefix(w, "-"):
			case isName(w):
				out = append(out, w)
			}
		}
		if len(out) == 0 {
			out = []string{"REPLY"}
		}
	default: // mapfile, readarray
		name := "MAPFILE"
		for i := 1; i < len(words); i++ {
			w := words[i]
			switch {
			case w == "-d" || w == "-n" || w == "-O" || w == "-s" || w == "-u" || w == "-C" || w == "-c":
				i++
			case strings.HasPrefix(w, "-"):
			case isName(w):
				name = w
			}
		}
		out = []string{name}
	}
	return out
}

// assignedName is the name of the assignment word w when it is literal.
func assignedName(s string, w Word) (string, bool) {
	n, _, _, ok := AssignedName(s, w)
	return n, ok
}

// AssignedName is the name of the assignment word w of script, when it is
// literal: NAME=value, NAME+=value, or an element of an array,
// NAME[subscript]=value or += (bashref, "Arrays"); with where its value
// starts, and whether it assigns an element.
func AssignedName(script string, w Word) (name string, value int, element, ok bool) {
	text := script[w.Span.Start:w.Span.End]
	n := 0
	for n < len(text) && isNameByte(text[n]) {
		n++
	}
	if n == 0 || !isNameStart(text[0]) || n == len(text) || len(w.Parts) == 0 || w.Parts[0].Kind != PartLiteral || w.Parts[0].Quote != QuoteNone || w.Parts[0].Span.End <= w.Span.Start+n {
		return "", 0, false, false
	}
	switch {
	case text[n] == '=':
		return text[:n], w.Span.Start + n + 1, false, true
	case strings.HasPrefix(text[n:], "+="):
		return text[:n], w.Span.Start + n + 2, false, true
	case text[n] == '[':
		end, op := strings.Index(text, "]="), 2
		if plus := strings.Index(text, "]+="); plus >= 0 && (end < 0 || plus < end) {
			end, op = plus, 3
		}
		if end > n {
			return text[:n], w.Span.Start + end + op, true, true
		}
	}
	return "", 0, false, false
}

// nameParam is the parameter n of the declaration word w of script when w
// is "$n=value" (or $n=, ${n}=): bash assigns value to the variable whose
// name is the value of n; with where value starts.
func nameParam(script string, w Word) (n string, value int, ok bool) {
	if len(w.Parts) < 2 || w.Parts[0].Kind != PartParam || !isName(w.Parts[0].Name.String()) {
		return "", 0, false
	}
	l := w.Parts[1]
	if l.Kind != PartLiteral || l.Span.Start != w.Parts[0].Span.End || !strings.HasPrefix(script[l.Span.Start:l.Span.End], "=") {
		return "", 0, false
	}
	return w.Parts[0].Name.String(), l.Span.Start + 1, true
}

// literalName is the one name that every assignment of as gives as its
// value, a literal word; false when one is the value from before the
// script, appends, unsets, has no value, or the values differ.
func literalName(script string, as []*Assignment) (string, bool) {
	name := ""
	for _, a := range as {
		if a.Before || a.Append || a.Unset || a.Descriptor || a.Value == nil {
			return "", false
		}
		v, ok := literalOf(script, *a.Value)
		if !ok || !isName(v) || (name != "" && v != name) {
			return "", false
		}
		name = v
	}
	return name, name != ""
}

// DeclaredName is the name of the variable the declaration word w of
// script ("$n=value", an argument of declare, local, export or readonly)
// assigns when n has one literal value there, read through v; with where
// value starts.
func (v *NameVisibility) DeclaredName(script string, w Word) (name string, value int, ok bool) {
	n, value, ok := nameParam(script, w)
	if !ok {
		return "", 0, false
	}
	rs := v.Reaching(VarName{n}, Span{Start: w.Parts[0].Span.Start, End: w.Parts[0].Span.Start})
	as := make([]*Assignment, len(rs))
	for i := range rs {
		as[i] = &rs[i]
	}
	if name, ok = literalName(script, as); !ok {
		return "", 0, false
	}
	return name, value, true
}

// valueWord is the word of the value of the assignment word w, whose value
// starts at from: its parts from there on.
func valueWord(w Word, from int) *Word {
	out := &Word{id: -1, Span: Span{from, w.Span.End}}
	for _, p := range w.Parts {
		switch {
		case p.Span.End <= from && !(p.Span.End == from && p.Span.Start == from):
			continue
		case p.Span.Start < from:
			p.Span.Start = from // the literal NAME=: its part after the =
		}
		out.Parts = append(out.Parts, p)
	}
	return out
}

// literalTarget is the target of the redirect r when it is literal, or "".
// closesVar is whether r is {name}>&- or {name}<&-, which closes the
// descriptor name holds and assigns nothing.
func closesVar(s string, r *Redirect) bool {
	return r.Var.String() != "" && (r.Op == RedirDupOut || r.Op == RedirDupIn) && literalTarget(s, r) == "-"
}

func literalTarget(s string, r *Redirect) string {
	n, _ := literalOf(s, r.Target)
	return n
}
