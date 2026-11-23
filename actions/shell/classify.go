package shell

import (
	"slices"
	"sort"
	"strings"
)

// Quoting is how a string put at a place of a script is read.
type Quoting uint8

const (
	// QuotingUnknown: the lexer cannot tell (see the package doc).
	QuotingUnknown Quoting = iota
	// Unquoted: outside quotes; the string is split into words and
	// globbed.
	Unquoted
	// DoubleQuoted: inside "...": the string is expanded ($, `), not split.
	DoubleQuoted
	// SingleQuoted: inside '...' or $'...': the string is taken as it is.
	SingleQuoted
	// Heredoc: in the body of a heredoc whose delimiter is not quoted:
	// expanded as inside "...".
	Heredoc
	// QuotedHeredoc: in the body of a heredoc whose delimiter is quoted:
	// taken as it is.
	QuotedHeredoc
	// Comment: after a # that starts a word.
	Comment
	// CommandString: what another program reads as code or runs: the
	// command word, the arguments of eval, of a shell's -c and of an
	// interpreter's code option (python -c, node -e and the like), and the
	// body of a heredoc given to a shell or an interpreter.
	CommandString
)

var quotingNames = [...]string{"QuotingUnknown", "Unquoted", "DoubleQuoted", "SingleQuoted", "Heredoc", "QuotedHeredoc", "Comment", "CommandString"}

func (c Quoting) String() string { return quotingNames[c] }

// Quotings is how a string put at each place at of script (byte offsets,
// in increasing order) would be read by bash or sh. A place past the end
// of script is Unknown; so is every place of a script the lexer cannot
// follow to its end, which bash would refuse to run.
func Quotings(script string, at []int) []Quoting {
	places := Places(script, at)
	out := make([]Quoting, len(places))
	for i, p := range places {
		out[i] = p.Quoting
	}
	return out
}

// Place is how a string put at a place of a script is read, and for a
// place in the body of a heredoc, the delimiter that ends it: a line of
// the string that is the delimiter ends the body.
type Place struct {
	Quoting     Quoting
	Delim       Delim       // the zero Delim outside a heredoc's body
	CondOperand CondOperand // CondOperandNone but at an operand of [[ ]] read as a string or a pattern
}

// CondOperand is what an operand of [[ ]] is read as. [[ ]] neither
// splits nor globs its words, so quoting changes how a string is read only
// in a pattern: quoted, it is matched as it is.
type CondOperand uint8

const (
	CondOperandNone    CondOperand = iota // not such an operand
	CondOperandString                     // compared as a string, or tested (-n, -f and the like)
	CondOperandPattern                    // the pattern after ==, = and !=, or the regular expression after =~
)

// Places is Contexts with the delimiter of each place in the body of a
// heredoc.
func Places(script string, at []int) []Place {
	p, _ := places(script, at)
	return p
}

// rule is a named rule of the classifier: a role of a word that makes
// how bash reads a place there differ from what the quotes alone say.
// Each has a row in bash_test.go.
type rule uint8

const (
	ruleUnset rule = iota
	// ruleRedirectTarget: the target of a redirect is the name of a file,
	// which bash expands but neither splits nor runs.
	ruleRedirectTarget
	// ruleCondOperand: an operand of [[ ]] other than one of arithmetic or
	// of -v is a string, a pattern or a regular expression, which bash
	// expands but neither splits nor runs.
	ruleCondOperand
)

var ruleNames = [...]string{"unset", "redirect-target", "cond-operand"}

func (r rule) String() string { return ruleNames[r] }

// places is Places with the rule that gave each place its context.
func places(script string, at []int) ([]Place, []rule) {
	lx := tokenize(script, at)
	return classify(script, lx, parse(script, lx), at)
}

// classify is how bash reads each place at of the script, tokenized as lx
// and parsed as sc, with the rule that gave each place its context.
func classify(script string, lx *lexed, sc *Script, at []int) ([]Place, []rule) {
	return classifyWith(script, lx, sc, at, func() *NameVisibility { return readFlowOf(script, sc, false) })
}

// classifyWith is classify, with newVis making the NameVisibility of sc
// when a command may call a function.
func classifyWith(script string, lx *lexed, sc *Script, at []int, newVis func() *NameVisibility) ([]Place, []rule) {
	c := &classifier{s: script, sc: sc, lx: lx, roles: map[Span]role{}, spans: make([]Span, lx.nwords), code: map[*HeredocBody]bool{}, readers: map[*Simple]int{}, valueAt: map[Span]int{}, intVars: intVariables(script, sc), newVis: newVis}
	c.findCoprocWrites()
	c.walk(sc.List)
	c.coprocWriters()
	return c.finish(sc, at)
}

// role is how bash reads a word of a command.
type role uint8

const (
	roleUnset   role = iota // a keyword, the name of a function: as the command word
	roleCommand             // the command word, or an option whose argument is code (-c"..."): what runs
	roleArg                 // an argument, read as data
	roleCode                // an argument read as code
	roleAssign
	roleTarget  // the target of a redirect
	roleCond    // an operand of [[ ]] read as a string (cond-operand)
	roleList    // a word after in of for or select: outside quotes, the words it is split into are what the loop goes over, which one quoted word is not
	rolePattern // the pattern or regular expression of [[ ]] (cond-operand)
)

// gapState is how a word put between the words of a command is read.
type gapState uint8

const (
	gapCommand gapState = iota // no command word yet: it would be the command word
	gapArg
	gapCode
)

type classifier struct {
	s            string
	sc           *Script
	allDefs      []*FuncDef      // the definitions of the script, found once (definitions)
	defsFound    bool            // allDefs is found
	vis          *NameVisibility // the definitions each call may run, read when the script defines a function (visibility)
	newVis       func() *NameVisibility
	info         *funcInfo        // the functions of the script, read once (funcs)
	codeAt       map[Span]bool    // the spans of bodies already made code
	coprocWrites map[Command]bool // the commands whose output may reach the input of a coproc that reads its input (findCoprocWrites)
	lx           *lexed
	roles        map[Span]role         // by the span of the word: the words inside substitutions too
	spans        []Span                // the span of each word of the script's own tokens, by its id
	code         map[*HeredocBody]bool // bodies read as code
	intVars      bool                  // a variable has the integer attribute: assignments are arithmetic
	simples      []simpleGaps          // in order
	readers      map[*Simple]int       // those that read their input as code, read either way: where the later of their command words starts
	valueAt      map[Span]int          // by the span of an assignment word: where its value starts (the end of the word when not known)
	targets      []Span                // between the operator of a redirect and its target, in order: a word put there is the target
	over         []override            // in order of application
	parts        []partAt              // every part of the tree, inside substitutions too (nested)
	inSub        bool                  // the command read is inside a substitution: its gaps are not the script's
}

// partAt is a part of the tree: where it is, its kind and its quote, and
// for a ${ } with an operator, what bash reads.
type partAt struct {
	span  Span
	kind  PartKind
	quote Quote
	param *ParamExpansion
}

// simpleGaps is how a word put at a place of a simple command is read:
// from each item's end, until the next.
type simpleGaps struct {
	start, ext int
	ends       []int
	states     []gapState
}

// override gives the places of span a context, whatever the words say.
type override struct {
	span Span
	ctx  Quoting
	skip func(mark) bool // places it does not touch
}

// substituted is whether env is the environment of the script of a
// command or process substitution.
func substituted(env *ExecutionEnvironment) bool {
	return env.Kind == ExecutionEnvironmentCommandSubstitution || env.Kind == ExecutionEnvironmentProcessSubstitution
}

// inSubstitution is whether env is a substitution, or a shell inside one.
func inSubstitution(env *ExecutionEnvironment) bool {
	for e := env; e != nil; e = e.Parent {
		if substituted(e) {
			return true
		}
	}
	return false
}

// walk reads the commands cs, inside substitutions too: each simple command
// before the commands after it, and, after the commands in it, the
// overrides of a pipeline and of a compound command, and those of a unit.
func (c *classifier) walk(cs []Command) {
	type frame struct {
		cmd Command
		env *ExecutionEnvironment
	}
	var stack []frame
	Walk(c.s, cs, Enclosing{}, Visitor{
		Command: func(cmd Command, at Enclosing) bool {
			stack = append(stack, frame{cmd, at.Env})
			if x, ok := cmd.(*Simple); ok {
				c.inSub = inSubstitution(at.Env)
				if x.isCond {
					c.cond(x)
				} else {
					c.simple(x)
				}
			}
			return true
		},
		Part: func(p *Part, _ Enclosing) {
			c.parts = append(c.parts, partAt{p.Span, p.Kind, p.Quote, p.Param})
		},
		Leave: func(cmd Command, at Enclosing) {
			stack = stack[:len(stack)-1]
			c.inSub = inSubstitution(at.Env)
			c.after(cmd)
			var parent Command
			if len(stack) > 0 && (stack[len(stack)-1].env == at.Env || !substituted(at.Env)) {
				parent = stack[len(stack)-1].cmd // the first commands of a substitution are a list of their own
			}
			switch parent.(type) {
			case nil, *Compound, *AndOr, *Asynchronous:
				c.unit(cmd) // a command of a list or of an and-or list
			}
		},
	})
}

// unit is a pipeline, or a command of a list that is none: a >( ) in it
// takes what it writes to a command not followed.
func (c *classifier) unit(cmd Command) {
	switch cmd.(type) {
	case *AndOr, *Asynchronous:
		return // its commands are units
	}
	if hasProcOut(c.s, cmd) {
		c.over = append(c.over, override{span: cmd.Span(), ctx: QuotingUnknown})
		for _, b := range c.bodies(cmd) {
			c.over = append(c.over, override{span: b, ctx: QuotingUnknown})
		}
	}
}

// after gives the overrides of cmd, after the commands in it.
func (c *classifier) after(cmd Command) {
	switch x := cmd.(type) {
	case *Pipeline:
		for i := 1; i < len(x.Commands); i++ {
			end, ok := c.reader(x.Commands[i])
			if !ok && c.writesToCoproc(x.Commands[i]) {
				// what reaches it, it may pass on to a coproc that reads code
				end, ok = x.Commands[i].Span().Start, true
			}
			from := PipeSources(c.s, x, i)
			if !ok || len(from) == 0 {
				continue
			}
			first := from[len(from)-1].Element
			// what the pipe carries is code for it: the commands before it
			// whose output reaches it, and what comes before its command word
			c.over = append(c.over, override{span: Span{x.Commands[first].Span().Start, end}, ctx: CommandString})
			for _, y := range x.Commands[first:i] {
				for _, b := range c.bodies(y) {
					c.over = append(c.over, override{span: b, ctx: CommandString})
				}
				for _, b := range c.calledBodies(y) {
					c.bodyCode(b)
				}
			}
		}
	case *Compound:
		switch x.Kind {
		case CompoundCase:
			c.over = append(c.over, override{span: Span{x.span.Start, caseEnd(x)}, ctx: QuotingUnknown})
		case CompoundFor, CompoundSelect:
			// the words after in: data, read as their quotes say; the name and
			// the arithmetic of for (( ; ; )): code
			for i := range x.In {
				c.set(x.In[i], roleList)
			}
			if x.Var != nil {
				c.set(*x.Var, roleCommand)
			}
			for _, a := range x.Arith {
				if a != nil {
					c.over = append(c.over, override{span: a.Span, ctx: CommandString})
				}
			}
		case CompoundArith:
			c.over = append(c.over, override{span: x.span, ctx: CommandString})
		}
		// the heredoc and the here-string of a compound command are code where
		// a command in it reads its input, as for the pipe (reader): what it
		// reads, it may pass on to a reader of code
		body := *x
		body.Redirects = nil // what its own redirects give it is what the commands in it read
		_, asCode := c.reader(&body)
		for i := range x.Redirects {
			r := &x.Redirects[i]
			code := asCode || !toStdin(*r)
			switch {
			case r.Heredoc != nil:
				c.code[r.Heredoc] = code
			case r.Op == RedirHereString:
				c.set(r.Target, pick(code, roleCode, roleArg))
			default:
				c.target(*r)
			}
		}
	}
}

// caseEnd is where the case of x ends, before its redirects.
func caseEnd(x *Compound) int {
	if len(x.Redirects) > 0 {
		return x.Redirects[0].Span.Start
	}
	return x.span.End
}

// definitions are the definitions of functions of the script.
func (c *classifier) definitions() []*FuncDef {
	if !c.defsFound && c.sc != nil {
		c.defsFound = true
		Walk(c.s, c.sc.List, Enclosing{}, Visitor{Command: func(x Command, _ Enclosing) bool {
			if d, ok := x.(*FuncDef); ok {
				c.allDefs = append(c.allDefs, d)
			}
			return true
		}})
	}
	return c.allDefs
}

// visibility is the NameVisibility of the script, read once.
func (c *classifier) visibility() *NameVisibility {
	if c.vis == nil {
		c.vis = c.newVis()
	}
	return c.vis
}

// callDefs are the definitions the simple command s may call where it
// runs (NameVisibility.Functions): by its command word, when literal.
func (c *classifier) callDefs(s *Simple) []*FuncDef {
	if len(s.Words) == 0 || c.sc == nil || len(c.definitions()) == 0 {
		return nil
	}
	ws := WordsOf(c.s, s)
	if !ws[0].Known {
		return nil
	}
	defs, _ := c.visibility().Functions(ws[0].Text, s.Span())
	return defs
}

// callReads is whether the simple command s may call a function whose body
// reads its standard input, read as a compound command is (reader): a
// command in the body reads the input, or the body has places the tree
// does not follow. The redirects of the definition are the body's own.
func (c *classifier) callReads(s *Simple) bool {
	for _, d := range c.callDefs(s) {
		if c.funcs().reads[d] || c.funcs().code[d] {
			return true
		}
	}
	return false
}

// callArgs makes code the arguments of s, a call of a function, that the
// body of a definition the call may run reads as code ($1 in f() { eval
// "$1"; }; f x; every argument for $@ and $*).
func (c *classifier) callArgs(s *Simple) {
	if len(s.Words) < 2 {
		return
	}
	if !slices.ContainsFunc(c.callDefs(s), func(d *FuncDef) bool { return c.funcs().code[d] }) {
		return
	}
	for i := 1; i < len(s.Words); i++ {
		c.set(s.Words[i], roleCode)
	}
}

// funcInfo is what the classifier knows of the functions of the script,
// by definition, read once for the whole script.
type funcInfo struct {
	calls map[*FuncDef][]*FuncDef // the definitions the calls in a body may run (callDefs)
	reads map[*FuncDef]bool       // a body reads its standard input (callReads)
	// code: a body, or a body it may call, has a place read as code
	// (readsCode): a call's arguments and standard input are then code,
	// whichever of them the body reads as code, as the positional
	// parameters can be shifted, set again or run in many ways
	code    map[*FuncDef]bool
	reached map[*FuncDef][]Span // the bodies a call of the definition may run, its own among them
}

// funcs is the funcInfo of the script, made once.
func (c *classifier) funcs() *funcInfo {
	if c.info != nil {
		return c.info
	}
	f := &funcInfo{calls: map[*FuncDef][]*FuncDef{}, reads: map[*FuncDef]bool{}, code: map[*FuncDef]bool{}, reached: map[*FuncDef][]Span{}}
	c.info = f
	assoc := assocNames(c.s, c.sc)
	for _, d := range c.definitions() {
		f.calls[d] = c.calledDefs(d.Body)
		readers, unread := PipeReaders(c.s, d.Body)
		f.reads[d] = len(readers) > 0 || unread
		f.code[d] = bodyReadsCode(c.s, d.Body) || readsArgsAsCode(c.s, assoc, []Command{d.Body}) || c.intVars && assigns(c.s, d.Body) || c.bodyWritesToCoproc(d.Body)
	}
	for changed := true; changed; {
		changed = false
		for d, ms := range f.calls {
			if !f.code[d] && slices.ContainsFunc(ms, func(m *FuncDef) bool { return f.code[m] }) {
				f.code[d], changed = true, true
			}
		}
	}
	for _, d := range c.definitions() {
		seen := map[*FuncDef]bool{d: true}
		queue := []*FuncDef{d}
		for len(queue) > 0 {
			m := queue[0]
			queue = queue[1:]
			f.reached[d] = append(f.reached[d], m.Body.Span())
			for _, k := range f.calls[m] {
				if !seen[k] {
					seen[k] = true
					queue = append(queue, k)
				}
			}
		}
	}
	return f
}

// assigns is whether the body of a function assigns a variable a value
// that holds a positional parameter (n=$1, export n="$2", declare n=$@,
// for k; do), or gives declare, typeset, local, export or readonly a word
// that is not an assignment and holds one (export "$1"): where a variable
// may have the integer attribute, the value is arithmetic.
func assigns(script string, body Command) bool {
	names, unnamed := argAssignments(script, []Command{body})
	return len(names) > 0 || unnamed
}

// bodyReadsCode is whether the body of a function, in its substitutions
// too, has a place that bash or a program reads as code: a command whose
// name is not literal or is known only after a wrapper, a command that
// reads its arguments or its standard input as code (eval, source, the
// shells), an option whose value is code or names a program, or
// arithmetic.
func bodyReadsCode(script string, body Command) bool {
	found := false
	Walk(script, []Command{body}, Enclosing{}, Visitor{
		Command: func(x Command, _ Enclosing) bool {
			switch y := x.(type) {
			case *Compound:
				found = found || y.Kind == CompoundArith || len(y.Arith) > 0
			case *Simple:
				if len(y.Words) == 0 {
					return true
				}
				ws := WordsOf(script, y)
				m := LookupCommand(ws)
				switch {
				case !ws[0].Known, m.Command >= 0 && !ws[m.Command].Known:
					found = true
				case m.Entry != nil && (m.Entry.Has(CommandTraitCodeArguments) || m.Entry.Has(CommandTraitVariableArguments) || m.Entry.Has(CommandTraitCodeStdin)):
					found = true
				case slices.ContainsFunc(m.Readings, func(r ArgumentReading) bool { return r == ArgumentReadingCode || r == ArgumentReadingProgram }):
					found = true
				}
			}
			return true
		},
		Part: func(p *Part, _ Enclosing) {
			found = found || p.Kind == PartArith
		},
	})
	return found
}

// coprocTargets are the names of the coprocs whose command reads its
// input (as a pipe into a compound command is read, reader); "" for any
// name, where the name of such a coproc is not literal. Empty where no
// such coproc is in the script.
func (c *classifier) coprocTargets() map[string]bool {
	names := map[string]bool{}
	Walk(c.s, c.sc.List, Enclosing{}, Visitor{Command: func(x Command, _ Enclosing) bool {
		y, ok := x.(*Compound)
		if !ok || y.Kind != CompoundCoproc {
			return true
		}
		// what the shell writes to the input of the coproc reaches its
		// command as a pipe does a compound command (reader)
		sub := Compound{span: y.span, Kind: CompoundSubshell, Body: y.Body}
		if readers, unread := PipeReaders(c.s, &sub); len(readers) == 0 && !unread {
			return true
		}
		name := "COPROC"
		if y.Name != nil {
			var lit bool
			if name, lit = literalOf(c.s, *y.Name); !lit {
				name = ""
			}
		}
		names[name] = true
		return true
	}})
	return names
}

// paramNamed is whether ps hold a parameter of one of names ("" for any).
func paramNamed(ps []Part, names map[string]bool) bool {
	for _, p := range ps {
		n := ""
		switch {
		case p.Kind == PartParam:
			n = p.Name.String()
		case p.Kind == PartParamOp && p.Param != nil:
			n = p.Param.Name.String()
		default:
			continue
		}
		if n != "" && (names[n] || names[""]) {
			return true
		}
	}
	return false
}

// findCoprocWrites finds the commands, simple or compound, with a redirect
// for output whose target holds an element of the array of a coproc whose
// command reads its input (>&${N[1]}, > /dev/fd/${N[1]}): what they write
// may reach the coproc's command. A descriptor the script copies from the
// array (exec 4>&${N[1]}; echo x >&4), a variable that holds an element,
// and the other ways to pass the descriptor are not followed.
func (c *classifier) findCoprocWrites() {
	if c.sc == nil {
		return
	}
	names := c.coprocTargets()
	if len(names) == 0 {
		return
	}
	c.coprocWrites = map[Command]bool{}
	Walk(c.s, c.sc.List, Enclosing{}, Visitor{Command: func(x Command, _ Enclosing) bool {
		var rs []Redirect
		switch y := x.(type) {
		case *Simple:
			rs = y.Redirects
		case *Compound:
			rs = y.Redirects
		}
		for _, r := range rs {
			switch r.Op {
			case RedirIn, RedirHereString, RedirHeredoc, RedirHeredocStrip:
				continue
			case RedirDupIn:
				if r.Fd <= 0 && r.Var.String() == "" {
					continue // the standard input: 1<&${N[1]} copies for output too
				}
			}
			if paramNamed(r.Target.Parts, names) {
				c.coprocWrites[x] = true
			}
		}
		return true
	}})
}

// writesToCoproc is whether a simple command of cmd writes to the input of
// a coproc that reads its input as code (findCoprocWrites).
func (c *classifier) writesToCoproc(cmd Command) bool {
	if len(c.coprocWrites) == 0 {
		return false
	}
	found := false
	Walk(c.s, []Command{cmd}, Enclosing{}, Visitor{Command: func(x Command, _ Enclosing) bool {
		found = found || c.coprocWrites[x]
		return !found
	}})
	return found
}

// bodyWritesToCoproc is whether the body of a function writes to the
// input of a coproc that reads its input as code: its arguments may be
// what is written.
func (c *classifier) bodyWritesToCoproc(body Command) bool { return c.writesToCoproc(body) }

// coprocWriters makes code what a command writes into a coproc whose
// command reads its input as code, as for a command before a pipe into a
// reader of code: the command, the bodies of its heredocs and of the
// functions it calls.
func (c *classifier) coprocWriters() {
	for x := range c.coprocWrites {
		c.over = append(c.over, override{span: x.Span(), ctx: CommandString})
		for _, b := range c.bodies(x) {
			c.over = append(c.over, override{span: b, ctx: CommandString})
		}
		for _, b := range c.calledBodies(x) {
			c.bodyCode(b)
		}
	}
}

// toStdin is whether the heredoc or the here-string r gives its text to
// the standard input (no number before the operator, or 0). Where it gives
// the text to another descriptor, a command can read the descriptor or
// make the descriptor its input (bash 0<&3), which the classifier does not
// follow: the text is taken as code.
func toStdin(r Redirect) bool {
	return r.Fd <= 0 && r.Var.String() == ""
}

func pick[T any](b bool, yes, no T) T {
	if b {
		return yes
	}
	return no
}

// target is the target of r, and the places before it; with no target,
// up to the blanks after the operator.
func (c *classifier) target(r Redirect) {
	c.set(r.Target, roleTarget)
	end := r.Target.Span.Start
	if len(r.Target.Parts) == 0 {
		for end < len(c.s) && isBlank(c.s[end]) {
			end++
		}
	}
	c.targets = append(c.targets, Span{r.Span.Start + 1, end + 1})
}

// roleOf is the role of the word of the script's own tokens with the id
// id: roleUnset for one that no command gave a role.
func (c *classifier) roleOf(id int) role {
	sp := c.spans[id]
	if sp == (Span{}) {
		return roleUnset
	}
	return c.roles[sp]
}

func (c *classifier) set(w Word, r role) {
	c.roles[w.Span] = r
	if w.id >= 0 && !c.inSub { // a word of a substitution is not of the script's own tokens (` ` is read by a tokenizer of its own)
		c.spans[w.id] = w.Span
	}
}

// name is what the word w names as a command or an option: its bytes
// without quotes and backslashes, or with an expansion in it, its letters
// alone ($(x)-c names -c; "$NODE" names nothing known).
func (c *classifier) name(w Word) string {
	var b strings.Builder
	for _, p := range w.Parts {
		switch {
		case p.Kind != PartLiteral:
		case p.Quote == QuoteNone:
			b.WriteString(unquote(c.s[p.Span.Start:p.Span.End]))
		default:
			b.WriteString(c.s[p.Span.Start:p.Span.End])
		}
	}
	return b.String()
}

// literalWord is whether the word w of script names one thing before it
// runs: w is of literals only, and has outside quotes no brace expansion
// ({a,b}, {a..b}) and no pattern (*, ?, a closed [...]), which bash expands
// into words or file names when it runs ({bash,-c} x runs bash -c x;
// /bin/ba?h runs /bin/bash). A lone [ is the command test.
func literalWord(script string, w Word) bool {
	var b strings.Builder // the bytes of w, a quoted or escaped byte as _
	for _, p := range w.Parts {
		if p.Kind != PartLiteral {
			return false
		}
		t := script[p.Span.Start:p.Span.End]
		if p.Quote != QuoteNone {
			b.WriteString(strings.Repeat("_", len(t)))
			continue
		}
		for i := 0; i < len(t); i++ {
			if t[i] == '\\' {
				b.WriteString("__")
				i++
				continue
			}
			b.WriteByte(t[i])
		}
	}
	u := b.String()
	if strings.ContainsAny(u, "*?") {
		return false
	}
	// a [ and a ] after the byte that follows it: []x] is one bracket
	// expression, [] is not one
	if i := strings.IndexByte(u, '['); i >= 0 && i+2 <= len(u) && strings.IndexByte(u[i+2:], ']') >= 0 {
		return false
	}
	for i := strings.IndexByte(u, '{'); i >= 0; {
		j := strings.IndexByte(u[i+1:], '}')
		if j < 0 {
			break
		}
		if in := u[i+1 : i+1+j]; strings.Contains(in, ",") || sequence(in) {
			return false
		}
		k := strings.IndexByte(u[i+1:], '{')
		if k < 0 {
			break
		}
		i += 1 + k
	}
	return true
}

// sequence is whether the text in of a { } is a sequence of bash's brace
// expansion, x..y with text on both sides ({1..3}, {a..c}; {y..} is not
// expanded).
func sequence(in string) bool {
	x, y, ok := strings.Cut(in, "..")
	return ok && x != "" && y != ""
}

// hasProcIn is whether w has a <( ).
func hasProcIn(w Word) bool {
	for _, p := range w.Parts {
		if p.Kind == PartProcIn {
			return true
		}
	}
	return false
}

// base is the command a name runs: its last element.
func base(name string) string { return name[strings.LastIndexByte(name, '/')+1:] }

// reading is how the words of a simple command are read in order: the
// command word, a shell or an interpreter named among the arguments, and
// whether what follows is code.
type reading struct {
	cmd, inner    string
	unknown       bool // the command word is not literal: a command known only when it runs
	at            int  // where the command word starts
	code, started bool
	next          bool // the next word is the value of an option that names a program
	value         bool // the next word is the value of another option of the command
	operands      bool // an operand of the command came: its options are over (git grep -c is not git -c)
}

// word reads the word w, named name; it is whether w is the command word,
// and whether it is an option whose argument is code (-c"...").
func (q *reading) word(c *classifier, w Word, name string) (command, option bool) {
	if !q.started {
		q.started, q.cmd, q.at = true, base(name), w.Span.Start
		// a command word that is not literal names a command known only when
		// it runs, which may read its arguments as code ($(echo eval),
		// "$BASH" -c)
		q.unknown = !literalWord(c.s, w)
		q.code = q.code || argumentsAreCode(q.cmd) || q.unknown
		return true, false
	}
	if q.next {
		q.next = false
		return false, true // the value of an option that names a program: it runs
	}
	if ok, holds := q.programOption(name); ok {
		if holds {
			return false, true // git -ccore.fsmonitor=x, --exec-path=x
		}
		q.next = true
	}
	if mayExpandToOption(c.s, w) && (runsOption(q.cmd) || runsOption(q.inner)) {
		// a brace expansion or a pattern outside quotes that may start with
		// - may make any option, the one whose value is code or names a
		// program among them (bash {-c,} x is bash -c x, git {-c,} k=v is
		// git -c k=v; bash 5.3.15)
		q.code = true
		return false, true
	}
	for _, cmd := range []string{q.cmd, q.inner} {
		if ok, holds, joined := codeOption(cmd, name); ok {
			// the words after are code; the word itself only when it holds
			// the code (python -c"...", whose code may be quoted after -c;
			// not bash -c"...", whose letters after -c are other options)
			q.code, option = true, option || holds || joined && w.Span.End-w.Span.Start > len(name)
		}
	}
	if b := base(name); isInterpreter(b) {
		q.inner = b
	}
	return false, option
}

// readsCode is whether the command read so far reads its standard input as
// code: none yet, one not literal, or one that does.
func (q *reading) readsCode() bool { return !q.started || q.unknown || readsCode(q.cmd) }

// simple gives the words of s their roles, in the order bash reads them:
// assignments, the command word and its arguments, and the targets of the
// redirects among them.
func (c *classifier) simple(s *Simple) {
	type item struct {
		w      *Word
		r      *Redirect
		assign bool
	}
	var items []item
	for i := range s.Assigns {
		items = append(items, item{w: &s.Assigns[i], assign: true})
	}
	for i := range s.Words {
		items = append(items, item{w: &s.Words[i]})
	}
	for i := range s.Redirects {
		items = append(items, item{r: &s.Redirects[i]})
	}
	start := func(it item) int {
		if it.w != nil {
			return it.w.Span.Start
		}
		return it.r.Span.Start
	}
	sort.SliceStable(items, func(i, j int) bool { return start(items[i]) < start(items[j]) })
	g := simpleGaps{start: s.span.Start, ext: s.ext}
	now := reading{}
	state := func() gapState {
		switch {
		case !now.started:
			return gapCommand
		case now.code || now.next:
			return gapCode
		}
		return gapArg
	}
	readerAt, reader := 0, false
	intArgs := c.intVars && assignsByArgument(c.s, s)
	called, callsRead := false, false
	calls := func() bool { // a function the command calls reads the input (callReads), asked once
		if !called {
			called, callsRead = true, c.callReads(s)
		}
		return callsRead
	}
	for _, it := range items {
		var end int
		switch {
		case it.r != nil:
			r := it.r
			end = r.Span.End
			if r.Op == RedirHereString && now.readsCode() {
				now.code = true // what follows is the input of a reader of code
			}
			// from the operator on, before the target is read
			g.ends, g.states = append(g.ends, r.Span.Start+1), append(g.states, state())
			switch {
			case r.Heredoc != nil:
				c.code[r.Heredoc] = now.readsCode() || !toStdin(*r) || calls()
			case r.Op == RedirHereString:
				c.set(r.Target, pick(now.code || !toStdin(*r) || calls(), roleCode, roleArg))
			default:
				c.target(*r)
			}
		case it.assign:
			end = it.w.Span.End
			c.set(*it.w, roleAssign)
			c.valueAt[it.w.Span] = it.w.Span.End
			if _, value, _, ok := AssignedName(c.s, *it.w); ok {
				c.valueAt[it.w.Span] = value // before it, the name and the subscript
			}
		default:
			end = it.w.Span.End
			code := now.code
			command, option := now.word(c, *it.w, c.name(*it.w))
			switch {
			case command, option:
				c.set(*it.w, roleCommand) // -c"..." is the option and its code
			case code:
				c.set(*it.w, roleCode)
			case intArgs && !optionWord(c.s, *it.w):
				// export n=v: the value of a variable that may be an integer is
				// arithmetic; a word that is not literally name=value may still
				// be one when it runs (export "$x", export "n=v")
				c.set(*it.w, roleCode)
			default:
				c.set(*it.w, roleArg)
			}
		}
		g.ends, g.states = append(g.ends, end), append(g.states, state())
		if now.started && now.readsCode() {
			readerAt, reader = now.at, true
		}
	}
	c.callArgs(s)
	// the output of a substitution read as code: what the functions it
	// calls write is code (eval "$(f)", bash <<< "$(f)")
	for _, w := range s.Words {
		if r := c.roles[w.Span]; r == roleCode || r == roleCommand {
			c.substCode(w.Parts)
		}
	}
	for i := range s.Redirects {
		r := &s.Redirects[i]
		switch {
		case r.Op == RedirHereString && c.roles[r.Target.Span] == roleCode:
			c.substCode(r.Target.Parts)
		case r.Heredoc != nil && c.code[r.Heredoc]:
			c.substCode(r.Heredoc.Parts)
		}
	}

	if !c.inSub {
		c.simples = append(c.simples, g)
	}
	if now.started && now.readsCode() || now.inner != "" && readsCode(now.inner) {
		// a <( ) whose file a reader of code reads, as its operand or its
		// standard input, is code (bash <(echo x), bash < <(echo x))
		for i := range s.Words {
			if i > 0 && hasProcIn(s.Words[i]) {
				c.set(s.Words[i], roleCode)
			}
		}
		for i := range s.Redirects {
			if r := &s.Redirects[i]; r.Op == RedirIn && (r.Fd < 0 || r.Fd == 0) && hasProcIn(r.Target) {
				c.set(r.Target, roleCode)
			}
		}
	}
	if reader {
		c.readers[s] = readerAt
	}
}

// cond gives the words of [[ ... ]] their roles; where they are not read,
// its places are QuotingUnknown. A word put between its words would be the
// operand of what is not known: code.
func (c *classifier) cond(s *Simple) {
	if s.cond == nil {
		c.over = append(c.over, override{span: Span{s.span.Start, s.Words[len(s.Words)-1].Span.End}, ctx: QuotingUnknown})
	}
	for i, w := range s.Words {
		r := roleCommand
		if s.cond != nil {
			r = [...]role{condOperator: roleCommand, condString: roleCond, condPattern: rolePattern, condArith: roleCode}[s.cond[i]]
		}
		c.set(w, r)
	}
	for i := range s.Redirects {
		switch r := &s.Redirects[i]; {
		case r.Heredoc != nil:
			c.code[r.Heredoc] = false
		case r.Op == RedirHereString:
			c.set(r.Target, roleArg)
		default:
			c.target(*r)
		}
	}
	if !c.inSub {
		c.simples = append(c.simples, simpleGaps{start: s.span.Start, ext: s.ext})
	}
}

// gap is how a word put at p, between words, is read.
func (c *classifier) gap(p int) Quoting {
	i := sort.Search(len(c.simples), func(i int) bool { return c.simples[i].ext >= p }) // at ext, the operator after it is not read yet
	if i == len(c.simples) || c.simples[i].start > p {
		return CommandString // where a command starts
	}
	g := c.simples[i]
	st := gapCommand
	for k, e := range g.ends {
		if e <= p {
			st = g.states[k]
		}
	}
	if st == gapArg {
		return Unquoted
	}
	return CommandString
}

// finish gives each place of at its context.
func (c *classifier) finish(sc *Script, at []int) ([]Place, []rule) {
	out, rules := make([]Place, len(at)), make([]rule, len(at))
	sort.Slice(c.targets, func(i, j int) bool { return c.targets[i].Start < c.targets[j].Start })
	chains := c.chains(at, func(i int) bool { m := c.lx.marks[i]; return m.set && m.nested && !m.joins })
	for i, p := range at {
		if m := c.lx.marks[i]; m.set {
			var r role
			if m.nested && !m.joins && (m.doc == nil || expanded(chains[i])) {
				out[i].Quoting, rules[i], r = c.nested(p, chains[i])
				if m.doc != nil && c.code[&m.doc.body] {
					out[i].Quoting, rules[i] = CommandString, ruleUnset // the body is the code of its command
				}
			} else {
				out[i].Quoting, rules[i] = c.place(p, m)
				if m.word >= 0 {
					r = c.roleOf(m.word)
				}
			}
			if rules[i] == ruleCondOperand {
				out[i].CondOperand = CondOperandString
				if r == rolePattern {
					out[i].CondOperand = CondOperandPattern
				}
			}
		}
	}
	if !sc.Complete {
		// a >( ) the tree does not have: what the command before it writes goes
		// to a command not followed
		from := 0
		if n := len(sc.List); n > 0 {
			from = sc.List[n-1].Span().Start
		}
		for _, q := range c.lx.procOuts {
			if q >= sc.Stop {
				c.over = append(c.over, override{span: Span{from, q + 1}, ctx: QuotingUnknown})
			}
		}
	}
	for _, o := range c.over {
		for i := sort.SearchInts(at, o.span.Start); i < len(at) && at[i] < o.span.End; i++ {
			if m := c.lx.marks[i]; m.set && (o.skip == nil || !o.skip(m)) {
				out[i].Quoting = o.ctx
			}
		}
	}
	for i, p := range at {
		m := c.lx.marks[i]
		// from where the tokenizer stopped, or after where the parser did
		if c.lx.unterminated || !sc.Complete && (p > sc.Stop || !c.lx.complete && p == sc.Stop) {
			out[i], rules[i] = Place{}, ruleUnset // bash would refuse it, or it is not followed
			continue
		}
		if out[i].Quoting != QuotingUnknown && m.doc != nil && !m.delimLine {
			out[i].Delim = m.doc.body.Delim
		}
		if out[i].Quoting == QuotingUnknown {
			rules[i], out[i].CondOperand = ruleUnset, CondOperandNone
		}
	}
	return out, rules
}

// around is a part or a word of the tree around a place: for a part, its
// kind, quote and ${ }; for a word, its role.
type around struct {
	span Span
	part *partAt // nil for a word
	role role
}

// chains are, for each place of at (in increasing order) that inside
// reports, the parts and the words around it, outer first. The parts and
// the words nest, so a sweep over at keeps those open in a stack: time
// linear in the parts, the words and at, after a sort.
func (c *classifier) chains(at []int, inside func(i int) bool) map[int][]around {
	all := make([]around, 0, len(c.parts)+len(c.roles))
	for i := range c.parts {
		all = append(all, around{span: c.parts[i].span, part: &c.parts[i]})
	}
	for sp, r := range c.roles {
		all = append(all, around{span: sp, role: r})
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i].span, all[j].span
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End != b.End {
			return a.End > b.End
		}
		return all[i].part == nil && all[j].part != nil // a word before a part of the same span
	})
	out := map[int][]around{}
	var stack []around
	j := 0
	for i, p := range at {
		for ; j < len(all) && all[j].span.Start <= p; j++ {
			for len(stack) > 0 && stack[len(stack)-1].span.End <= all[j].span.Start {
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, all[j])
		}
		for len(stack) > 0 && stack[len(stack)-1].span.End <= p {
			stack = stack[:len(stack)-1]
		}
		if !inside(i) {
			continue
		}
		var chain []around
		for _, x := range stack {
			if x.span.Start <= p && p < x.span.End {
				chain = append(chain, x)
			}
		}
		out[i] = chain
	}
	return out
}

// nested is the context of p inside an expansion, by the tree: the quote of
// the innermost part p is in, and the role of the innermost word with one
// that p is in; and that role. chain is what is around p, outer first.
// Any word around p that bash runs or reads as code (the command word, an
// argument of eval, -c and the like), and any arithmetic around it, makes p
// code, whatever the words inside say: what p is in becomes part of what
// that code holds (eval "$(echo "x")", a[$(echo x)]). Inside a <( ), p is
// in what a command reads as a file, which the classifier does not follow
// (code where a reader of code reads that file: simple); inside the words
// after the operator of a ${ } other than :-, :=, :? and :+, it is not read
// here either. Those are QuotingUnknown.
func (c *classifier) nested(p int, chain []around) (Quoting, rule, role) {
	code, procIn := false, false
	var inner *partAt
	word := -1 // the index in chain of the innermost word
	for i, x := range chain {
		if x.part == nil {
			switch x.role {
			case roleUnset, roleCommand, roleCode:
				code = true
			case roleAssign:
				code = code || c.intVars || p < c.valueAt[x.span]
			case roleList:
				code = code || c.intVars // for n in v assigns v to n
			}
			word = i
			continue
		}
		inner = x.part
		switch r := paramRead(x.part, p); {
		case x.part.kind == PartArith, r == paramCode:
			code = true // arithmetic, whatever encloses it: a subscript's $( ) runs
		case r == paramValue && x.part.param.Op == ParamOpAssign && c.intVars:
			code = true // ${n:=v} assigns v to n, which may be an integer
		case x.part.kind == PartProcIn:
			procIn = true
		}
	}
	if code {
		return CommandString, ruleUnset, roleCode
	}
	if procIn || word < 0 || inner == nil || inner.kind != PartLiteral {
		return QuotingUnknown, ruleUnset, roleUnset
	}
	w := chain[word].span
	for _, x := range chain[word+1:] {
		// an expansion around p inside the innermost word that no word inside it covers
		if x.part != nil && x.part != inner && x.part.kind != PartLiteral && paramRead(x.part, p) != paramValue {
			return QuotingUnknown, ruleUnset, roleUnset
		}
	}
	if inner.span.Start < w.Start || inner.span.End > w.End {
		return QuotingUnknown, ruleUnset, roleUnset
	}
	ctx := [...]Quoting{QuoteNone: Unquoted, QuoteSingle: SingleQuoted, QuoteANSI: SingleQuoted, QuoteDouble: DoubleQuoted}[inner.quote]
	switch r := chain[word].role; r {
	case roleTarget:
		return ctx, ruleRedirectTarget, r
	case roleCond, rolePattern:
		return ctx, ruleCondOperand, r
	case roleList:
		if ctx == Unquoted {
			return QuotingUnknown, ruleUnset, r
		}
		return ctx, ruleUnset, r
	default:
		return ctx, ruleUnset, r
	}
}

// expanded is whether a part around a place is an expansion.
func expanded(chain []around) bool {
	for _, x := range chain {
		if x.part != nil && x.part.kind != PartLiteral {
			return true
		}
	}
	return false
}

// paramReading is how bash reads a place inside a ${ }.
type paramReading uint8

const (
	paramOther paramReading = iota // not inside one, or in a word not read here: a pattern, a replacement
	paramValue                     // in a word of :-, :=, :? or :+ (and those without :): a value, read as its quotes say
	paramCode                      // in the subscript, the offset or the length: arithmetic
)

// paramRead is how bash reads the place p inside the part x, a ${ }.
func paramRead(x *partAt, p int) paramReading {
	e := x.param
	if x.kind != PartParamOp || e == nil {
		return paramOther
	}
	in := func(w *Word) bool { return w != nil && w.Span.Start <= p && p < w.Span.End }
	if in(e.Subscript) || in(e.Offset) || in(e.Length) {
		return paramCode
	}
	switch e.Op {
	case ParamOpDefault, ParamOpAssign, ParamOpError, ParamOpAlternate:
		for i := range e.Words {
			if in(&e.Words[i]) {
				return paramValue
			}
		}
	}
	return paramOther
}

// place is the context of p by its mark and the role of its word.
func (c *classifier) place(p int, m mark) (Quoting, rule) {
	ctx := m.ctx
	if m.joins {
		ctx = QuotingUnknown // a string put here would join the byte before it
	}
	switch {
	case m.doc != nil:
		if !m.delimLine && c.code[&m.doc.body] && !m.joins {
			ctx = CommandString // the body is the code of its command
		}
	case m.ctx == Comment:
	case m.word >= 0:
		switch c.roleOf(m.word) {
		case roleUnset, roleCommand:
			ctx = CommandString
		case roleCode:
			if ctx != QuotingUnknown {
				ctx = CommandString
			}
		case roleAssign:
			switch {
			case p < c.valueAt[c.spans[m.word]]:
				ctx = CommandString // the name and the subscript: arithmetic, and what makes the word an assignment
			case c.intVars:
				ctx = QuotingUnknown // an integer variable's value is arithmetic
			}
		case roleTarget:
			return ctx, ruleRedirectTarget
		case roleCond, rolePattern:
			return ctx, ruleCondOperand
		case roleList:
			if ctx == Unquoted || c.intVars {
				ctx = QuotingUnknown // for n in v assigns v to n, which may be an integer
			}
		}
	case ctx == Unquoted:
		if i := sort.Search(len(c.targets), func(i int) bool { return c.targets[i].End > p }); i < len(c.targets) && c.targets[i].Start <= p {
			return ctx, ruleRedirectTarget
		}
		ctx = c.gap(p)
	}
	return ctx, ruleUnset
}

// reader is whether cmd, after a pipe, reads what the pipe carries as code,
// and where the place of code ends: a command that reads the pipe
// (PipeReaders) and reads its input as code, read either way (a command
// word not literal counts as one). For cmd itself, that is where the
// later of its command words starts; a compound command in which a
// command reads the pipe is taken as one, up to where it starts. A
// command with places the tree does not follow (PipeReaders' unread) is
// taken as one, up to where it starts. A redirect's target is not the
// command word (echo | A=x <bash reads the file bash, and runs no
// command).
func (c *classifier) reader(cmd Command) (int, bool) {
	readers, unread := PipeReaders(c.s, cmd)
	if _, ok := cmd.(*Compound); ok && (len(readers) > 0 || unread) {
		// what a command in it reads, it may pass on through its own pipes
		// and variables to a reader of code (echo "$x" | { cat | bash; })
		return cmd.Span().Start, true
	}
	for _, r := range readers {
		switch at, ok := c.readers[r]; {
		case ok && r == cmd:
			return at, true
		case ok:
			return cmd.Span().Start, true
		case c.callReads(r):
			// a call of a function whose body reads the input, as for a
			// compound command (f() { bash; }; echo x | f)
			return cmd.Span().Start, true
		}
	}
	if unread {
		return cmd.Span().Start, true // a place the tree does not follow may read it
	}
	return 0, false
}

// hasProcOut is whether a word of cmd, or of a script inside it, has >( ).
func hasProcOut(s string, cmd Command) bool {
	found := false
	Walk(s, []Command{cmd}, Enclosing{}, Visitor{Part: func(p *Part, _ Enclosing) {
		found = found || p.Kind == PartProcOut
	}})
	return found
}

// calledBodies are the spans of the bodies of the functions that the
// commands of cmd may call, in its substitutions too, and of those that
// those bodies may call: what a body writes may reach the output of cmd
// (f() { echo x; }; f | bash, echo "$(f)" | bash). A whole body is taken,
// wherever in it a command writes, and whichever call runs it.
func (c *classifier) calledBodies(cmd Command) []Span {
	var out []Span
	seen := map[Span]bool{}
	for _, d := range c.calledDefs(cmd) {
		for _, b := range c.funcs().reached[d] {
			if !seen[b] {
				seen[b] = true
				out = append(out, b)
			}
		}
	}
	return out
}

// calledDefs are the definitions the commands of cmd, in its substitutions
// too, may call, each once.
func (c *classifier) calledDefs(cmd Command) []*FuncDef {
	var out []*FuncDef
	Walk(c.s, []Command{cmd}, Enclosing{}, Visitor{
		Command: func(x Command, _ Enclosing) bool {
			if s, ok := x.(*Simple); ok {
				out = unionOf(out, c.callDefs(s))
			}
			return true
		},
	})
	return out
}

// substCode makes code the bodies of the functions that the commands of
// the substitutions in ps may call: their output is read as code.
func (c *classifier) substCode(ps []Part) {
	for _, p := range ps {
		if (p.Kind == PartSubst || p.Kind == PartProcIn) && p.Sub != nil {
			for _, cmd := range p.Sub.List {
				for _, b := range c.calledBodies(cmd) {
					c.bodyCode(b)
				}
			}
		}
	}
}

// bodyCode makes the body span b code, once.
func (c *classifier) bodyCode(b Span) {
	if c.codeAt[b] {
		return
	}
	if c.codeAt == nil {
		c.codeAt = map[Span]bool{}
	}
	c.codeAt[b] = true
	c.over = append(c.over, override{span: b, ctx: CommandString})
}

// bodies are the spans of the bodies of the heredocs of cmd and of the
// commands in it, outside substitutions, with the lines of their
// delimiters.
func (c *classifier) bodies(cmd Command) []Span {
	var out []Span
	Walk(c.s, []Command{cmd}, Enclosing{}, Visitor{
		Command: func(_ Command, at Enclosing) bool { return !substituted(at.Env) },
		Redirect: func(r *Redirect, at Enclosing) {
			if r.Heredoc == nil || substituted(at.Env) {
				return
			}
			end := r.Heredoc.end
			if end == 0 {
				end = len(c.s) // not followed to its end
			}
			out = append(out, Span{r.Heredoc.Body.Start, end})
		},
	})
	return out
}

func startsWord(c byte) bool { return !isBlank(c) && c != '\n' && c != '#' && !isOperator(c) }
func isOperator(c byte) bool { return strings.IndexByte(";&|<>()", c) >= 0 }
func isBlank(c byte) bool    { return c == ' ' || c == '\t' || c == '\r' }

// envAssignment is whether name, a word of env with its quotes taken off,
// is NAME=value, which env reads as an assignment: a name, then =
// (bash 5.3.15: env "A=b" bash -c 'echo $A' prints b).
func envAssignment(name string) bool {
	n := 0
	for n < len(name) && isNameByte(name[n]) {
		n++
	}
	return n > 0 && isNameStart(name[0]) && n < len(name) && name[n] == '='
}

// intVariables is whether a variable of the script sc may have the
// integer attribute, whose assignments bash evaluates as arithmetic: a
// declare, typeset or local command of the tree with an option word
// holding i (declare -i n, declare -x -i n, builtin declare -i n, command
// -p declare -i n), or with
// a word that may be an option and is not literal (declare "$o" n); a
// command whose name is not literal with a literal option holding i
// (d=declare; $d -i n); or such a command in the literal words of eval
// (eval 'declare -i n').
func intVariables(script string, sc *Script) bool {
	found := false
	WalkSimple(sc.List, func(s *Simple) {
		ws, words := builtinWords(script, s)
		if found || len(ws) == 0 {
			return
		}
		switch {
		case !ws[0].Known:
			// a command named only when it runs may be declare ($d -i n):
			// a literal option with i
			for _, w := range ws[1:] {
				found = found || w.Known && shortOptions(w.Text) && strings.ContainsRune(w.Text, 'i')
			}
			return
		case ws[0].Text == "eval":
			// eval 'declare -i n': the script eval runs, when its words are
			// literal
			text := make([]string, 0, len(ws)-1)
			for _, w := range ws[1:] {
				if !w.Known {
					return
				}
				text = append(text, w.Text)
			}
			if t := strings.Join(text, " "); strings.Contains(t, "-") {
				found = intVariables(t, Parse(t))
			}
			return
		}
		switch ws[0].Text {
		case "declare", "typeset", "local":
		default:
			return
		}
		for i, w := range ws[1:] {
			if len(words[i+1].Parts) == 0 {
				continue
			}
			switch first := words[i+1].Parts[0]; {
			case w.Known:
				found = found || strings.HasPrefix(w.Text, "-") && strings.ContainsRune(w.Text, 'i')
			case first.Kind == PartLiteral && first.Span.End > first.Span.Start:
				found = found || script[first.Span.Start] == '-' // a literal head: an option only with -
			default:
				found = true // its head is not known: it may be an option
			}
		}
	})
	return found
}

// shortOptions is whether w is a word of short options, as declare takes
// them: - or + and letters (-i, -xi, +i), not a long option (--file).
func shortOptions(w string) bool {
	if len(w) < 2 || w[0] != '-' && w[0] != '+' {
		return false
	}
	for i := 1; i < len(w); i++ {
		if !isLetter(w[i]) {
			return false
		}
	}
	return true
}

// builtinWords are the words of s from the name of the builtin it runs:
// builtin declare and command declare run the builtin, and so do command
// -p and -- before the name (command -v describes it).
func builtinWords(script string, s *Simple) ([]CommandWord, []Word) {
	ws, words := WordsOf(script, s), s.Words
	for len(ws) > 1 && ws[0].Known && (ws[0].Text == "builtin" || ws[0].Text == "command") {
		skip := 1
		for skip < len(ws) && ws[skip].Known && (ws[skip].Text == "--" || ws[0].Text == "command" && ws[skip].Text == "-p") {
			skip++
		}
		if skip == len(ws) || strings.HasPrefix(ws[skip].Text, "-") {
			break
		}
		ws, words = ws[skip:], words[skip:]
	}
	return ws, words
}

// assignsByArgument is whether s runs export or readonly, whose arguments
// of the form name=value assign the value to name: where a variable may
// have the integer attribute, bash reads the value as arithmetic.
func assignsByArgument(script string, s *Simple) bool {
	ws, _ := builtinWords(script, s)
	return len(ws) > 0 && ws[0].Known && (ws[0].Text == "export" || ws[0].Text == "readonly")
}

// optionWord is whether w starts with a - outside quotes: an option, not
// an operand.
func optionWord(script string, w Word) bool {
	return len(w.Parts) > 0 && w.Parts[0].Kind == PartLiteral && w.Parts[0].Quote == QuoteNone &&
		w.Parts[0].Span.End > w.Parts[0].Span.Start && script[w.Parts[0].Span.Start] == '-'
}

// argumentsAreCode is whether the command cmd reads its arguments as code:
// it runs them (runs-operand), or reads them as code or as names of
// variables, whose subscripts are arithmetic (commands.json).
func argumentsAreCode(cmd string) bool {
	e := commandNamed(cmd)
	return e != nil && (e.Has(CommandTraitRunsOperand) || e.Has(CommandTraitCodeArguments) || e.Has(CommandTraitVariableArguments))
}

// runsOption is whether the command cmd has an option whose value is code
// or names a program (-c of a shell, -e of perl, -c of git).
func runsOption(cmd string) bool {
	e := commandNamed(cmd)
	return e != nil && slices.ContainsFunc(e.Options, func(o CommandOption) bool {
		return o.Reading == ArgumentReadingCode || o.Reading == ArgumentReadingProgram
	})
}

// mayExpandToOption is whether w, of literals only, has a brace expansion
// or a pattern outside quotes (literalWord): what it expands to is known
// only when it runs, and may start with - ('-'{c,} is -c and -).
func mayExpandToOption(script string, w Word) bool {
	return literalParts(w) && !literalWord(script, w)
}

// literalParts is whether w is of literals only, quoted or not.
func literalParts(w Word) bool {
	return !slices.ContainsFunc(w.Parts, func(p Part) bool { return p.Kind != PartLiteral })
}

// codeOption is whether the argument arg of the command cmd is an option
// whose value is code, so that the arguments after it are: -c of a shell or
// python, -e of node and the like, -v of printf (commands.json); and
// whether arg holds the value too (python -c"code"), and whether the
// option takes its value joined to it.
func codeOption(cmd, arg string) (match, holdsValue, joined bool) {
	e := commandNamed(cmd)
	if e == nil {
		return false, false, false
	}
	o, holds := e.option(arg)
	if o == nil || o.Reading != ArgumentReadingCode {
		return false, false, false
	}
	return true, holds, o.Joined
}

// programOption is whether the word name, an argument of the command, is
// an option whose value names a program (git -c core.fsmonitor=x), and
// whether name holds the value too. Only the value is code: the words
// after it are read as they are. The options of a command come before its
// first operand, which for git is the subcommand: git grep -c reads -c
// itself. An option the command does not declare may take the next word as
// its value, so that word does not end the options.
func (q *reading) programOption(name string) (match, holdsValue bool) {
	e := commandNamed(q.cmd)
	if e == nil || q.operands {
		return false, false
	}
	if q.value {
		q.value = false
		return false, false
	}
	if name == "--" || name == "-" || !strings.HasPrefix(name, "-") {
		q.operands = true
		return false, false
	}
	o, holds := e.option(name)
	switch {
	case o == nil:
		q.value = true
	case o.Reading == ArgumentReadingProgram:
		return true, holds
	case o.Value && !holds:
		q.value = true
	}
	return false, false
}

// readsCode is whether the command cmd reads its standard input as code
// (or, xargs, as commands); "" (no command yet) counts as one.
func readsCode(cmd string) bool {
	if cmd == "" {
		return true
	}
	e := commandNamed(cmd)
	return e != nil && e.Has(CommandTraitCodeStdin)
}

// isInterpreter is whether the command name is an interpreter: it reads
// code from its standard input and from an option, so that an option of it
// named among the arguments of another command is read (xargs python -c).
func isInterpreter(name string) bool {
	e := commandNamed(name)
	if e == nil || !e.Has(CommandTraitCodeStdin) {
		return false
	}
	for _, o := range e.Options {
		if o.Reading == ArgumentReadingCode {
			return true
		}
	}
	return false
}

// unquote is the word w without its quotes and backslashes: what the shell
// reads as a command name or a heredoc's delimiter.
func unquote(w string) string {
	return strings.Map(func(r rune) rune {
		if r == '\'' || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, w)
}
