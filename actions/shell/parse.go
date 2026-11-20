package shell

import "strings"

// Parse reads script as bash reads it: its lists, pipelines and commands,
// the words of each and their parts, redirects and heredocs, and the
// commands inside $( ), <( ) and >( ). Where it cannot follow the script
// (the package doc), Complete is false and the tree ends at Stop.
func Parse(script string) *Script {
	return parse(script, tokenize(script, nil))
}

func parse(s string, lx *lexed) *Script {
	return parseWith(&parser{}, s, lx)
}

// parseWith is parse with the parser p, which may be some depth into
// another script's commands.
func parseWith(p *parser, s string, lx *lexed) *Script {
	toks := lx.toks
	for len(toks) > 0 && toks[len(toks)-1].span.End > lx.stop {
		toks = toks[:len(toks)-1] // what the tokenizer did not follow to its end is not in the tree
	}
	p.s, p.toks, p.end, p.err = s, toks, len(s), -1
	sc := &Script{Complete: lx.complete, Stop: lx.stop, unterminated: lx.unterminated}
	sc.List = p.list()
	if p.err < 0 && p.i < len(p.toks) {
		p.err = p.toks[p.i].span.Start // a keyword or a ) with nothing to end
	}
	if p.err >= 0 && (sc.Complete || p.err < sc.Stop) {
		sc.Complete, sc.Stop = false, p.err
	}
	return sc
}

// maxDepth is how deep commands and substitutions nest before the parser
// stops following them, so that the stack does not run out.
const maxDepth = 1000

// parser makes the tree of a list of tokens. It is lenient where bash is
// not, so that a script the tokenizer follows keeps its tree: a ; or & with
// no command before it is passed over, and a redirect with no target has
// an empty one. err is where the tokens stop making a script, or -1; end is
// where the tokens' script ends; depth is how deep the command being read
// is.
type parser struct {
	s        string
	toks     []token
	i        int
	end      int
	err      int
	depth    int
	condEnds []int // condEnd for each token, found once
}

func (p *parser) done() bool { return p.i >= len(p.toks) || p.err >= 0 }
func (p *parser) tok() token { return p.toks[p.i] }

func (p *parser) fail() {
	if p.err < 0 {
		p.err = p.at()
	}
}

// at is where the token at i starts, or the end of the script.
func (p *parser) at() int {
	if p.i < len(p.toks) {
		return p.toks[p.i].span.Start
	}
	return p.end
}

// kw is whether the token at i is the word name, unquoted.
func (p *parser) kw(i int, name string) bool {
	if i >= len(p.toks) || p.toks[i].kind != tokWord {
		return false
	}
	w := p.toks[i].w
	return len(w.Parts) == 1 && w.Parts[0].Kind == PartLiteral && w.Parts[0].Quote == QuoteNone && p.s[w.Span.Start:w.Span.End] == name
}

// listEnds is whether the token at i ends a list: ;, &, a line break or
// the end of the tokens.
func (p *parser) listEnds(i int) bool {
	return i >= len(p.toks) || p.toks[i].kind == tokNewline || p.toks[i].kind == tokOp && (p.toks[i].op == opSemi || p.toks[i].op == opAmp)
}

func (p *parser) isOp(i int, op opKind) bool {
	return i < len(p.toks) && p.toks[i].kind == tokOp && p.toks[i].op == op
}

// ends is whether the token at i ends a list for the construct around it.
func (p *parser) ends() bool {
	for _, k := range []string{"then", "elif", "else", "fi", "do", "done", "esac", "}"} {
		if p.kw(p.i, k) {
			return true
		}
	}
	return p.isOp(p.i, opRParen) || p.isOp(p.i, opCaseEnd)
}

func (p *parser) skipNewlines() {
	for !p.done() && p.tok().kind == tokNewline {
		p.i++
	}
}

// list reads and-or lists up to a token that ends it.
func (p *parser) list() []Command {
	var out []Command
	for {
		for !p.done() && (p.tok().kind == tokNewline || p.isOp(p.i, opSemi) || p.isOp(p.i, opAmp)) {
			p.i++
		}
		if p.done() || p.ends() {
			return out
		}
		start := p.at()
		c := p.andOr()
		if p.err < 0 && !p.done() && p.tok().kind != tokNewline && !p.isOp(p.i, opSemi) && !p.isOp(p.i, opAmp) && !p.ends() {
			p.fail() // a command goes on with what cannot follow it: echo a ( b )
		}
		if p.err >= 0 {
			p.err = min(p.err, start) // bash reads the whole and-or list before it runs it
			return out
		}
		if c == nil {
			return out
		}
		if p.isOp(p.i, opAmp) {
			c = &Asynchronous{span: Span{c.Span().Start, p.toks[p.i].span.End}, Command: c}
			p.i++
		}
		out = append(out, c)
	}
}

func (p *parser) andOr() Command {
	first := p.pipeline()
	if first == nil {
		return nil
	}
	a := &AndOr{Commands: []Command{first}}
	for !p.done() && (p.isOp(p.i, opAnd) || p.isOp(p.i, opOr)) {
		op := AndOrAnd
		if p.isOp(p.i, opOr) {
			op = AndOrOr
		}
		p.i++
		p.skipNewlines()
		c := p.pipeline()
		if c == nil {
			p.fail()
			break
		}
		a.Commands, a.Ops = append(a.Commands, c), append(a.Ops, op)
	}
	if len(a.Commands) == 1 {
		return first
	}
	a.span = Span{first.Span().Start, a.Commands[len(a.Commands)-1].Span().End}
	return a
}

func (p *parser) pipeline() Command {
	start, timed := p.i, false
	for p.kw(p.i, "!") || p.kw(p.i, "time") {
		t := p.kw(p.i, "time")
		timed = timed || t
		p.i++
		if t {
			// bash reads one -p and then one -- after time as part of the
			// reserved word (bash 5.3.15: time -p -- echo runs echo; time -p
			// -p echo and time -- -p echo run -p)
			if p.kw(p.i, "-p") {
				p.i++
			}
			if p.kw(p.i, "--") {
				p.i++
			}
		}
	}
	if timed && p.listEnds(p.i) {
		// time with no command before ;, &, a line break or the end
		// (time -p; echo): bash runs nothing and prints the times, a
		// command of no words; elsewhere (time && x, (time)) bash refuses
		// the script
		sp := Span{p.toks[start].span.Start, p.toks[p.i-1].span.End}
		return &Simple{span: sp, ext: sp.End}
	}
	first := p.command()
	if first == nil {
		return nil
	}
	pl := &Pipeline{Commands: []Command{first}}
	for !p.done() && (p.isOp(p.i, opPipe) || p.isOp(p.i, opPipeAll)) {
		all := p.isOp(p.i, opPipeAll)
		p.i++
		p.skipNewlines()
		c := p.command()
		if c == nil {
			p.fail()
			break
		}
		pl.Commands, pl.Stderr = append(pl.Commands, c), append(pl.Stderr, all)
	}
	if len(pl.Commands) == 1 {
		return first
	}
	pl.span = Span{first.Span().Start, pl.Commands[len(pl.Commands)-1].Span().End}
	return pl
}

func (p *parser) command() Command {
	if p.done() {
		return nil
	}
	start := p.tok().span.Start
	if p.depth++; p.depth > maxDepth {
		p.fail()
		return nil
	}
	defer func() { p.depth-- }()
	var c *Compound
	switch {
	case p.kw(p.i, "coproc"):
		return p.coproc(start)
	case p.kw(p.i, "{"):
		p.i++
		c = &Compound{Kind: CompoundBrace, Body: p.list()}
		p.expect("}")
	case p.isOp(p.i, opLParen) && p.isOp(p.i+1, opLParen) && p.toks[p.i+1].span.Start == p.toks[p.i].span.End:
		c = &Compound{Kind: CompoundArith}
		from := p.i
		p.arith()
		if p.err < 0 {
			c.Arith = p.arithSubs(arithmetics(p.s, Span{p.toks[from].span.Start, p.toks[p.i-1].span.End}, false))
		}
	case p.isOp(p.i, opLParen):
		p.i++
		c = &Compound{Kind: CompoundSubshell, Body: p.list()}
		if !p.isOp(p.i, opRParen) {
			p.fail()
			return nil
		}
		p.i++
	case p.kw(p.i, "if"):
		c = p.ifClause()
	case p.kw(p.i, "while"), p.kw(p.i, "until"):
		c = &Compound{Kind: CompoundWhile}
		if p.kw(p.i, "until") {
			c.Kind = CompoundUntil
		}
		p.i++
		c.lists = append(c.lists, 0)
		c.Body = p.list()
		p.expect("do")
		c.lists = append(c.lists, len(c.Body))
		c.Body = append(c.Body, p.list()...)
		p.expect("done")
	case p.kw(p.i, "for"), p.kw(p.i, "select"):
		c = p.forClause()
	case p.kw(p.i, "case"):
		c = p.caseClause()
	case p.kw(p.i, "[["):
		return p.cond()
	case p.kw(p.i, "function"):
		return p.funcDef(start, true)
	case p.tok().kind == tokWord && p.isOp(p.i+1, opLParen) && p.isOp(p.i+2, opRParen) && isName(p.s[p.tok().span.Start:p.tok().span.End]):
		return p.funcDef(start, false)
	case p.ends():
		return nil
	default:
		return p.simple()
	}
	if p.err >= 0 {
		p.err = min(p.err, start) // a compound command not closed is not in the tree
		return nil
	}
	c.span = Span{start, p.toks[p.i-1].span.End}
	for !p.done() && p.tok().kind == tokRedir {
		c.Redirects = append(c.Redirects, p.redirect())
	}
	if n := len(c.Redirects); n > 0 {
		c.span.End = c.Redirects[n-1].Span.End
	}
	return c
}

// coproc reads coproc [NAME] command (bash's parse.y): the word right
// after coproc is read as a reserved word, and a word is the name only
// when a compound command follows it.
func (p *parser) coproc(start int) Command {
	p.i++
	var name *Word
	if !p.startsShellCommand(p.i) && !p.done() && p.tok().kind == tokWord && p.startsShellCommand(p.i+1) {
		w := p.word(p.tok().w)
		name = &w
		p.i++
	}
	body := p.command()
	if body == nil {
		p.fail() // bash refuses coproc with no command after it
		return nil
	}
	return &Compound{span: Span{start, body.Span().End}, Kind: CompoundCoproc, Name: name, Body: []Command{body}}
}

// startsShellCommand is whether the token at i starts a compound command,
// which may follow the name of a coproc.
func (p *parser) startsShellCommand(i int) bool {
	if p.isOp(i, opLParen) {
		return true
	}
	for _, k := range []string{"{", "if", "while", "until", "for", "select", "case", "[["} {
		if p.kw(i, k) {
			return true
		}
	}
	return false
}

func (p *parser) expect(name string) {
	if !p.kw(p.i, name) {
		p.fail()
		return
	}
	p.i++
}

func (p *parser) ifClause() *Compound {
	c := &Compound{Kind: CompoundIf}
	list := func() {
		c.lists = append(c.lists, len(c.Body))
		c.Body = append(c.Body, p.list()...)
	}
	p.i++
	list()
	p.expect("then")
	list()
	for p.kw(p.i, "elif") {
		p.i++
		list()
		p.expect("then")
		list()
	}
	if p.kw(p.i, "else") {
		p.i++
		list()
		c.elseAt = true
	}
	p.expect("fi")
	return c
}

// arith reads (( ... )) up to the )) that closes it.
func (p *parser) arith() {
	depth := 0
	for !p.done() {
		t := p.tok()
		p.i++
		switch {
		case t.kind == tokOp && t.op == opLParen:
			depth++
		case t.kind == tokOp && t.op == opRParen:
			depth--
			if depth == 0 {
				return
			}
		}
	}
	p.fail()
}

func (p *parser) forClause() *Compound {
	c := &Compound{Kind: CompoundFor}
	if p.kw(p.i, "select") {
		c.Kind = CompoundSelect
	}
	p.i++
	switch {
	case p.isOp(p.i, opLParen): // for (( ; ; ))
		from := p.i
		p.arith()
		if p.err < 0 {
			c.Arith = p.arithSubs(arithmetics(p.s, Span{p.toks[from].span.Start, p.toks[p.i-1].span.End}, true))
		}
	case !p.done() && p.tok().kind == tokWord:
		// the words up to the first operator or line, which the classifier does
		// not follow (the lexer before the tree did not)
		c.list = Span{p.tok().span.End, p.end}
		for k := p.i; k < len(p.toks); k++ {
			if p.toks[k].kind == tokOp || p.toks[k].kind == tokNewline {
				c.list.End = p.toks[k].span.Start
				break
			}
		}
		name := p.word(p.tok().w)
		c.Var = &name
		p.i++
		p.skipNewlines()
		if p.kw(p.i, "in") {
			c.HasIn = true
			p.i++
			for !p.done() && p.tok().kind == tokWord {
				c.In = append(c.In, p.word(p.tok().w))
				p.i++
			}
		}
	default:
		p.fail()
		return c
	}
	for !p.done() && (p.isOp(p.i, opSemi) || p.tok().kind == tokNewline) {
		p.i++
	}
	p.expect("do")
	c.Body = p.list()
	p.expect("done")
	return c
}

// caseClause reads case ... esac without reading the patterns and the
// commands inside: a case inside at the place of a command opens another.
func (p *parser) caseClause() *Compound {
	c := &Compound{Kind: CompoundCase}
	p.i++
	depth, cmdPos := 1, false
	for !p.done() {
		t := p.tok()
		switch {
		case t.kind == tokWord && cmdPos && p.kw(p.i, "case"):
			depth++
		case t.kind == tokWord && cmdPos && p.kw(p.i, "esac"):
			depth--
			if depth == 0 {
				p.i++
				return c
			}
		}
		cmdPos = t.kind == tokNewline || t.kind == tokOp
		p.i++
	}
	p.fail()
	return c
}

func (p *parser) funcDef(start int, keyword bool) Command {
	if keyword {
		p.i++
	}
	if p.done() || p.tok().kind != tokWord {
		p.fail()
		return nil
	}
	f := &FuncDef{Name: p.word(p.tok().w)}
	p.i++
	if p.isOp(p.i, opLParen) && p.isOp(p.i+1, opRParen) {
		p.i += 2
	}
	p.skipNewlines()
	body := p.command()
	if _, ok := body.(*Compound); !ok {
		p.fail()
		return nil
	}
	f.Body = body
	f.span = Span{start, body.Span().End}
	return f
}

func (p *parser) simple() Command {
	s := &Simple{span: Span{Start: p.tok().span.Start, End: -1}}
loop:
	for !p.done() {
		switch t := p.tok(); t.kind {
		case tokWord:
			w := p.word(t.w)
			if p.err >= 0 {
				break loop // a substitution the parser cannot follow: the tree ends before the word
			}
			if len(s.Words) == 0 && isAssign(p.s, w) || len(s.Words) == 0 && isElementAssign(p.s, w) {
				s.Assigns = append(s.Assigns, w)
			} else {
				s.Words = append(s.Words, w)
			}
			s.span.End = t.span.End
			p.i++
		case tokRedir:
			r := p.redirect()
			s.Redirects = append(s.Redirects, r)
			s.span.End = r.Span.End
		default:
			break loop
		}
	}
	if s.span.End < 0 {
		p.fail() // an operator where a command should be
		return nil
	}
	s.ext = p.at()
	return s
}

// cond reads [[ ... ]] up to its ]] as one simple command: && and ||
// inside do not end it, and < and > are its operators. With no ]] before
// what ends a command, it is read as any simple command, which bash
// refuses.
func (p *parser) cond() Command {
	end := p.condEnd(p.i + 1)
	if !p.kw(end, "]]") {
		return p.simple()
	}
	s := &Simple{span: Span{p.tok().span.Start, p.toks[end].span.End}, isCond: true}
	inside := p.toks[p.i+1 : end]
	for ; p.i <= end; p.i++ {
		if t := p.tok(); t.kind == tokWord {
			if s.Words = append(s.Words, p.word(t.w)); p.err >= 0 {
				return nil // a substitution the parser cannot follow
			}
		}
	}
	s.cond = condRoles(p.s, inside)
	for !p.done() && p.tok().kind == tokRedir {
		r := p.redirect()
		s.Redirects = append(s.Redirects, r)
		s.span.End = r.Span.End
	}
	s.ext = p.at()
	return s
}

// condEnd is the first token from k on that is ]] or ends a command
// before one (;, &, ;;, a heredoc), or the end of the tokens: found for
// all the tokens at once, so that many [[ with no ]] are read in linear
// time.
func (p *parser) condEnd(k int) int {
	if p.condEnds == nil {
		n := len(p.toks)
		p.condEnds = make([]int, n+1)
		p.condEnds[n] = n
		for j := n - 1; j >= 0; j-- {
			t := p.toks[j]
			p.condEnds[j] = p.condEnds[j+1]
			if p.kw(j, "]]") || t.kind == tokOp && (t.op == opSemi || t.op == opAmp || t.op == opCaseEnd) || t.kind == tokRedir && t.doc != nil {
				p.condEnds[j] = j
			}
		}
	}
	return p.condEnds[min(k, len(p.toks))]
}

// isElementAssign is whether w assigns an element of an array,
// NAME[subscript]=value or += (AssignedName), which bash reads as an
// assignment before the command word.
func isElementAssign(s string, w Word) bool {
	_, _, element, ok := AssignedName(s, w)
	return ok && element
}

// isAssign is whether w is NAME=value: its first part unquoted, starting
// with a name and =.
func isAssign(s string, w Word) bool {
	if len(w.Parts) == 0 || w.Parts[0].Kind != PartLiteral || w.Parts[0].Quote != QuoteNone {
		return false
	}
	lit := s[w.Parts[0].Span.Start:w.Parts[0].Span.End]
	eq := strings.IndexByte(lit, '=')
	return eq > 0 && isName(strings.TrimSuffix(lit[:eq], "+"))
}

func (p *parser) redirect() Redirect {
	t := p.tok()
	p.i++
	r := Redirect{Span: t.span, Op: t.redir, Fd: t.fd, Var: VarName{t.fdVar}}
	switch {
	case t.doc != nil:
		r.Target, r.Heredoc = t.doc.delim, &t.doc.body
		if !p.subs(t.doc.body.Parts) && (p.err < 0 || t.span.Start < p.err) {
			p.err = t.span.Start
		}
	case !p.done() && p.tok().kind == tokWord:
		r.Target = p.word(p.tok().w)
		r.Span.End = r.Target.Span.End
		p.i++
	default:
		r.Target = Word{id: -1, Span: Span{t.span.End, t.span.End}} // no target: bash would refuse it
	}
	return r
}

// word is w with the scripts of its substitutions. When one of them is not
// a script, the parser fails at the word.
func (p *parser) word(w *Word) Word {
	out := *w
	out.Parts = append([]Part(nil), w.Parts...)
	if !p.subs(out.Parts) && (p.err < 0 || w.Span.Start < p.err) {
		p.err = w.Span.Start
	}
	return out
}

// subs makes the scripts of the substitutions of ps; it is false when one
// of them is not a script, which then stops where the parser stopped in
// it.
func (p *parser) subs(ps []Part) bool {
	ok := true
	for i := range ps {
		pt := &ps[i]
		switch {
		case pt.Kind == PartSubst && pt.Backquote:
			pt.Sub = backquote(p.s, pt, p.depth+1) // not complete: bash refuses it when it runs
		case pt.Kind == PartSubst || pt.Kind == PartProcIn || pt.Kind == PartProcOut:
			sub := &parser{s: p.s, toks: pt.toks, end: pt.Span.End, err: -1, depth: p.depth}
			pt.Sub = &Script{List: sub.list(), Complete: true, Stop: pt.Span.End}
			if sub.err < 0 && sub.i < len(sub.toks) {
				sub.err = sub.toks[sub.i].span.Start
			}
			if sub.err >= 0 {
				pt.Sub.Complete, pt.Sub.Stop, ok = false, sub.err, false
			}
			pt.toks = nil
		case pt.Kind == PartParamOp:
			if pt.Param != nil && !p.paramSubs(pt.Param) {
				ok = false
			}
		case pt.Kind == PartArith:
			if pt.Arith != nil && !p.subs(pt.Arith.Parts) {
				ok = false
			}
		}
	}
	return ok
}

// arithSubs makes the scripts of the substitutions of the expressions as,
// as subs does; an expression one of whose substitutions is not a script
// is left out.
func (p *parser) arithSubs(as []*Arithmetic) []*Arithmetic {
	var out []*Arithmetic
	for _, a := range as {
		if p.subs(a.Parts) {
			out = append(out, a)
		}
	}
	return out
}

// paramSubs makes the scripts of the substitutions in the words of the
// ${ } x, as subs does.
func (p *parser) paramSubs(x *ParamExpansion) bool {
	ok := true
	for _, w := range []*Word{x.Subscript, x.Offset, x.Length} {
		if w != nil && !p.subs(w.Parts) {
			ok = false
		}
	}
	for i := range x.Words {
		if !p.subs(x.Words[i].Parts) {
			ok = false
		}
	}
	return ok
}
