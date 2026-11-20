package shell

import (
	"regexp"
	"strings"
)

// the tokens of a script (tokenize): the lexer of quotes, expansions and
// heredocs, which knows nothing of what a command does

type tokKind uint8

const (
	tokUnset tokKind = iota
	tokWord          // w
	tokOp            // op
	tokRedir         // redir and fd; the next token is its target, but a heredoc's is doc
	tokNewline
)

type opKind uint8

const (
	opUnset   opKind = iota
	opSemi           // ;
	opAmp            // &
	opAnd            // &&
	opOr             // ||
	opPipe           // |
	opPipeAll        // |&
	opLParen         // (
	opRParen         // )
	opCaseEnd        // ;;, ;& and ;;&
)

type token struct {
	kind  tokKind
	span  Span
	w     *Word
	op    opKind
	redir RedirOp
	fd    int
	fdVar string // the name of {name} before the operator of a redirect, or ""
	doc   *pendingDoc
}

// pendingDoc is a heredoc: its delimiter as written, and once the line of
// its operator ends, its body.
type pendingDoc struct {
	strip bool
	delim Word
	body  HeredocBody
	at    int // where its operator is
}

// mark is what the tokenizer knows of a place of at: its context by the
// quotes alone (Unknown inside an expansion, in a unit read at once, on a
// line of an unquoted heredoc's body with $(, ${ or `), whether a string
// put there joins the byte before it, the word of the top frame it is in
// or ends (-1: none), and the heredoc whose body or delimiter's line it is
// in.
type mark struct {
	set       bool
	ctx       Quoting
	joins     bool
	word      int
	doc       *pendingDoc
	delimLine bool
	nested    bool // inside $( ), <( ), >( ), $(( )), ` ` or ${ }: the tree tells how it is read
}

// lexed is what tokenize gives: the tokens of the top frame, the marks of
// at, and where it stopped.
type lexed struct {
	toks           []token
	marks          []mark
	complete       bool
	unterminated   bool // a quote, an expansion or a heredoc left open: bash would not run it
	stop           int
	nwords         int
	afterContinued map[int]bool // where a word starts right after a line continued
	procOuts       []int        // where each >( ) of the top frame starts
}

type lexState uint8

const (
	inNormal   lexState = iota // outside quotes
	inDouble                   // "..."
	inSingle                   // '...'
	inANSI                     // $'...'
	inComment                  // # to the end of the line
	inSubst                    // $( ), <( ), >( ): counting parentheses
	inArith                    // $(( )) and an array's ( ): counting parentheses, making no tokens
	inBacktick                 // ` ... `
	inBrace                    // ${ ... }
	inHeredoc                  // the body of an unquoted heredoc, read for its parts
	inOperand                  // a word after the operator of a ${ } (operand), read for its parts
)

// frame is a list of tokens being made: the script's, or that of a $( ),
// <( ) or >( ). level is the index in the stack of the state its words
// are read in.
type frame struct {
	level     int
	toks      []token
	wordStart bool
	cur       *Word
	qopen     int        // the parts of cur when its quote opened
	open      []openPart // the parts of cur being read: expansions not closed
}

type openPart struct {
	idx  int // the index in the stack of its state
	part Part
}

type tokenizer struct {
	s              string
	i, end         int
	at             []int
	nxt            int
	marks          []mark
	stack          []lexState
	starts         []int // where each state of stack began
	depths         []int
	frames         []*frame
	pending        []*pendingDoc
	poisoned       bool
	stopAt         int
	nwords         int
	afterContinued map[int]bool
	procOuts       []int
	outerQuote     Quote // the quote of the parts read outside a quote of their own (operand)
	singleQuotes   bool  // operand: ' begins a quote
	paramDepth     int   // how many ${ } the bytes are inside (paramExpansion)
}

// tokenize reads the script s, and marks the places at (in increasing
// order).
func tokenize(s string, at []int) *lexed {
	l := &tokenizer{s: s, end: len(s), at: at, marks: make([]mark, len(at)), stack: []lexState{inNormal}, starts: []int{0}, depths: []int{1}}
	l.frames = []*frame{{wordStart: true}}
	l.run()
	out := &lexed{toks: l.frames[0].toks, marks: l.marks, complete: true, stop: len(s), nwords: l.nwords, afterContinued: l.afterContinued, procOuts: l.procOuts}
	switch {
	case l.poisoned:
		out.complete, out.stop = false, l.stopAt
	case len(l.stack) != 1 || len(l.pending) > 0:
		out.complete, out.unterminated, out.stop = false, true, l.openAt()
	}
	return out
}

// openAt is where the outermost construct left open begins, or the word
// it is in, which is not in the tree.
func (l *tokenizer) openAt() int {
	at := len(l.s)
	if len(l.starts) > 1 {
		at = l.starts[1]
	}
	for _, d := range l.pending {
		at = min(at, d.at)
	}
	if w := l.frames[0].cur; w != nil {
		at = min(at, w.Span.Start)
	}
	return at
}

// poison stops the lexer at a form it does not follow; the word it is in
// is not in the tree.
func (l *tokenizer) poison() {
	l.poisoned, l.stopAt = true, l.i
	if w := l.frames[0].cur; w != nil {
		l.stopAt = w.Span.Start
	}
}

func (l *tokenizer) top() lexState { return l.stack[len(l.stack)-1] }
func (l *tokenizer) fr() *frame    { return l.frames[len(l.frames)-1] }

// rel is how far the state is below the level of the frame's words: 0
// among them, 1 inside a quote of one.
func (l *tokenizer) rel() int { return len(l.stack) - 1 - l.fr().level }

// partLevel is whether a part read here is a part of the frame's word:
// among its words, or inside a quote of one.
func (l *tokenizer) partLevel() bool {
	r := l.rel()
	return r == 0 && l.top() != inArith || r == 1 && isQuote(l.top())
}

func isQuote(s lexState) bool { return s == inDouble || s == inSingle || s == inANSI }

// quote is the quote of a part read here.
func (l *tokenizer) quote() Quote {
	f := l.fr()
	if len(l.stack)-1 > f.level {
		switch l.stack[f.level+1] {
		case inDouble:
			return QuoteDouble
		case inSingle:
			return QuoteSingle
		case inANSI:
			return QuoteANSI
		}
	}
	if len(l.frames) == 1 {
		return l.outerQuote // the word of operand; a substitution in it has its own words
	}
	return QuoteNone
}

func (l *tokenizer) next(k int) byte {
	if l.i+k < l.end {
		return l.s[l.i+k]
	}
	return 0
}

// mark marks the places of at up to l.i, as the state is before the byte
// at l.i.
func (l *tokenizer) mark() {
	f0 := l.frames[0]
	for l.nxt < len(l.at) && l.at[l.nxt] < l.i {
		l.nxt++ // inside a unit read at once: not marked, so Unknown
	}
	if l.nxt < len(l.at) && l.at[l.nxt] == l.i && len(l.stack) == 1 && f0.wordStart && l.i < l.end && startsWord(l.s[l.i]) && !l.continued() {
		l.startWord() // a place at the first byte of a word is in the word
	}
	for l.nxt < len(l.at) && l.at[l.nxt] <= l.i {
		if l.at[l.nxt] == l.i {
			m := mark{set: true, ctx: l.base(), joins: l.joins(l.i), word: -1, nested: l.inExpansion()}
			if f0.cur != nil {
				m.word = f0.cur.id
			}
			l.marks[l.nxt] = m
		}
		l.nxt++
	}
}

func (l *tokenizer) joins(i int) bool { return i > 0 && (l.s[i-1] == '$' || l.s[i-1] == '\\') }

// continued is whether l.i is a backslash that continues the line.
func (l *tokenizer) continued() bool { return l.s[l.i] == '\\' && l.next(1) == '\n' }

// inExpansion is whether the state is inside $( ), <( ), >( ), $(( )),
// the ( ) of an array, ` ` or ${ }.
func (l *tokenizer) inExpansion() bool {
	for _, s := range l.stack {
		switch s {
		case inSubst, inArith, inBacktick, inBrace:
			return true
		}
	}
	return false
}

// base is the context of the state by the quotes alone; inside an
// expansion, QuotingUnknown (the tree tells: classifier.nested).
func (l *tokenizer) base() Quoting {
	if l.inExpansion() {
		return QuotingUnknown
	}
	switch l.top() {
	case inComment:
		return Comment
	case inDouble:
		return DoubleQuoted
	case inSingle, inANSI:
		return SingleQuoted
	}
	return Unquoted
}

func (l *tokenizer) run() {
	for l.i < l.end && !l.poisoned {
		l.mark()
		switch l.top() {
		case inNormal, inSubst, inArith:
			l.normal()
		case inDouble:
			l.double()
		case inSingle:
			if l.s[l.i] == '\'' {
				l.closeQuote()
			} else {
				l.lit(1)
			}
		case inANSI:
			switch l.s[l.i] {
			case '\\':
				l.lit(2)
			case '\'':
				l.closeQuote()
			default:
				l.lit(1)
			}
		case inComment:
			if l.s[l.i] == '\n' {
				l.pop()
				continue
			}
			l.i++
		case inBacktick:
			switch l.s[l.i] {
			case '\\':
				l.i += 2
			case '`':
				l.pop()
				l.i++
			default:
				l.i++
			}
		case inBrace:
			l.brace()
		case inHeredoc:
			l.heredocByte()
		case inOperand:
			l.operandByte()
		}
	}
	if l.poisoned {
		return
	}
	l.i = min(l.i, l.end) // a backslash at the end
	if l.top() == inComment {
		l.mark()
		l.pop() // a comment ends with the script
		return
	}
	l.mark()                                                                     // a place at the end is in the word it ends
	if len(l.stack) == 1 && l.stack[0] != inHeredoc && l.stack[0] != inOperand { // lexBody and operand take the parts of their word as they are
		l.endWord()
	}
}

// lit reads n bytes as they are: a literal of the word, when among the
// frame's words or inside a quote of one.
func (l *tokenizer) lit(n int) {
	end := min(l.i+n, l.end)
	if l.partLevel() {
		l.addLit(l.i, end)
	}
	l.i += n
}

func (l *tokenizer) addLit(start, end int) {
	w := l.fr().cur
	if w == nil {
		return
	}
	q := l.quote()
	if n := len(w.Parts); n > 0 {
		if p := &w.Parts[n-1]; p.Kind == PartLiteral && p.Quote == q && p.Span.End == start {
			p.Span.End = end
			return
		}
	}
	w.Parts = append(w.Parts, Part{Span: Span{start, end}, Quote: q})
}

func (l *tokenizer) push(s lexState) {
	l.stack = append(l.stack, s)
	l.starts = append(l.starts, l.i)
	l.depths = append(l.depths, 1)
}

// pop closes the state on top: the frame of a substitution it is, and the
// part it reads, which ends after the byte at l.i.
func (l *tokenizer) pop() {
	idx := len(l.stack) - 1
	var sub *frame
	if f := l.fr(); f.level == idx && idx > 0 {
		l.endWord()
		sub = f
		l.frames = l.frames[:len(l.frames)-1]
	}
	l.stack, l.starts, l.depths = l.stack[:idx], l.starts[:idx], l.depths[:idx]
	f := l.fr()
	if n := len(f.open); n > 0 && f.open[n-1].idx == idx {
		o := f.open[n-1]
		f.open = f.open[:n-1]
		o.part.Span.End = min(l.i+1, l.end)
		if o.part.Kind == PartParam {
			inside := Span{o.part.Span.Start + 2, max(o.part.Span.Start+2, o.part.Span.End-1)}
			o.part.Kind, o.part.Name = braced(l.s[inside.Start:inside.End])
			if o.part.Kind == PartParamOp && l.s[o.part.Span.End-1] == '}' {
				q := o.part.Quote
				if q == QuoteNone && len(l.frames) == 1 && l.stack[0] == inHeredoc {
					q = QuoteDouble // the body of a heredoc is expanded as inside "..."
				}
				o.part.Param = l.paramExpansion(inside, q)
			}
		}
		if sub != nil {
			o.part.toks = sub.toks
		}
		if o.part.Kind == PartOpaque && l.s[o.part.Span.Start] == '`' && o.part.Span.End-o.part.Span.Start >= 2 && l.s[o.part.Span.End-1] == '`' {
			o.part.Kind, o.part.Backquote = PartSubst, true // parse makes its Sub
			// bash takes the backslash off \" inside it only when the ` ` is
			// right inside "...": not in a ${ } operand of "${ }" (bash 5.3)
			o.part.inDouble = l.top() == inDouble && l.outerQuote != QuoteDouble
		}
		if o.part.Kind == PartOpaque && strings.HasPrefix(l.s[o.part.Span.Start:], "$((") && strings.HasSuffix(l.s[:o.part.Span.End], "))") && o.part.Span.End-o.part.Span.Start >= 5 {
			o.part.Kind = PartArith
			o.part.Arith = arithmeticAt(l.s, Span{o.part.Span.Start + 3, o.part.Span.End - 2}, l.paramDepth)
		}
		if f.cur != nil {
			f.cur.Parts = append(f.cur.Parts, o.part)
		}
	}
}

// braced is what ${inside} is: a parameter, or one with an operator, and
// the name it expands.
func braced(inside string) (PartKind, VarName) {
	if isName(inside) || len(inside) == 1 && strings.IndexByte("@*#?-$!", inside[0]) >= 0 || inside != "" && strings.Trim(inside, "0123456789") == "" {
		return PartParam, VarName{inside}
	}
	s := strings.TrimLeft(inside, "#!")
	n := 0
	for n < len(s) && isNameByte(s[n]) {
		n++
	}
	return PartParamOp, VarName{s[:n]}
}

// openPart starts a part of kind k at l.i, which a state pushed next reads;
// withFrame, the state is a substitution with a frame of its own.
func (l *tokenizer) openPart(k PartKind, withFrame bool) {
	if !l.partLevel() {
		return
	}
	f := l.fr()
	f.open = append(f.open, openPart{idx: len(l.stack), part: Part{Span: Span{Start: l.i}, Quote: l.quote(), Kind: k}})
	if withFrame {
		l.frames = append(l.frames, &frame{level: len(l.stack), wordStart: true})
	}
}

func (l *tokenizer) openQuote(s lexState, n int) {
	if f := l.fr(); l.rel() == 0 && f.cur != nil {
		f.qopen = len(f.cur.Parts)
	}
	l.push(s)
	l.i += n
}

// closeQuote closes a quote at l.i: an empty one is an empty part.
func (l *tokenizer) closeQuote() {
	f := l.fr()
	if l.rel() == 1 && f.cur != nil && len(f.cur.Parts) == f.qopen {
		f.cur.Parts = append(f.cur.Parts, Part{Span: Span{l.i, l.i}, Quote: l.quote()})
	}
	l.pop()
	l.i++
}

// expansion handles $(, $((, ${, ` and $[ at l.i, and $' outside quotes;
// it is false when there is none.
func (l *tokenizer) expansion(ansi bool) bool {
	c, next := l.s[l.i], l.next(1)
	switch {
	case c == '`':
		l.openPart(PartOpaque, false)
		l.push(inBacktick)
		l.i++
	case c == '$' && next == '(' && l.next(2) == '(':
		l.openPart(PartOpaque, false)
		l.push(inArith) // the second ( is counted inside
		l.i += 2
	case c == '$' && next == '(':
		l.openPart(PartSubst, true)
		l.push(inSubst)
		l.i += 2
	case c == '$' && next == '{':
		l.openPart(PartParam, false)
		l.push(inBrace)
		l.i += 2
	case c == '$' && next == '[': // $[ ], old arithmetic: not followed
		l.poison()
	case ansi && c == '$' && next == '\'':
		l.openQuote(inANSI, 2)
	default:
		return false
	}
	return true
}

// param reads $NAME, $1 or one of $@ $* $# $? $- $$ $! at l.i as a part.
func (l *tokenizer) param() bool {
	c := l.next(1)
	j := l.i + 2
	switch {
	case isNameStart(c):
		for j < l.end && isNameByte(l.s[j]) {
			j++
		}
	case '0' <= c && c <= '9', c != 0 && strings.IndexByte("@*#?-$!", c) >= 0:
	default:
		return false
	}
	if w := l.fr().cur; l.partLevel() && w != nil {
		w.Parts = append(w.Parts, Part{Span: Span{l.i, j}, Quote: l.quote(), Kind: PartParam, Name: VarName{l.s[l.i+1 : j]}})
	}
	l.i = j
	return true
}

// normal reads a byte outside quotes: among the words of a frame, or
// inside $(( )) or an array's ( ).
func (l *tokenizer) normal() {
	f := l.fr()
	own := l.rel() == 0 && l.top() != inArith
	c := l.s[l.i]
	if l.top() == inArith && l.arithmetic() {
		l.arith() // inside $(( )): blanks, lines, # and << are of the expression
		return
	}
	switch {
	case c == '\\':
		if l.next(1) == '\n' && len(l.pending) > 0 {
			l.poison() // a heredoc on a continued line
			return
		}
		if l.next(1) == '\n' && f.wordStart {
			l.i += 2 // a line continued: no word
			if l.afterContinued == nil {
				l.afterContinued = map[int]bool{}
			}
			l.afterContinued[l.i] = true
			return
		}
		l.startWord()
		l.lit(2)
		return
	case c == '#' && f.wordStart:
		l.endWord()
		l.push(inComment)
		l.i++
		return
	case c == '\n':
		l.endWord()
		if own {
			f.toks = append(f.toks, token{kind: tokNewline, span: Span{l.i, l.i + 1}})
		}
		l.i++
		if len(l.stack) == 1 {
			l.heredocs()
		} else if len(l.pending) > 0 {
			l.poison() // a heredoc begun inside $( )
		}
		f.wordStart = true
		return
	case isBlank(c):
		l.endWord()
		f.wordStart = true
		l.i++
		return
	case strings.HasPrefix(l.s[l.i:l.end], "<<<"):
		l.endWord()
		l.emitRedir(RedirHereString, 3, own)
		return
	case strings.HasPrefix(l.s[l.i:l.end], "<<"):
		l.endWord()
		l.readHeredoc(own)
		return
	case (c == '<' || c == '>') && l.next(1) == '(':
		l.endWord()
		f.wordStart = true
		l.startWord() // <( ) and >( ) are a word of their own
		k := PartProcIn
		if c == '>' {
			k = PartProcOut
			if len(l.frames) == 1 {
				l.procOuts = append(l.procOuts, l.i)
			}
		}
		l.openPart(k, true)
		l.push(inSubst)
		l.i += 2
		return
	case l.rel() > 0: // inside $(( )) or an array's ( ): parentheses and quotes only
		l.arith()
		return
	case len(l.stack) > 1 && f.wordStart && strings.HasPrefix(l.s[l.i:l.end], "case") && (l.i+4 == l.end || isBlank(l.s[l.i+4])):
		l.poison() // a case pattern's ) would close the $( )
		return
	case c == '(' && own && f.cur != nil && arrayAssign.MatchString(l.s[f.cur.Span.Start:l.i]):
		l.openPart(PartOpaque, false)
		l.push(inArith) // X=( ... ): the list, not read
		l.i++
		return
	case l.top() == inSubst && c == '(':
		l.endWord()
		l.depths[len(l.depths)-1]++
		l.emitOp(opLParen, 1)
		return
	case l.top() == inSubst && c == ')':
		l.endWord()
		l.depths[len(l.depths)-1]--
		if l.depths[len(l.depths)-1] == 0 {
			l.pop()
			l.i++
			return
		}
		l.emitOp(opRParen, 1)
		return
	case isOperator(c):
		l.endWord()
		l.operator()
		return
	}
	l.startWord()
	switch {
	case c == '"':
		l.openQuote(inDouble, 1)
	case c == '\'':
		l.openQuote(inSingle, 1)
	case l.expansion(true):
	case c == '$' && l.param():
	default:
		l.lit(1)
	}
}

// arithmetic is whether the inArith state on top is an arithmetic
// expansion $(( )), not the ( ) of an array's assignment.
func (l *tokenizer) arithmetic() bool {
	return strings.HasPrefix(l.s[l.starts[len(l.starts)-1]:], "$((")
}

// arith reads a byte inside $(( )) or an array's ( ): quotes, expansions
// and parentheses, to find where it ends.
func (l *tokenizer) arith() {
	switch c := l.s[l.i]; {
	case c == '#' && !l.arithmetic() && l.i > 0 && (isBlank(l.s[l.i-1]) || l.s[l.i-1] == '\n' || l.s[l.i-1] == '('):
		l.push(inComment) // in the ( ) of an array, a # that starts a word begins a comment
		l.i++
	case c == '\\':
		l.i += 2
	case c == '"':
		l.push(inDouble)
		l.i++
	case c == '\'':
		l.push(inSingle)
		l.i++
	case c == '(':
		l.depths[len(l.depths)-1]++
		l.i++
	case c == ')':
		l.depths[len(l.depths)-1]--
		if l.depths[len(l.depths)-1] == 0 {
			l.pop()
		}
		l.i++
	case l.expansion(false):
	default:
		l.i++
	}
}

var arrayAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=$`)

func (l *tokenizer) emitOp(op opKind, n int) {
	if f := l.fr(); l.rel() == 0 {
		f.toks = append(f.toks, token{kind: tokOp, span: Span{l.i, l.i + n}, op: op})
		f.wordStart = true
	}
	l.i += n
}

// emitRedir makes a redirect of n bytes at l.i, taking as its number the
// word of digits right before it, or as its variable the word {name} right
// before it (bashref, "Redirections").
func (l *tokenizer) emitRedir(op RedirOp, n int, own bool) {
	f := l.fr()
	t := token{kind: tokRedir, span: Span{l.i, l.i + n}, redir: op, fd: -1}
	if own {
		l.takeFd(&t)
		f.toks = append(f.toks, t)
	}
	l.i += n
	f.wordStart = true
}

// takeFd takes the word right before the redirect t at l.i as the number
// of t, when the word is digits, or as its variable, when the word is
// {name} (bashref, "Redirections"), for every redirect operator, the
// heredoc's among them.
func (l *tokenizer) takeFd(t *token) {
	f := l.fr()
	k := len(f.toks)
	if k == 0 || f.toks[k-1].kind != tokWord || f.toks[k-1].span.End != l.i {
		return
	}
	w := l.s[f.toks[k-1].span.Start:l.i]
	ps := f.toks[k-1].w.Parts
	switch {
	case w != "" && strings.Trim(w, "0123456789") == "" && fdNumber(w):
		t.fd = atoi(strings.TrimLeft(w, "0"))
	case len(w) > 2 && w[0] == '{' && w[len(w)-1] == '}' && isName(w[1:len(w)-1]) && len(ps) == 1 && ps[0].Kind == PartLiteral && ps[0].Quote == QuoteNone:
		t.fdVar = w[1 : len(w)-1]
	default:
		return
	}
	t.span.Start = f.toks[k-1].span.Start
	f.toks = f.toks[:k-1]
}

// fdNumber is whether the digits w are a number that fits in an int of
// bash (at most 2147483647, leading zeros aside): bash takes such a word
// right before a redirect operator as its descriptor, and a larger one as
// a word (bash 5.3.15: 1000<<<x and 0003<<<x are descriptors,
// 2147483648<<<x cat runs the command 2147483648).
func fdNumber(w string) bool {
	w = strings.TrimLeft(w, "0")
	return len(w) < 10 || len(w) == 10 && w <= "2147483647"
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// operators are the operators of lists and pipelines by how they are
// written, longest first; & comes after &>> and &>, which redirOps has.
var operators = []struct {
	s  string
	op opKind
}{
	{";;&", opCaseEnd}, {";;", opCaseEnd}, {";&", opCaseEnd}, {";", opSemi}, {"&&", opAnd},
	{"||", opOr}, {"|&", opPipeAll}, {"|", opPipe}, {"(", opLParen}, {")", opRParen},
}

// operator reads the operator at l.i: a redirect, or one of lists and
// pipelines.
func (l *tokenizer) operator() {
	own := l.rel() == 0
	rest := l.s[l.i:l.end]
	for _, r := range redirOps {
		if !strings.HasPrefix(rest, r.s) {
			continue
		}
		l.emitRedir(r.op, len(r.s), own)
		return
	}
	for _, o := range operators {
		if strings.HasPrefix(rest, o.s) {
			l.emitOp(o.op, len(o.s))
			return
		}
	}
	l.emitOp(opAmp, 1) // &
}

// double reads a byte inside "...".
func (l *tokenizer) double() {
	switch c := l.s[l.i]; {
	case c == '\\':
		l.lit(2)
	case c == '"':
		l.closeQuote()
	case l.expansion(false):
	case c == '$' && l.param():
	default:
		l.lit(1)
	}
}

// brace reads a byte inside ${ }.
func (l *tokenizer) brace() {
	switch c := l.s[l.i]; {
	case c == '\\':
		l.i += 2
	case c == '"':
		l.push(inDouble)
		l.i++
	case c == '\'':
		l.push(inSingle)
		l.i++
	case c == '{':
		l.depths[len(l.depths)-1]++
		l.i++
	case c == '}':
		l.depths[len(l.depths)-1]--
		if l.depths[len(l.depths)-1] == 0 {
			l.pop()
		}
		l.i++
	case l.expansion(false):
	default:
		l.i++
	}
}

// heredocByte reads a byte of the body of an unquoted heredoc (lexBody).
func (l *tokenizer) heredocByte() {
	switch c := l.s[l.i]; {
	case c == '\\':
		l.lit(2)
	case l.expansion(false):
	case c == '$' && l.param():
	default:
		l.lit(1)
	}
}

func (l *tokenizer) startWord() {
	f := l.fr()
	if f.wordStart && l.rel() == 0 && f.cur == nil {
		f.cur = &Word{id: -1, Span: Span{Start: l.i}}
		if len(l.frames) == 1 && l.stack[0] != inHeredoc && l.stack[0] != inOperand {
			f.cur.id = l.nwords
			l.nwords++
		}
	}
	f.wordStart = false
}

// endWord ends the word of the frame being read.
func (l *tokenizer) endWord() {
	f := l.fr()
	w := f.cur
	if w == nil || l.rel() != 0 {
		return
	}
	f.cur = nil
	w.Span.End = min(l.i, l.end)
	f.toks = append(f.toks, token{kind: tokWord, span: w.Span, w: w})
}

// readHeredoc reads << or <<- and the delimiter at l.i; the body starts at
// the next line.
func (l *tokenizer) readHeredoc(own bool) {
	d := &pendingDoc{at: l.i}
	t := token{kind: tokRedir, span: Span{Start: l.i}, redir: RedirHeredoc, fd: -1, doc: d}
	if own {
		l.takeFd(&t)
	}
	l.i += 2
	if l.i < l.end && l.s[l.i] == '-' {
		d.strip, t.redir = true, RedirHeredocStrip
		l.i++
	}
	for l.i < l.end && isBlank(l.s[l.i]) {
		l.i++
	}
	start := l.i
	for l.i < l.end && !isBlank(l.s[l.i]) && l.s[l.i] != '\n' && !isOperator(l.s[l.i]) {
		switch q := l.s[l.i]; q {
		case '\'', '"':
			end := strings.IndexByte(l.s[l.i+1:l.end], q)
			if end < 0 {
				l.poison()
				return
			}
			l.i += end + 2
			continue
		case '\\':
			l.i++
		}
		l.i++
	}
	l.i = min(l.i, l.end)
	raw := l.s[start:l.i]
	if raw == "" {
		l.poison()
		return
	}
	d.body.Quoted = strings.ContainsAny(raw, `'"\`)
	d.body.Delim = Delim{unquote(raw)}
	d.delim = delimWord(l.s, start, l.i)
	t.span.End = l.i
	l.pending = append(l.pending, d)
	f := l.fr()
	if own {
		f.toks = append(f.toks, t)
	}
	f.wordStart = true
}

// delimWord is the delimiter s[start:end] as a word: its quoted and
// unquoted parts.
func delimWord(s string, start, end int) Word {
	w := Word{id: -1, Span: Span{start, end}}
	for i := start; i < end; {
		switch q := s[i]; q {
		case '\'', '"':
			j := i + 1 + strings.IndexByte(s[i+1:end], q)
			quote := QuoteSingle
			if q == '"' {
				quote = QuoteDouble
			}
			w.Parts = append(w.Parts, Part{Span: Span{i + 1, j}, Quote: quote})
			i = j + 1
		default:
			j := i
			for j < end && s[j] != '\'' && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			j = min(j, end)
			w.Parts = append(w.Parts, Part{Span: Span{i, j}})
			i = j
		}
	}
	return w
}

// heredocs reads the bodies of the heredocs of the line that ended at
// l.i, in order, and marks their places.
func (l *tokenizer) heredocs() {
	for len(l.pending) > 0 {
		d := l.pending[0]
		d.body.Body.Start = l.i
		for {
			if l.i >= l.end {
				return // not closed
			}
			end := strings.IndexByte(l.s[l.i:l.end], '\n')
			if end < 0 {
				end = l.end - l.i
			}
			line := l.s[l.i : l.i+end]
			check := line
			if d.strip {
				check = strings.TrimLeft(line, "\t")
			}
			ctx := QuotedHeredoc
			if !d.body.Quoted {
				ctx = Heredoc
			}
			// a line with an expansion: the tree tells how a place in it is read
			expands := !d.body.Quoted && (strings.ContainsAny(line, "`") || strings.Contains(line, "$(") || strings.Contains(line, "${"))
			done := check == d.body.Delim.s
			if !done && !d.body.Quoted && strings.HasSuffix(line, "\\") {
				l.poison()                     // a line continued in the body: bash joins it to the next
				l.stopAt = min(l.stopAt, d.at) // and the heredoc, whose body is not known, is not in the tree
				return
			}
			if done {
				d.body.Body.End = l.i
			}
			for l.nxt < len(l.at) && l.at[l.nxt] <= l.i+end {
				m := mark{set: true, ctx: ctx, word: -1, doc: d, delimLine: done, nested: expands && !done}
				switch {
				case done:
					m.ctx = Unquoted
				case l.joins(l.at[l.nxt]):
					m.ctx, m.joins = QuotingUnknown, true
				}
				l.marks[l.nxt] = m
				l.nxt++
			}
			l.i += end
			if l.i < l.end {
				l.i++ // the line break
			}
			if done {
				d.body.end = l.i
				break
			}
		}
		if !d.body.Quoted {
			d.body.Parts = lexBody(l.s, d.body.Body)
		}
		l.pending = l.pending[1:]
	}
}

// lexBody is the parts of the body b of an unquoted heredoc, which the
// shell expands as inside "...".
func lexBody(s string, b Span) []Part {
	l := &tokenizer{s: s, i: b.Start, end: b.End, stack: []lexState{inHeredoc}, starts: []int{b.Start}, depths: []int{1}}
	f := &frame{wordStart: true}
	l.frames = []*frame{f}
	l.startWord()
	l.run()
	if l.poisoned || len(l.stack) != 1 || f.cur == nil {
		return []Part{{Span: b, Kind: PartOpaque}}
	}
	return f.cur.Parts
}
