package expr

import (
	"strconv"
	"strings"
	"unicode"
)

// Node is a node of an expression tree. Its Span is in the string given to
// Parse.
type Node interface{ Span() Span }

type LitKind uint8

const (
	LitNull LitKind = iota
	LitBool
	LitNumber
	LitString
)

// Literal is null, true, false, a number or a string. Raw is the text as
// written; Str is the value of a string.
type Literal struct {
	Kind LitKind
	Raw  string
	Str  string
	span Span
}

// Context is a named value such as github or steps.
type Context struct {
	Name string
	span Span
}

// Property is X.Name.
type Property struct {
	X        Node
	Name     string
	NameSpan Span
	span     Span
}

// Index is X[Index].
type Index struct {
	X, Index Node
	span     Span
}

// Star is X.* or, with Bracket, X[*].
type Star struct {
	X       Node
	Bracket bool
	span    Span
}

// Call is Name(Args...).
type Call struct {
	Name     string
	NameSpan Span
	Args     []Node
	span     Span
}

type Not struct {
	X    Node
	span Span
}

type Op uint8

const (
	OpEq Op = iota
	OpNe
	OpLt
	OpLe
	OpGt
	OpGe
	OpAnd
	OpOr
)

var opNames = [...]string{OpEq: "==", OpNe: "!=", OpLt: "<", OpLe: "<=", OpGt: ">", OpGe: ">=", OpAnd: "&&", OpOr: "||"}

func (o Op) String() string { return opNames[o] }

// Compare is X Op Y for ==, !=, <, <=, > and >=.
type Compare struct {
	Op   Op
	X, Y Node
	span Span
}

// Logical is Xs joined by one of && and ||; it has two or more operands.
type Logical struct {
	Op   Op
	Xs   []Node
	span Span
}

// Group is (X).
type Group struct {
	X    Node
	span Span
}

// Wildcard is a * used as an operand inside an index, as in a[*.b]; the
// runner accepts it, though it means nothing.
type Wildcard struct {
	span Span
}

func (n *Literal) Span() Span  { return n.span }
func (n *Context) Span() Span  { return n.span }
func (n *Property) Span() Span { return n.span }
func (n *Index) Span() Span    { return n.span }
func (n *Star) Span() Span     { return n.span }
func (n *Call) Span() Span     { return n.span }
func (n *Not) Span() Span      { return n.span }
func (n *Compare) Span() Span  { return n.span }
func (n *Logical) Span() Span  { return n.span }
func (n *Group) Span() Span    { return n.span }
func (n *Wildcard) Span() Span { return n.span }

// Children are the nodes directly under n, in the order they are written.
func Children(n Node) []Node {
	switch x := n.(type) {
	case *Property:
		return []Node{x.X}
	case *Index:
		return []Node{x.X, x.Index}
	case *Star:
		return []Node{x.X}
	case *Call:
		return x.Args
	case *Not:
		return []Node{x.X}
	case *Compare:
		return []Node{x.X, x.Y}
	case *Logical:
		return x.Xs
	case *Group:
		return []Node{x.X}
	}
	return nil
}

const (
	maxDepth = 50 // ExpressionConstants.MaxDepth
	// MaxLength is the longest expression, in UTF-16 code units
	// (ExpressionConstants.MaxLength); see UTF16Len.
	MaxLength = 21000
)

// Parse reads the expression src (the text between ${{ and }}, or a bare
// if). It returns the tree, or nil and the first error.
func Parse(src string) (Node, []Error) {
	if UTF16Len(strings.TrimFunc(src, unicode.IsSpace)) > MaxLength { // TemplateReader trims first
		return nil, []Error{{Code: ErrLength, Span: Span{0, len(src)}, Msg: "the expression is longer than 21000 characters"}}
	}
	toks, lerr := lex(src)
	if lerr != nil {
		return nil, []Error{*lerr}
	}
	if len(toks) == 0 {
		return nil, []Error{{Code: ErrEmpty, Span: Span{0, len(src)}, Msg: "an expression was expected"}}
	}
	p := &parser{toks: toks, src: src}
	n := p.or()
	if p.err == nil && p.i < len(p.toks) {
		p.unexpected(p.toks[p.i])
	}
	if p.err != nil {
		return nil, []Error{*p.err}
	}
	if depth(n) > maxDepth {
		return nil, []Error{{Code: ErrDepth, Span: n.Span(), Msg: "the expression is nested deeper than 50"}}
	}
	return n, nil
}

// UTF16Len is the length of s in UTF-16 code units, which the runner's
// limits count.
func UTF16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// The lexer has already checked which token follows which; the parser
// only has to see where the input ends early.
type parser struct {
	toks []token
	src  string
	i    int
	err  *Error
}

func (p *parser) unexpected(t token) {
	p.fail(ErrUnexpected, t.span, "unexpected symbol "+strconv.Quote(t.raw))
}

func (p *parser) fail(c ErrorCode, s Span, msg string) {
	if p.err == nil {
		p.err = &Error{Code: c, Span: s, Msg: msg}
	}
}

// peek returns the next token, or false at the end of the input.
func (p *parser) peek() (token, bool) {
	if p.err != nil || p.i >= len(p.toks) {
		return token{}, false
	}
	return p.toks[p.i], true
}

// take returns the next token; at the end of the input it records
// ErrUnexpectedEnd.
func (p *parser) take() (token, bool) {
	t, ok := p.peek()
	if !ok {
		p.fail(ErrUnexpectedEnd, p.toks[len(p.toks)-1].span, "unexpected end of expression")
		return token{}, false
	}
	p.i++
	return t, true
}

func (p *parser) isOp(ops ...string) (token, bool) {
	t, ok := p.peek()
	if !ok || t.kind != tokLogicalOperator {
		return token{}, false
	}
	for _, o := range ops {
		if t.raw == o {
			return t, true
		}
	}
	return token{}, false
}

var opOf = map[string]Op{"==": OpEq, "!=": OpNe, "<": OpLt, "<=": OpLe, ">": OpGt, ">=": OpGe, "&&": OpAnd, "||": OpOr}

func (p *parser) or() Node  { return p.logical(OpOr, "||", p.and) }
func (p *parser) and() Node { return p.logical(OpAnd, "&&", p.eq) }

func (p *parser) logical(op Op, sym string, next func() Node) Node {
	x := next()
	if _, ok := p.isOp(sym); !ok {
		return x
	}
	xs := []Node{x}
	for {
		if _, ok := p.isOp(sym); !ok {
			break
		}
		p.i++
		y := next()
		if y == nil {
			return nil
		}
		xs = append(xs, y)
	}
	return &Logical{Op: op, Xs: xs, span: Span{x.Span().Start, xs[len(xs)-1].Span().End}}
}

func (p *parser) eq() Node  { return p.compare(p.rel, "==", "!=") }
func (p *parser) rel() Node { return p.compare(p.unary, "<", "<=", ">", ">=") }

// compare is left-associative (Token.Associativity).
func (p *parser) compare(next func() Node, ops ...string) Node {
	x := next()
	for x != nil {
		t, ok := p.isOp(ops...)
		if !ok {
			break
		}
		p.i++
		y := next()
		if y == nil {
			return nil
		}
		x = &Compare{Op: opOf[t.raw], X: x, Y: y, span: Span{x.Span().Start, y.Span().End}}
	}
	return x
}

func (p *parser) unary() Node {
	if t, ok := p.isOp("!"); ok {
		p.i++
		x := p.unary()
		if x == nil {
			return nil
		}
		return &Not{X: x, span: Span{t.span.Start, x.Span().End}}
	}
	return p.postfix()
}

func (p *parser) postfix() Node {
	x := p.primary()
	for x != nil {
		t, ok := p.peek()
		if !ok {
			break
		}
		switch t.kind {
		case tokDereference:
			p.i++
			n, ok := p.take()
			if !ok {
				return nil
			}
			if n.kind == tokWildcard {
				x = &Star{X: x, span: Span{x.Span().Start, n.span.End}}
			} else {
				x = &Property{X: x, Name: n.raw, NameSpan: n.span, span: Span{x.Span().Start, n.span.End}}
			}
		case tokStartIndex:
			p.i++
			if p.i+1 < len(p.toks) && p.toks[p.i].kind == tokWildcard && p.toks[p.i+1].kind == tokEndIndex {
				p.i += 2
				x = &Star{X: x, Bracket: true, span: Span{x.Span().Start, p.toks[p.i-1].span.End}}
				continue
			}
			i := p.or()
			end, ok := p.take()
			if i == nil || !ok {
				return nil
			}
			x = &Index{X: x, Index: i, span: Span{x.Span().Start, end.span.End}}
		default:
			return x
		}
	}
	return x
}

func (p *parser) primary() Node {
	t, ok := p.take()
	if !ok {
		return nil
	}
	switch t.kind {
	case tokNull:
		return &Literal{Kind: LitNull, Raw: t.raw, span: t.span}
	case tokBoolean:
		return &Literal{Kind: LitBool, Raw: t.raw, span: t.span}
	case tokNumber:
		return &Literal{Kind: LitNumber, Raw: t.raw, span: t.span}
	case tokString:
		return &Literal{Kind: LitString, Raw: t.raw, Str: t.str, span: t.span}
	case tokNamedValue:
		return &Context{Name: t.raw, span: t.span}
	case tokFunction:
		if _, ok := p.take(); !ok { // (
			return nil
		}
		c := &Call{Name: t.raw, NameSpan: t.span}
		for {
			n, ok := p.peek()
			if !ok {
				p.take()
				return nil
			}
			if n.kind == tokEndParameters {
				p.i++
				c.span = Span{t.span.Start, n.span.End}
				return c
			}
			if n.kind == tokSeparator {
				p.i++
			}
			a := p.or()
			if a == nil {
				return nil
			}
			c.Args = append(c.Args, a)
		}
	case tokWildcard:
		return &Wildcard{span: t.span}
	case tokStartGroup:
		x := p.or()
		end, ok := p.take()
		if x == nil || !ok {
			return nil
		}
		return &Group{X: x, span: Span{t.span.Start, end.span.End}}
	}
	p.unexpected(t)
	return nil
}

// depth counts nodes the way ExpressionParser.CheckMaxDepth does: a group
// is no node, nested && (or ||) are one node, and X.name and X.* are an
// index with a literal or wildcard child.
func depth(n Node) int {
	switch n := n.(type) {
	case *Group:
		return depth(n.X)
	case *Property, *Star:
		return 1 + max(depth(Children(n)[0]), 1)
	case *Logical:
		d := 0
		var flat func(Node)
		flat = func(x Node) {
			for {
				g, ok := x.(*Group)
				if !ok {
					break
				}
				x = g.X
			}
			if l, ok := x.(*Logical); ok && l.Op == n.Op {
				for _, y := range l.Xs {
					flat(y)
				}
				return
			}
			d = max(d, depth(x))
		}
		for _, x := range n.Xs {
			flat(x)
		}
		return 1 + d
	}
	d := 0
	for _, c := range Children(n) {
		d = max(d, depth(c))
	}
	return 1 + d
}
