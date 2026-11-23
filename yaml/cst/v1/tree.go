package cst

import "iter"

// Tree is a parsed YAML stream. It keeps src without copying; callers must
// not modify src after Parse.
type Tree struct {
	src        []byte
	tokens     []token
	nodes      []node
	errs       []Error
	lineStarts []uint32
	mode       Mode
}

// token ends where the next token starts, or at len(src).
type token struct {
	kind  TokenKind
	start uint32
}

// node is stored in preorder. The node's tokens are [tokStart, tokEnd);
// its descendants are nodes (index, subtreeEnd).
type node struct {
	kind       NodeKind
	parent     int32
	subtreeEnd int32
	tokStart   int32
	tokEnd     int32
}

// Span is a byte range [Start, End) of the input.
type Span struct{ Start, End int }

// Node is a handle to a node of a Tree.
type Node struct {
	t *Tree
	i int32
}

// Token is a handle to a token of a Tree.
type Token struct {
	t *Tree
	i int32
}

// Element is a child of a node: either a Node or a Token.
type Element struct {
	t      *Tree
	i      int32
	isNode bool
}

func (e Element) Node() (Node, bool) {
	if !e.isNode {
		return Node{}, false
	}
	return Node{e.t, e.i}, true
}

func (e Element) Token() (Token, bool) {
	if e.isNode {
		return Token{}, false
	}
	return Token{e.t, e.i}, true
}

func (t *Tree) Root() Node      { return Node{t, 0} }
func (t *Tree) Bytes() []byte   { return t.src }
func (t *Tree) Errors() []Error { return t.errs }

// Reparse reads src the way t was read, so that an edit of t's bytes is
// read back by the same rules.
func (t *Tree) Reparse(src []byte) *Tree { return ParseMode(src, t.mode) }

// Mode is the mode t was read in.
func (t *Tree) Mode() Mode { return t.mode }

func (t *Tree) tokenStart(i int32) int {
	if int(i) >= len(t.tokens) {
		return len(t.src)
	}
	return int(t.tokens[i].start)
}

func (n Node) Kind() NodeKind { return n.t.nodes[n.i].kind }

func (n Node) Parent() (Node, bool) {
	p := n.t.nodes[n.i].parent
	if p < 0 {
		return Node{}, false
	}
	return Node{n.t, p}, true
}

// Children yields child nodes and the node's own tokens in source order.
func (n Node) Children() iter.Seq[Element] {
	return func(yield func(Element) bool) {
		ns := n.t.nodes
		nd := ns[n.i]
		tok := nd.tokStart
		for c := n.i + 1; c < nd.subtreeEnd; c = ns[c].subtreeEnd {
			for ; tok < ns[c].tokStart; tok++ {
				if !yield(Element{n.t, tok, false}) {
					return
				}
			}
			if !yield(Element{n.t, c, true}) {
				return
			}
			tok = ns[c].tokEnd
		}
		for ; tok < nd.tokEnd; tok++ {
			if !yield(Element{n.t, tok, false}) {
				return
			}
		}
	}
}

// Tokens yields every token in the node's range, descendants' included.
func (n Node) Tokens() iter.Seq[Token] {
	return func(yield func(Token) bool) {
		nd := n.t.nodes[n.i]
		for i := nd.tokStart; i < nd.tokEnd; i++ {
			if !yield(Token{n.t, i}) {
				return
			}
		}
	}
}

// Span covers all of the node's tokens; see ContentSpan for what that
// includes. An empty node's Span is the empty range at the start of the
// next token.
func (n Node) Span() Span {
	nd := n.t.nodes[n.i]
	s := n.t.tokenStart(nd.tokStart)
	if nd.tokStart == nd.tokEnd {
		return Span{s, s}
	}
	return Span{s, n.t.tokenStart(nd.tokEnd)}
}

// Bytes returns the node's bytes as a subslice of src, capacity capped.
func (n Node) Bytes() []byte {
	s := n.Span()
	return n.t.src[s.Start:s.End:s.End]
}

func (k Token) Kind() TokenKind { return k.t.tokens[k.i].kind }

func (k Token) Span() Span {
	return Span{int(k.t.tokens[k.i].start), k.t.tokenStart(k.i + 1)}
}

func (k Token) Bytes() []byte {
	s := k.Span()
	return k.t.src[s.Start:s.End:s.End]
}

// ContentSpan is Span without the leading and trailing Space, Newline and
// Comment tokens. Span keeps them where the grammar attaches them: an entry
// or collection ends after the line breaks, blank lines and comment lines
// that follow its last content, including comments written above the next
// sibling. An empty node's ContentSpan is its Span.
func (n Node) ContentSpan() Span {
	nd := n.t.nodes[n.i]
	first, last := nd.tokStart, nd.tokEnd-1
	for first <= last && trivia(n.t.tokens[first].kind) {
		first++
	}
	for last >= first && trivia(n.t.tokens[last].kind) {
		last--
	}
	if first > last {
		return n.Span()
	}
	return Span{n.t.tokenStart(first), n.t.tokenStart(last + 1)}
}

func trivia(k TokenKind) bool { return k == TokSpace || k == TokNewline || k == TokComment }
