package cst

// Mode selects which inputs the parser accepts.
type Mode uint8

const (
	// ModeSpec follows YAML 1.2.2.
	ModeSpec Mode = iota
	// ModeGitHub accepts what GitHub accepts in a workflow file, as observed
	// on GitHub: inside a flow
	// collection or a quoted scalar the columns of the lines are not
	// checked, and an implicit key of a flow mapping must have its ':' on
	// the line it starts on and at most 1024 characters.
	ModeGitHub
)

// Parse reads src into a Tree by YAML 1.2.2. It is ParseMode(src, ModeSpec).
func Parse(src []byte) *Tree { return ParseMode(src, ModeSpec) }

// ParseMode reads src into a Tree by the rules of m; a Mode it does not
// know is ModeSpec. It never panics; problems are reported by Tree.Errors
// and the tree still covers every byte of src.
func ParseMode(src []byte, m Mode) *Tree {
	if m != ModeGitHub {
		m = ModeSpec
	}
	p := newParser(src)
	p.mode = m
	p.t.mode = m
	p.t.lineStarts = buildLineStarts(src) // checkFlowKey compares lines
	if badEncoding(src) {
		e := p.open(NodeError)
		p.emit(TokError, len(src))
		p.close(e)
		p.errorAt(ErrEncoding, Span{0, len(src)}, "only UTF-8 is supported")
	} else {
		p.lYAMLStream()
		p.checkChars()
		if p.deepAt >= 0 {
			p.errorAt(ErrDepth, Span{p.deepAt, p.deepAt}, "nesting is too deep")
		}
	}
	return p.finish()
}

type parser struct {
	src  []byte
	pos  int
	t    *Tree
	mode Mode

	// ModeGitHub: the parser is inside loose flow collections and quoted
	// scalars, where line columns are not checked, unless strict is set:
	// after an unclosed flow collection, to the end of the document
	// (flowCollection).
	loose    int
	strict   bool
	laxFlows int     // flow collections being read loosely
	stack    []int32 // open nodes, innermost last

	suffixed bool // the last document ended with l-document-suffix
	deepAt   int  // where nesting first exceeded maxDepth, or -1
	keyStart int  // start of the outermost implicit key being read, or -1
	keyOver  bool // that key already has more than 1024 characters

	failed   map[memoKey]bool // attempts known to fail (memoFail)
	deepHits int              // times tooDeep has refused a node

	// directives of the current document
	handles  map[string]bool // named tag handles from %TAG
	yamlSeen bool
}

// lax is whether this parse may read loosely: ModeGitHub, and not after an
// unclosed flow collection in this document.
func (p *parser) lax() bool { return p.mode == ModeGitHub && !p.strict }

// looseHere is whether the line columns are not checked here.
func (p *parser) looseHere() bool { return p.loose > 0 && p.lax() }

func (p *parser) openDocument() int32 {
	p.handles = nil
	p.yamlSeen = false
	p.strict = false
	return p.open(NodeDocument)
}

// newParser returns a parser with the Stream root open.
func newParser(src []byte) *parser {
	p := &parser{src: src, t: &Tree{src: src}, deepAt: -1, keyStart: -1}
	p.open(NodeStream)
	return p
}

// finish closes every open node, the root included.
func (p *parser) finish() *Tree {
	for len(p.stack) > 0 {
		p.close(p.stack[len(p.stack)-1])
	}
	return p.t
}

type mark struct {
	pos                       int
	ntok, nnode, nerr, nstack int32
}

func (p *parser) mark() mark {
	return mark{p.pos, int32(len(p.t.tokens)), int32(len(p.t.nodes)), int32(len(p.t.errs)), int32(len(p.stack))}
}

// reset undoes everything since m. The attempt between mark and reset must
// not close a node opened before m.
func (p *parser) reset(m mark) {
	p.pos = m.pos
	p.t.tokens = p.t.tokens[:m.ntok]
	p.t.nodes = p.t.nodes[:m.nnode]
	p.t.errs = p.t.errs[:m.nerr]
	p.stack = p.stack[:m.nstack]
}

// emit makes [p.pos, end) one token. An empty range emits nothing.
func (p *parser) emit(k TokenKind, end int) {
	if end <= p.pos {
		return
	}
	p.t.tokens = append(p.t.tokens, token{k, uint32(p.pos)})
	p.pos = end
}

func (p *parser) open(k NodeKind) int32 {
	parent := int32(-1)
	if len(p.stack) > 0 {
		parent = p.stack[len(p.stack)-1]
	}
	i := int32(len(p.t.nodes))
	p.t.nodes = append(p.t.nodes, node{kind: k, parent: parent, subtreeEnd: -1, tokStart: int32(len(p.t.tokens)), tokEnd: -1})
	p.stack = append(p.stack, i)
	return i
}

// close closes node i, which must be the innermost open node.
func (p *parser) close(i int32) {
	p.stack = p.stack[:len(p.stack)-1]
	n := &p.t.nodes[i]
	n.tokEnd = int32(len(p.t.tokens))
	n.subtreeEnd = int32(len(p.t.nodes))
}

func (p *parser) errorAt(c ErrorCode, s Span, msg string) {
	p.t.errs = append(p.t.errs, Error{c, s, msg})
}
