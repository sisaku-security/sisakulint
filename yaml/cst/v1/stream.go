package cst

// Spec chapter 9: documents and the stream.

// [211] l-yaml-stream. A document takes its own l-document-suffix
// (endDocument); p.suffixed then allows what may follow a suffix.
func (p *parser) lYAMLStream() {
	p.lDocumentPrefixes()
	p.suffixed = false
	p.lAnyDocument()
	for !p.eof() {
		start := p.pos
		switch {
		case p.suffixed || p.lDocumentSuffix():
			for p.lDocumentSuffix() {
			}
			p.lDocumentPrefixes()
			p.suffixed = false
			p.lAnyDocument()
		case p.bom():
		case p.lComment():
		case p.lExplicitDocument(-1):
		}
		if p.pos == start {
			p.recoverStream()
			p.suffixed = false
		}
	}
}

// [202] l-document-prefix, repeated
func (p *parser) lDocumentPrefixes() {
	for {
		start := p.pos
		p.bom()
		for p.lComment() {
		}
		if p.pos == start {
			return
		}
	}
}

func (p *parser) bom() bool {
	if !p.hasBOM(p.pos) {
		return false
	}
	p.emit(TokBOM, p.pos+3)
	return true
}

// forbidden is [206] c-forbidden at pos.
func (p *parser) forbidden(pos int) bool {
	if pos+3 > len(p.src) {
		return false
	}
	save := p.pos
	p.pos = pos
	sol := p.startOfLine()
	p.pos = save
	if !sol {
		return false
	}
	s := string(p.src[pos : pos+3])
	if s != "---" && s != "..." {
		return false
	}
	b := p.at(pos + 3)
	return pos+3 == len(p.src) || isWhite(b) || b == '\n' || b == '\r'
}

// marker emits "---" or "..." if it is not followed by a non-space character.
func (p *parser) marker(s string, k TokenKind) bool {
	if p.pos+3 > len(p.src) || string(p.src[p.pos:p.pos+3]) != s || p.nsChar(p.pos+3) > 0 {
		return false
	}
	p.emit(k, p.pos+3)
	return true
}

// [210] l-any-document
func (p *parser) lAnyDocument() bool {
	return p.lDirectiveDocument() || p.lExplicitDocument(-1) || p.lBareDocument()
}

// [209] l-directive-document
func (p *parser) lDirectiveDocument() bool {
	if p.at(p.pos) != '%' {
		return false
	}
	m := p.mark()
	doc := p.openDocument()
	n := 0
	for p.lDirective() {
		n++
	}
	if n == 0 || !p.lExplicitDocument(doc) {
		p.reset(m)
		return false
	}
	return true
}

// [208] l-explicit-document. doc is the Document node opened for the
// directives, or -1.
func (p *parser) lExplicitDocument(doc int32) bool {
	m := p.mark()
	if doc < 0 {
		doc = p.openDocument()
	}
	if !p.marker("---", TokDocStart) {
		p.reset(m)
		return false
	}
	if !p.sLBlockNode(-1, ctxBlockIn) {
		p.emptyNode()
		if !p.sLComments() {
			p.reset(m)
			return false
		}
	}
	p.endDocument(doc)
	return true
}

// [207] l-bare-document
func (p *parser) lBareDocument() bool {
	if p.eof() || p.forbidden(p.pos) {
		return false
	}
	m := p.mark()
	doc := p.openDocument()
	if !p.sLBlockNode(-1, ctxBlockIn) {
		p.reset(m)
		return false
	}
	p.endDocument(doc)
	return true
}

// endDocument takes one [205] l-document-suffix into the document, then
// closes it.
func (p *parser) endDocument(doc int32) {
	p.suffixed = p.lDocumentSuffix()
	p.close(doc)
}

// [205] l-document-suffix
func (p *parser) lDocumentSuffix() bool {
	m := p.mark()
	if !p.marker("...", TokDocEnd) || !p.sLComments() {
		p.reset(m)
		return false
	}
	return true
}

// emptyNode is [106] e-node.
func (p *parser) emptyNode() { p.close(p.open(NodeScalar)) }

// recoverStream wraps the current line and the following lines, up to a
// document marker at the start of a line, in an Error node.
func (p *parser) recoverStream() {
	e := p.open(NodeError)
	start := p.pos
	for first := true; !p.eof() && (first || !p.forbidden(p.pos)); first = false {
		p.emit(TokError, p.lineEnd(p.pos))
		p.bBreak()
	}
	p.close(e)
	p.errorAt(ErrUnexpected, Span{start, p.pos}, "cannot parse this content")
}
