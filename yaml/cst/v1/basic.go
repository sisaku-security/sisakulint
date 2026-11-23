package cst

// Spec chapter 6: indentation, separation, comments, directives, properties.

// ctx is the production context c.
type ctx uint8

const (
	ctxBlockIn ctx = iota
	ctxBlockOut
	ctxBlockKey
	ctxFlowIn
	ctxFlowOut
	ctxFlowKey
)

func (p *parser) at(pos int) byte {
	if pos < len(p.src) {
		return p.src[pos]
	}
	return 0
}

func (p *parser) eof() bool { return p.pos >= len(p.src) }

func (p *parser) spaces(pos int) int {
	n := 0
	for pos+n < len(p.src) && p.src[pos+n] == ' ' {
		n++
	}
	return n
}

func (p *parser) whites(pos int) int {
	n := 0
	for pos+n < len(p.src) && isWhite(p.src[pos+n]) {
		n++
	}
	return n
}

// startOfLine is <start-of-line>. A byte order mark at the start of a line
// is transparent.
func (p *parser) startOfLine() bool {
	i := p.pos
	if i >= 3 && p.hasBOM(i-3) {
		i -= 3
	}
	return i == 0 || p.src[i-1] == '\n' || p.src[i-1] == '\r'
}

// [63] s-indent(n)
func (p *parser) sIndent(n int) bool {
	if n <= 0 {
		return true
	}
	if p.spaces(p.pos) < n {
		return false
	}
	p.emit(TokSpace, p.pos+n)
	return true
}

// [64] s-indent-less-than(n)
func (p *parser) sIndentLessThan(n int) {
	p.emit(TokSpace, p.pos+max(0, min(p.spaces(p.pos), n-1)))
}

// [66] s-separate-in-line
func (p *parser) sSeparateInLine() bool {
	if w := p.whites(p.pos); w > 0 {
		p.emit(TokSpace, p.pos+w)
		return true
	}
	return p.startOfLine()
}

func (p *parser) optWhite() { p.emit(TokSpace, p.pos+p.whites(p.pos)) }

// [67] s-line-prefix(n,c)
func (p *parser) sLinePrefix(n int, c ctx) bool {
	if c == ctxFlowIn || c == ctxFlowOut {
		return p.sFlowLinePrefix(n)
	}
	return p.sIndent(n)
}

// [69] s-flow-line-prefix(n). In ModeGitHub, inside a flow collection or
// a quoted scalar, fewer than n spaces are accepted too, as GitHub does
// except before a document marker at column 0.
func (p *parser) sFlowLinePrefix(n int) bool {
	if !p.sIndent(n) && (!p.looseHere() || p.forbidden(p.pos)) {
		return false
	}
	p.optWhite()
	return true
}

// bBreak emits one b-break ([28]).
func (p *parser) bBreak() bool {
	if n := p.breakLen(p.pos); n > 0 {
		p.emit(TokNewline, p.pos+n)
		return true
	}
	return false
}

// [70] l-empty(n,c)
func (p *parser) lEmpty(n int, c ctx) bool {
	m := p.mark()
	if p.sLinePrefix(n, c) && p.bBreak() {
		return true
	}
	p.reset(m)
	p.sIndentLessThan(n)
	if p.bBreak() {
		return true
	}
	p.reset(m)
	return false
}

// [71] b-l-trimmed(n,c) | [72] b-as-space, which is [73] b-l-folded(n,c).
func (p *parser) bLFolded(n int, c ctx) bool {
	if !p.bBreak() {
		return false
	}
	for p.lEmpty(n, c) {
	}
	return true
}

// [74] s-flow-folded(n)
func (p *parser) sFlowFolded(n int) bool {
	m := p.mark()
	p.optWhite()
	if p.bLFolded(n, ctxFlowIn) && p.sFlowLinePrefix(n) {
		return true
	}
	p.reset(m)
	return false
}

// [75] c-nb-comment-text
func (p *parser) cNbCommentText() bool {
	if p.at(p.pos) != '#' {
		return false
	}
	p.emit(TokComment, p.lineEnd(p.pos))
	return true
}

// [76] b-comment
func (p *parser) bComment() bool { return p.bBreak() || p.eof() }

// [77] s-b-comment
func (p *parser) sBComment() bool {
	m := p.mark()
	if p.sSeparateInLine() {
		p.cNbCommentText()
		if p.bComment() {
			return true
		}
	}
	p.reset(m)
	return p.bComment()
}

// [78] l-comment
func (p *parser) lComment() bool {
	if p.eof() {
		return false
	}
	m := p.mark()
	if p.sSeparateInLine() {
		p.cNbCommentText()
		if p.bComment() {
			return true
		}
	}
	p.reset(m)
	return false
}

// [79] s-l-comments
func (p *parser) sLComments() bool {
	if !p.sBComment() && !p.startOfLine() {
		return false
	}
	for p.lComment() {
	}
	return true
}

// [80] s-separate(n,c)
func (p *parser) sSeparate(n int, c ctx) bool {
	if c == ctxBlockKey || c == ctxFlowKey {
		return p.sSeparateInLine()
	}
	return p.sSeparateLines(n)
}

// [81] s-separate-lines(n)
func (p *parser) sSeparateLines(n int) bool {
	m := p.mark()
	if p.sLComments() && p.sFlowLinePrefix(n) {
		return true
	}
	p.reset(m)
	return p.sSeparateInLine()
}

// nsRun emits the ns-char+ run at pos as one token.
func (p *parser) nsRun(k TokenKind) bool {
	end := p.pos
	for {
		s := p.nsChar(end)
		if s == 0 {
			break
		}
		end += s
	}
	if end == p.pos {
		return false
	}
	p.emit(k, end)
	return true
}

// [82] l-directive
func (p *parser) lDirective() bool {
	if p.at(p.pos) != '%' {
		return false
	}
	m := p.mark()
	d := p.open(NodeDirective)
	start := p.pos
	end := p.pos + 1
	for {
		s := p.nsChar(end)
		if s == 0 {
			break
		}
		end += s
	}
	name := string(p.src[start+1 : end])
	if name == "" {
		p.reset(m)
		return false
	}
	p.emit(TokDirective, end)
	ok := true
	switch name {
	case "YAML":
		ok = p.nsYAMLDirective()
	case "TAG":
		ok = p.nsTagDirective()
	default:
		p.nsReservedDirective()
	}
	p.close(d)
	if !ok || !p.sLComments() {
		p.reset(m)
		return false
	}
	return true
}

// [83] ns-reserved-directive, after the name
func (p *parser) nsReservedDirective() {
	for {
		m := p.mark()
		if p.whites(p.pos) == 0 || !p.sSeparateInLine() || !p.nsRun(TokDirectiveParam) {
			p.reset(m)
			return
		}
	}
}

// [86] ns-yaml-directive, after "YAML"; [87] ns-yaml-version
func (p *parser) nsYAMLDirective() bool {
	if p.whites(p.pos) == 0 || !p.sSeparateInLine() {
		return false
	}
	i := p.pos
	d1 := 0
	for isDecDigit(p.at(i + d1)) {
		d1++
	}
	if d1 == 0 || p.at(i+d1) != '.' {
		return false
	}
	d2 := 0
	for isDecDigit(p.at(i + d1 + 1 + d2)) {
		d2++
	}
	if d2 == 0 {
		return false
	}
	p.emit(TokDirectiveParam, i+d1+1+d2)
	if p.yamlSeen {
		p.errorAt(ErrDuplicateDirective, Span{i, p.pos}, "a document may have one %YAML directive")
	}
	p.yamlSeen = true
	return true
}

// [88] ns-tag-directive, after "TAG"
func (p *parser) nsTagDirective() bool {
	if p.whites(p.pos) == 0 || !p.sSeparateInLine() {
		return false
	}
	h := p.tagHandle(p.pos)
	if h == 0 {
		return false
	}
	handle := string(p.src[p.pos : p.pos+h])
	if p.handles[handle] {
		p.errorAt(ErrDuplicateDirective, Span{p.pos, p.pos + h}, "a document may have one %TAG directive per handle")
	}
	if p.handles == nil {
		p.handles = map[string]bool{}
	}
	p.handles[handle] = true
	p.emit(TokDirectiveParam, p.pos+h)
	if p.whites(p.pos) == 0 || !p.sSeparateInLine() {
		return false
	}
	// [93] ns-tag-prefix
	end := p.pos
	if p.at(end) == '!' {
		end++
	} else if s := p.tagChar(end); s > 0 {
		end += s
	} else {
		return false
	}
	for s := p.uriChar(end); s > 0; s = p.uriChar(end) {
		end += s
	}
	p.emit(TokDirectiveParam, end)
	return true
}

// tagHandle is the length of the c-tag-handle ([89]) at pos, or 0.
func (p *parser) tagHandle(pos int) int {
	if p.at(pos) != '!' {
		return 0
	}
	// [92] c-named-tag-handle
	i := pos + 1
	for isWordChar(p.at(i)) {
		i++
	}
	if i > pos+1 && p.at(i) == '!' {
		return i + 1 - pos
	}
	// [91] c-secondary-tag-handle, [90] c-primary-tag-handle
	if p.at(pos+1) == '!' {
		return 2
	}
	return 1
}

// [96] c-ns-properties(n,c), as a Properties node.
func (p *parser) cNsProperties(n int, c ctx) bool { return p.properties(n, c, false) }

// properties is c-ns-properties(n,c); single stops after the first property.
func (p *parser) properties(n int, c ctx, single bool) bool {
	m := p.mark()
	pr := p.open(NodeProperties)
	first := p.cNsTagProperty()
	var second func() bool = p.cNsAnchorProperty
	if !first {
		first = p.cNsAnchorProperty()
		second = p.cNsTagProperty
	}
	if !first {
		p.reset(m)
		return false
	}
	m2 := p.mark()
	if single || !p.sSeparate(n, c) || !second() {
		p.reset(m2)
	}
	for !single { // a further property on the same line can only be a duplicate
		m3 := p.mark()
		start := p.pos + p.whites(p.pos)
		if start == p.pos || !p.sSeparateInLine() || !p.cNsAnchorProperty() && !p.cNsTagProperty() {
			p.reset(m3)
			break
		}
		p.errorAt(ErrDuplicateProperty, Span{start, p.pos}, "a node may have one anchor and one tag")
	}
	p.close(pr)
	return true
}

// [97] c-ns-tag-property
func (p *parser) cNsTagProperty() bool {
	i := p.pos
	if p.at(i) != '!' {
		return false
	}
	// [98] c-verbatim-tag
	if p.at(i+1) == '<' {
		j := i + 2
		for s := p.uriChar(j); s > 0; s = p.uriChar(j) {
			j += s
		}
		if j == i+2 || p.at(j) != '>' {
			return false
		}
		p.emit(TokTag, j+1)
		return true
	}
	// [99] c-ns-shorthand-tag: the named handle only when a tag char follows it
	for _, h := range []int{p.tagHandle(i), 2, 1} {
		if h == 2 && p.at(i+1) != '!' {
			continue
		}
		j := i + h
		for s := p.tagChar(j); s > 0; s = p.tagChar(j) {
			j += s
		}
		if j > i+h {
			if h > 2 && !p.handles[string(p.src[i:i+h])] {
				p.errorAt(ErrUndefinedTagHandle, Span{i, i + h}, "tag handle "+string(p.src[i:i+h])+" has no %TAG directive")
			}
			p.emit(TokTag, j)
			return true
		}
	}
	// [100] c-non-specific-tag
	p.emit(TokTag, i+1)
	return true
}

// [101] c-ns-anchor-property
func (p *parser) cNsAnchorProperty() bool { return p.anchorName('&', TokAnchor) }

// '&' or '*' followed by [103] ns-anchor-name
func (p *parser) anchorName(ind byte, k TokenKind) bool {
	if p.at(p.pos) != ind {
		return false
	}
	end := p.pos + 1
	for {
		s := p.nsChar(end)
		if s == 0 || isFlowIndicator(p.src[end]) {
			break
		}
		end += s
	}
	if end == p.pos+1 {
		return false
	}
	p.emit(k, end)
	return true
}
