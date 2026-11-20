package cst

// Recovery from structural errors. Each
// function wraps what it skips in an Error node and records an error; each
// either consumes at least one byte or reports that it did not.

const maxDepth = 1000

// tooDeep reports whether one more node would exceed maxDepth, noting the
// first place this happens; Parse reports it as ErrDepth. Inside an implicit
// key the whole outermost key is given up (keyOver), as for its length:
// otherwise every enclosing level retries its alternatives down to the limit.
func (p *parser) tooDeep() bool {
	if len(p.stack) < maxDepth {
		return false
	}
	p.deepHits++
	if p.deepAt < 0 {
		p.deepAt = p.pos
	}
	if p.keyStart >= 0 {
		p.keyOver = true
	}
	return true
}

// errorRun wraps [p.pos, end) in the open Error node, as one Error token per
// line and a Newline per break.
func (p *parser) errorRun(end int) {
	for p.pos < end {
		i := p.pos
		for i < end && p.src[i] != '\n' && p.src[i] != '\r' {
			i++
		}
		p.emit(TokError, i)
		if i < end {
			p.emit(TokNewline, min(i+p.breakLen(i), end))
		}
	}
}

func (p *parser) lineEnd(pos int) int {
	for pos < len(p.src) && p.src[pos] != '\n' && p.src[pos] != '\r' {
		pos++
	}
	return pos
}

// blank reports whether the line at pos holds only white space.
func (p *parser) blank(pos int) bool {
	return p.lineEnd(pos) == pos+p.whites(pos)
}

// indentedLinesEnd is the end of the lines from pos (a line start) that are
// indented more than n, blank lines between them included.
func (p *parser) indentedLinesEnd(pos, n int) int {
	end := pos
	for pos < len(p.src) {
		if !p.blank(pos) {
			if p.spaces(pos) <= n || p.forbidden(pos) {
				break
			}
		}
		e := p.lineEnd(pos)
		e += p.breakLen(e)
		if !p.blank(pos) {
			end = e
		}
		if e == pos {
			break
		}
		pos = e
	}
	return end
}

// recoverBlockLine handles a line at the start of which a block collection
// expects an entry but finds none. A line indented more than boundary
// cannot belong to an enclosing collection, so it and the lines indented
// more than it are wrapped in an Error node. It reports whether it did so.
func (p *parser) recoverBlockLine(boundary int) bool {
	if p.eof() || !p.startOfLine() || p.blank(p.pos) || p.forbidden(p.pos) {
		return false
	}
	k := p.spaces(p.pos)
	if k <= boundary || p.at(p.pos+k) == '#' {
		return false
	}
	start := p.pos
	e := p.lineEnd(start)
	e += p.breakLen(e)
	end := max(e, p.indentedLinesEnd(e, k))
	p.wrapError(end, "cannot parse this line")
	return true
}

// recoverRestOfLine wraps what follows a complete node on its line, and the
// lines indented more than n after it, in an Error node.
func (p *parser) recoverRestOfLine(n int) {
	end := p.lineEnd(p.pos)
	if next := end + p.breakLen(end); next > end {
		if e := p.indentedLinesEnd(next, n); e > next {
			end = e
		}
	}
	p.wrapError(end, "unexpected content after the node")
}

func (p *parser) wrapError(end int, msg string) {
	start := p.pos
	i := p.open(NodeError)
	p.errorRun(end)
	p.close(i)
	p.errorAt(ErrUnexpected, Span{start, end}, msg)
}

type flowSync uint8

const (
	syncComma flowSync = iota
	syncClose
	syncStop
)

// recoverFlow skips to the next ',' or the closing indicator at this
// bracket depth, which it emits, or stops before a line indented less than
// n, a document marker, a closing indicator of an enclosing collection, or
// the end of input. The skipped bytes go in an Error node.
func (p *parser) recoverFlow(n int, close byte, ck TokenKind) flowSync {
	start := p.pos
	depth := 0
	i := p.pos
	sync := syncStop
scan:
	for i < len(p.src) {
		switch b := p.src[i]; {
		case b == '\n' || b == '\r':
			next := i + p.breakLen(i)
			if next < len(p.src) && !p.blank(next) && (p.spaces(next) < n || p.forbidden(next)) {
				break scan
			}
			i = next
			continue
		case depth == 0 && b == ',':
			sync = syncComma
			break scan
		case depth == 0 && b == close:
			sync = syncClose
			break scan
		case b == '[' || b == '{':
			depth++
		case b == ']' || b == '}':
			if depth == 0 {
				break scan
			}
			depth--
		}
		i++
	}
	if i > start {
		e := p.open(NodeError)
		p.errorRun(i)
		p.close(e)
		p.errorAt(ErrUnexpected, Span{start, i}, "cannot parse this flow entry")
	} else if sync == syncComma {
		p.errorAt(ErrUnexpected, Span{i, i + 1}, "missing flow entry")
	}
	switch sync {
	case syncComma:
		p.emit(TokFlowEntry, p.pos+1)
	case syncClose:
		p.emit(ck, p.pos+1)
	}
	return sync
}

// maybePair reports whether a flow pair ([150]) can start at pos: it is an
// explicit '?' entry, or a ':' follows at this bracket depth on the same
// line, within the 1024 characters an implicit key may have. It saves
// parsing every flow sequence entry twice. It must not miss a pair, so a
// quote is taken to open a quoted scalar only where a node can start (at
// pos, after '[', '{', ',', after "? " or ": ", or after a property);
// elsewhere it is part of a plain scalar ("it's").
func (p *parser) maybePair(pos int) bool {
	if p.at(pos) == '?' {
		return true
	}
	depth, chars := 0, 0
	nodeStart := true
	for i := pos; i < len(p.src) && chars <= 1025; i++ {
		if p.src[i]&0xC0 != 0x80 {
			chars++
		}
		b := p.src[i]
		switch b {
		case '\n', '\r':
			return false
		case ' ', '\t':
			continue
		case '[', '{':
			depth++
			nodeStart = true
			continue
		case ']', '}':
			if depth == 0 {
				return false
			}
			depth--
		case ',':
			if depth == 0 {
				return false
			}
			nodeStart = true
			continue
		case ':', '?':
			if b == ':' && depth == 0 {
				return true
			}
			nodeStart = isWhite(p.at(i + 1))
			continue
		case '#':
			if i > pos && isWhite(p.src[i-1]) {
				return false
			}
		case '&', '!':
			if nodeStart {
				for i+1 < len(p.src) && p.nsChar(i+1) > 0 && !isFlowIndicator(p.src[i+1]) {
					i++
				}
				continue
			}
		case '"', '\'':
			if nodeStart {
				for i++; i < len(p.src) && p.src[i] != b; i++ {
					if p.src[i] == '\n' || p.src[i] == '\r' {
						return false
					}
					if b == '"' && p.src[i] == '\\' {
						i++
					}
				}
			}
		}
		nodeStart = false
	}
	return false
}
