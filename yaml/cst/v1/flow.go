package cst

import "unicode/utf8"

// Spec chapter 7: flow styles.

func (p *parser) setKind(i int32, k NodeKind) { p.t.nodes[i].kind = k }

// [104] c-ns-alias-node, in node i
func (p *parser) cNsAliasNode(i int32) bool {
	if !p.anchorName('*', TokAlias) {
		return false
	}
	p.setKind(i, NodeAlias)
	return true
}

// escapeLen is the length of the [62] c-ns-esc-char at pos (a '\'), or 0.
func (p *parser) escapeLen(pos int) int {
	hex := 0
	switch p.at(pos + 1) {
	case '0', 'a', 'b', 't', '\t', 'n', 'v', 'f', 'r', 'e', ' ', '"', '/', '\\', 'N', '_', 'L', 'P':
		return 2
	case 'x':
		hex = 2
	case 'u':
		hex = 4
	case 'U':
		hex = 8
	default:
		return 0
	}
	for i := 0; i < hex; i++ {
		if !isHexDigit(p.at(pos + 2 + i)) {
			return 0
		}
	}
	return 2 + hex
}

// [109] c-double-quoted(n,c) and [120] c-single-quoted(n,c). Each line of
// the scalar is one token; line folding between them is Space and Newline
// tokens ([112] s-double-escaped, [74] s-flow-folded).
//
// In ModeGitHub the continuation lines are read loosely, in a block too,
// as GitHub was seen to read them. A scalar without its closing quote fails
// either way, so it
// needs no strict reading again.
func (p *parser) cQuoted(n int, c ctx, q byte, k TokenKind) bool {
	if p.at(p.pos) != q {
		return false
	}
	p.loose++
	defer func() { p.loose-- }()
	m := p.mark()
	multi := c == ctxFlowIn || c == ctxFlowOut
	i := p.pos + 1
	for {
		escapedBreak := false
		keep := p.pos // trailing white after this is not content; an escape's is
		for i < len(p.src) && p.src[i] != '\n' && p.src[i] != '\r' {
			b := p.src[i]
			if b == q {
				if q == '\'' && p.at(i+1) == '\'' { // [117] c-quoted-quote
					i += 2
					continue
				}
				p.emit(k, i+1)
				return true
			}
			if b == '\\' && q == '"' {
				if p.breakLen(i+1) > 0 {
					escapedBreak = true
					i++
					break
				}
				if e := p.escapeLen(i); e > 0 {
					i += e
					keep = i
					continue
				}
				p.errorAt(ErrInvalidEscape, Span{i, i + 2}, "invalid escape sequence")
				i++
				continue
			}
			_, s := utf8.DecodeRune(p.src[i:])
			i += s
		}
		if i >= len(p.src) || !multi {
			p.reset(m)
			return false
		}
		end := i
		if !escapedBreak {
			for end > keep && isWhite(p.src[end-1]) {
				end--
			}
		}
		p.emit(k, end)
		p.emit(TokSpace, i)
		if !p.bLFolded(n, ctxFlowIn) || !p.sFlowLinePrefix(n) || p.forbidden(p.pos) {
			p.reset(m)
			return false
		}
		i = p.pos
	}
}

// plainSafe is the length of the ns-plain-safe(c) ([127]) at pos, or 0.
func (p *parser) plainSafe(pos int, c ctx) int {
	s := p.nsChar(pos)
	if s > 0 && (c == ctxFlowIn || c == ctxFlowKey) && isFlowIndicator(p.src[pos]) {
		return 0
	}
	return s
}

// [126] ns-plain-first(c)
func (p *parser) plainFirst(pos int, c ctx) int {
	s := p.nsChar(pos)
	if s == 0 {
		return 0
	}
	b := p.src[pos]
	if !isIndicator(b) {
		return s
	}
	if (b == '?' || b == ':' || b == '-') && p.plainSafe(pos+1, c) > 0 {
		return 1
	}
	return 0
}

// [130] ns-plain-char(c)
func (p *parser) plainChar(pos int, c ctx) int {
	switch p.at(pos) {
	case ':':
		if p.plainSafe(pos+1, c) > 0 {
			return 1
		}
		return 0
	case '#':
		if pos > 0 && p.nsChar(pos-1) > 0 {
			return 1
		}
		return 0
	}
	return p.plainSafe(pos, c)
}

// [132] nb-ns-plain-in-line(c): the end of the run starting at pos.
func (p *parser) plainInLine(pos int, c ctx) int {
	for {
		j := pos + p.whites(pos)
		s := p.plainChar(j, c)
		if s == 0 {
			return pos
		}
		pos = j + s
	}
}

// [131] ns-plain(n,c)
func (p *parser) nsPlain(n int, c ctx) bool {
	s := p.plainFirst(p.pos, c)
	if s == 0 || p.forbidden(p.pos) {
		return false
	}
	p.emit(TokPlain, p.plainInLine(p.pos+s, c))
	if c != ctxFlowIn && c != ctxFlowOut {
		return true
	}
	for { // [134] s-ns-plain-next-line(n,c)
		m := p.mark()
		if !p.sFlowFolded(n) || p.forbidden(p.pos) {
			p.reset(m)
			return true
		}
		s := p.plainChar(p.pos, c)
		if s == 0 {
			p.reset(m)
			return true
		}
		p.emit(TokPlain, p.plainInLine(p.pos+s, c))
	}
}

// [157] c-flow-json-content(n,c), in node i
func (p *parser) cFlowJSONContent(n int, c ctx, i int32) bool {
	return p.cFlowSequence(n, c, i) || p.cFlowMapping(n, c, i) ||
		p.cQuoted(n, c, '\'', TokSingleQuoted) || p.cQuoted(n, c, '"', TokDoubleQuoted)
}

// [158] ns-flow-content(n,c)
func (p *parser) nsFlowContent(n int, c ctx, i int32) bool {
	return p.nsPlain(n, c) || p.cFlowJSONContent(n, c, i)
}

// propsThen is c-ns-properties(n,c) followed by s-separate(n,c) and content,
// or by [105] e-scalar.
func (p *parser) propsThen(n int, c ctx, content func() bool) bool {
	if !p.cNsProperties(n, c) {
		return false
	}
	m := p.mark()
	if p.sSeparate(n, c) && content() {
		return true
	}
	p.reset(m)
	return true
}

// node runs f inside a new node, keeping it only if f succeeds.
func (p *parser) node(f func(i int32) bool) bool {
	if p.tooDeep() || p.keyTooLong() {
		return false
	}
	m := p.mark()
	i := p.open(NodeScalar)
	if !f(i) {
		p.reset(m)
		return false
	}
	p.close(i)
	return true
}

// [161] ns-flow-node(n,c)
func (p *parser) nsFlowNode(n int, c ctx) bool {
	return p.node(func(i int32) bool {
		return p.cNsAliasNode(i) || p.nsFlowContent(n, c, i) ||
			p.propsThen(n, c, func() bool { return p.nsFlowContent(n, c, i) })
	})
}

// [159] ns-flow-yaml-node(n,c). The properties-and-e-scalar alternative is
// not taken before JSON content: the grammar then needs [160]
// c-flow-json-node, and an ordered choice would never reach it.
func (p *parser) nsFlowYAMLNode(n int, c ctx) bool {
	return p.node(func(i int32) bool {
		if p.cNsAliasNode(i) || p.nsPlain(n, c) {
			return true
		}
		m := p.mark()
		if !p.propsThen(n, c, func() bool { return p.nsPlain(n, c) }) {
			return false
		}
		if len(p.t.nodes) == int(i)+2 { // only the Properties child: e-scalar
			m2 := p.mark()
			if p.sSeparate(n, c) {
				switch p.at(p.pos) {
				case '[', '{', '"', '\'':
					p.reset(m)
					return false
				}
			}
			p.reset(m2)
		}
		return true
	})
}

// [160] c-flow-json-node(n,c)
func (p *parser) cFlowJSONNode(n int, c ctx) bool {
	return p.node(func(i int32) bool {
		m := p.mark()
		if p.cNsProperties(n, c) && p.sSeparate(n, c) && p.cFlowJSONContent(n, c, i) {
			return true
		}
		p.reset(m)
		return p.cFlowJSONContent(n, c, i)
	})
}

func (p *parser) indicator(b byte, k TokenKind) bool {
	if p.at(p.pos) != b || p.eof() {
		return false
	}
	p.emit(k, p.pos+1)
	return true
}

func (p *parser) optSeparate(n int, c ctx) {
	m := p.mark()
	if !p.sSeparate(n, c) {
		p.reset(m)
	}
}

// [136] in-flow(c)
func inFlow(c ctx) ctx {
	if c == ctxBlockKey || c == ctxFlowKey {
		return ctxFlowKey
	}
	return ctxFlowIn
}

// flowCollection is [137] c-flow-sequence(n,c) and [140] c-flow-mapping(n,c)
// in node i: open, s-separate(n,c)?, entries, close. [138] and [141] are the
// entry loop, which allows a trailing ','.
// Outside implicit keys the collection is committed once open: nothing else
// can start with '[' or '{', so unparsable content is recovered from
// instead of failing.
//
// In ModeGitHub the lines inside are read loosely (sFlowLinePrefix). If a
// collection then finds no closing indicator, the rest of the document is
// read strictly, and the outermost loose collection is read again strictly,
// so that a forgotten bracket is recovered from as in ModeSpec instead of
// taking in the rest of the document. GitHub rejects such a file anyway.
// Reading again only once per document keeps the time linear however many
// collections are unclosed.
func (p *parser) flowCollection(n int, c ctx, i int32, kind NodeKind, open, close byte, ok, ck TokenKind, entry func(int, ctx) bool) bool {
	if p.at(p.pos) != open || p.tooDeep() {
		return false
	}
	if !p.lax() {
		done, _ := p.flowEntries(n, c, i, kind, open, close, ok, ck, entry)
		return done
	}
	outermost := p.laxFlows == 0
	m, deepAt := p.mark(), p.deepAt
	p.laxFlows++
	done, closed := p.flowEntries(n, c, i, kind, open, close, ok, ck, entry)
	p.laxFlows--
	if done && !closed {
		p.strict = true
	}
	if !p.strict || !outermost {
		return done
	}
	p.reset(m)
	p.deepAt = deepAt // a limit reached by the loose reading is not reported
	done, _ = p.flowEntries(n, c, i, kind, open, close, ok, ck, entry)
	return done
}

// flowEntries is the body of flowCollection. closed is false when the
// collection was recovered from at its end without a closing indicator.
func (p *parser) flowEntries(n int, c ctx, i int32, kind NodeKind, open, close byte, ok, ck TokenKind, entry func(int, ctx) bool) (done, closed bool) {
	m := p.mark()
	start := p.pos
	p.indicator(open, ok)
	p.setKind(i, kind)
	p.loose++
	defer func() { p.loose-- }()
	recoverable := c == ctxFlowIn || c == ctxFlowOut
	p.optSeparate(n, c)
	c = inFlow(c)
	for {
		if p.keyTooLong() {
			p.reset(m)
			return false, false
		}
		if p.indicator(close, ck) {
			return true, true
		}
		if entry(n, c) {
			p.optSeparate(n, c)
			if p.indicator(',', TokFlowEntry) {
				p.optSeparate(n, c)
				continue
			}
			if p.indicator(close, ck) {
				return true, true
			}
		}
		if !recoverable {
			p.reset(m)
			return false, false
		}
		switch p.recoverFlow(n, close, ck) {
		case syncComma:
			p.optSeparate(n, c)
		case syncClose:
			return true, true
		case syncStop:
			p.errorAt(ErrUnclosedFlow, Span{start, start + 1}, "flow collection is not closed")
			return true, false
		}
	}
}

// [137] c-flow-sequence(n,c)
func (p *parser) cFlowSequence(n int, c ctx, i int32) bool {
	return p.at(p.pos) == '[' && p.memoFail(memoCollection, n, c, func() bool {
		return p.flowCollection(n, c, i, NodeFlowSequence, '[', ']', TokFlowSeqStart, TokFlowSeqEnd, p.nsFlowSeqEntry)
	})
}

// [140] c-flow-mapping(n,c)
func (p *parser) cFlowMapping(n int, c ctx, i int32) bool {
	return p.at(p.pos) == '{' && p.memoFail(memoCollection, n, c, func() bool {
		return p.flowCollection(n, c, i, NodeFlowMapping, '{', '}', TokFlowMapStart, TokFlowMapEnd, p.nsFlowMapEntry)
	})
}

// [139] ns-flow-seq-entry(n,c)
func (p *parser) nsFlowSeqEntry(n int, c ctx) bool {
	return p.nsFlowPair(n, c) || p.nsFlowNode(n, c)
}

// pair runs f inside a new FlowPair node, keeping it only if f succeeds.
func (p *parser) pair(f func() bool) bool {
	m := p.mark()
	i := p.open(NodeFlowPair)
	if !f() {
		p.reset(m)
		return false
	}
	p.close(i)
	return true
}

// explicitKey is '?' (not followed by a non-space character) and s-separate(n,c).
func (p *parser) explicitKey(n int, c ctx) bool {
	if p.at(p.pos) != '?' || p.nsChar(p.pos+1) > 0 {
		return false
	}
	m := p.mark()
	p.emit(TokMapKey, p.pos+1)
	if !p.sSeparate(n, c) {
		p.reset(m)
		return false
	}
	return true
}

// [142] ns-flow-map-entry(n,c)
func (p *parser) nsFlowMapEntry(n int, c ctx) bool {
	return p.pair(func() bool {
		if p.explicitKey(n, c) {
			return p.nsFlowMapExplicitEntry(n, c)
		}
		pair := p.stack[len(p.stack)-1]
		if !p.nsFlowMapImplicitEntry(n, c) {
			return false
		}
		if p.mode == ModeGitHub {
			p.checkFlowKey(pair)
		}
		return true
	})
}

// checkFlowKey reports, in ModeGitHub, what GitHub rejects in the implicit
// key of the flow mapping entry pair: a ':' that is
// not on the line the key starts on, and more than 1024 characters from the
// key's start to the ':'. YAML 1.2.2 limits neither for a flow mapping
// ([144]); YamlDotNet drops a possible simple key at a new line and past
// 1024 characters (Scanner.StaleSimpleKeys) and then finds no ':'. GitHub
// counts code points, where YamlDotNet on .NET counts UTF-16 units.
func (p *parser) checkFlowKey(pair int32) {
	k := pair + 1
	if int(k) >= len(p.t.nodes) || p.t.nodes[k].parent != pair {
		return
	}
	kn := p.t.nodes[k]
	if kn.tokStart == kn.tokEnd { // [146]: an empty key
		return
	}
	colon := -1
	for j := int(kn.tokEnd); j < len(p.t.tokens); j++ {
		if p.t.tokens[j].kind == TokMapValue {
			colon = int(p.t.tokens[j].start)
			break
		}
	}
	if colon < 0 {
		return
	}
	start := int(p.t.tokens[kn.tokStart].start)
	if p.t.line(start) != p.t.line(colon) {
		p.errorAt(ErrImplicitKeyLine, Span{colon, colon + 1}, "GitHub needs the ':' of this key on the line the key starts on")
	}
	// A character is at most 4 bytes, so past 4096 bytes nothing is counted:
	// nested keys would otherwise count the same bytes at every level.
	if n := colon - start; n > 4*1024 || n > 1024 && utf8.RuneCount(p.src[start:colon]) > 1024 {
		p.errorAt(ErrImplicitKeyLength, Span{start, p.t.tokenStart(kn.tokEnd)}, "GitHub allows at most 1024 characters from the start of a key to its ':'")
	}
}

// [143] ns-flow-map-explicit-entry(n,c)
func (p *parser) nsFlowMapExplicitEntry(n int, c ctx) bool {
	if !p.nsFlowMapImplicitEntry(n, c) {
		p.emptyNode()
		p.emptyNode()
	}
	return true
}

// [144] ns-flow-map-implicit-entry(n,c)
func (p *parser) nsFlowMapImplicitEntry(n int, c ctx) bool {
	return p.keyThen(func() bool { return p.nsFlowYAMLNode(n, c) }, func() bool { return p.sepThen(n, c, p.cNsFlowMapSeparateValue) }, true) ||
		p.cNsFlowMapEmptyKeyEntry(n, c) ||
		p.keyThen(func() bool { return p.cFlowJSONNode(n, c) }, func() bool { return p.sepThen(n, c, p.cNsFlowMapAdjacentValue) }, true)
}

// keyThen is key followed by value, or by e-node when optional.
func (p *parser) keyThen(key, value func() bool, optional bool) bool {
	m := p.mark()
	if !key() {
		return false
	}
	if value() {
		return true
	}
	if optional {
		p.emptyNode()
		return true
	}
	p.reset(m)
	return false
}

// sepThen is s-separate(n,c)? followed by value.
func (p *parser) sepThen(n int, c ctx, value func(int, ctx) bool) bool {
	m := p.mark()
	p.optSeparate(n, c)
	if value(n, c) {
		return true
	}
	p.reset(m)
	return false
}

// [146] c-ns-flow-map-empty-key-entry(n,c)
func (p *parser) cNsFlowMapEmptyKeyEntry(n int, c ctx) bool {
	m := p.mark()
	p.emptyNode()
	if p.cNsFlowMapSeparateValue(n, c) {
		return true
	}
	p.reset(m)
	return false
}

// [147] c-ns-flow-map-separate-value(n,c)
func (p *parser) cNsFlowMapSeparateValue(n int, c ctx) bool {
	if p.at(p.pos) != ':' || p.eof() || p.plainSafe(p.pos+1, c) > 0 {
		return false
	}
	p.emit(TokMapValue, p.pos+1)
	m := p.mark()
	if p.sSeparate(n, c) && p.nsFlowNode(n, c) {
		return true
	}
	p.reset(m)
	p.emptyNode()
	return true
}

// [149] c-ns-flow-map-adjacent-value(n,c)
func (p *parser) cNsFlowMapAdjacentValue(n int, c ctx) bool {
	if !p.indicator(':', TokMapValue) {
		return false
	}
	m := p.mark()
	p.optSeparate(n, c)
	if p.nsFlowNode(n, c) {
		return true
	}
	p.reset(m)
	p.emptyNode()
	return true
}

// [150] ns-flow-pair(n,c)
func (p *parser) nsFlowPair(n int, c ctx) bool {
	if !p.maybePair(p.pos) {
		return false
	}
	return p.memoFail(memoPair, n, c, func() bool {
		return p.pair(func() bool {
			if p.explicitKey(n, c) {
				return p.nsFlowMapExplicitEntry(n, c)
			}
			return p.nsFlowPairEntry(n, c)
		})
	})
}

type memoProd uint8

const (
	memoPair memoProd = iota
	memoCollection
)

type memoKey struct {
	pos, n, key int
	c           ctx
	prod        memoProd
	lax         bool
}

// memoFail runs f unless it is known to fail here, and remembers a failure.
// Without this, nested flow collections try each entry as a pair and then
// as a node, and every level doubles the work. A failure depends on the
// position, n, c and the enclosing implicit key; one caused by the key's
// length or by the nesting limit is not remembered, since it depends on
// more than that. A strict reading again (flowCollection) fails elsewhere
// than a loose one, so lax is part of the key.
func (p *parser) memoFail(prod memoProd, n int, c ctx, f func() bool) bool {
	k := memoKey{p.pos, n, p.keyStart, c, prod, p.lax()}
	if p.failed[k] {
		return false
	}
	deep := p.deepHits
	if f() {
		return true
	}
	if !p.keyOver && p.deepHits == deep {
		if p.failed == nil {
			p.failed = map[memoKey]bool{}
		}
		p.failed[k] = true
	}
	return false
}

// [151] ns-flow-pair-entry(n,c)
func (p *parser) nsFlowPairEntry(n int, c ctx) bool {
	return p.keyThen(func() bool { return p.nsSImplicitYAMLKey(ctxFlowKey) }, func() bool { return p.cNsFlowMapSeparateValue(n, c) }, false) ||
		p.cNsFlowMapEmptyKeyEntry(n, c) ||
		p.keyThen(func() bool { return p.cSImplicitJSONKey(ctxFlowKey) }, func() bool { return p.cNsFlowMapAdjacentValue(n, c) }, false)
}

// implicitKey is node followed by s-separate-in-line?, at most 1024
// characters altogether. A key inside a key is shorter than the outer one,
// so once the outermost key passes the limit every production fails at
// once (keyTooLong) instead of retrying alternatives that cannot succeed.
func (p *parser) implicitKey(node func() bool) bool {
	m := p.mark()
	start := p.pos
	if p.keyStart < 0 {
		p.keyStart = start
		defer func() { p.keyStart, p.keyOver = -1, false }()
	}
	if !node() {
		return false
	}
	p.optWhite()
	if p.keyTooLong() || utf8.RuneCount(p.src[start:p.pos]) > 1024 {
		p.reset(m)
		return false
	}
	return true
}

// keyTooLong reports whether the outermost implicit key being read has
// reached more than 1024 characters. It stays true after a reset moves the
// position back, until that key is given up.
func (p *parser) keyTooLong() bool {
	if p.keyOver {
		return true
	}
	if p.keyStart < 0 || p.pos-p.keyStart <= 1024 {
		return false
	}
	p.keyOver = p.pos-p.keyStart > 4*1024 || utf8.RuneCount(p.src[p.keyStart:p.pos]) > 1024
	return p.keyOver
}

// [154] ns-s-implicit-yaml-key(c)
func (p *parser) nsSImplicitYAMLKey(c ctx) bool {
	return p.implicitKey(func() bool { return p.nsFlowYAMLNode(0, c) })
}

// [155] c-s-implicit-json-key(c)
func (p *parser) cSImplicitJSONKey(c ctx) bool {
	return p.implicitKey(func() bool { return p.cFlowJSONNode(0, c) })
}
