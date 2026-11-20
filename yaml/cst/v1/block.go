package cst

// Spec chapter 8: block styles.

// [196] s-l+block-node(n,c), with [198] s-l+block-in-block(n,c)
func (p *parser) sLBlockNode(n int, c ctx) bool {
	if p.tooDeep() {
		return false
	}
	return p.sLBlockScalar(n, c) || p.sLBlockCollection(n, c) || p.sLFlowInBlock(n)
}

// [200] s-l+block-collection(n,c). Without properties the collection's
// node starts at its first entry, after the first line's indentation.
// Properties that turn out not to be followed by a line end belong to the
// first key instead, so the collection is retried with only the first
// property (the second may be on the key's line) and then without them.
func (p *parser) sLBlockCollection(n int, c ctx) bool {
	m := p.mark()
	for _, single := range []bool{false, true} {
		if p.sSeparate(n+1, c) {
			node := p.open(NodeScalar)
			if p.properties(n+1, c, single) && p.blockCollectionBody(n, c, &node) {
				return true
			}
		}
		p.reset(m)
	}
	node := int32(-1)
	if p.blockCollectionBody(n, c, &node) {
		return true
	}
	p.reset(m)
	return false
}

// blockCollectionBody is s-l-comments and [201] seq-space(n,c) or
// l+block-mapping(n), closing *node. Lines indented more than n belong to
// the collection even when seq-space lets its entries start at n.
func (p *parser) blockCollectionBody(n int, c ctx, node *int32) bool {
	if !p.sLComments() {
		return false
	}
	sn := n
	if c == ctxBlockOut {
		sn = n - 1
	}
	if !p.blockEntries(sn, n, node, NodeBlockSequence, p.cLBlockSeqEntry) &&
		!p.blockEntries(n, n, node, NodeBlockMapping, p.nsLBlockMapEntry) {
		return false
	}
	p.close(*node)
	return true
}

// blockEntries is [183] l+block-sequence(n) and [187] l+block-mapping(n):
// entries at one detected indentation k > n, each at the start of a line.
// A node of kind k is opened in *node after the first indentation unless
// the caller already opened one for properties; the caller closes it.
// Lines indented more than boundary that are not entries are recovered.
func (p *parser) blockEntries(n, boundary int, node *int32, kind NodeKind, entry func(int) bool) bool {
	if !p.startOfLine() || p.tooDeep() {
		return false
	}
	k := p.spaces(p.pos)
	if k < n+1 {
		return false
	}
	m := p.mark()
	p.sIndent(k)
	opened := *node < 0
	if opened {
		*node = p.open(kind)
	}
	if !entry(k) {
		p.reset(m)
		if opened {
			*node = -1
		}
		return false
	}
	p.moreEntries(k, boundary, entry)
	if !opened {
		p.setKind(*node, kind)
	}
	return true
}

// moreEntries is (s-indent(n) entry(n))*, recovering lines indented more
// than boundary that are not entries.
func (p *parser) moreEntries(n, boundary int, entry func(int) bool) {
	for !p.eof() {
		m := p.mark()
		if p.sIndent(n) && entry(n) {
			continue
		}
		p.reset(m)
		if !p.recoverBlockLine(boundary) {
			return
		}
	}
}

// blockIndicator emits b if it is not followed by a non-space character.
func (p *parser) blockIndicator(b byte, k TokenKind) bool {
	if p.at(p.pos) != b || p.eof() || p.nsChar(p.pos+1) > 0 {
		return false
	}
	p.emit(k, p.pos+1)
	return true
}

// [184] c-l-block-seq-entry(n)
func (p *parser) cLBlockSeqEntry(n int) bool {
	m := p.mark()
	e := p.open(NodeBlockSequenceEntry)
	if !p.blockIndicator('-', TokSeqEntry) || !p.sLBlockIndented(n, ctxBlockIn) {
		p.reset(m)
		return false
	}
	p.close(e)
	return true
}

// [185] s-l+block-indented(n,c)
func (p *parser) sLBlockIndented(n int, c ctx) bool {
	m := p.mark()
	k := p.spaces(p.pos)
	p.sIndent(k)
	if p.compact(n+1+k, n, NodeBlockSequence, p.cLBlockSeqEntry) || p.compact(n+1+k, n, NodeBlockMapping, p.nsLBlockMapEntry) {
		return true
	}
	p.reset(m)
	if p.sLBlockNode(n, c) {
		return true
	}
	p.emptyNode()
	if p.sLComments() {
		return true
	}
	p.reset(m)
	return false
}

// compact is [186] ns-l-compact-sequence(n) and [195] ns-l-compact-mapping(n).
func (p *parser) compact(n, boundary int, kind NodeKind, entry func(int) bool) bool {
	if p.tooDeep() {
		return false
	}
	m := p.mark()
	i := p.open(kind)
	if !entry(n) {
		p.reset(m)
		return false
	}
	p.moreEntries(n, boundary, entry)
	p.close(i)
	return true
}

// [188] ns-l-block-map-entry(n)
func (p *parser) nsLBlockMapEntry(n int) bool {
	m := p.mark()
	e := p.open(NodeBlockMappingEntry)
	if !p.cLBlockMapExplicitEntry(n) && !p.nsLBlockMapImplicitEntry(n) {
		p.reset(m)
		return false
	}
	p.close(e)
	return true
}

// [189] c-l-block-map-explicit-entry(n), with [190] c-l-block-map-explicit-key(n)
// and [191] l-block-map-explicit-value(n)
func (p *parser) cLBlockMapExplicitEntry(n int) bool {
	m := p.mark()
	if !p.blockIndicator('?', TokMapKey) || !p.sLBlockIndented(n, ctxBlockOut) {
		p.reset(m)
		return false
	}
	m2 := p.mark()
	if p.sIndent(n) && p.blockIndicator(':', TokMapValue) && p.sLBlockIndented(n, ctxBlockOut) {
		return true
	}
	p.reset(m2)
	p.emptyNode()
	return true
}

// [192] ns-l-block-map-implicit-entry(n), with [193] ns-s-block-map-implicit-key
// and [194] c-l-block-map-implicit-value(n)
func (p *parser) nsLBlockMapImplicitEntry(n int) bool {
	m := p.mark()
	if !p.cSImplicitJSONKey(ctxBlockKey) && !p.nsSImplicitYAMLKey(ctxBlockKey) {
		p.emptyNode()
	}
	if !p.blockIndicator(':', TokMapValue) {
		p.reset(m)
		return false
	}
	if p.sLBlockNode(n, ctxBlockOut) {
		return true
	}
	p.emptyNode()
	if p.sLComments() {
		return true
	}
	p.reset(m)
	return false
}

// [197] s-l+flow-in-block(n). It is the last alternative of s-l+block-node,
// so once the node is read, content after it on its line is recovered.
func (p *parser) sLFlowInBlock(n int) bool {
	m := p.mark()
	if !p.sSeparate(n+1, ctxFlowOut) || !p.nsFlowNode(n+1, ctxFlowOut) {
		p.reset(m)
		return false
	}
	if !p.sLComments() {
		p.recoverRestOfLine(n)
		p.sLComments()
	}
	return true
}

// [199] s-l+block-scalar(n,c)
func (p *parser) sLBlockScalar(n int, c ctx) bool {
	m := p.mark()
	if !p.sSeparate(n+1, c) {
		return false
	}
	i := p.open(NodeScalar)
	m2 := p.mark()
	if !p.cNsProperties(n+1, c) || !p.sSeparate(n+1, c) {
		p.reset(m2)
	}
	if !p.blockScalar(n, i) {
		p.reset(m)
		return false
	}
	return true
}

// blockScalar is [170] c-l+literal(n) and [174] c-l+folded(n) in the open
// node i, which it closes. Literal and folded content have the same lines:
// each is the indentation (Space), the text (BlockContent) and a Newline;
// they differ only in how the value is read. The node ends after the last
// empty line; [169] l-trail-comments follow it.
func (p *parser) blockScalar(n int, i int32) bool {
	b := p.at(p.pos)
	if b != '|' && b != '>' {
		return false
	}
	// [162] c-b-block-header(t), [163] c-indentation-indicator, [164] c-chomping-indicator
	h := p.pos + 1
	indicator, chomp := 0, false
	for {
		d := p.at(h)
		if indicator == 0 && d >= '1' && d <= '9' {
			indicator = int(d - '0')
		} else if !chomp && (d == '-' || d == '+') {
			chomp = true
		} else {
			break
		}
		h++
	}
	p.emit(TokBlockHeader, h)
	if !p.sBComment() {
		return false
	}
	indent := n + indicator
	if indicator == 0 {
		indent = p.detectIndent(n)
	}
	for !p.eof() {
		k := p.spaces(p.pos)
		rest := p.pos + k
		if p.breakLen(rest) > 0 || rest == len(p.src) {
			if k <= indent { // [70] l-empty
				if p.breakLen(rest) == 0 {
					break
				}
				p.emit(TokSpace, rest)
				p.bBreak()
				continue
			}
		} else if k < indent || indent == 0 && p.forbidden(p.pos) {
			break
		}
		p.sIndent(indent)
		p.emit(TokBlockContent, p.lineEnd(p.pos))
		p.bBreak()
	}
	p.close(i)
	p.lTrailComments(indent)
	return true
}

// detectIndent is the content indentation of a block scalar without an
// indentation indicator (8.1.1.1): the leading spaces of the first
// non-empty line, or of the longest empty line when there is none. Leading
// empty lines must not be longer than the first non-empty line.
func (p *parser) detectIndent(n int) int {
	longest, longestAt := 0, -1
	for pos := p.pos; pos < len(p.src); {
		k := p.spaces(pos)
		rest := pos + k
		bl := p.breakLen(rest)
		if bl == 0 && rest < len(p.src) {
			if k <= n || p.forbidden(pos) {
				break
			}
			if longest > k {
				p.errorAt(ErrIndent, Span{longestAt, longestAt + longest}, "a leading empty line is indented more than the block scalar's content")
			}
			return k
		}
		if k > longest {
			longest, longestAt = k, pos
		}
		if bl == 0 {
			break
		}
		pos = rest + bl
	}
	return max(longest, n+1)
}

// [169] l-trail-comments(n)
func (p *parser) lTrailComments(n int) {
	k := p.spaces(p.pos)
	if k >= n || p.at(p.pos+k) != '#' {
		return
	}
	p.sIndentLessThan(n)
	p.cNbCommentText()
	p.bComment()
	for p.lComment() {
	}
}
