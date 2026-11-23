package edit

import (
	"bytes"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/scalar"
)

// owned is the range of lines a block element (a BlockMappingEntry or a
// BlockSequenceEntry) takes: from the start of its first line, or from its
// start when it shares that line with its parent (sharesLine), to the end
// of its last line, the line break included. The tree puts comments where
// the grammar does: those above the next sibling at the end of the
// previous element, those above the first child in the parent. Which
// element a comment is about is a guess at what the author meant, since
// YAML gives comments no meaning (3.2.3.3). The guess: comment lines just
// above an element, at its column and with no blank line between, are its
// own. When the guess is wrong, deleting the element leaves the comment.
func owned(n cst.Node) cst.Span {
	src := treeBytes(n)
	cs := n.ContentSpan()
	end := nextLineStart(src, cs.End)
	if b := blockEnd(n); b > end {
		end = b
	}
	if sharesLine(n) {
		return cst.Span{Start: cs.Start, End: end}
	}
	start := lineStart(src, cs.Start)
	col := cs.Start - start
	for start > 0 {
		prev := lineStart(src, start-1)
		line := src[prev:start]
		k := 0
		for k < len(line) && line[k] == ' ' {
			k++
		}
		if k != col || k == len(line) || line[k] != '#' {
			break
		}
		start = prev
	}
	return cst.Span{Start: start, End: end}
}

// blockEnd is, when the last scalar of n is a block scalar, the end of
// its last line that is part of its value: ContentSpan leaves out, as
// white space and line breaks, the empty lines of a keep scalar, which its
// value keeps (8.1.1.2), and a line of more spaces than the indentation,
// which is content. The empty lines of a clip or strip scalar and the
// comment lines after it ([169] l-trail-comments) are no part of the value.
// It is 0 for any other n.
func blockEnd(n cst.Node) int {
	last := lastLeaf(n)
	if !isBlockScalar(last) {
		return 0
	}
	v, _ := scalar.Decode(last)
	keep := scalar.ChompingOf(last) == scalar.ChompKeep
	end, comment, content := 0, false, false
	for t := range last.Tokens() {
		switch t.Kind() {
		case cst.TokComment:
			comment = true
		case cst.TokBlockContent:
			content = true
		case cst.TokSpace:
			content = content || len(t.Bytes()) > v.Indent()
		case cst.TokNewline:
			if !comment && (keep || content) {
				end = t.Span().End
			}
			comment, content = false, false
		}
	}
	if sp := last.Span(); !comment && (keep || content) && sp.End > end {
		end = sp.End // the last line, without a line break at the end of the input
	}
	return end
}

// sharesLine is whether the element starts on the line of its parent's
// indicator, after "- " ([186] ns-l-compact-sequence, [195] ns-l-compact-mapping).
func sharesLine(n cst.Node) bool {
	src := treeBytes(n)
	s := n.ContentSpan().Start
	for _, c := range src[lineStart(src, s):s] {
		if c != ' ' {
			return true
		}
	}
	return false
}

// layoutAt is how to write elements into the collection c: its column,
// the width of one level of indentation, the form of a sequence under a
// key, and the line break, taken from c and its document.
//   - unit: c's column less the column of the key it is the value of; when
//     c is no key's value or has no greater column, the first such
//     difference in the document; 2 when there is none.
//   - seqUnder: whether the document's first block sequence under a key is
//     indented; true when there is none.
//   - nl: the document's first line break.
//
// What it takes from the document, e finds once for each document.
func (e *Editor) layoutAt(c cst.Node) layout {
	src := treeBytes(c)
	doc := e.docLayout(documentOf(c), src)
	l := layout{flow: c.IsFlow(), col: column(src, firstContent(c)), unit: 2, seqUnder: doc.seqUnder, nl: e.newline(rootOf(c), src)}
	switch d, ok := keyIndent(src, c); {
	case ok && d > 0:
		l.unit = d
	case doc.unit > 0:
		l.unit = doc.unit
	}
	return l
}

// docLayout is what layoutAt takes from a document: the first difference
// of a block collection's column and its key's that is greater than 0 (0
// when there is none), and whether the first block sequence under a key
// is indented (true when there is none).
type docLayout struct {
	unit     int
	seqUnder bool
}

func findDocLayout(doc cst.Node, src []byte) docLayout {
	l := docLayout{seqUnder: true}
	unitFound, seqFound := false, false
	var visit func(n cst.Node) bool
	visit = func(n cst.Node) bool {
		if unitFound && seqFound {
			return false
		}
		if d, ok := keyIndent(src, n); ok && !n.IsFlow() {
			if d > 0 && !unitFound {
				l.unit, unitFound = d, true
			}
			if n.Kind() == cst.NodeBlockSequence && !seqFound {
				l.seqUnder, seqFound = d > 0, true
			}
		}
		for e := range n.Children() {
			if x, ok := e.Node(); ok && !visit(x) {
				return false
			}
		}
		return true
	}
	visit(doc)
	return l
}

// firstContent is where the first element of c starts, or c's content
// when it has none: properties on the line above do not count.
func firstContent(c cst.Node) int {
	if e, ok := firstElement(c); ok && !c.IsFlow() {
		return e.ContentSpan().Start
	}
	return c.ContentSpan().Start
}

// firstElement is the first of elementNodes(c), found without listing the
// others: layoutAt asks it of every collection it passes.
func firstElement(c cst.Node) (cst.Node, bool) {
	if m, ok := c.Mapping(); ok {
		for e := range m.Entries() {
			return e.Node, true
		}
		return cst.Node{}, false
	}
	s, _ := c.Sequence()
	for x := range s.Items() {
		if p, ok := x.Parent(); ok && p.Kind() == cst.NodeBlockSequenceEntry {
			x = p
		}
		return x, true
	}
	return cst.Node{}, false
}

// keyIndent is, for a block collection that is the value of a block
// mapping entry, its column less the key's column.
func keyIndent(src []byte, n cst.Node) (int, bool) {
	if n.Kind() != cst.NodeBlockMapping && n.Kind() != cst.NodeBlockSequence {
		return 0, false
	}
	p, ok := n.Parent()
	if !ok || p.Kind() != cst.NodeBlockMappingEntry {
		return 0, false
	}
	e := pairOf(p)
	if e.Key.Span() == n.Span() {
		return 0, false
	}
	return column(src, firstContent(n)) - column(src, p.ContentSpan().Start), true
}

// pairOf is the key and value of a block mapping entry: its first two
// child nodes other than Error and Properties, as Mapping.Entries gives
// them. It looks at the entry alone, not at the other entries of the
// mapping, so that walking a mapping stays linear.
func pairOf(entry cst.Node) cst.Entry {
	ent := cst.Entry{Node: entry}
	i := 0
	for e := range entry.Children() {
		c, ok := e.Node()
		if !ok || c.Kind() == cst.NodeError || c.Kind() == cst.NodeProperties {
			continue
		}
		switch i {
		case 0:
			ent.Key = c
		case 1:
			ent.Value = c
			return ent
		}
		i++
	}
	return ent
}

func column(src []byte, pos int) int { return pos - lineStart(src, pos) }

// nextLineStart is the position after the line break that ends the line of
// pos, or the end of src.
func nextLineStart(src []byte, pos int) int {
	i := bytes.IndexAny(src[pos:], "\r\n")
	if i < 0 {
		return len(src)
	}
	i += pos
	if src[i] == '\r' && i+1 < len(src) && src[i+1] == '\n' {
		return i + 2
	}
	return i + 1
}
