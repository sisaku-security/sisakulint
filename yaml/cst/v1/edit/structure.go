package edit

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// Place is where Insert puts entries in a mapping.
type Place struct {
	kind placeKind
	key  string
}

type placeKind uint8

const (
	placeFirst placeKind = iota
	placeLast
	placeBefore
	placeAfter
)

func First() Place            { return Place{kind: placeFirst} }
func Last() Place             { return Place{kind: placeLast} }
func Before(key string) Place { return Place{kind: placeBefore, key: key} }
func After(key string) Place  { return Place{kind: placeAfter, key: key} }

// Insert makes the edit that puts pairs into the mapping m at at, in their
// order. It fails when at names a key m does not have, when m has a key of
// pairs or pairs have one twice, and when pairs cannot be written there.
func (e *Editor) Insert(m cst.Node, at Place, pairs Map) (Edit, error) {
	if m.Kind() != cst.NodeBlockMapping && m.Kind() != cst.NodeFlowMapping {
		return Edit{}, fmt.Errorf("Insert needs a mapping, not a %v", m.Kind())
	}
	coll := e.collection(m)
	added := map[string]bool{}
	for _, p := range pairs {
		if hasKey(coll.keys, p.Key) || added[p.Key] {
			return Edit{}, fmt.Errorf("the mapping has key %q already; SetValue replaces its value", p.Key)
		}
		added[p.Key] = true
	}
	i := len(coll.entries) // the index the first pair gets
	switch at.kind {
	case placeFirst:
		i = 0
	case placeBefore, placeAfter:
		k, ok := coll.keys[at.key]
		if !ok {
			return Edit{}, fmt.Errorf("the mapping has no key %q", at.key)
		}
		i = k
		if at.kind == placeAfter {
			i++
		}
	}
	l := e.layoutAt(m)
	text, err := writePairs(pairs, l)
	if err != nil {
		return Edit{}, err
	}
	elems := coll.elems // the entries' nodes
	keysOf := make([]string, len(pairs))
	values := make([]Value, len(pairs))
	for k, p := range pairs {
		keysOf[k], values[k] = p.Key, p.Value
	}
	ed, err := place(m, elems, i, text, l, len(pairs) > 0 && endsInBreak(pairs[len(pairs)-1].Value))
	if err != nil {
		return Edit{}, err
	}
	ed.want = &expect{kind: Added, node: m, added: neighbors(elems, i, &addedWant{keys: keysOf, values: values})}
	return ed, nil
}

// neighbors fills in the elements around the place i.
func neighbors(elems []cst.Node, i int, w *addedWant) *addedWant {
	if i > 0 {
		w.before = elems[i-1]
	}
	if i < len(elems) {
		w.after = elems[i]
	}
	return w
}

// InsertItem makes the edit that puts v into the sequence s as its item i,
// 0 <= i <= the number of items.
func (e *Editor) InsertItem(s cst.Node, i int, v Value) (Edit, error) {
	if s.Kind() != cst.NodeBlockSequence && s.Kind() != cst.NodeFlowSequence {
		return Edit{}, fmt.Errorf("InsertItem needs a sequence, not a %v", s.Kind())
	}
	coll := e.collection(s)
	items := coll.items
	if i < 0 || i > len(items) {
		return Edit{}, fmt.Errorf("index %d is outside the %d items", i, len(items))
	}
	l := e.layoutAt(s)
	text, err := writeItem(v, l)
	if err != nil {
		return Edit{}, err
	}
	ed, err := place(s, coll.elems, i, text, l, endsInBreak(v))
	if err != nil {
		return Edit{}, err
	}
	ed.want = &expect{kind: Added, node: s, added: neighbors(items, i, &addedWant{values: []Value{v}})}
	return ed, nil
}

// place makes the edit that puts text, written for the layout l, before
// the element i of the collection c, or after the last one. At the end of
// an input with no final line break, text loses its own, unless keepBreak:
// a block scalar's value needs it. In a block,
// text is whole lines and goes at the start of the element's lines
// (lines.go); before an element on its parent's line, as in "- run: a",
// it goes where the element starts and moves it to the next line. In a
// flow collection, text is one element and a ", " separates it.
func place(c cst.Node, elems []cst.Node, i int, text []byte, l layout, keepBreak bool) (Edit, error) {
	src := treeBytes(c)
	var pos int
	var b []byte
	switch {
	case l.flow && len(elems) == 0:
		pos = flowStart(c)
		b = text
	case l.flow && i < len(elems):
		pos = elems[i].ContentSpan().Start
		b = append(text, ", "...)
	case l.flow:
		pos = elems[i-1].ContentSpan().End
		b = append([]byte(", "), text...)
		if src[pos-1] == '?' || src[pos-1] == ':' {
			b = append([]byte(" "), b...) // "?," is no indicator followed by white space
		}
	case len(elems) == 0:
		return Edit{}, errors.New("a block collection has an element")
	case i < len(elems) && sharesLine(elems[i]):
		pos = elems[i].ContentSpan().Start
		b = append(bytes.Clone(text[l.col:]), l.pad(l.col)...)
	case i < len(elems):
		pos = owned(elems[i]).Start
		b = text
	default:
		pos = owned(elems[i-1]).End
		b = text
		if pos == len(src) && (pos == 0 || src[pos-1] != '\n' && src[pos-1] != '\r') {
			if last := lastLeaf(elems[i-1]); isBlockScalar(last) && !strips(last) {
				return Edit{}, errors.New("a line break after the block scalar at the end of the input would join its value")
			}
			b = append([]byte(l.nl), text...)
			if !keepBreak {
				b = bytes.TrimSuffix(b, []byte(l.nl))
			}
		}
	}
	return Edit{Span: cst.Span{Start: pos, End: pos}, Old: []byte{}, New: b}, nil
}

// flowStart is the position after the '[' or '{' of a flow collection.
func flowStart(c cst.Node) int {
	for e := range c.Children() {
		if t, ok := e.Token(); ok && (t.Kind() == cst.TokFlowSeqStart || t.Kind() == cst.TokFlowMapStart) {
			return t.Span().End
		}
	}
	return c.ContentSpan().Start
}

// Delete makes the edit that removes an entry of a mapping or an item of
// a sequence (given by its value or its "- " entry), with the lines it
// takes (lines.go) in a block, with the ", " next to it in a flow
// collection. It fails for the only element of a block collection, which
// cannot be empty, and when an alias outside the element refers to an
// anchor inside it.
func (e *Editor) Delete(n cst.Node) (Edit, error) {
	elem, item, coll, ok := elementOf(n)
	if !ok {
		return Edit{}, fmt.Errorf("Delete needs an entry or an item, not a %v", n.Kind())
	}
	if err := e.aliasesOutside(elem); err != nil {
		return Edit{}, err
	}
	src := treeBytes(elem)
	cf := e.collection(coll)
	elems := cf.elems
	i, found := cf.at[elem]
	if !found {
		return Edit{}, errors.New("the element is not one of its collection's, as in a tree with errors")
	}
	var sp cst.Span
	switch {
	case coll.IsFlow() && len(elems) == 1:
		sp = cst.Span{Start: flowStart(coll), End: flowEnd(coll)}
	case coll.IsFlow() && i < len(elems)-1:
		sp = cst.Span{Start: elem.ContentSpan().Start, End: elems[i+1].ContentSpan().Start}
	case coll.IsFlow():
		sp = cst.Span{Start: elems[i-1].ContentSpan().End, End: elem.ContentSpan().End}
	case len(elems) == 1:
		empty := "Map{}"
		if _, isSeq := coll.Sequence(); isSeq {
			empty = "Seq{}"
		}
		return Edit{}, fmt.Errorf("a block collection cannot be empty: delete its parent, or SetValue(its node, %s)", empty)
	case sharesLine(elem) && owned(elems[i+1]).Start == owned(elem).End:
		n := elems[i+1]
		sp = cst.Span{Start: elem.ContentSpan().Start, End: owned(n).Start + column(src, n.ContentSpan().Start)}
	case sharesLine(elem):
		// Lines between that are no element's stay, and the next element
		// starts on a line of its own: "-\n# note\n  name: b".
		start := elem.ContentSpan().Start
		for start > 0 && isWhite(src[start-1]) {
			start--
		}
		sp = cst.Span{Start: start, End: lineBreakBefore(src, owned(elem).End)}
	default:
		sp = owned(elem)
		var before cst.Node // the block scalar the element follows, if any
		if i > 0 && isBlockScalar(lastLeaf(elems[i-1])) {
			before = lastLeaf(elems[i-1])
		}
		// At the end of an input with no final line break, the line break
		// before the element goes with it, unless it ends the value of the
		// scalar before (a clipped or kept one)
		if sp.End == len(src) && !endsLine(src) && (before == (cst.Node{}) || strips(before)) {
			sp.Start = lineBreakBefore(src, sp.Start)
		}
		if before != (cst.Node{}) {
			sp.End = afterJoiningLines(src, sp.End, before) // they would be the scalar's
		}
	}
	if sp.Start > sp.End {
		return Edit{}, errors.New("the elements are out of order, as in a tree with errors")
	}
	return Edit{
		Span: sp,
		Old:  bytes.Clone(src[sp.Start:sp.End]),
		New:  []byte{},
		want: &expect{kind: Removed, node: item},
	}, nil
}

// SetValue makes the edit that replaces n, the value of an entry or an
// item of a sequence, by v, which may be of another kind. Its anchor and
// tag go. A comment on the line of the entry's key stays on that line.
// It fails for a key, and when an alias outside n refers to an anchor in
// it.
func (e *Editor) SetValue(n cst.Node, v Value) (Edit, error) {
	parent, ok := n.Parent()
	if !ok {
		return Edit{}, errors.New("SetValue needs a value")
	}
	var coll cst.Node
	afterKey := false
	switch parent.Kind() {
	case cst.NodeBlockMappingEntry, cst.NodeFlowPair:
		if pairOfEntry(parent).Value != n {
			return Edit{}, errors.New("SetValue replaces a value, not a key")
		}
		coll, _ = parent.Parent()
		afterKey = true
	case cst.NodeBlockSequenceEntry:
		coll, _ = parent.Parent()
	case cst.NodeFlowSequence:
		coll = parent
	default:
		return Edit{}, fmt.Errorf("SetValue needs a value of an entry or an item, not the content of a %v", parent.Kind())
	}
	if err := e.aliasesOutside(n); err != nil {
		return Edit{}, err
	}
	l := e.layoutAt(coll)
	l.flow = parent.IsFlow()
	text, err := writeValue(v, l, afterKey)
	if err != nil {
		return Edit{}, err
	}
	src := treeBytes(n)
	cs := n.ContentSpan()
	want := &expect{kind: Changed, node: n, set: v}
	if l.flow {
		b := text
		if _, colon := indicatorEnd(parent); afterKey && !colon {
			b = append([]byte(": "), text...) // { a } has no ':' before its empty value
		} else if cs.Start == cs.End && cs.Start > 0 && !isWhite(src[cs.Start-1]) {
			b = append([]byte(" "), text...)
		}
		return Edit{Span: cs, Old: bytes.Clone(src[cs.Start:cs.End]), New: b, want: want}, nil
	}
	ind, ok := indicatorEnd(parent)
	if !ok {
		return Edit{}, errors.New("the entry has no ':'")
	}
	if cs.Start == cs.End {
		cs = cst.Span{Start: ind, End: ind}
	}
	lineBreak := len(src)
	if k := bytes.IndexAny(src[ind:], "\r\n"); k >= 0 {
		lineBreak = ind + k
	}
	// The key's line keeps what follows the value on it: a comment, when
	// the value starts there and ends there, or when it starts below.
	var sp cst.Span
	var tail []byte
	switch {
	case cs.Start >= lineBreak:
		sp, tail = cst.Span{Start: ind, End: cs.End}, src[ind:lineBreak]
	case cs.End <= lineBreak:
		sp, tail = cst.Span{Start: ind, End: lineBreak}, src[cs.End:lineBreak]
	default:
		sp = cst.Span{Start: ind, End: cs.End}
	}
	if isBlockValue(v) {
		// A comment after the old value on its last line would be the
		// block scalar's content: it goes to the header's line.
		if k := bytes.IndexAny(src[sp.End:], "\r\n"); sp.End == cs.End && k != 0 {
			le := len(src)
			if k > 0 {
				le = sp.End + k
			}
			if len(bytes.TrimSpace(src[sp.End:le])) > 0 {
				tail = append(bytes.Clone(tail), src[sp.End:le]...)
				sp.End = le
			}
		}
		// The lines after the value that the block scalar would read as its
		// content are no part of the value: SetValue does not take them in
		indent, indented := blockIndent(text, l.col)
		if next := nextLineStart(src, sp.End); afterLinesOf(src, next, indent, blockKeeps(text), indented) > next {
			return Edit{}, errors.New("a line after the value would be the block scalar's content: a comment at its indentation or more, or a line of more spaces")
		}
	}
	first, rest, multi := strings.Cut(string(text), l.nl)
	b := afterIndicator(first) + string(tail)
	if multi {
		b += l.nl + rest
	}
	if sp.End == len(src) && !endsLine(src) && endsInBreak(v) {
		b += l.nl // the value's last line break, which the input's end would lose
	}
	return Edit{Span: sp, Old: bytes.Clone(src[sp.Start:sp.End]), New: []byte(b), want: want}, nil
}

// elementOf is, for an entry, an item or an item's "- " entry, the element
// as the collection holds it, the node its Change names (the entry, or the
// item), and the collection.
func elementOf(n cst.Node) (elem, item, coll cst.Node, ok bool) {
	p, ok := n.Parent()
	if !ok {
		return
	}
	switch {
	case n.Kind() == cst.NodeBlockSequenceEntry:
		for c := range n.Children() {
			if x, isNode := c.Node(); isNode && x.Kind() != cst.NodeError {
				return n, x, p, true
			}
		}
		return
	case p.Kind() == cst.NodeBlockSequenceEntry:
		coll, _ = p.Parent()
		return p, n, coll, true
	case p.Kind() == cst.NodeFlowSequence:
		return n, n, p, true
	case n.Kind() == cst.NodeBlockMappingEntry || n.Kind() == cst.NodeFlowPair && p.Kind() == cst.NodeFlowMapping:
		return n, n, p, true
	}
	return cst.Node{}, cst.Node{}, cst.Node{}, false
}

// elementNodes is the elements of a collection as elementOf gives them.
func elementNodes(c cst.Node) []cst.Node {
	var out []cst.Node
	for _, x := range elementsOf(c) {
		if p, ok := x.Parent(); ok && p.Kind() == cst.NodeBlockSequenceEntry {
			x = p
		}
		out = append(out, x)
	}
	return out
}

// indicatorEnd is the position after the ':' of an entry or the '-' of an
// item.
func indicatorEnd(entry cst.Node) (int, bool) {
	for e := range entry.Children() {
		if t, ok := e.Token(); ok && (t.Kind() == cst.TokMapValue || t.Kind() == cst.TokSeqEntry) {
			return t.Span().End, true
		}
	}
	return 0, false
}

// flowEnd is the position of the ']' or '}' of a flow collection.
func flowEnd(c cst.Node) int {
	for e := range c.Children() {
		if t, ok := e.Token(); ok && (t.Kind() == cst.TokFlowSeqEnd || t.Kind() == cst.TokFlowMapEnd) {
			return t.Span().Start
		}
	}
	return c.ContentSpan().End
}

func endsLine(src []byte) bool {
	return len(src) > 0 && (src[len(src)-1] == '\n' || src[len(src)-1] == '\r')
}

// lineBreakBefore is where the line break that ends at pos starts.
func lineBreakBefore(src []byte, pos int) int {
	if pos > 0 && src[pos-1] == '\n' {
		pos--
	}
	if pos > 0 && src[pos-1] == '\r' {
		pos--
	}
	return pos
}

func isBlockScalar(n cst.Node) bool {
	return n.Kind() == cst.NodeScalar && (n.Style() == cst.Literal || n.Style() == cst.Folded)
}

func strips(n cst.Node) bool { return scalar.ChompingOf(n) == scalar.ChompStrip }

// afterJoiningLines is the end of the lines from pos that the block
// scalar sc would read as its own if they followed it, as they do once
// what is between is deleted (afterLinesOf).
func afterJoiningLines(src []byte, pos int, sc cst.Node) int {
	keep := scalar.ChompingOf(sc) == scalar.ChompKeep
	if !hasContent(sc) {
		// no line decided its indentation: the first line indented more
		// than its parent's would (8.1.1.1)
		return afterLinesOf(src, pos, parentIndent(sc)+1, keep, false)
	}
	v, _ := scalar.Decode(sc)
	return afterLinesOf(src, pos, v.Indent(), keep, true)
}

// hasContent is whether the block scalar sc has a line of content.
func hasContent(sc cst.Node) bool {
	for t := range sc.Tokens() {
		if t.Kind() == cst.TokBlockContent {
			return true
		}
	}
	return false
}

// parentIndent is the indentation of the entry or item whose value the
// scalar sc is, -1 for none (a document's).
func parentIndent(sc cst.Node) int {
	p, ok := sc.Parent()
	if !ok || p.Kind() != cst.NodeBlockMappingEntry && p.Kind() != cst.NodeBlockSequenceEntry {
		return -1
	}
	return column(treeBytes(sc), p.ContentSpan().Start)
}

// afterLinesOf is the end of the lines from pos that a block scalar of the
// indentation indent, which keeps its final empty lines when keep, would
// read as its own if they followed it: a line of white space, when keep
// (8.1.1.2), or when indented is true (the indentation is known) and the
// line has more than indent (content, [170] l-nb-literal-text); a comment
// line at indent or more, which is content there. It reads the lines of
// white space and comments from pos, which no element has, and stops at a
// comment line less indented, after which the scalar has ended ([169]
// l-trail-comments), or at other content. The lines it passes that would
// not join are in the range too when a later one does.
func afterLinesOf(src []byte, pos, indent int, keep, indented bool) int {
	end := pos
	for p := pos; p < len(src); {
		k := p
		for k < len(src) && src[k] == ' ' {
			k++
		}
		spaces := k - p
		for k < len(src) && isWhite(src[k]) {
			k++
		}
		next := nextLineStart(src, k)
		switch {
		case k == len(src) || src[k] == '\n' || src[k] == '\r': // white space only
			if keep || indented && (spaces > indent || spaces == indent && k > p+spaces) {
				end = next
			}
		case src[k] == '#' && spaces >= indent:
			end = next
		default:
			return end
		}
		p = next
	}
	return end
}

// endsInBreak is whether the last scalar v writes is a block scalar whose
// value ends in a line break: at the end of the input, it needs one there.
func endsInBreak(v Value) bool {
	switch x := v.(type) {
	case Map:
		return len(x) > 0 && endsInBreak(x[len(x)-1].Value)
	case Seq:
		return len(x) > 0 && endsInBreak(x[len(x)-1])
	case Scalar:
		return x.styled && (x.style == cst.Literal || x.style == cst.Folded) && strings.HasSuffix(x.s, "\n")
	}
	return false
}

// blockIndent is the indentation of the content of the block scalar text
// writes, as the value of an entry or item of the collection at the column
// col, and whether it is known: from the indentation indicator of its
// header, from col (8.1.1.1), else from its first line of content; with
// neither, a line indented more than col would decide it (col+1, false).
func blockIndent(text []byte, col int) (int, bool) {
	header, body, _ := bytes.Cut(text, []byte("\n"))
	if k := bytes.IndexAny(header, "123456789"); k >= 0 {
		return col + int(header[k]-'0'), true
	}
	for _, line := range bytes.Split(body, []byte("\n")) {
		if t := bytes.TrimLeft(line, " "); len(bytes.TrimSpace(t)) > 0 {
			return len(line) - len(t), true
		}
	}
	return col + 1, false
}

// blockKeeps is whether the block scalar text writes keeps its final
// empty lines: its header has the indicator +.
func blockKeeps(text []byte) bool {
	header, _, _ := bytes.Cut(text, []byte("\n"))
	return bytes.Contains(header, []byte("+"))
}

// isBlockValue is whether v is a literal or folded scalar.
func isBlockValue(v Value) bool {
	x, ok := v.(Scalar)
	return ok && x.styled && (x.style == cst.Literal || x.style == cst.Folded)
}
