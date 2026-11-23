package edit

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// LineComment makes the edit that sets the comment at the end of the line
// n ends on to "# " + text, adding one or replacing the one there; an empty
// text removes it, with the white space before it. A new comment is put as
// far from the content as the document's first comment after content is,
// or one space. It fails when text has a line break, when something other
// than a comment follows n on its line, for an empty node, which sits
// where the next token starts, and for a block scalar, whose last line is
// content to its end. It promises no change in the logical tree.
func (e *Editor) LineComment(n cst.Node, text string) (Edit, error) {
	if text != "" {
		if err := commentText(text); err != nil {
			return Edit{}, err
		}
	}
	if last := lastLeaf(n); isBlockScalar(last) {
		return Edit{}, errors.New("a '#' after a block scalar's last line is part of its content")
	}
	src := treeBytes(n)
	if cs := n.ContentSpan(); cs.Start == cs.End {
		return Edit{}, errors.New("an empty node has no line of its own")
	}
	end := n.ContentSpan().End
	hash, lineBreak, ok := trailing(src, end)
	if !ok {
		return Edit{}, fmt.Errorf("%q follows the node on its line", src[end:lineBreak])
	}
	want := &expect{node: n, comment: &text}
	var sp cst.Span
	var b string
	switch {
	case hash >= 0 && text == "":
		sp = cst.Span{Start: end, End: lineBreak}
	case hash >= 0:
		sp, b = cst.Span{Start: hash, End: lineBreak}, "# "+text
	case text == "":
		sp = cst.Span{Start: end, End: end}
	default: // white space at the end of the line goes: it would end the comment
		sp, b = cst.Span{Start: end, End: lineBreak}, strings.Repeat(" ", e.commentGap(rootOf(n)))+"# "+text
	}
	return Edit{Span: sp, Old: bytes.Clone(src[sp.Start:sp.End]), New: []byte(b), want: want}, nil
}

// trailing looks at what follows end on its line: white space, then a
// comment starting at hash (-1 without one), up to lineBreak. ok is false
// when anything else follows.
func trailing(src []byte, end int) (hash, lineBreak int, ok bool) {
	i := end
	for i < len(src) && isWhite(src[i]) {
		i++
	}
	lineBreak = len(src)
	if k := bytes.IndexAny(src[i:], "\r\n"); k >= 0 {
		lineBreak = i + k
	}
	switch {
	case i == lineBreak:
		return -1, lineBreak, true
	case src[i] == '#':
		return i, lineBreak, true
	}
	return -1, lineBreak, false
}

// commentGap is the white space before the first comment in the tree that
// follows content on its line.
func commentGap(root cst.Node) int {
	src := treeBytes(root)
	for t := range root.Tokens() {
		if t.Kind() != cst.TokComment {
			continue
		}
		start := t.Span().Start
		ls := lineStart(src, start)
		k := start
		for k > ls && isWhite(src[k-1]) {
			k--
		}
		if k > ls {
			return start - k
		}
	}
	return 1
}

// lastLeaf is the last node in n that has no child node but properties.
func lastLeaf(n cst.Node) cst.Node {
	for {
		var last cst.Node
		found := false
		for e := range n.Children() {
			if c, ok := e.Node(); ok && c.Kind() != cst.NodeError && c.Kind() != cst.NodeProperties {
				last, found = c, true
			}
		}
		if !found {
			return n
		}
		n = last
	}
}
