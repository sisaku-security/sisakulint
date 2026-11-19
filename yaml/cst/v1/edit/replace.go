package edit

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// Replace makes the edit that turns the value's bytes [s,e) into text,
// written in the scalar's own style: the style never changes (Rewrite
// changes it). It fails when [s,e) does not map exactly to input bytes,
// when the style cannot write the result, and when a plain scalar's
// untagged value would change type in the core schema.
func Replace(v scalar.Value, s, e int, text string) (Edit, error) {
	old := v.String()
	if s < 0 || s > e || e > len(old) {
		return Edit{}, fmt.Errorf("range [%d,%d) is outside the %d bytes of the value", s, e, len(old))
	}
	span, exact := v.Source(s, e)
	if !exact {
		return Edit{}, fmt.Errorf("range [%d,%d) cuts what an escape, a folding or a line break made", s, e)
	}
	n := v.Node()
	src := treeBytes(n)
	value := old[:s] + text + old[e:]
	if text == old[s:e] { // nothing to write, whatever the style's layout
		b := bytes.Clone(src[span.Start:span.End])
		return Edit{Span: span, Old: b, New: bytes.Clone(b)}, nil
	}
	want := &expect{kind: Changed, node: n, scalar: &scalarWant{old: old, s: s, e: e, text: text}}
	body, ok := scalar.Body(v.Style(), text, v.Indent())
	if !ok {
		return Edit{}, fmt.Errorf("%q cannot be written in this scalar's style", text)
	}
	prefix := ""
	switch v.Style() {
	case cst.Plain:
		if err := plainFits(n, old, value, s, len(text)); err != nil {
			return Edit{}, err
		}
		if old == "" && span.Start > 0 && !isWhite(src[span.Start-1]) {
			prefix = " " // key: → key: x, not key:x
		}
	case cst.Literal, cst.Folded:
		var err error
		if prefix, body, span, err = blockFits(v, src, span, body, s, e, text, value); err != nil {
			return Edit{}, err
		}
	}
	return Edit{
		Span: span,
		Old:  bytes.Clone(src[span.Start:span.End]),
		New:  append([]byte(prefix), body...),
		want: want,
	}, nil
}

// indicators is [22] c-indicator.
const indicators = "-?:,[]{}#&*!|>'\"%@`"

// plainFits checks what the place of text in the value decides for a plain
// scalar ([126] ns-plain-first, [130] ns-plain-char): the first character,
// white space at the ends, a trailing ':', ": " and " #" across the edges
// of text, flow indicators in a flow collection, and the type.
func plainFits(n cst.Node, old, value string, s, tl int) error {
	flow := inFlow(n)
	if value != "" {
		if err := plainEdges(value, flow); err != nil {
			return err
		}
	}
	w := value[max(0, s-1):min(len(value), s+tl+1)]
	for _, bad := range []string{": ", ":\t", " #", "\t#"} {
		if strings.Contains(w, bad) {
			return fmt.Errorf("a plain scalar cannot contain %q", bad)
		}
	}
	if flow && strings.ContainsAny(value[s:s+tl], ",[]{}") {
		return errors.New("a plain scalar in a flow collection cannot contain a flow indicator")
	}
	if _, tagged := scalar.Explicit(n, scalar.DirectivesOf(documentOf(n))); !tagged && old != "" && scalar.PlainTag(old) != scalar.PlainTag(value) {
		return fmt.Errorf("the value would change from %s to %s", scalar.PlainTag(old), scalar.PlainTag(value))
	}
	return nil
}

// plainEdges checks the ends of a non-empty plain scalar: the first
// character ([126] ns-plain-first), white space at the ends, and a
// trailing ':' ([130] ns-plain-char needs a safe character after ':').
func plainEdges(value string, flow bool) error {
	c := value[0]
	next := byte(' ')
	if len(value) > 1 {
		next = value[1]
	}
	safe := !isWhite(next) && !(flow && strings.IndexByte(",[]{}", next) >= 0)
	if strings.IndexByte(indicators, c) >= 0 && !((c == '-' || c == '?' || c == ':') && safe) {
		return fmt.Errorf("a plain scalar cannot start with %q", c)
	}
	if isWhite(value[0]) || isWhite(value[len(value)-1]) {
		return errors.New("a plain scalar cannot start or end with white space")
	}
	if value[len(value)-1] == ':' {
		return errors.New("a plain scalar cannot end with ':'")
	}
	return nil
}

// blockFits places body in a block scalar's lines. The indentation of a
// line is in no segment of the value, so a range that ends in a line feed
// followed by content takes the next line's indentation along, and body
// gives it back after its own last line feed. Text at the start of a line
// before the indentation, as at the end of the value, gets it first.
func blockFits(v scalar.Value, src []byte, span cst.Span, body []byte, s, e int, text, value string) (string, []byte, cst.Span, error) {
	old, indent := v.String(), v.Indent()
	if s == 0 && strings.HasPrefix(value, " ") && !hasIndentIndicator(v.Node()) {
		return "", nil, span, errors.New("a first line starting with a space would change the detected indentation (8.1.1.1)")
	}
	pad := strings.Repeat(" ", indent)
	follows := e < len(old)
	lineEnd := strings.HasSuffix(text, "\n")
	if follows && e > 0 && old[e-1] == '\n' {
		k := 0 // an empty line has fewer spaces, or none
		for k < indent && span.End+k < len(src) && src[span.End+k] == ' ' {
			k++
		}
		span.End += k
		if lineEnd {
			body = append(body, pad[:k]...)
		}
	} else if follows && lineEnd && span.End < len(src) && src[span.End] != '\n' && src[span.End] != '\r' {
		body = append(body, pad...) // the rest of the line becomes a line of its own
	}
	prefix := ""
	if first, _, _ := strings.Cut(text, "\n"); first != "" {
		if col := span.Start - lineStart(src, span.Start); col < indent {
			prefix = pad[col:]
		}
	}
	if bytes.Contains(v.Node().Bytes(), []byte("\r\n")) {
		body = bytes.ReplaceAll(body, []byte("\n"), []byte("\r\n"))
	}
	return prefix, body, span, nil
}

func hasIndentIndicator(n cst.Node) bool {
	for t := range n.Tokens() {
		if t.Kind() == cst.TokBlockHeader {
			return bytes.ContainsAny(t.Bytes(), "123456789")
		}
	}
	return false
}

// bom is [3] c-byte-order-mark in UTF-8.
var bom = []byte("\xef\xbb\xbf")

// lineStart is where the line of pos starts: after its line break, and
// after a byte order mark there, which comes before a document ([202]
// l-document-prefix) and is no indentation or content of the line.
func lineStart(src []byte, pos int) int {
	ls := bytes.LastIndexByte(src[:pos], '\n') + 1
	if pos >= ls+len(bom) && bytes.HasPrefix(src[ls:], bom) {
		ls += len(bom)
	}
	return ls
}

func isWhite(c byte) bool { return c == ' ' || c == '\t' }

func inFlow(n cst.Node) bool {
	for {
		p, ok := n.Parent()
		if !ok {
			return false
		}
		if p.IsFlow() {
			return true
		}
		n = p
	}
}

func documentOf(n cst.Node) cst.Node {
	for n.Kind() != cst.NodeDocument {
		p, ok := n.Parent()
		if !ok {
			return n
		}
		n = p
	}
	return n
}

// treeBytes is the input of the tree n belongs to.
func treeBytes(n cst.Node) []byte { return rootOf(n).Bytes() }

// Rewrite makes the edit that replaces the whole content of the scalar
// with value written in style: plain, single- or double-quoted. The
// properties stay, and so does a comment on a block scalar's header line,
// which follows the new value.
func Rewrite(v scalar.Value, style cst.ScalarStyle, value string) (Edit, error) {
	if style != cst.Plain && style != cst.SingleQuoted && style != cst.DoubleQuoted {
		return Edit{}, errors.New("Rewrite writes plain, single- or double-quoted scalars only")
	}
	n := v.Node()
	body, ok := scalar.Body(style, value, 0)
	if !ok {
		return Edit{}, fmt.Errorf("%q cannot be written in this style", value)
	}
	if style == cst.Plain {
		if err := plainFits(n, "", value, 0, len(value)); err != nil {
			return Edit{}, err
		}
		// Taking the quotes off "3.10" or "true" would make a float or a bool.
		d := scalar.DirectivesOf(documentOf(n))
		if _, tagged := scalar.Explicit(n, d); !tagged && v.String() != "" && scalar.PlainTag(value) != scalar.Resolve(n, d) {
			return Edit{}, fmt.Errorf("as a plain scalar, %q would be %s, not %s", value, scalar.PlainTag(value), scalar.Resolve(n, d))
		}
	}
	src := treeBytes(n)
	span, comment, empty := content(n)
	prefix := ""
	if empty && span.Start > 0 && !isWhite(src[span.Start-1]) {
		prefix = " " // key: → key: "x"
	}
	var b []byte
	b = append(b, prefix...)
	switch style {
	case cst.SingleQuoted:
		b = append(append(append(b, '\''), body...), '\'')
	case cst.DoubleQuoted:
		b = append(append(append(b, '"'), body...), '"')
	default:
		b = append(b, body...)
	}
	if comment != nil {
		b = append(append(b, ' '), comment...)
	}
	old := v.String()
	return Edit{
		Span: span,
		Old:  bytes.Clone(src[span.Start:span.End]),
		New:  b,
		want: &expect{kind: Changed, node: n, scalar: &scalarWant{old: old, s: 0, e: len(old), text: value}},
	}, nil
}

// content is the range of n after its properties and the white space that
// follows them, to the end of its content, the comment on a block scalar's
// header line, and whether n has no content.
func content(n cst.Node) (cst.Span, []byte, bool) {
	start := n.Span().Start
	var comment []byte
	found, header := false, false
	for e := range n.Children() {
		if c, ok := e.Node(); ok {
			if c.Kind() == cst.NodeProperties {
				start = c.Span().End
			}
			continue
		}
		t, _ := e.Token()
		switch t.Kind() {
		case cst.TokPlain, cst.TokSingleQuoted, cst.TokDoubleQuoted, cst.TokBlockHeader:
			if !found {
				start, found = t.Span().Start, true
			}
			header = header || t.Kind() == cst.TokBlockHeader
		case cst.TokComment:
			if header && comment == nil {
				comment = t.Bytes()
			}
		case cst.TokNewline:
			header = false
		}
	}
	if !found {
		return cst.Span{Start: start, End: start}, nil, true
	}
	return cst.Span{Start: start, End: n.ContentSpan().End}, comment, false
}
