package scalar

import cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"

// blockLine is one line after the header: its content, or none for an
// empty line, and its line break, or none at the end of the input.
type blockLine struct {
	content cst.Token
	text    bool // has content
	brk     cst.Span
	hasBrk  bool
}

// blockScalar reads [170] c-l+literal and [174] c-l+folded. The parser
// makes each line an indentation Space, a BlockContent and a Newline, and an
// empty line a Space and a Newline. Each line feed of the value is made
// from one Newline token; indentation and dropped breaks are in no segment.
func blockScalar(b *builder, n cst.Node, style cst.ScalarStyle) (indent int, chomp Chomping) {
	// An empty value is at the start of the line after the header, but
	// content there needs an indentation that no byte offset gives.
	b.loose = true
	var lines []blockLine
	var prev cst.Token
	// before: the properties and the header line, which may be on
	// different lines
	before, headerLine, seen, cur := true, false, false, blockLine{}
	for t := range n.Tokens() {
		if before {
			if t.Kind() == cst.TokBlockHeader {
				headerLine = true
				chomp = chompingOf(t.Bytes())
			}
			if headerLine {
				b.origin = t.Span().End
			}
			before = !(headerLine && t.Kind() == cst.TokNewline)
			prev = t
			continue
		}
		switch t.Kind() {
		case cst.TokNewline:
			cur.brk, cur.hasBrk = t.Span(), true
			lines = append(lines, cur)
			cur = blockLine{}
		case cst.TokBlockContent:
			if !seen && prev.Kind() == cst.TokSpace {
				sp := prev.Span()
				indent = sp.End - sp.Start
			}
			seen = true
			cur.content, cur.text = t, true
		}
		prev = t
	}
	if cur.text {
		lines = append(lines, cur)
	}
	last := -1
	for i, l := range lines {
		if l.text {
			last = i
		}
	}
	for i, l := range lines {
		switch {
		case i > last:
			if chomp == ChompKeep { // [168] l-keep-empty
				b.made(l.brk, "\n")
			}
		case !l.text:
			b.made(l.brk, "\n") // [70] l-empty
		default:
			b.verbatim(l.content.Span(), l.content.Bytes())
			if l.hasBrk {
				b.made(l.brk, lineFeed(style, lines, i, last, chomp))
			}
		}
	}
	return indent, chomp
}

// Chomping is what becomes of the final line break of a block scalar and
// the empty lines after it (8.1.1.2).
type Chomping uint8

const (
	ChompClip  Chomping = iota // no indicator: the line break is kept, the empty lines are not
	ChompStrip                 // -: neither is kept
	ChompKeep                  // +: both are kept
)

// ChompingOf is the chomping of the header of the block scalar n; ChompClip
// for a node that is none.
func ChompingOf(n cst.Node) Chomping {
	for t := range n.Tokens() {
		if t.Kind() == cst.TokBlockHeader {
			return chompingOf(t.Bytes())
		}
	}
	return ChompClip
}

// chompingOf is the [164] c-chomping-indicator of a block header.
func chompingOf(h []byte) Chomping {
	for _, c := range h[1:] {
		switch c {
		case '-':
			return ChompStrip
		case '+':
			return ChompKeep
		}
	}
	return ChompClip
}

// lineFeed is the text of the break after the content line i: [165]
// b-chomped-last after the last one, else b-as-line-feed, or for folded
// scalars [73] b-l-folded between two lines that do not start with white
// space: a space, or nothing when empty lines follow ([71] b-l-trimmed).
func lineFeed(style cst.ScalarStyle, lines []blockLine, i, last int, chomp Chomping) string {
	if i == last {
		if chomp == ChompStrip {
			return ""
		}
		return "\n"
	}
	if style != cst.Folded || spaced(lines[i]) {
		return "\n"
	}
	j := i + 1
	for !lines[j].text {
		j++
	}
	if spaced(lines[j]) {
		return "\n"
	}
	if j == i+1 {
		return " "
	}
	return ""
}

// spaced is [177] s-nb-spaced-text: content that starts with white space.
func spaced(l blockLine) bool {
	c := l.content.Bytes()[0]
	return c == ' ' || c == '\t'
}
