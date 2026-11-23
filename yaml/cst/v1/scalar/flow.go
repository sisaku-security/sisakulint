package scalar

import (
	"strings"
	"unicode/utf8"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// Decode reads the value of n, which must be a Scalar node. The parser has
// already reported every problem the value can have, so Decode has no
// error: an invalid escape is kept as written.
func Decode(n cst.Node) (Value, bool) {
	if n.Kind() != cst.NodeScalar {
		return Value{}, false
	}
	b := builder{origin: n.ContentSpan().End}
	style := n.Style()
	var v Value
	switch style {
	case cst.Literal, cst.Folded:
		indent, chomp := blockScalar(&b, n, style)
		v = b.value()
		v.indent, v.chomp = indent, chomp
	default:
		flowScalar(&b, n, style)
		v = b.value()
	}
	v.style, v.node = style, n
	return v, true
}

// flowScalar reads [109] c-double-quoted, [120] c-single-quoted and [131]
// ns-plain. The parser makes each line one token; between two lines are
// Space and Newline tokens, which fold as [74] s-flow-folded: one break is
// a space, k > 1 breaks are k-1 line feeds. Trailing white space of a line
// is a Space token already, so it is dropped with the break.
func flowScalar(b *builder, n cst.Node, style cst.ScalarStyle) {
	var lines []cst.Token
	var breaks []int // breaks[i]: line breaks between lines[i-1] and lines[i]
	k := 0
	for e := range n.Children() {
		t, ok := e.Token()
		if !ok {
			continue
		}
		switch t.Kind() {
		case cst.TokPlain, cst.TokSingleQuoted, cst.TokDoubleQuoted:
			lines = append(lines, t)
			breaks = append(breaks, k)
			k = 0
		case cst.TokNewline:
			k++
		}
	}
	quoted := style != cst.Plain
	if quoted && len(lines) > 0 {
		b.origin = lines[0].Span().Start + 1 // an empty value is inside the quotes
	}
	prevEnd, escaped := 0, false
	for i, t := range lines {
		sp, text := t.Span(), t.Bytes()
		if quoted && i == 0 {
			sp.Start++
			text = text[1:]
		}
		if quoted && i == len(lines)-1 && len(text) > 0 && text[len(text)-1] == text0(t) {
			sp.End--
			text = text[:len(text)-1]
		}
		if i > 0 {
			b.made(cst.Span{Start: prevEnd, End: sp.Start}, folding(breaks[i], escaped))
		}
		// [112] s-double-escaped: a line ending in an escaping \ joins the
		// next line without the break.
		escaped = style == cst.DoubleQuoted && i < len(lines)-1 && trailingBackslashes(text)%2 == 1
		if escaped {
			sp.End--
			text = text[:len(text)-1]
		}
		switch style {
		case cst.SingleQuoted:
			singleLine(b, sp, text)
		case cst.DoubleQuoted:
			doubleLine(b, sp, text)
		default:
			b.verbatim(sp, text)
		}
		prevEnd = sp.End
	}
}

// text0 is the quote that opens the scalar of line t.
func text0(t cst.Token) byte {
	if t.Kind() == cst.TokSingleQuoted {
		return '\''
	}
	return '"'
}

// folding is the text between two lines with k line breaks. An escaped
// first break adds nothing; each further one is an l-empty line feed. The
// parser puts at least one break between two lines, so k is at least 1;
// were it 0, the lines would join with nothing, rather than panic.
func folding(k int, escaped bool) string {
	switch {
	case k < 1:
		return ""
	case k == 1 && !escaped:
		return " "
	}
	return strings.Repeat("\n", k-1)
}

func trailingBackslashes(text []byte) int {
	n := 0
	for n < len(text) && text[len(text)-1-n] == '\\' {
		n++
	}
	return n
}

// singleLine copies one line of a single-quoted scalar; [117]
// c-quoted-quote ” is '.
func singleLine(b *builder, sp cst.Span, text []byte) {
	for {
		i := strings.Index(string(text), "''")
		if i < 0 {
			b.verbatim(sp, text)
			return
		}
		b.verbatim(cst.Span{Start: sp.Start, End: sp.Start + i}, text[:i])
		b.made(cst.Span{Start: sp.Start + i, End: sp.Start + i + 2}, "'")
		sp.Start += i + 2
		text = text[i+2:]
	}
}

// doubleLine copies one line of a double-quoted scalar, reading each [62]
// c-ns-esc-char. An escape that is no character is copied as written.
func doubleLine(b *builder, sp cst.Span, text []byte) {
	for len(text) > 0 {
		i := strings.IndexByte(string(text), '\\')
		if i < 0 {
			b.verbatim(sp, text)
			return
		}
		b.verbatim(cst.Span{Start: sp.Start, End: sp.Start + i}, text[:i])
		sp.Start += i
		text = text[i:]
		n, s := escape(text)
		if n == 0 {
			n = min(2, len(text))
			b.verbatim(cst.Span{Start: sp.Start, End: sp.Start + n}, text[:n])
		} else {
			b.made(cst.Span{Start: sp.Start, End: sp.Start + n}, s)
		}
		sp.Start += n
		text = text[n:]
	}
}

var simpleEscapes = map[byte]string{
	'0': "\x00", 'a': "\a", 'b': "\b", 't': "\t", '\t': "\t", 'n': "\n",
	'v': "\v", 'f': "\f", 'r': "\r", 'e': "\x1b", ' ': " ", '"': "\"",
	'/': "/", '\\': "\\", 'N': "\xc2\x85", '_': "\xc2\xa0", 'L': "\xe2\x80\xa8", 'P': "\xe2\x80\xa9",
}

// escape reads the escape at the start of text: its length and its value,
// or 0 when it is invalid or no Unicode scalar value. A \u high surrogate
// followed by a \u low surrogate is one character, as in JSON.
func escape(text []byte) (int, string) {
	if len(text) < 2 {
		return 0, ""
	}
	if s, ok := simpleEscapes[text[1]]; ok {
		return 2, s
	}
	r, n := hexEscape(text)
	if n == 0 {
		return 0, ""
	}
	if r >= 0xd800 && r < 0xdc00 {
		if lo, m := hexEscape(text[n:]); m == 6 && lo >= 0xdc00 && lo < 0xe000 {
			return n + m, string(rune(0x10000 + (r-0xd800)<<10 + (lo - 0xdc00)))
		}
	}
	if !utf8.ValidRune(r) {
		return 0, ""
	}
	return n, string(r)
}

// hexEscape reads \xXX, \uXXXX or \UXXXXXXXX.
func hexEscape(text []byte) (rune, int) {
	if len(text) < 2 {
		return 0, 0
	}
	digits := map[byte]int{'x': 2, 'u': 4, 'U': 8}[text[1]]
	if digits == 0 || len(text) < 2+digits {
		return 0, 0
	}
	var r rune
	for _, c := range text[2 : 2+digits] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, 0
		}
		r = r<<4 | rune(d)
	}
	return r, 2 + digits
}
