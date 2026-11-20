package scalar

import (
	"fmt"
	"strings"
	"unicode/utf8"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// Body writes text as the content of a scalar of style, without quotes or
// a block header: the inverse of Decode. indent is the content indentation
// of a block scalar, put after each line feed that a line follows. It is
// false when style cannot write text. For plain scalars it checks only
// what text alone decides; a leading indicator, white space at the ends of
// the value or a trailing ':' depend on where text goes in the value.
func Body(style cst.ScalarStyle, text string, indent int) ([]byte, bool) {
	if !utf8.ValidString(text) {
		return nil, false
	}
	if style == cst.DoubleQuoted {
		return doubleBody(text), true
	}
	for _, r := range text {
		if !printable(r) || r == '\r' || r == '\n' && style != cst.Literal {
			return nil, false
		}
	}
	switch style {
	case cst.SingleQuoted:
		return []byte(strings.ReplaceAll(text, "'", "''")), true // [117]
	case cst.Plain:
		for _, bad := range []string{": ", ":\t", " #", "\t#"} {
			if strings.Contains(text, bad) {
				return nil, false
			}
		}
	case cst.Literal:
		return literalBody(text, indent), true
	}
	return []byte(text), true
}

// printable is [1] c-printable without the BOM, which 5.2 allows inside
// quoted scalars only, and asks to escape on output.
func printable(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r' || r >= 0x20 && r <= 0x7e || r == 0x85:
		return true
	case r >= 0xa0 && r <= 0xd7ff || r >= 0xe000 && r <= 0xfffd:
		return r != 0xfeff
	}
	return r >= 0x10000 && r <= 0x10ffff
}

// doubleBody escapes with [62] c-ns-esc-char what is no printable
// character, and '"', '\' and line breaks, which end the scalar or fold.
func doubleBody(text string) []byte {
	var b strings.Builder
	for _, r := range text {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case printable(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&b, "\\u%04X", r)
		default:
			fmt.Fprintf(&b, `\U%08X`, r)
		}
	}
	return []byte(b.String())
}

// literalBody indents each line after the first that has content.
func literalBody(text string, indent int) []byte {
	pad := strings.Repeat(" ", indent)
	lines := strings.Split(text, "\n")
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteByte('\n')
			if l != "" {
				b.WriteString(pad)
			}
		}
		b.WriteString(l)
	}
	return []byte(b.String())
}
