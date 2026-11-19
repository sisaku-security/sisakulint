package cli

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// clean is s as the text may show it on a terminal: the bytes of a
// workflow are an attacker's, and a terminal takes a control character as
// a command. The C0 controls but the tab, DEL and bytes not UTF-8 become
// \xHH; a newline \n; the C1 controls and the marks that reorder text
// (the Bidi_Control of Unicode, such as U+202E) \uHHHH, so that a line
// shows as it is read (Trojan Source, CVE-2021-42574).
func clean(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n':
			b.WriteString(`\n`)
		case r < 0x20 && r != '\t', r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case hazard(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// hazard is whether clean replaces r.
func hazard(r rune) bool {
	switch {
	case r < 0x20:
		return r != '\t'
	case r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	}
	return unicode.Is(unicode.Bidi_Control, r)
}

// width is how many runes clean(s) has: the columns under which the
// carets go, where a rune is one column wide.
func width(s string) int { return utf8.RuneCountInString(clean(s)) }

// pad is blank as wide as clean(s): its tabs, and a space for each other
// rune.
func pad(s string) string {
	var b strings.Builder
	for _, r := range clean(s) {
		if r == '\t' {
			b.WriteByte('\t')
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}
