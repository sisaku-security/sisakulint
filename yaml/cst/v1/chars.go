package cst

import "unicode/utf8"

// Spec chapter 5: characters.

// [31]-[33]
func isWhite(b byte) bool { return b == ' ' || b == '\t' }

// [23] c-flow-indicator
func isFlowIndicator(b byte) bool {
	switch b {
	case ',', '[', ']', '{', '}':
		return true
	}
	return false
}

// [22] c-indicator
func isIndicator(b byte) bool {
	switch b {
	case '-', '?', ':', ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`':
		return true
	}
	return false
}

func isDecDigit(b byte) bool { return '0' <= b && b <= '9' }

func isHexDigit(b byte) bool {
	return isDecDigit(b) || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
}

// [38] ns-word-char
func isWordChar(b byte) bool {
	return isDecDigit(b) || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || b == '-'
}

// breakLen is the length of the b-break ([28]) at pos, or 0.
func (p *parser) breakLen(pos int) int {
	if pos >= len(p.src) {
		return 0
	}
	switch p.src[pos] {
	case '\n':
		return 1
	case '\r':
		if pos+1 < len(p.src) && p.src[pos+1] == '\n' {
			return 2
		}
		return 1
	}
	return 0
}

// nbChar is the byte length of the nb-char ([27]) at pos, or 0. Characters
// the YAML 1.2.2 specification does not allow are accepted here and
// reported by checkChars, so
// that one bad character does not change the tree around it. The BOM is the
// exception: it must stay distinguishable from content.
func (p *parser) nbChar(pos int) int {
	if pos >= len(p.src) {
		return 0
	}
	b := p.src[pos]
	if b < utf8.RuneSelf {
		if b == '\n' || b == '\r' {
			return 0
		}
		return 1
	}
	r, size := utf8.DecodeRune(p.src[pos:])
	if r == 0xFEFF {
		return 0
	}
	return size
}

// nsChar is the byte length of the ns-char ([34]) at pos, or 0.
func (p *parser) nsChar(pos int) int {
	if pos < len(p.src) && isWhite(p.src[pos]) {
		return 0
	}
	return p.nbChar(pos)
}

// uriChar is the byte length of the ns-uri-char ([39]) at pos, or 0.
func (p *parser) uriChar(pos int) int {
	if pos >= len(p.src) {
		return 0
	}
	b := p.src[pos]
	if b == '%' {
		if pos+2 < len(p.src) && isHexDigit(p.src[pos+1]) && isHexDigit(p.src[pos+2]) {
			return 3
		}
		return 0
	}
	if isWordChar(b) {
		return 1
	}
	switch b {
	case '#', ';', '/', '?', ':', '@', '&', '=', '+', '$', ',', '_', '.', '!', '~', '*', '\'', '(', ')', '[', ']':
		return 1
	}
	return 0
}

// tagChar is the byte length of the ns-tag-char ([40]) at pos, or 0.
func (p *parser) tagChar(pos int) int {
	if pos < len(p.src) && (p.src[pos] == '!' || isFlowIndicator(p.src[pos])) {
		return 0
	}
	return p.uriChar(pos)
}

func (p *parser) hasBOM(pos int) bool {
	return pos+3 <= len(p.src) && p.src[pos] == 0xEF && p.src[pos+1] == 0xBB && p.src[pos+2] == 0xBF
}

// checkChars reports the characters the parser accepted leniently (see
// nbChar): invalid UTF-8, and characters outside [1] c-printable, or
// outside [2] nb-json inside quoted scalars. One error per token.
func (p *parser) checkChars() {
	for i := range p.t.tokens {
		tk := Token{p.t, int32(i)}
		k := tk.Kind()
		if k == TokBOM || k == TokError {
			continue
		}
		quoted := k == TokSingleQuoted || k == TokDoubleQuoted
		s := tk.Span()
		for pos := s.Start; pos < s.End; {
			if b := p.src[pos]; b >= 0x20 && b < 0x7F || b == '\t' || b == '\n' || b == '\r' {
				pos++
				continue
			}
			r, size := utf8.DecodeRune(p.src[pos:s.End])
			if r == utf8.RuneError && size == 1 {
				p.errorAt(ErrInvalidUTF8, Span{pos, pos + 1}, "invalid UTF-8")
				break
			}
			if !quoted && !printable(r) || quoted && r != '\t' && r < 0x20 {
				p.errorAt(ErrInvalidChar, Span{pos, pos + size}, "character not allowed here")
				break
			}
			pos += size
		}
	}
}

// printable is [1] c-printable without the BOM, which is only allowed as a
// TokBOM or inside quoted scalars.
func printable(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r' || 0x20 <= r && r <= 0x7E || r == 0x85:
		return true
	case r == 0xFEFF:
		return false
	case 0xA0 <= r && r <= 0xD7FF || 0xE000 <= r && r <= 0xFFFD || 0x10000 <= r && r <= 0x10FFFF:
		return true
	}
	return false
}

// badEncoding reports a UTF-16 or UTF-32 stream, detected by its byte
// order mark or by the null bytes of an ASCII first character (5.2).
func badEncoding(src []byte) bool {
	if len(src) < 2 {
		return false
	}
	if src[0] == 0xFE && src[1] == 0xFF || src[0] == 0xFF && src[1] == 0xFE {
		return true
	}
	return src[0] == 0 || src[1] == 0
}
