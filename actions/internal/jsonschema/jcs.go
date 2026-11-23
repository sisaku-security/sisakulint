package jsonschema

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"unicode/utf16"
)

// Canonical writes data in the form of RFC 8785 (JCS): no white space,
// the members of an object in the order of their keys as UTF-16 code
// units, and strings escaped as ECMAScript's JSON.stringify does. JCS
// writes numbers as ECMAScript does; only integers whose absolute value is
// at most 2^53 are accepted here, so that the form is exact without that
// algorithm: such a number written with a fraction or an exponent (1.0,
// 1e3) is the integer, written without them. Other numbers are an error.
func Canonical(data []byte) ([]byte, error) {
	v, err := parse(data)
	if err != nil {
		return nil, err
	}
	return canon(v)
}

func canon(v *value) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanon(&b, v, ""); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanon(b *bytes.Buffer, v *value, at string) error {
	switch v.kind {
	case kNull:
		b.WriteString("null")
	case kBool:
		b.WriteString(strconv.FormatBool(v.b))
	case kNumber:
		n, ok := integer(v.num)
		if !ok {
			return fmt.Errorf("%s: %s is not an integer of at most 2^53", pointerOr(at), v.num)
		}
		b.WriteString(strconv.FormatInt(n, 10))
	case kString:
		writeString(b, v.str)
	case kArray:
		b.WriteByte('[')
		for i, e := range v.arr {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanon(b, e, at+"/"+strconv.Itoa(i)); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case kObject:
		ms := slices.Clone(v.obj)
		slices.SortFunc(ms, func(x, y member) int {
			return slices.Compare(utf16.Encode([]rune(x.key)), utf16.Encode([]rune(y.key)))
		})
		b.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, m.key)
			b.WriteByte(':')
			if err := writeCanon(b, m.val, at+"/"+escapePointer(m.key)); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	}
	return nil
}

// writeString escapes as JSON.stringify: the two-character escapes for
// \b \t \n \f \r " and \, a six-character escape with lower-case hex for
// the other control characters, and everything else as it is.
func writeString(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hex[r>>4])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
