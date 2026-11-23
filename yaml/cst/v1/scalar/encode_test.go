package scalar

import (
	"strings"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

var allStyles = []cst.ScalarStyle{cst.Plain, cst.SingleQuoted, cst.DoubleQuoted, cst.Literal, cst.Folded}

// wrap puts body between the characters a and b in a scalar of style, so
// that the checks that depend on the position in the value (a leading
// indicator, white space at the ends) do not apply. Its value is
// "a" + text + "b", plus a line feed for block scalars.
func wrap(style cst.ScalarStyle, body []byte, text string) (src, want string) {
	b := string(body)
	switch style {
	case cst.SingleQuoted:
		return "- 'a" + b + "b'\n", "a" + text + "b"
	case cst.DoubleQuoted:
		return "- \"a" + b + "b\"\n", "a" + text + "b"
	case cst.Literal, cst.Folded:
		h := "|"
		if style == cst.Folded {
			h = ">"
		}
		if strings.HasSuffix(b, "\n") {
			b += "  "
		}
		return "- " + h + "\n  a" + b + "b\n", "a" + text + "b\n"
	}
	return "- a" + b + "b\n", "a" + text + "b"
}

// roundTrip checks that body, read back in its style, is text.
func roundTrip(t *testing.T, style cst.ScalarStyle, text string, body []byte) {
	t.Helper()
	src, want := wrap(style, body, text)
	tr := cst.Parse([]byte(src))
	if len(tr.Errors()) > 0 {
		t.Fatalf("style %v, %q: %q has errors %v", style, text, src, tr.Errors())
	}
	vs := scalars(t, src)
	if len(vs) != 1 || vs[0].String() != want {
		t.Fatalf("style %v, %q: %q reads as %q, want %q", style, text, src, values(vs), want)
	}
}

func values(vs []Value) []string {
	var s []string
	for _, v := range vs {
		s = append(s, v.String())
	}
	return s
}

func TestBody(t *testing.T) {
	cases := []struct {
		style cst.ScalarStyle
		text  string
		want  string
	}{
		{cst.DoubleQuoted, `x"y\z`, `x\"y\\z`},
		{cst.DoubleQuoted, "x\ny\rz", `x\ny\rz`},
		{cst.DoubleQuoted, "x\ty", "x\ty"},
		{cst.DoubleQuoted, "\x00\x1b\x7f", `\x00\x1b\x7f`},
		{cst.DoubleQuoted, "\xc2\x9f", `\x9f`},
		{cst.DoubleQuoted, "\xef\xbb\xbf", "\\" + "uFEFF"},
		{cst.DoubleQuoted, "\xc3\xa9", "\xc3\xa9"},
		{cst.SingleQuoted, "it's", "it''s"},
		{cst.Plain, "a b", "a b"},
		{cst.Plain, "a:b", "a:b"},
		{cst.Literal, "x\ny", "x\n  y"},
		{cst.Literal, "x\n\ny\n", "x\n\n  y\n"},
		{cst.Literal, "x\n  y", "x\n    y"},
		{cst.Folded, "x  y", "x  y"},
	}
	for _, c := range cases {
		got, ok := Body(c.style, c.text, 2)
		if !ok || string(got) != c.want {
			t.Errorf("Body(%v, %q) = %q %v, want %q", c.style, c.text, got, ok, c.want)
			continue
		}
		roundTrip(t, c.style, c.text, got)
	}
}

func TestBodyRejects(t *testing.T) {
	cases := []struct {
		style cst.ScalarStyle
		text  string
	}{
		{cst.SingleQuoted, "a\nb"},
		{cst.SingleQuoted, "a\rb"},
		{cst.Plain, "a: b"},
		{cst.Plain, "a:\tb"},
		{cst.Plain, "a #b"},
		{cst.Plain, "a\t#b"},
		{cst.Plain, "a\nb"},
		{cst.Folded, "a\nb"},
		{cst.Literal, "a\rb"},
	}
	for _, c := range cases {
		if got, ok := Body(c.style, c.text, 2); ok {
			t.Errorf("Body(%v, %q) = %q, want false", c.style, c.text, got)
		}
	}
	// an invalid UTF-8 byte is no character, which is all
	// a double-quoted escape can write.
	for _, s := range allStyles {
		if got, ok := Body(s, "a\xffb", 2); ok {
			t.Errorf("Body(%v, invalid UTF-8) = %q", s, got)
		}
		if s != cst.DoubleQuoted {
			if got, ok := Body(s, "a\x01b", 2); ok {
				t.Errorf("Body(%v, a control character) = %q", s, got)
			}
		}
	}
}

// FuzzEncode checks that whatever Body writes reads back as the text.
func FuzzEncode(f *testing.F) {
	for _, s := range []string{"", "a b", "it's", "x\ny", "x\n\n  y\n", `"\`, "a: b", "\t#", "\xc3\xa9", "\x00\x7f", "\xef\xbb\xbf"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		for _, s := range allStyles {
			if body, ok := Body(s, text, 2); ok {
				roundTrip(t, s, text, body)
			}
		}
	})
}
