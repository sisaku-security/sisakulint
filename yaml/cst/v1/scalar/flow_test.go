package scalar

import (
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/internal/suitewalk"
)

// scalars decodes every Scalar of src in event order.
func scalars(t *testing.T, src string) []Value {
	t.Helper()
	var vs []Value
	for _, n := range suitewalk.Nodes(cst.Parse([]byte(src))) {
		if n.Kind() != cst.NodeScalar {
			continue
		}
		v, ok := Decode(n)
		if !ok {
			t.Fatalf("%q: Decode failed on %v", src, n.Span())
		}
		vs = append(vs, v)
	}
	return vs
}

// only is the value of the only scalar in src.
func only(t *testing.T, src string) Value {
	t.Helper()
	vs := scalars(t, src)
	if len(vs) != 1 {
		t.Fatalf("%q: %d scalars", src, len(vs))
	}
	return vs[0]
}

func TestFlowValues(t *testing.T) {
	cases := []struct{ src, want string }{
		// plain
		{"- a b\n", "a b"},
		{"- a\n  b\n", "a b"},
		{"- a\n\n  b\n", "a\nb"},
		{"- a\n\n\n  b\n", "a\n\nb"},
		{"- a \t\n  b\n", "a b"},
		{"- !t a\n", "a"},
		// single-quoted
		{"- 'it''s'\n", "it's"},
		{"- 'a\n  b'\n", "a b"},
		{"- 'a  \n\n b'\n", "a\nb"},
		{"- ''\n", ""},
		{"- ''''\n", "'"},
		// double-quoted escapes
		{"- \"\\x41\"\n", "A"},
		{"- \"\\xe9\"\n", "\xc3\xa9"},
		{"- \"\\U0001F642\"\n", "\xf0\x9f\x99\x82"},
		{"- \"\\ud83d\\ude42\"\n", "\xf0\x9f\x99\x82"},
		{"- \"a\\tb\\\tc\"\n", "a\tb\tc"},
		{"- \"a\\ b\\/c\\\"d\\\\e\"\n", "a b/c\"d\\e"},
		{"- \"\\0\\a\\b\\v\\f\\r\\e\\n\"\n", "\x00\a\b\v\f\r\x1b\n"},
		{"- \"\\N\\_\\L\\P\"\n", "\xc2\x85\xc2\xa0\xe2\x80\xa8\xe2\x80\xa9"},
		// double-quoted line breaks
		{"- \"a\n  b\"\n", "a b"},
		{"- \"a\n\n  b\"\n", "a\nb"},
		{"- \"a \t\n b\"\n", "a b"},
		{"- \"a\\\n  b\"\n", "ab"},
		{"- \"a\\\n\n\n  b\"\n", "a\n\nb"},
		{"- \"a \\\n  b\"\n", "a b"},
		{"- \"a\\\\\n b\"\n", "a\\ b"},
		{"- \"a\\\\\\\n b\"\n", "a\\b"},
	}
	for _, c := range cases {
		if got := only(t, c.src).String(); got != c.want {
			t.Errorf("%q = %q, want %q", c.src, got, c.want)
		}
	}
}

// TestFlowKeptEscapes: an invalid escape, which the parser reports, is kept as
// written; escapes the grammar accepts but that are no character too.
func TestFlowKeptEscapes(t *testing.T) {
	cases := []struct{ src, want string }{
		{"- \"\\q\"\n", "\\q"},
		{"- \"a\\x4g\"\n", "a\\x4g"},
		{"- \"\\ud800x\"\n", "\\ud800x"},
		{"- \"\\ude42\\ud83d\"\n", "\\ude42\\ud83d"},
		{"- \"\\U00110000\"\n", "\\U00110000"},
	}
	for _, c := range cases {
		v := only(t, c.src)
		if v.String() != c.want {
			t.Errorf("%q = %q, want %q", c.src, v.String(), c.want)
		}
		if sp, exact := v.Source(0, len(v.String())); !exact || string(c.src[sp.Start:sp.End]) != c.want {
			t.Errorf("%q: Source = %v %v, want the escape copied", c.src, sp, exact)
		}
	}
}

func TestFlowNotScalar(t *testing.T) {
	tr := cst.Parse([]byte("- \"unclosed\n"))
	if _, ok := Decode(tr.Root()); ok {
		t.Error("Decode accepted a Stream")
	}
	for n := range allNodes(tr.Root()) {
		if n.Kind() == cst.NodeScalar {
			t.Errorf("unexpected Scalar %v", n.Span())
		}
		Decode(n)
	}
}

func allNodes(n cst.Node) func(func(cst.Node) bool) {
	return func(yield func(cst.Node) bool) {
		var rec func(cst.Node) bool
		rec = func(n cst.Node) bool {
			if !yield(n) {
				return false
			}
			for e := range n.Children() {
				if c, ok := e.Node(); ok && !rec(c) {
					return false
				}
			}
			return true
		}
		rec(n)
	}
}

// CRLF gives the same values, and the ranges are in the
// CRLF input.
func TestFlowCRLF(t *testing.T) {
	for _, lf := range []string{
		"- a\n\n  bb\n",
		"- 'a\n\n  bb'\n",
		"- \"a\\\n  bb\"\n",
		"- \"a\n  bb\"\n",
	} {
		crlf := ""
		for _, r := range lf {
			if r == '\n' {
				crlf += "\r"
			}
			crlf += string(r)
		}
		v1, v2 := only(t, lf), only(t, crlf)
		if v1.String() != v2.String() {
			t.Errorf("%q = %q, CRLF %q", lf, v1.String(), v2.String())
		}
		i := len(v2.String()) - 2
		sp, exact := v2.Source(i, i+2)
		if !exact || crlf[sp.Start:sp.End] != "bb" {
			t.Errorf("%q: Source of bb = %v %v", crlf, sp, exact)
		}
	}
}

// TestFlowEmpty: empty scalars have no segments and sit where their
// content would be.
func TestFlowEmpty(t *testing.T) {
	cases := []struct {
		src    string
		i, pos int
		exact  bool
	}{
		{"k:\n", 1, 2, true},
		{"- &a\n", 0, 4, true},
		{"- !t\n", 0, 4, true},
		{"-\n", 0, 1, true},
		{"--- \n", 0, 3, true},
		// inside the quotes
		{"- ''\n", 0, 3, true},
		{"run: \"\"\n", 1, 6, true},
		{"- !t ''\n", 0, 6, true},
		// a block scalar's content starts on the line after the header, at
		// an indentation no byte offset gives: never exact
		{"- |\n", 0, 4, false},
		{"- |   # c\n", 0, 10, false},
		{"- >-\n\n", 0, 5, false},
		{"- |", 0, 3, false},
	}
	for _, c := range cases {
		vs := scalars(t, c.src)
		v := vs[c.i]
		sp, exact := v.Source(0, 0)
		if v.String() != "" || len(v.segs) != 0 || exact != c.exact || sp != (cst.Span{Start: c.pos, End: c.pos}) {
			t.Errorf("%q: %q, %d segments, Source(0,0) = %v %v, want at %d %v", c.src, v.String(), len(v.segs), sp, exact, c.pos, c.exact)
		}
	}
}

// folding does not panic on 0 breaks, which the parser never gives.
func TestFoldingNoBreak(t *testing.T) {
	for _, escaped := range []bool{false, true} {
		if got := folding(0, escaped); got != "" {
			t.Errorf("folding(0, %v) = %q, want empty", escaped, got)
		}
	}
}

func TestFlowSource(t *testing.T) {
	src := "- \"one\n  two th\\x72ee\"\n"
	v := only(t, src)
	if v.String() != "one two three" {
		t.Fatalf("value %q", v.String())
	}
	if sp, exact := v.Source(4, 7); !exact || src[sp.Start:sp.End] != "two" {
		t.Errorf("two: %v %v", sp, exact)
	}
	if sp, exact := v.Source(8, 13); !exact || src[sp.Start:sp.End] != "th\\x72ee" {
		t.Errorf("three: %v %v", sp, exact)
	}
	if sp, exact := v.Source(3, 4); !exact || src[sp.Start:sp.End] != "\n  " {
		t.Errorf("folded break: %v %v", sp, exact)
	}
	if p := v.Position(10); src[p.Start:p.End] != "\\x72" {
		t.Errorf("Position of r = %v", p)
	}
}
