package scalar

import (
	"strings"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

func TestBlockValues(t *testing.T) {
	cases := []struct{ src, want string }{
		// literal
		{"- |\n  a\n  b\n", "a\nb\n"},
		{"- |\n\n  a\n", "\na\n"},
		{"- |\n  a\n\n  b\n", "a\n\nb\n"},
		{"- |\n  a\n    b\n", "a\n  b\n"},
		{"- |\n  a\n   \n  b\n", "a\n \nb\n"},
		{"- |\n  a", "a"},
		{"- !t | # c\n  a\n", "a\n"},
		{"- !t\n  |\n   a\n", "a\n"},
		// chomping
		{"- |-\n  a\n\n", "a"},
		{"- |\n  a\n\n\n", "a\n"},
		{"- |+\n  a\n\n\n", "a\n\n\n"},
		{"- |+\n  a", "a"},
		// [165] b-chomped-last and [70] l-empty at <end-of-input>: a last
		// line without a line break adds none (suite L24T/01, JEF9/02)
		{"- |\n  x\n   ", "x\n "},
		{"- |+\n   ", ""},
		{"- |-\n\n", ""},
		{"- |\n\n", ""},
		// folded
		{"- >\n  a\n  b\n", "a b\n"},
		{"- >\n  a\n\n  b\n", "a\nb\n"},
		{"- >\n  a\n\n\n  b\n", "a\n\nb\n"},
		{"- >\n  a\n   b\n  c\n", "a\n b\nc\n"},
		{"- >\n  a\n\n   b\n", "a\n\n b\n"},
		{"- >\n  a\n   b\n   c\n  d\n", "a\n b\n c\nd\n"},
		{"- >\n  a\n  \tb\n", "a\n\tb\n"},
		{"- >\n\n  a\n  b\n", "\na b\n"},
		{"- >-\n  a\n  b\n\n", "a b"},
		{"- >+\n  a\n\n", "a\n\n"},
	}
	for _, c := range cases {
		if got := only(t, c.src).String(); got != c.want {
			t.Errorf("%q = %q, want %q", c.src, got, c.want)
		}
	}
}

func TestBlockKept(t *testing.T) {
	cases := []struct {
		src    string
		indent int
		chomp  Chomping
		style  cst.ScalarStyle
	}{
		{"- |-\n    a\n", 4, ChompStrip, cst.Literal},
		{"- >\n\n    a\n", 4, ChompClip, cst.Folded},
		{"- |+\n\n", 0, ChompKeep, cst.Literal},
		{"--- |\na\n  b\n", 0, ChompClip, cst.Literal},
	}
	for _, c := range cases {
		v := only(t, c.src)
		if v.indent != c.indent || v.chomp != c.chomp || v.style != c.style || v.node.Kind() != cst.NodeScalar {
			t.Errorf("%q: indent %d chomp %v style %v, want %d %v %v", c.src, v.indent, v.chomp, v.style, c.indent, c.chomp, c.style)
		}
	}
}

// CRLF gives the same values, and the ranges are in the
// CRLF input.
func TestBlockCRLF(t *testing.T) {
	for _, lf := range []string{
		"- |\n  a\n\n  bb\n\n",
		"- >+\n  a\n\n  bb\n\n",
		"- >\n  a\n   x\n  bb\n",
	} {
		crlf := strings.ReplaceAll(lf, "\n", "\r\n")
		v1, v2 := only(t, lf), only(t, crlf)
		if v1.String() != v2.String() {
			t.Errorf("%q = %q, CRLF %q", lf, v1.String(), v2.String())
		}
		i := strings.Index(v2.String(), "bb")
		sp, exact := v2.Source(i, i+2)
		if !exact || crlf[sp.Start:sp.End] != "bb" {
			t.Errorf("%q: Source of bb = %v %v", crlf, sp, exact)
		}
	}
}

func TestBlockSource(t *testing.T) {
	src := "run: |\n  echo a\n  echo b\n  echo ${{ github.event.issue.title }}\n"
	vs := scalars(t, src)
	v := vs[1]
	expr := "${{ github.event.issue.title }}"
	i := strings.Index(v.String(), expr)
	if sp, exact := v.Source(i, i+len(expr)); !exact || src[sp.Start:sp.End] != expr {
		t.Errorf("expression: %v %v", sp, exact)
	}
	// the second line with its line break
	j := strings.Index(v.String(), "echo b")
	if sp, exact := v.Source(j, j+len("echo b\n")); !exact || src[sp.Start:sp.End] != "echo b\n" {
		t.Errorf("line 2: %v %v", sp, exact)
	}

	src = "k: >\n  one\n  two\n  three word\n"
	v = scalars(t, src)[1]
	w := strings.Index(v.String(), "word")
	p := v.Position(w)
	tr := cst.Parse([]byte(src))
	if tr.Position(p.Start).Line != 4 || src[p.Start:p.Start+4] != "word" {
		t.Errorf("Position of word = %v, line %d", p, tr.Position(p.Start).Line)
	}
}
