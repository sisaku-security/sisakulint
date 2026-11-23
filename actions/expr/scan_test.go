package expr

import (
	"strings"
	"testing"
)

// seg describes a Segment by its text: an expression is written with its
// ${{ and }}.
func segTexts(s string, segs []Segment) []string {
	var out []string
	for _, g := range segs {
		out = append(out, s[g.Span.Start:g.Span.End])
	}
	return out
}

func TestScan(t *testing.T) {
	tests := []struct {
		in    string
		want  []string // segment texts
		exprs []string // inner texts of the expression segments
		err   ErrorCode
	}{
		{in: "", want: nil},
		{in: "plain", want: []string{"plain"}},
		{in: "${{ a }}", want: []string{"${{ a }}"}, exprs: []string{" a "}},
		{in: "x ${{ a }} y", want: []string{"x ", "${{ a }}", " y"}, exprs: []string{" a "}},
		{in: "${{a}}${{b}}", want: []string{"${{a}}", "${{b}}"}, exprs: []string{"a", "b"}},
		// }} inside a string literal does not close.
		{in: "${{ '}}' }}", want: []string{"${{ '}}' }}"}, exprs: []string{" '}}' "}},
		{in: "${{ 'a''b' }}", want: []string{"${{ 'a''b' }}"}, exprs: []string{" 'a''b' "}},
		{in: "${{ a }}}", want: []string{"${{ a }}", "}"}, exprs: []string{" a "}},
		{in: "$", want: []string{"$"}},
		{in: "${", want: []string{"${"}},
		{in: "${ {", want: []string{"${ {"}},
		{in: "a ${{ b", want: []string{"a ", "${{ b"}, err: ErrUnclosed},
		{in: "${{ ' }}", want: []string{"${{ ' }}"}, err: ErrUnclosed},
		{in: "${{ }}", want: []string{"${{ }}"}, exprs: []string{" "}, err: ErrEmpty},
		{in: "${{}}", want: []string{"${{}}"}, exprs: []string{""}, err: ErrEmpty},
	}
	for _, tt := range tests {
		segs, errs := Scan(tt.in)
		if got := segTexts(tt.in, segs); strings.Join(got, "|") != strings.Join(tt.want, "|") || len(got) != len(tt.want) {
			t.Errorf("Scan(%q) segments = %q, want %q", tt.in, got, tt.want)
		}
		var exprs []string
		for _, g := range segs {
			if g.Expr && g.Inner.End >= g.Inner.Start && tt.err != ErrUnclosed {
				exprs = append(exprs, tt.in[g.Inner.Start:g.Inner.End])
			}
		}
		if tt.err != ErrUnclosed && strings.Join(exprs, "|") != strings.Join(tt.exprs, "|") {
			t.Errorf("Scan(%q) inner = %q, want %q", tt.in, exprs, tt.exprs)
		}
		switch {
		case tt.err == 0 && len(errs) > 0:
			t.Errorf("Scan(%q) errors = %v, want none", tt.in, errs)
		case tt.err != 0 && (len(errs) != 1 || errs[0].Code != tt.err):
			t.Errorf("Scan(%q) errors = %v, want one %v", tt.in, errs, tt.err)
		}
		checkCover(t, tt.in, segs)
	}
}

// checkCover checks that the segments tile s in order.
func checkCover(t *testing.T, s string, segs []Segment) {
	t.Helper()
	at := 0
	for _, g := range segs {
		if g.Span.Start != at || g.Span.End <= g.Span.Start {
			t.Errorf("Scan(%q): segment %v does not continue at %d", s, g.Span, at)
			return
		}
		if g.Expr && (g.Inner.Start < g.Span.Start || g.Inner.End > g.Span.End || g.Inner.Start > g.Inner.End) {
			t.Errorf("Scan(%q): inner %v outside %v", s, g.Inner, g.Span)
		}
		at = g.Span.End
	}
	if at != len(s) {
		t.Errorf("Scan(%q): segments end at %d, want %d", s, at, len(s))
	}
}
