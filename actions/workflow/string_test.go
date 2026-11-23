package workflow

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
)

// exprSources returns the input bytes each expression part of run-name
// comes from.
func exprSources(t *testing.T, src string) []string {
	t.Helper()
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	s := w.RunName.Value
	var out []string
	for _, p := range s.Parts {
		if !p.Expr {
			continue
		}
		sp, exact := s.Source(p.Span)
		if !exact {
			t.Errorf("%q: part %v is not exact", src, p.Span)
		}
		out = append(out, text(src, sp))
	}
	return out
}

func TestStringSource(t *testing.T) {
	const e = "${{ github.event.issue.title }}"
	for _, tt := range []struct {
		name, src string
		want      []string
	}{
		{"plain", "run-name: x " + e + "\n", []string{e}},
		{"multi-byte", "run-name: \"\xc3\xa9 " + e + "\"\n", []string{e}},
		{"escape", "run-name: \"\\t" + e + "\"\n", []string{e}},
		{"single", "run-name: 'it''s " + e + "'\n", []string{e}},
		{"plain lines", "run-name: a\n  b " + e + "\n", []string{e}},
		{"folded", "run-name: >\n  a\n  b " + e + "\n", []string{e}},
		{"literal", "run-name: |\n  a\n  b " + e + "\n  c ${{ github.x }}\n", []string{e, "${{ github.x }}"}},
		{"CRLF", "run-name: |\r\n  a\r\n  b " + e + "\r\n", []string{e}},
	} {
		src := tt.src + "on: push\n" + jobsOK
		got := exprSources(t, src)
		if len(got) != len(tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("%s: %q, want %q", tt.name, got[i], tt.want[i])
			}
		}
	}
}

// A node of the expression tree maps back through InValue and Source.
func TestStringTreeSource(t *testing.T) {
	src := "run-name: \"\\t${{ github.event.issue.title == 'x' }}\"\non: push\n" + jobsOK
	w, _, _ := parse(t, src)
	s := w.RunName.Value
	p := s.Parts[1]
	c := p.Tree.(*expr.Compare)
	sp, exact := s.Source(p.InValue(c.X.Span()))
	if !exact || text(src, sp) != "github.event.issue.title" {
		t.Errorf("source %q exact %v", text(src, sp), exact)
	}
}

// A range that cuts what one escape made is not exact.
func TestStringSourceInexact(t *testing.T) {
	src := "run-name: \"\\xe9\"\non: push\n" + jobsOK
	w, _, _ := parse(t, src)
	s := w.RunName.Value
	if s.Text() != "\xc3\xa9" {
		t.Fatalf("value %q", s.Text())
	}
	if _, exact := s.Source(expr.Span{Start: 0, End: 1}); exact {
		t.Error("half of \\xe9 is exact")
	}
}

func TestIsExpr(t *testing.T) {
	for _, tt := range []struct {
		v    string
		want bool
	}{
		{"${{ a }}", true},
		{"'${{ a }} '", true},
		{"a ${{ a }}", false},
		{"${{ a }}${{ b }}", false},
		{"a", false},
	} {
		src := "run-name: " + tt.v + "\non: push\n" + jobsOK
		w, _, _ := parse(t, src)
		if got := w.RunName.Value.IsExpr(); got != tt.want {
			t.Errorf("IsExpr(%s) = %v, want %v", tt.v, got, tt.want)
		}
	}
}

// TestAsString: a value that is no string is the string GitHub makes of it.
func TestAsString(t *testing.T) {
	src := "on: push\nenv: {A: ~, B: 0x10, C: True, D: 1.50, E: \"${{ 'x' }}\", F: text}\n" + jobsOK
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	want := map[string]string{"A": "", "B": "16", "C": "true", "D": "1.5", "E": "x", "F": "text"}
	for _, e := range w.Env.Value.Entries {
		if got := e.Value.Value.AsString(); got != want[e.Key.Text()] {
			t.Errorf("%s = %q, want %q", e.Key.Text(), got, want[e.Key.Text()])
		}
	}
}
