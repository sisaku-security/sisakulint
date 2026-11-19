package workflow

import (
	"slices"
	"strings"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// jobsOK is a jobs section GitHub accepts, for inputs about other keys.
const jobsOK = "jobs:\n  a:\n    runs-on: x\n    steps: [{run: y}]\n"

func parse(t *testing.T, src string) (*Workflow, []Diagnostic, *cst.Tree) {
	t.Helper()
	tr := cst.ParseMode([]byte(src), cst.ModeGitHub)
	w, diags := Parse(tr)
	for _, d := range diags {
		if d.Span.Start < 0 || d.Span.End > len(src) || d.Span.Start > d.Span.End {
			t.Errorf("%q: diagnostic %v has a span outside the input", src, d)
		}
	}
	return w, diags, tr
}

func codes(diags []Diagnostic) []Code {
	var cs []Code
	for _, d := range diags {
		cs = append(cs, d.Code)
	}
	return cs
}

// wantCodes checks the codes of diags, in order.
func wantCodes(t *testing.T, src string, diags []Diagnostic, want ...Code) {
	t.Helper()
	if got := codes(diags); !slices.Equal(got, want) {
		t.Errorf("%q: diagnostics %v, want %v", src, diags, want)
	}
}

// text is the input under a span.
func text(src string, s cst.Span) string { return src[s.Start:s.End] }

// at is the span of the first occurrence of sub in src.
func at(t *testing.T, src, sub string) cst.Span {
	t.Helper()
	i := strings.Index(src, sub)
	if i < 0 {
		t.Fatalf("%q not in %q", sub, src)
	}
	return cst.Span{Start: i, End: i + len(sub)}
}
