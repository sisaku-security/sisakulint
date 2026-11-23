package reportview

import (
	"reflect"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/rules"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

func TestEditOf(t *testing.T) {
	for _, c := range []struct {
		name, src  string
		start, end int
		repl       string
		want       FixEdit
	}{
		{"in a line", "a: 1\nb: x\nc: 3\n", 8, 9, "y", FixEdit{Line: 2, Old: []string{"b: x"}, New: []string{"b: y"}}},
		{"lines inserted at the start of a line", "a: 1\nb: 2\n", 5, 5, "env:\n  X: 1\n", FixEdit{Line: 2, Old: []string{"b: 2"}, New: []string{"env:", "  X: 1", "b: 2"}}},
		{"no line break at the end", "a: 1\nb: x", 8, 9, "y", FixEdit{Line: 2, Old: []string{"b: x"}, New: []string{"b: y"}}},
		{"crlf", "a: 1\r\nb: x\r\n", 9, 10, "y", FixEdit{Line: 2, Old: []string{"b: x"}, New: []string{"b: y"}}},
		{"at the end", "a: 1\n", 5, 5, "b: 2\n", FixEdit{Line: 2, Old: []string{}, New: []string{"b: 2"}}},
	} {
		if got := editsOf([]byte(c.src), []edit.Edit{{Span: cst.Span{Start: c.start, End: c.end}, New: []byte(c.repl)}}); !reflect.DeepEqual(got, []FixEdit{c.want}) {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestEditsOf: edits on the same lines are one change, as the lines are
// after all of them; changes are in the order of their lines.
func TestEditsOf(t *testing.T) {
	src := []byte("a: 1\nuses: x@v4\nc: 3\nd: 4\n")
	edits := []edit.Edit{
		{Span: cst.Span{Start: 24, End: 25}, New: []byte("5")},   // d: 4 → d: 5
		{Span: cst.Span{Start: 13, End: 15}, New: []byte("sha")}, // @v4 → @sha
		{Span: cst.Span{Start: 15, End: 15}, New: []byte(" # v4")},
	}
	want := []FixEdit{
		{Line: 2, Old: []string{"uses: x@v4"}, New: []string{"uses: x@sha # v4"}},
		{Line: 4, Old: []string{"d: 4"}, New: []string{"d: 5"}},
	}
	if got := editsOf(src, edits); !reflect.DeepEqual(got, want) {
		t.Errorf("%+v, want %+v", got, want)
	}
}

// TestBuildFix: a finding's fix, with its side effects and its edits as
// lines, and a finding's reason for none.
func TestBuildFix(t *testing.T) {
	src := "on: issues\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}; eval ${{ github.event.issue.body }}\n"
	rep, in := runOn(t, map[string]string{".github/workflows/w.yml": src})
	p, err := Build(rep, in, testRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	var fix *Fix
	var none *NoFix
	for _, f := range p.Findings {
		if f.Rule != rules.CodeInjectionID {
			continue
		}
		if f.Fix != nil {
			fix = f.Fix
		}
		if f.NoFix != nil {
			none = f.NoFix
		}
	}
	if fix == nil || fix.KindID.String() != "env-var-review" || fix.Safety != lint.SafetyReview {
		t.Fatalf("fix %+v", fix)
	}
	if !slices.Equal(fix.SideEffects, []FixSideEffect{{ID: ir.SideEffectUnquotedOneWord, Text: ir.SideEffectUnquotedOneWord.Text()}, {ID: ir.SideEffectValueNotReadAsScript, Text: ir.SideEffectValueNotReadAsScript.Text()}}) {
		t.Errorf("side effects %+v", fix.SideEffects)
	}
	if !slices.ContainsFunc(fix.Edits, func(e FixEdit) bool { return slices.Contains(e.New, "        env:") }) {
		t.Errorf("edits %+v", fix.Edits)
	}
	if none == nil || none.Reason != ir.NoFixReasonManual || none.Note == "" {
		t.Errorf("no fix %+v", none)
	}
}

func testRegistry(t *testing.T) *lint.Registry {
	t.Helper()
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	return reg
}
