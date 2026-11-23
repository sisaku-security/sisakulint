package lint

import (
	"github.com/gh-intel/sisakulint/actions/facts"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

func stepFindings(t *testing.T, files map[string]string, anchor func(workflow.Step) string) Report {
	t.Helper()
	return run(t, files, nil, everyStep(meta("every-step"), func(c *RuleContext, s workflow.Step) FindingDraft {
		a := ""
		if anchor != nil {
			a = anchor(s)
		}
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Anchor: a}
	}))
}

func fingerprints(r Report) []string {
	var out []string
	for _, f := range r.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		out = append(out, f.Fingerprint.String())
	}
	slices.Sort(out)
	return out
}

func TestPath(t *testing.T) {
	src := `on: push
jobs:
  build:
    runs-on: x
    env: {"a.b": 1, "": 2}
    steps:
      - id: checkout
        uses: actions/checkout@v4
      - run: echo
      - id: 9bad
        run: echo
`
	in, _ := Single(InputBytes{Name: facts.MustCleanInputPath("w.yml"), Bytes: []byte(src)})
	w := in.List[0].Workflow
	job := w.Jobs.Value.Entries[0].Value.Value
	st := job.Steps.Value.Items
	env := job.Env.Value.Entries
	for _, c := range []struct {
		at   Location
		want string
	}{
		{At(in.List[0], st[0].Base), "jobs.build.steps[checkout]"},
		{At(in.List[0], st[0].Uses.Value.Base), "jobs.build.steps[checkout].uses"},
		{At(in.List[0], st[1].Base), "jobs.build.steps[1]"},
		{At(in.List[0], st[2].Base), "jobs.build.steps[2]"},
		{At(in.List[0], env[0].Value.Value.Base), `jobs.build.env["a.b"]`},
		{At(in.List[0], env[1].Value.Value.Base), `jobs.build.env[""]`},
		{At(in.List[0], job.Base), "jobs.build"},
		{At(in.List[0], w.Base), ""},
	} {
		if got := pathOf(c.at); got != c.want {
			t.Errorf("pathOf = %q, want %q", got, c.want)
		}
	}
}

func TestFingerprintStable(t *testing.T) {
	base := stepFindings(t, wf(twoSteps), nil)
	moved := stepFindings(t, wf("# a comment\nname: x\n"+twoSteps), nil)
	if !slices.Equal(fingerprints(base), fingerprints(moved)) {
		t.Error("lines added elsewhere changed the fingerprints")
	}
	renamed := stepFindings(t, map[string]string{".github/workflows/other.yml": twoSteps}, nil)
	if slices.Equal(fingerprints(base), fingerprints(renamed)) {
		t.Error("another input name kept the fingerprints")
	}
}

func TestFingerprintStepOrder(t *testing.T) {
	withIDs := "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - id: a\n        run: echo a\n      - id: b\n        run: echo b\n"
	swapped := "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - id: b\n        run: echo b\n      - id: a\n        run: echo a\n"
	if !slices.Equal(fingerprints(stepFindings(t, wf(withIDs), nil)), fingerprints(stepFindings(t, wf(swapped), nil))) {
		t.Error("steps with ids, reordered, changed fingerprints")
	}
	noIDs := strings.ReplaceAll(withIDs, "id: ", "name: ")
	noIDsSwapped := strings.ReplaceAll(swapped, "id: ", "name: ")
	x := fingerprints(stepFindings(t, wf(noIDs), func(s workflow.Step) string { return s.Name.Value.Text() }))
	y := fingerprints(stepFindings(t, wf(noIDsSwapped), func(s workflow.Step) string { return s.Name.Value.Text() }))
	if slices.Equal(x, y) {
		t.Error("steps without ids, reordered, kept their fingerprints: the index is part of the path")
	}
}

func TestFingerprintAnchor(t *testing.T) {
	src := "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: echo\n"
	i := 0
	r := run(t, wf(src), nil, everyStep(meta("two-here"), func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Anchor: "a"}
	}), everyStep(meta("two-there"), func(c *RuleContext, s workflow.Step) FindingDraft {
		i++
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Anchor: strings.Repeat("b", i)}
	}))
	fps := fingerprints(r)
	if len(fps) != 2 || fps[0] == fps[1] {
		t.Errorf("fingerprints %v", fps)
	}
}

// TestFingerprintAlias: a step and its alias in another job have two
// fingerprints, and the alias's place says through which alias.
func TestFingerprintAlias(t *testing.T) {
	src := `on: push
jobs:
  a:
    runs-on: x
    steps:
      - &s
        run: echo
  b:
    runs-on: x
    steps:
      - *s
`
	fixer := meta("fixer")
	fixer = fixing(fixer, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	r := run(t, wf(src), nil, unmarkedStep(fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "f")}}}
	}))
	if len(r.Errors) != 0 || len(r.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 2 {
		t.Fatalf("findings %d, errors %+v", len(r.FindingsWith(CertaintyConfirmed, CertaintyConditional)), r.Errors)
	}
	a, b := r.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0], r.FindingsWith(CertaintyConfirmed, CertaintyConditional)[1]
	if a.Fingerprint == b.Fingerprint {
		t.Error("a step and its alias have one fingerprint")
	}
	if len(a.Location.Via) != 0 || len(b.Location.Via) != 1 {
		t.Errorf("via: %v and %v", a.Location.Via, b.Location.Via)
	}
	if pathOf(b.Location) != "jobs.b.steps[0]" {
		t.Errorf("the alias's path = %q", pathOf(b.Location))
	}
	if a.Fix.Edits[0].Span != b.Fix.Edits[0].Span {
		t.Error("the fixes of the anchor's two uses differ")
	}
}

// TestFingerprintInsideAlias: what is inside an element reached through an
// alias has the path of the alias followed by its path inside the anchor.
func TestFingerprintInsideAlias(t *testing.T) {
	src := `on: push
jobs:
  a:
    runs-on: x
    steps:
      - &s
        name: n
        run: echo ${{ github.sha }}
  b:
    runs-on: x
    steps:
      - *s
`
	var paths []string
	rule := everyStep(meta("inner"), func(c *RuleContext, s workflow.Step) FindingDraft {
		c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Name.Value.Base), Anchor: "name"})
		sp := s.Run.Value.Base.Node.ContentSpan()
		return FindingDraft{Args: said("x"), Location: AtSpan(c.input, s.Run.Value.Base, cstSpan(sp.Start+5, sp.End), true), Anchor: "expr"}
	})
	rep := run(t, wf(src), nil, rule)
	if len(rep.Errors) != 0 || len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 4 {
		t.Fatalf("findings %d, errors %+v", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)), rep.Errors)
	}
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		paths = append(paths, pathOf(f.Location))
	}
	slices.Sort(paths)
	want := "jobs.a.steps[0].name jobs.a.steps[0].run jobs.b.steps[0].name jobs.b.steps[0].run"
	if strings.Join(paths, " ") != want {
		t.Errorf("paths = %v, want %s", paths, want)
	}
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		if strings.HasPrefix(pathOf(f.Location), "jobs.b") != (len(f.Location.Via) == 1) {
			t.Errorf("%s: via %v", pathOf(f.Location), f.Location.Via)
		}
	}
}
