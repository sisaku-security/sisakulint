package lint

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/workflow"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// gapMeta is the Meta of a rule that declares the kind kindG.
func gapMeta(id string) Meta {
	m := meta(id)
	m.InconclusiveKinds = []InconclusiveKind{{ID: kindG, Text: "an inconclusive place", Disposition: Todo(NeedSameFile), Examples: []Example{exampleOf("g.yml")}}}
	return m
}

// everyStepGap is a rule that reports each step as inconclusive, in the
// reverse order of the steps.
func everyStepGap(m Meta) Rule {
	return testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		s := steps(c)
		for i := len(s) - 1; i >= 0; i-- {
			c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, s[i].Base), Note: "step " + s[i].Name.Value.Text()})
		}
		return nil
	}}
}

func TestRunInconclusive(t *testing.T) {
	rep := run(t, wf(twoSteps), nil, everyStepGap(gapMeta("b-gaps")), everyStepGap(gapMeta("a-gaps")))
	if len(rep.Errors) != 0 {
		t.Fatalf("errors: %+v", rep.Errors)
	}
	var got []string
	for _, g := range rep.FindingsWith(CertaintyInconclusive) {
		got = append(got, g.Rule.String()+" "+g.InconclusiveKind.String()+" "+g.Note)
	}
	// by place, then by rule
	want := "a-gaps g step |b-gaps g step |a-gaps g step second|b-gaps g step second"
	if strings.Join(got, "|") != want {
		t.Errorf("Inconclusive = %q, want %q", strings.Join(got, "|"), want)
	}
	// An inconclusive finding is no confirmed or conditional finding, and
	// sets bit 8 alone.
	if n := len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)); n != 0 || len(rep.Findings) != 4 || Classify(rep, SeverityInfo) != InconclusiveBit {
		t.Errorf("findings %d, of which confirmed or conditional %d, exit code %d; want 4, none, and bit 8 alone", len(rep.Findings), n, Classify(rep, SeverityInfo))
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"findings":[{"rule":"a-gaps","severity":"high","certainty":"inconclusive","location":{"file":{"input":".github/workflows/w.yml"},"start":`) ||
		!strings.Contains(string(b), `"args":{"kind_id":"a-gaps.g"},"detected":"step ",`) || strings.Contains(string(b), `"inconclusive":`) {
		t.Errorf("the JSON of the report: %s", b)
	}
}

// TestInconclusiveFindingShape: the engine makes of an inconclusive place
// a finding whose certainty is inconclusive, with no args, the severity
// and the problem of its rule, InconclusiveRemedy, and the text of its
// kind when the rule gives no note.
func TestInconclusiveFindingShape(t *testing.T) {
	m := gapMeta("shape")
	rule := testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, steps(c)[1].Base)})
		return nil
	}}
	rep := run(t, wf(twoSteps), nil, rule)
	g := rep.FindingsWith(CertaintyInconclusive)
	if len(rep.Errors) != 0 || len(g) != 1 || len(rep.Findings) != 1 {
		t.Fatalf("errors %+v, findings %+v", rep.Errors, rep.Findings)
	}
	f := g[0]
	if f.Args != nil || f.InconclusiveKind != kindG || f.Severity != m.Severity() || f.Consequence != m.Problem || f.Remedy != InconclusiveRemedy(m.ID) ||
		f.Detected() != "an inconclusive place" || f.KindText() != "shape.g" || f.KeyPath.String() != "jobs.build.steps[1]" ||
		f.SpanText == "" || f.Fingerprint.String() == "" || f.Fix != nil || f.NoFix != nil || f.Condition != nil {
		t.Errorf("the inconclusive finding: %+v", f)
	}
}

// TestInconclusiveFingerprintsDistinct: places of one kind in one element,
// with other texts and with the same text, have fingerprints of their own,
// and no error says that a finding is reported twice.
func TestInconclusiveFingerprintsDistinct(t *testing.T) {
	rule := testRule{meta: gapMeta("distinct"), check: func(_ context.Context, c *RuleContext) error {
		s := steps(c)[1]
		sp := s.Base.Primary()
		for _, x := range []cst.Span{{Start: sp.Start, End: sp.Start + 4}, {Start: sp.Start + 6, End: sp.Start + 12}} {
			c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: AtSpan(c.input, s.Base, x, true)})
		}
		c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, s.Base), Note: "one"})
		c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, s.Base), Note: "two"})
		return nil
	}}
	rep := run(t, wf(twoSteps), nil, rule)
	if len(rep.Errors) != 0 {
		t.Fatalf("errors: %+v", rep.Errors)
	}
	seen := map[Fingerprint]bool{}
	for _, f := range rep.Findings {
		seen[f.Fingerprint] = true
	}
	if len(rep.Findings) != 4 || len(seen) != 4 {
		t.Errorf("%d findings, %d fingerprints; want 4 and 4", len(rep.Findings), len(seen))
	}
}

// TestInconclusiveFingerprintAlias: the fingerprint of a place reached
// through an alias does not change when a comment line is added between
// the anchor and the alias.
func TestInconclusiveFingerprintAlias(t *testing.T) {
	src := func(between string) string {
		return "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - &s\n        run: echo hi\n" + between + "      - *s\n"
	}
	rule := testRule{meta: gapMeta("alias"), check: func(_ context.Context, c *RuleContext) error {
		c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, steps(c)[1].Base)})
		return nil
	}}
	fp := func(between string) Fingerprint {
		rep := run(t, wf(src(between)), nil, rule)
		if len(rep.Errors) != 0 || len(rep.Findings) != 1 || len(rep.Findings[0].Location.Via) == 0 {
			t.Fatalf("errors %+v, findings %+v", rep.Errors, rep.Findings)
		}
		return rep.Findings[0].Fingerprint
	}
	if a, b := fp(""), fp("      # a comment\n"); a != b {
		t.Errorf("the fingerprint changed: %s, %s", a, b)
	}
}

// TestInconclusiveRelatedCopied: the related places of an inconclusive
// place are those of its finding.
func TestInconclusiveRelatedCopied(t *testing.T) {
	rule := testRule{meta: gapMeta("related"), check: func(_ context.Context, c *RuleContext) error {
		s := steps(c)
		c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, s[0].Base), Related: []Related{{Location: At(c.input, s[1].Base), Note: "runs the code"}}})
		return nil
	}}
	rep := run(t, wf(twoSteps), nil, rule)
	if len(rep.Errors) != 0 || len(rep.Findings) != 1 {
		t.Fatalf("errors %+v, findings %+v", rep.Errors, rep.Findings)
	}
	r := rep.Findings[0].Related
	if len(r) != 1 || r[0].Note != "runs the code" || r[0].Location.KeyPath().String() != "jobs.build.steps[1]" || len(rep.Findings[0].Evidence) != 0 {
		t.Errorf("related %+v, evidence %+v", r, rep.Findings[0].Evidence)
	}
}

// TestRunInconclusiveRejects: a rule that breaks the contract of the
// inconclusive places loses them, and the error says why.
func TestRunInconclusiveRejects(t *testing.T) {
	gapRule := func(id string, f func(c *RuleContext, s workflow.Step) InconclusiveDraft) Rule {
		return testRule{meta: gapMeta(id), check: func(_ context.Context, c *RuleContext) error {
			for _, s := range steps(c) {
				c.Inconclusive(f(c, s))
			}
			return nil
		}}
	}
	for _, c := range []struct {
		name string
		rule Rule
		want string
	}{
		{"a kind not declared", gapRule("undeclared", func(c *RuleContext, s workflow.Step) InconclusiveDraft {
			return InconclusiveDraft{KindID: MustInconclusiveKindID("other"), Location: At(c.input, s.Base)}
		}), "other"},
		{"a location not made by At", gapRule("no-at", func(c *RuleContext, s workflow.Step) InconclusiveDraft { return InconclusiveDraft{KindID: kindG} }), "location"},
		{"the rule fails", testRule{meta: gapMeta("fails"), check: func(_ context.Context, c *RuleContext) error {
			for _, s := range steps(c) {
				c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, s.Base)})
			}
			return errors.New("broken")
		}}, "broken"},
		{"the rule panics", testRule{meta: gapMeta("panics"), check: func(_ context.Context, c *RuleContext) error {
			for _, s := range steps(c) {
				c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, s.Base)})
			}
			panic("boom")
		}}, "boom"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := run(t, wf(twoSteps), nil, c.rule)
			if len(rep.FindingsWith(CertaintyInconclusive)) != 0 {
				t.Errorf("Inconclusive = %+v, want none", rep.FindingsWith(CertaintyInconclusive))
			}
			if len(rep.Errors) == 0 || !strings.Contains(rep.Errors[0].Message, c.want) {
				t.Errorf("errors = %+v, want one that mentions %q", rep.Errors, c.want)
			}
		})
	}
}

func TestRunInconclusiveAfterCheck(t *testing.T) {
	var kept *RuleContext
	save := testRule{meta: gapMeta("a-save"), check: func(_ context.Context, c *RuleContext) error {
		kept = c
		return nil
	}}
	late := testRule{meta: meta("b-late"), check: func(_ context.Context, c *RuleContext) error {
		kept.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(kept.input, kept.workflow.Base)})
		return nil
	}}
	rep := run(t, wf(twoSteps), nil, save, late)
	if len(rep.FindingsWith(CertaintyInconclusive)) != 0 || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Message, "after") || rep.Errors[0].Rule != save.meta.ID {
		t.Errorf("an inconclusive place after Check returned: unexamined %d, errors %+v", len(rep.FindingsWith(CertaintyInconclusive)), rep.Errors)
	}
	kept.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(kept.input, kept.workflow.Base)}) // after Run: nothing to add to, no panic
}

// TestInconclusiveFingerprintSibling: the fingerprint of a place does not
// change when another element with a place of the same kind and text (the
// same step in another job) is removed: the count is of one element.
func TestInconclusiveFingerprintSibling(t *testing.T) {
	const job = "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	rule := testRule{meta: gapMeta("sibling"), check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, s.Base)})
		}
		return nil
	}}
	fpOfB := func(src string) Fingerprint {
		rep := run(t, wf(src), nil, rule)
		if len(rep.Errors) != 0 {
			t.Fatalf("errors: %+v", rep.Errors)
		}
		for _, f := range rep.Findings {
			if f.KeyPath.String() == "jobs.b.steps[0]" {
				return f.Fingerprint
			}
		}
		t.Fatalf("no finding at jobs.b.steps[0]: %+v", rep.Findings)
		return Fingerprint{}
	}
	both := fpOfB("on: push\njobs:\n  a:\n" + job + "  b:\n" + job)
	alone := fpOfB("on: push\njobs:\n  b:\n" + job)
	if both != alone {
		t.Errorf("the fingerprint of jobs.b.steps[0] changed when the job a was removed: %s, %s", both, alone)
	}
}
