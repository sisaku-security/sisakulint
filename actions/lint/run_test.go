package lint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

func cstSpan(s, e int) cst.Span { return cst.Span{Start: s, End: e} }

const twoSteps = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: checkout
        uses: actions/checkout@v4
      - name: second
        run: echo hi
`

// steps yields the steps of the jobs of c's workflow.
func steps(c *RuleContext) []workflow.Step {
	var out []workflow.Step
	if c.workflow == nil {
		return nil
	}
	for _, j := range c.workflow.Jobs.Value.Entries {
		out = append(out, j.Value.Value.Steps.Value.Items...)
	}
	return out
}

// everyStep is a rule that reports every step, with what f makes of it.
func everyStep(m Meta, f func(c *RuleContext, s workflow.Step) FindingDraft) Rule {
	return testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			c.Report(f(c, s))
		}
		return nil
	}}
}

// The rules of these tests that fix report a step until its fix marks it
// with a comment at the end of the step's first line, so that the fix
// closes its finding: a fix that does not is dropped.

// firstLineEnd is where the first line of s ends in c's bytes.
func firstLineEnd(c *RuleContext, s workflow.Step) int {
	src := c.tree.Bytes()
	i := s.Base.Node.ContentSpan().Start
	for i < len(src) && src[i] != '\n' && src[i] != '\r' {
		i++
	}
	return i
}

// marked is whether the first line of s has a comment.
func marked(c *RuleContext, s workflow.Step) bool {
	return bytes.Contains(c.tree.Bytes()[s.Base.Node.ContentSpan().Start:firstLineEnd(c, s)], []byte(" # "))
}

// markEdit puts the comment text at the end of the first line of s.
func markEdit(c *RuleContext, s workflow.Step, text string) edit.Edit {
	e := firstLineEnd(c, s)
	return edit.Edit{Span: cstSpan(e, e), New: []byte(" # " + text)}
}

// unmarkedStep is a rule that reports every step not marked, with what f
// makes of it.
func unmarkedStep(m Meta, f func(c *RuleContext, s workflow.Step) FindingDraft) Rule {
	return testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			if !marked(c, s) {
				c.Report(f(c, s))
			}
		}
		return nil
	}}
}

// fixF is the kind of fix the tests' rules declare and give.
var fixF = MustFixKindID("f")

type mapResolver map[facts.Query]facts.RawAnswer

func (m mapResolver) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	if r, ok := m[q]; ok {
		return r
	}
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "not in the map"}
}

func run(t *testing.T, files map[string]string, r facts.Resolver, rules ...Rule) Report {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := newRegistry(rules, true)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		r = mapResolver{}
	}
	return Run(context.Background(), in, reg, r)
}

func wf(src string) map[string]string { return map[string]string{".github/workflows/w.yml": src} }

func TestRunConfirmed(t *testing.T) {
	m := meta("every-step")
	m.FindingKinds[0].CVSS = baseFor(SeverityMedium)
	rep := run(t, wf(twoSteps), nil, everyStep(m, func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("a step"), Location: At(c.input, s.Base)}
	}))
	if len(rep.Errors) != 0 {
		t.Fatalf("errors: %+v", rep.Errors)
	}
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 2 {
		t.Fatalf("findings: %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional))
	}
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		if f.Rule != m.ID || f.Severity != SeverityMedium || f.Certainty != CertaintyConfirmed || len(f.Fingerprint.String()) != 64 {
			t.Errorf("finding: rule %s severity %v certainty %v fingerprint %q", f.Rule, f.Severity, f.Certainty, f.Fingerprint)
		}
	}
	if rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Location.Span.Start >= rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[1].Location.Span.Start {
		t.Error("findings are not in the order of their places")
	}
}

// The impact and the remedy of a finding are its kind's in the registry,
// whatever the rule; the JSON of a finding has them, and no message.
func TestRunImpactFromRegistry(t *testing.T) {
	rep := run(t, wf(twoSteps), nil, everyStep(meta("every-step"), func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("a step"), Location: At(c.input, s.Base)}
	}))
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) == 0 || len(rep.Errors) != 0 {
		t.Fatalf("findings %+v, errors %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
	}
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		if f.Consequence != "it was said" || f.Remedy != "say it not" {
			t.Errorf("impact %q, remedy %q; want the kind's in the registry", f.Consequence, f.Remedy)
		}
	}
	b, err := json.Marshal(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"detected":"a step","consequence":"it was said","remedy":"say it not"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("no %s in\n%s", want, b)
		}
	}
	if strings.Contains(string(b), `"message"`) {
		t.Errorf("a message in a finding:\n%s", b)
	}
}

// A finding that detects nothing would make a report that does not fit its
// schema: it is an internal error.
func TestRunEmptyDetected(t *testing.T) {
	rep := run(t, wf(twoSteps), nil, everyStep(meta("every-step"), func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said(""), Location: At(c.input, s.Base)}
	}))
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 0 || len(rep.Errors) == 0 || !strings.Contains(rep.Errors[0].Message, "detects nothing") {
		t.Errorf("findings %+v, errors %+v; want none, and an error about what it detects", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
	}
}

func TestRunConditions(t *testing.T) {
	m := meta("cond-step")
	m = asking(m, facts.KindTestFlag)
	rule := everyStep(m, func(c *RuleContext, s workflow.Step) FindingDraft {
		cond, err := FactEq(facts.TestFlag{Name: s.Name.Value.Text() + "x"}, true)
		if err != nil {
			panic(err)
		}
		return FindingDraft{Args: said("maybe"), Location: At(c.input, s.Base), Condition: &cond}
	})
	// The first step has no name: it detects "x".
	for _, c := range []struct {
		name  string
		raw   facts.RawAnswer
		count int
		cert  Certainty
	}{
		{"true", facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(`true`)}, 1, CertaintyConfirmed},
		{"false", facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(`false`)}, 0, 0},
		{"unknown", facts.RawAnswer{State: facts.StateUnknown, Reason: "no token"}, 1, CertaintyConditional},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := mapResolver{facts.TestFlag{Name: "x"}: c.raw, facts.TestFlag{Name: "secondx"}: {State: facts.StateAbsent}}
			rep := run(t, wf(twoSteps), res, rule)
			if len(rep.Errors) != 0 {
				t.Fatalf("errors: %+v", rep.Errors)
			}
			if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != c.count {
				t.Fatalf("findings: %d, want %d", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)), c.count)
			}
			if c.count == 1 && rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Certainty != c.cert {
				t.Errorf("certainty %v, want %v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Certainty, c.cert)
			}
			if len(rep.Facts) != 2 {
				t.Errorf("facts: %+v, want the two asked", rep.Facts)
			}
		})
	}
}

func TestRunUndeclaredFact(t *testing.T) {
	rep := run(t, wf(twoSteps), nil, everyStep(meta("no-facts"), func(c *RuleContext, s workflow.Step) FindingDraft {
		cond := FactAbsent(facts.TestFlag{Name: "a"})
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Condition: &cond}
	}))
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 0 || len(rep.Errors) != 2 || !strings.Contains(rep.Errors[0].Message, "test.flag") {
		t.Errorf("findings %d, errors %+v", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)), rep.Errors)
	}
}

// TestRunPerKind: what a finding gives is checked against its own kind:
// a kind that declares no fix gives none, and a condition asks only about
// the facts of its kind, though another kind of the rule declares more.
func TestRunPerKind(t *testing.T) {
	m := asking(fixing(meta("two-kinds"), FixKind{ID: fixF, Title: "f", Safety: SafetySafe}), facts.KindTestFlag)
	m.FindingKinds = append(m.FindingKinds, saidOf(otherKind))
	cond := FactAbsent(facts.TestFlag{Name: "a"})
	for _, c := range []struct {
		name string
		f    func(c *RuleContext, s workflow.Step) FindingDraft
		want string
	}{
		{"a fix", func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: other("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}}}
		}, "declares no Fixes"},
		{"a condition", func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: other("x"), Location: At(c.input, s.Base), Condition: &cond}
		}, "test.flag"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := run(t, wf(twoSteps), nil, unmarkedStep(m, c.f))
			if len(rep.Errors) != 2 || !strings.Contains(rep.Errors[0].Message, c.want) {
				t.Errorf("findings %+v, errors %+v; want 2 errors about %s", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors, c.want)
			}
		})
	}
}

// TestRunFixOfAnotherKind: a fix, and a fact a reason for no fix names,
// that the rule has but only another kind refers to, are an error.
func TestRunFixOfAnotherKind(t *testing.T) {
	fixG := MustFixKindID("g")
	m := fixing(meta("two-fixes"), FixKind{ID: fixF, Title: "f", FactKinds: []facts.Kind{facts.KindTestFlag}, Safety: SafetySafe})
	m.FixKinds = append(m.FixKinds, FixKind{ID: fixG, Title: "g", FactKinds: []facts.Kind{facts.KindTestText}, Safety: SafetySafe})
	second := saidOf(otherKind)
	second.Fixes = []FixKindID{fixG}
	m.FindingKinds = append(m.FindingKinds, second)
	for _, c := range []struct {
		name string
		f    func(c *RuleContext, s workflow.Step) FindingDraft
		want string
	}{
		{"a fix", func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: other("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}}}
		}, "not of a kind the kind test.other refers to"},
		{"a reason", func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: other("x"), Location: At(c.input, s.Base), NoFix: &NoFix{Reason: ir.NoFixReasonFact, Queries: []facts.Query{facts.TestFlag{Name: "a"}}}}
		}, "no fix of the kind test.other needs"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := run(t, wf(twoSteps), nil, unmarkedStep(m, c.f))
			if len(rep.Errors) != 2 || !strings.Contains(rep.Errors[0].Message, c.want) {
				t.Errorf("findings %+v, errors %+v; want 2 errors about %s", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors, c.want)
			}
		})
	}
}

// TestRunFixSideEffects: a fix whose side effects its kind does not
// declare, a fix to review with none and a safe fix with one are errors.
func TestRunFixSideEffects(t *testing.T) {
	review := fixing(meta("review"), FixKind{ID: fixF, Title: "f", Safety: SafetyReview, PossibleSideEffects: []ir.SideEffect{ir.SideEffectUnquotedOneWord}})
	safe := fixing(meta("safe"), FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	give := func(es ...ir.SideEffect) func(c *RuleContext, s workflow.Step) FindingDraft {
		return func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}, SideEffects: es}}
		}
	}
	for _, c := range []struct {
		name string
		m    Meta
		f    func(c *RuleContext, s workflow.Step) FindingDraft
		want string
	}{
		{"not declared", review, give(ir.SideEffectPatternLiteral), "does not declare"},
		{"to review with none", review, give(), "one at least to review"},
		{"safe with one", safe, give(ir.SideEffectUnquotedOneWord), "a safe one none"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := run(t, wf(twoSteps), nil, unmarkedStep(c.m, c.f))
			if len(rep.Errors) != 2 || !strings.Contains(rep.Errors[0].Message, c.want) {
				t.Errorf("findings %+v, errors %+v; want 2 errors about %s", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors, c.want)
			}
			for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
				if f.Fix != nil || f.NoFix == nil || f.NoFix.Reason != ir.NoFixReasonManual {
					t.Errorf("fix %+v, no fix %+v; want the reason manual", f.Fix, f.NoFix)
				}
			}
		})
	}
	rep := run(t, wf(twoSteps), nil, unmarkedStep(review, give(ir.SideEffectUnquotedOneWord)))
	if len(rep.Errors) != 0 || rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Fix == nil || !slices.Equal(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Fix.SideEffects, []ir.SideEffect{ir.SideEffectUnquotedOneWord}) {
		t.Errorf("findings %+v, errors %+v; want the fix with its side effect", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
	}
}

// TestRunFixSideEffectsCopied: the side effects of a finding's fix are its
// own, though the rule gave one slice to every finding.
func TestRunFixSideEffectsCopied(t *testing.T) {
	rep := run(t, wf(twoSteps), nil, marker("mark", "m", SafetyReview))
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 2 {
		t.Fatalf("findings %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional))
	}
	rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Fix.SideEffects[0] = ir.SideEffectPatternLiteral
	if got := rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[1].Fix.SideEffects; !slices.Equal(got, []ir.SideEffect{ir.SideEffectUnquotedOneWord}) {
		t.Errorf("the second finding's side effects %v changed with the first's", got)
	}
}

// TestRunSeverityOfKind: a finding is as bad as its kind, not as the worst
// kind of its rule.
func TestRunSeverityOfKind(t *testing.T) {
	m := meta("two-kinds")
	m.FindingKinds[0].CVSS = baseFor(SeverityMedium)
	worse := saidOf(otherKind)
	worse.CVSS = baseFor(SeverityCritical)
	m.FindingKinds = append(m.FindingKinds, worse)
	rep := run(t, wf(twoSteps), nil, everyStep(m, func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("a step"), Location: At(c.input, s.Base)}
	}))
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 2 || len(rep.Errors) != 0 {
		t.Fatalf("findings %+v, errors %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
	}
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		if f.Severity != SeverityMedium {
			t.Errorf("the severity of a finding of test.said is %v, want its kind's, medium (the rule's is critical)", f.Severity)
		}
	}
	if len(rep.Rules) != 1 || rep.Rules[0].Severity != SeverityCritical {
		t.Errorf("the rules of the report are %+v, want two-kinds as critical, the worst of its kinds", rep.Rules)
	}
}

func TestRunErrorAndPanic(t *testing.T) {
	failing := testRule{meta: meta("fails"), check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base)})
		}
		return errors.New("broken")
	}}
	panicking := testRule{meta: meta("panics"), check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base)})
		}
		panic("boom")
	}}
	rep := run(t, wf(twoSteps), nil, failing, panicking)
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 0 {
		t.Errorf("the findings of a failed check were kept: %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional))
	}
	if len(rep.Errors) != 2 || rep.Errors[0].Rule != failing.meta.ID || !strings.Contains(rep.Errors[0].Message, "broken") ||
		rep.Errors[1].Rule != panicking.meta.ID || !strings.Contains(rep.Errors[1].Message, "boom") || rep.Errors[0].Input != facts.MustCleanInputPath(".github/workflows/w.yml") {
		t.Errorf("errors: %+v", rep.Errors)
	}
}

func TestRunFixes(t *testing.T) {
	fixer := meta("fixer")
	fixer = fixing(fixer, FixKind{ID: fixF, Title: "rename it", FactKinds: []facts.Kind{facts.KindTestFlag}, Safety: SafetySafe})
	good := func(c *RuleContext, s workflow.Step) *Fix {
		return &Fix{KindID: fixF, Title: "x", Edits: []edit.Edit{markEdit(c, s, "renamed")}}
	}
	for _, c := range []struct {
		name   string
		meta   Meta
		f      func(c *RuleContext, s workflow.Step) FindingDraft
		fixes  int
		errors int
	}{
		{"a fix", fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: good(c, s)}
		}, 2, 0},
		{"no fix, with a reason", fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), NoFix: &NoFix{Reason: ir.NoFixReasonFact, Queries: []facts.Query{facts.TestFlag{Name: "a"}}}}
		}, 0, 0},
		{"neither", fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base)}
		}, 0, 2},
		{"both", fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: good(c, s), NoFix: &NoFix{Reason: ir.NoFixReasonManual}}
		}, 0, 2},
		{"undeclared kind", fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
			f := good(c, s)
			f.KindID = MustFixKindID("other")
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: f}
		}, 0, 2},
		{"edit out of range", fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Edits: []edit.Edit{{Span: cstSpan(-1, 3)}}}}
		}, 0, 2},
		{"a rule that fixes nothing gives a fix", meta("plain"), func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: good(c, s)}
		}, 0, 2},
		{"a rule that fixes nothing gives a reason", meta("plain"), func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), NoFix: &NoFix{Reason: ir.NoFixReasonForm}}
		}, 0, 2},
		{"a reason names a fact no fix needs", fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), NoFix: &NoFix{Reason: ir.NoFixReasonFact, Queries: []facts.Query{facts.TestText{Name: "a"}}}}
		}, 0, 2},
		{"a reason out of range", fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), NoFix: &NoFix{}}
		}, 0, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := run(t, wf(twoSteps), nil, unmarkedStep(c.meta, c.f))
			fixes := 0
			for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
				if f.Fix != nil {
					fixes++
				}
				if c.meta.ID == fixer.ID && (f.Fix != nil) == (f.NoFix != nil) {
					t.Errorf("a finding of a rule that fixes gives %+v and %+v, not one of them", f.Fix, f.NoFix)
				}
			}
			if fixes != c.fixes || len(rep.Errors) != c.errors {
				t.Errorf("fixes %d, errors %+v; want %d fixes, %d errors", fixes, rep.Errors, c.fixes, c.errors)
			}
			if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 2 {
				t.Errorf("findings %d, want 2: a bad fix does not drop the finding", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)))
			}
		})
	}
}

func TestRunInputs(t *testing.T) {
	var seen []string
	rule := testRule{meta: meta("sees"), check: func(_ context.Context, c *RuleContext) error {
		seen = append(seen, c.input.Name.String())
		return nil
	}}
	run(t, map[string]string{
		".github/workflows/ok.yml":      twoSteps,
		".github/workflows/invalid.yml": "on: push\n",
		".github/workflows/latin.yml":   "on: caf\xe9\n",
		"action.yml":                    okAction,
	}, nil, rule)
	if got := strings.Join(seen, " "); got != ".github/workflows/invalid.yml .github/workflows/ok.yml" {
		t.Errorf("the rule saw %s; it must see the workflows it can read, invalid ones included, and no action", got)
	}
}

// TestRunMisbehavingRules: a rule that reports after its check has
// returned, and other rules that break the contract.
func TestRunMisbehavingRules(t *testing.T) {
	var kept *RuleContext
	save := testRule{meta: meta("a-save"), check: func(_ context.Context, c *RuleContext) error {
		kept = c
		return nil
	}}
	late := testRule{meta: meta("b-late"), check: func(_ context.Context, c *RuleContext) error {
		kept.Report(FindingDraft{Args: said("x"), Location: At(kept.input, kept.workflow.Base)})
		return nil
	}}
	rep := run(t, wf(twoSteps), nil, save, late)
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 0 || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Message, "after") || rep.Errors[0].Rule != save.meta.ID {
		t.Errorf("a report after Check returned: findings %d, errors %+v", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)), rep.Errors)
	}
	kept.Report(FindingDraft{Args: said("x"), Location: At(kept.input, kept.workflow.Base)}) // after Run: nothing to add to, no panic

	twice := everyStep(meta("twice"), func(c *RuleContext, s workflow.Step) FindingDraft {
		f := FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Related: []Related{{Location: At(c.input, s.Base), Note: "a"}}}
		c.Report(f)
		f.Related[0].Note = "changed"
		return f
	})
	rep = run(t, wf(twoSteps), nil, twice)
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 2 {
		t.Errorf("findings %d, want 2 (the second report of each is a duplicate)", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)))
	}
	if len(rep.Errors) != 2 || !strings.Contains(rep.Errors[0].Message, "twice") {
		t.Errorf("errors: %+v", rep.Errors)
	}
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		if f.Related[0].Note != "a" {
			t.Errorf("the engine keeps the rule's slice: %q", f.Related[0].Note)
		}
	}

	noPlace := everyStep(meta("no-place"), func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: Location{File: File{Input: c.input.Name}, Span: s.Base.Primary()}}
	})
	rep = run(t, wf(twoSteps), nil, noPlace)
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 0 || len(rep.Errors) != 2 {
		t.Errorf("a location not made by At: findings %d, errors %+v", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)), rep.Errors)
	}
}

func TestRunCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in, _ := Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(twoSteps)}})
	ran := false
	reg, _ := newRegistry([]Rule{testRule{meta: meta("r"), check: func(context.Context, *RuleContext) error { ran = true; return nil }}}, true)
	rep := Run(ctx, in, reg, mapResolver{})
	if ran || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Message, "canceled") {
		t.Errorf("ran %v, errors %+v", ran, rep.Errors)
	}
}

// TestReportCopiesConditions: a rule that reuses a buffer for the parts of
// its conditions must not change the conditions it reported before.
func TestReportCopiesConditions(t *testing.T) {
	m := meta("reuse")
	m = asking(m, facts.KindTestFlag)
	var buf []Condition
	i := 0
	rule := everyStep(m, func(c *RuleContext, s workflow.Step) FindingDraft {
		names := []string{"a", "b"}
		e, _ := FactEq(facts.TestFlag{Name: names[i]}, true)
		i++
		buf = append(buf[:0], e)
		cond := All(buf...)
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Condition: &cond}
	})
	res := mapResolver{
		facts.TestFlag{Name: "a"}: {State: facts.StateFound, Value: json.RawMessage(`true`)},
		facts.TestFlag{Name: "b"}: {State: facts.StateFound, Value: json.RawMessage(`false`)},
	}
	rep := run(t, wf(twoSteps), res, rule)
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 || len(rep.Errors) != 0 {
		t.Errorf("findings %d, errors %+v; want the first step's finding", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)), rep.Errors)
	}
}

// TestReportCopiesEdits: the bytes of an edit are the engine's once
// reported.
func TestReportCopiesEdits(t *testing.T) {
	m := meta("reuse")
	m = fixing(m, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	buf := []byte(" # 0")
	var mu sync.Mutex // Check runs at once on the fixed inputs
	rep := run(t, wf(twoSteps), nil, testRule{meta: m, check: func(ctx context.Context, c *RuleContext) error {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range steps(c) {
			if marked(c, s) {
				continue
			}
			e := firstLineEnd(c, s)
			c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{{Span: cstSpan(e, e), New: buf}}}})
			buf[3]++
		}
		return nil
	}})
	var got []string
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		got = append(got, string(f.Fix.Edits[0].New))
	}
	if strings.Join(got, "|") != " # 0| # 1" {
		t.Errorf("the new bytes = %q, want # 0 and # 1", got)
	}
}

// TestReportCopiesFix: a rule may give several findings one *Fix (a fix of
// the step closes them all) and change it after Report; the findings keep
// the fix as it was reported.
func TestReportCopiesFix(t *testing.T) {
	m := meta("shared")
	m = fixing(m, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	rep := run(t, wf(twoSteps), nil, testRule{meta: m, check: func(ctx context.Context, c *RuleContext) error {
		ss := steps(c)
		if marked(c, ss[0]) {
			return nil
		}
		x := &Fix{KindID: fixF, Title: "reported", Edits: []edit.Edit{markEdit(c, ss[0], "m")}}
		for _, anchor := range []string{"a", "b"} {
			c.Report(FindingDraft{Args: said("x"), Location: At(c.input, ss[0].Base), Fix: x, Anchor: anchor})
		}
		x.Title = "changed after"
		return nil
	}})
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 2 {
		t.Fatalf("findings %+v, errors %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
	}
	a, b := rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Fix, rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[1].Fix
	if a == nil || b == nil || a.Title != "reported" || b.Title != "reported" || a == b {
		t.Errorf("fixes %+v and %+v, want two copies titled as reported", a, b)
	}
}

// TestFixOfAFindingInAnotherInput: a fix is of the input being checked, even
// when the finding is in another; the report shows that input's bytes and
// does not panic.
func TestFixOfAFindingInAnotherInput(t *testing.T) {
	other := "on: push\njobs: {}\n"
	m := meta("cross")
	m = fixing(m, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	rule := testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		if c.input.Name != facts.MustCleanInputPath(".github/workflows/w.yml") {
			return nil
		}
		o, st := c.inputs.Lookup(facts.MustCleanInputPath(".github/workflows/a.yml"))
		if st != LookupFound {
			t.Fatal("no other input")
		}
		run := steps(c)[1].Run.Value.Base.Node.ContentSpan()
		if bytes.Contains(c.tree.Bytes(), []byte("# x")) { // the fix of w.yml closes the finding in a.yml
			return nil
		}
		c.Report(FindingDraft{Args: said("x"), Location: At(o, o.Workflow.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{{Span: run, New: []byte("echo hi # x")}}}})
		return nil
	}}
	rep := run(t, map[string]string{".github/workflows/w.yml": twoSteps, ".github/workflows/a.yml": other}, nil, rule)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			Fix *struct{ Edits []struct{ Old string } }
		}
	}
	json.Unmarshal(b, &doc)
	if len(doc.Findings) != 1 || doc.Findings[0].Fix == nil || doc.Findings[0].Fix.Edits[0].Old != "echo hi" {
		t.Errorf("findings %+v", doc.Findings)
	}
}

// TestRunRejectsArgs: a finding whose Args are missing or of a kind not
// declared is refused.
func TestRunRejectsArgs(t *testing.T) {
	for _, c := range []struct {
		name string
		args FindingArgs
		want string
	}{
		{"no args", nil, "without Args"},
		{"a kind not declared", undeclared{"x"}, "test.other"},
		{"JSON of another kind", wrongKind{"x"}, "kind"},
	} {
		rep := run(t, wf(twoSteps), nil, everyStep(meta("args"), func(ctx *RuleContext, s workflow.Step) FindingDraft {
			return FindingDraft{Location: At(ctx.input, s.Base), Args: c.args}
		}))
		if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 0 || len(rep.Errors) == 0 {
			t.Errorf("%s: %d findings, errors %+v; want none, and why", c.name, len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)), rep.Errors)
		}
		for _, e := range rep.Errors {
			if !strings.Contains(e.Message, c.want) {
				t.Errorf("%s: the error %q does not say %q", c.name, e.Message, c.want)
			}
		}
	}
}
