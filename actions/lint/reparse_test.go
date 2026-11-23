package lint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gh-intel/sisakulint/actions/ir"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// TestFixIsReparsed is the check after a fix: the
// engine applies each fix, reads the input again and runs the rule on it;
// a fix that leaves its finding, makes a new one or new diagnostics, or
// makes the rule fail, is dropped with an internal error, and the finding
// stays without it.
func TestFixIsReparsed(t *testing.T) {
	fixer := meta("fixer")
	fixer = fixing(fixer, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	mark := func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}}}
	}
	for _, c := range []struct {
		name   string
		rule   Rule
		fixes  int
		errors []string // what each internal error says, in order
	}{
		{"a fix that closes its finding", unmarkedStep(fixer, mark), 2, nil},
		{"a fix that leaves its finding", everyStep(fixer, mark), 0, []string{"does not close", "does not close"}},
		{"a fix that makes a new finding", testRule{meta: fixer, check: func(_ context.Context, c *RuleContext) error {
			for _, s := range steps(c) {
				if !marked(c, s) {
					f := mark(c, s)
					f.Anchor = "before"
					c.Report(f)
				} else {
					c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Anchor: "after", NoFix: &NoFix{Reason: ir.NoFixReasonManual}})
				}
			}
			return nil
		}}, 0, []string{"new finding", "new finding"}},
		{"a fix that makes a new diagnostic", unmarkedStep(fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
			if s.Run.Status != workflow.Present {
				return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), NoFix: &NoFix{Reason: ir.NoFixReasonManual}}
			}
			broken := edit.Edit{Span: s.Run.Value.Base.Node.ContentSpan(), New: []byte("${{ ( }}")}
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m"), broken}}}
		}), 0, []string{"diagnostic"}},
		{"a rule that panics on the fixed input", testRule{meta: fixer, check: func(_ context.Context, c *RuleContext) error {
			for _, s := range steps(c) {
				if marked(c, s) {
					panic("marked")
				}
				c.Report(mark(c, s))
			}
			return nil
		}}, 0, []string{"panic", "panic"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := run(t, wf(twoSteps), nil, c.rule)
			fixes := 0
			for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
				if f.Fix != nil {
					fixes++
				}
			}
			if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 2 || fixes != c.fixes || len(rep.Errors) != len(c.errors) {
				t.Fatalf("findings %d, fixes %d, errors %+v; want 2 findings, %d fixes, %d errors", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)), fixes, rep.Errors, c.fixes, len(c.errors))
			}
			for i, want := range c.errors {
				if e := rep.Errors[i]; !strings.Contains(e.Message, want) || e.Rule != fixer.ID {
					t.Errorf("error %d = %+v, want it to say %q", i, e, want)
				}
			}
		})
	}
}

// TestFixCheckLimitBroken: a fix past the bounds that breaks the contract
// is not given as not checked (limit) but dropped, as within them: an
// internal error, and the reason manual.
func TestFixCheckLimitBroken(t *testing.T) {
	n := maxCheckedFixes + 1
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n")
	for i := range n - 1 {
		b.WriteString("      - run: echo " + strings.Repeat("x", i%7+1) + "\n")
	}
	b.WriteString("      - run: echo last\n")
	fixer := meta("fixer")
	fixer = fixing(fixer, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	var last atomic.Int32 // Check runs at once on the fixed inputs
	rep := run(t, wf(b.String()), nil, unmarkedStep(fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
		k := fixF
		if sp := At(c.input, s.Base).Span; strings.Contains(string(c.tree.Bytes()[sp.Start:sp.End]), "last") {
			k = MustFixKindID("other")
			last.Add(1)
		}
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: k, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}}}
	}))
	fixed, manual := 0, 0
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		switch {
		case f.Fix != nil && f.NoFix == nil:
			fixed++
		case f.Fix == nil && f.NoFix != nil && f.NoFix.Reason == ir.NoFixReasonManual:
			manual++
		default:
			t.Errorf("finding %+v", f)
		}
	}
	if last.Load() == 0 || fixed != maxCheckedFixes || manual != 1 || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Message, "not of a kind") {
		t.Errorf("fixed %d, manual %d, errors %+v", fixed, manual, rep.Errors)
	}
}

// TestFixCheckLimit: the engine checks at most maxCheckedFixes fixes of one
// rule on one input; the findings past that keep no fix, with the reason
// limit, which is not an internal error and changes no bit of the exit
// code.
func TestFixCheckLimit(t *testing.T) {
	n := maxCheckedFixes + 3
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n")
	for i := range n {
		b.WriteString("      - run: echo " + strings.Repeat("x", i%7+1) + "\n")
	}
	fixer := meta("fixer")
	fixer = fixing(fixer, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	rep := run(t, wf(b.String()), nil, unmarkedStep(fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}}}
	}))
	fixed, limited := 0, 0
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		switch {
		case f.Fix != nil && f.NoFix == nil:
			fixed++
		case f.Fix == nil && f.NoFix != nil && f.NoFix.Reason == ir.NoFixReasonTooManyFixes:
			limited++
		default:
			t.Errorf("finding %+v", f)
		}
	}
	if fixed != maxCheckedFixes || limited != 3 || len(rep.Errors) != 0 {
		t.Errorf("fixed %d, limited %d, errors %+v", fixed, limited, rep.Errors)
	}
	if got := Classify(rep, SeverityInfo); got != ConfirmedBit {
		t.Errorf("Classify = %d, want only the found bit", got)
	}
}

func TestRuleCannotSayLimit(t *testing.T) {
	fixer := meta("fixer")
	fixer = fixing(fixer, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	rep := run(t, wf(twoSteps), nil, unmarkedStep(fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), NoFix: &NoFix{Reason: ir.NoFixReasonTooManyFixes}}
	}))
	if len(rep.Errors) != 2 {
		t.Errorf("errors %+v; want the reason limit refused, since only the engine gives it", rep.Errors)
	}
}

// TestParallelChecksAreDeterministic: the fixes are checked at once, and the
// report is the same bytes each time.
func TestParallelChecksAreDeterministic(t *testing.T) {
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n")
	for i := range 64 {
		b.WriteString("      - run: echo " + strings.Repeat("y", i%5+1) + "\n")
	}
	fixer := meta("fixer")
	fixer = fixing(fixer, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	var first []byte
	for i := range 5 {
		// every third fix leaves its finding, so that errors come out of the checks too
		rep := run(t, wf(b.String()), nil, everyStepOr(fixer, 3))
		got, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = got
			if len(rep.Errors) == 0 {
				t.Fatal("no errors to compare")
			}
		} else if !bytes.Equal(got, first) {
			t.Fatalf("run %d differs", i)
		}
	}
}

// everyStepOr reports the steps not marked, and every k-th step even when
// marked, so that the fix of every k-th step does not close its finding.
func everyStepOr(m Meta, k int) Rule {
	return testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		for i, s := range steps(c) {
			if !marked(c, s) || i%k == 0 {
				c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}}})
			}
		}
		return nil
	}}
}

// TestSharedFix: findings that give the same fix (the same edits) are
// checked with it once, count once against the bounds, and each keeps the
// fix; the fix must close every one of them.
func TestSharedFix(t *testing.T) {
	fixer := meta("fixer")
	fixer = fixing(fixer, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	var checks atomic.Int32
	many := func(n int, closes func(i int) bool) Rule {
		return testRule{meta: fixer, check: func(_ context.Context, c *RuleContext) error {
			checks.Add(1)
			s := steps(c)[0]
			for i := range n {
				if marked(c, s) && closes(i) {
					continue
				}
				c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Anchor: fmt.Sprint(i),
					Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}}})
			}
			return nil
		}}
	}
	t.Run("closes all", func(t *testing.T) {
		checks.Store(0)
		rep := run(t, wf(twoSteps), nil, many(2*maxCheckedFixes, func(int) bool { return true }))
		if len(rep.Errors) != 0 {
			t.Fatalf("errors: %+v", rep.Errors[:1])
		}
		for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
			if f.Fix == nil || f.NoFix != nil {
				t.Fatalf("a finding lost its fix: %+v", f.NoFix)
			}
		}
		if n := checks.Load(); n != 2 {
			t.Errorf("the rule ran %d times, want 2: once, and once with the fix", n)
		}
	})
	t.Run("leaves one", func(t *testing.T) {
		rep := run(t, wf(twoSteps), nil, many(3, func(i int) bool { return i != 1 }))
		kept := 0
		for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
			if f.Fix != nil {
				kept++
			}
		}
		// the fix leaves finding 1: it is dropped from that one, as a fix
		// is dropped from each finding it does not close
		if kept != 2 || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Message, "does not close") {
			t.Errorf("fixes kept %d, errors %+v", kept, rep.Errors)
		}
		// a finding whose fixes were all dropped says why
		for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
			if f.Fix == nil && (f.NoFix == nil || f.NoFix.Reason != ir.NoFixReasonManual) {
				t.Errorf("a finding without its fix and without a reason: %+v", f.NoFix)
			}
		}
	})
}

// TestFixBudgetReports: each check of a fix runs the rule again, which
// makes its findings and their evidence and related places again; the
// checks stop when they would make more than maxCheckedReports of them,
// whatever the size of the input.
func TestFixBudgetReports(t *testing.T) {
	for _, c := range []struct {
		name               string
		findings, evidence int
	}{
		{"few reports", 30, 1000},  // 30 030 reports a check: 17 checks
		{"many reports", 60, 9999}, // 600 000 reports a check: none
		{"one each", 300, 0},       // 300 reports a check: the bound of the number of fixes
	} {
		big := make([]Related, c.evidence) // shared: the count is what matters
		found := make([]FindingDraft, c.findings)
		for i := range found {
			found[i] = FindingDraft{Evidence: big, Fix: &Fix{KindID: fixF, Edits: []edit.Edit{{Span: cst.Span{Start: i, End: i}}}}}
		}
		b := newFixBudget(found)
		checked := 0
		for _, f := range found {
			if b.take(f.Fix, 100) {
				checked++
			}
		}
		w := c.findings * (c.evidence + 1)
		if want := min(c.findings, maxCheckedFixes, maxCheckedReports/w); checked != want {
			t.Errorf("%s: %d checked, want %d", c.name, checked, want)
		}
	}
}
