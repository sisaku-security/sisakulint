package lint

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
)

// TestCheckExamplesNoAddedGainInconclusive: the example of an undetected
// form of no-added-gain does not hold when the rule gives an inconclusive
// place on it, as the form says the flaw adds nothing to what an attacker
// gets; the same example of a todo form holds.
func TestCheckExamplesNoAddedGainInconclusive(t *testing.T) {
	step := withCause(exampleOf("l.yml"))
	step.Text = "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n"
	for _, c := range []struct {
		name  string
		d     Disposition
		holds bool
	}{
		{"no-added-gain", NoAddedGain(), false},
		{"todo", Todo(NeedSameFile), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := gapMeta("test")
			m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "l", Disposition: c.d, Examples: []Example{step}}}
			reg, err := NewRegistry([]Rule{everyStepGap(m)})
			if err != nil {
				t.Fatal(err)
			}
			var got []ExampleCheck
			for _, x := range reg.CheckExamples(context.Background()) {
				if x.What == ExampleUndetected {
					got = append(got, x)
				}
			}
			if len(got) != 1 {
				t.Fatalf("undetected checks %+v", got)
			}
			if got[0].Holds != c.holds {
				t.Errorf("holds %v, want %v (why %q)", got[0].Holds, c.holds, got[0].Why)
			}
			if !c.holds && !strings.Contains(got[0].Why, kindG.String()) {
				t.Errorf("why %q does not name the inconclusive kind %s", got[0].Why, kindG)
			}
		})
	}
}

// TestCheckExamplesTrueNegativeText: the text of a true negative's check
// says that the rule reports nothing there, by TrueNegativeText; a true
// positive's is the consequence of its kind.
func TestCheckExamplesTrueNegativeText(t *testing.T) {
	m := ruleOf("a-rule")
	reg, err := NewRegistry([]Rule{testRule{meta: m}})
	if err != nil {
		t.Fatal(err)
	}
	k := m.FindingKinds[0]
	var n int
	for _, x := range reg.CheckExamples(context.Background()) {
		switch x.What {
		case ExampleTrueNegative:
			n++
			if x.Text != TrueNegativeText(k.FindingText) {
				t.Errorf("a true negative: %q, want %q", x.Text, TrueNegativeText(k.FindingText))
			}
		case ExampleTruePositive:
			if x.Text != k.Consequence {
				t.Errorf("a true positive: %q, want the consequence %q", x.Text, k.Consequence)
			}
		}
	}
	if n == 0 {
		t.Fatal("no true negative was checked")
	}
	if got := TrueNegativeText(k.FindingText); !strings.Contains(got, k.ID.String()) || !strings.Contains(got, k.Detected) {
		t.Errorf("TrueNegativeText = %q: want the kind and its detected", got)
	}
}

// TestTrueNegativeTextWithoutArguments: the text of a kind with no
// arguments does not speak of arguments.
func TestTrueNegativeTextWithoutArguments(t *testing.T) {
	k := FindingText{ID: MustFindingKindID("a-rule.said"), Detected: "the job writes"}
	if got := TrueNegativeText(k); strings.Contains(got, "{name}") {
		t.Errorf("TrueNegativeText = %q: a kind without arguments", got)
	}
}

// TestExampleRunFactLines: a line for each fact the run asked, in the
// order of Report.Facts: the answer's value, absent or unknown, and a mark
// on a kind answered the other way.
func TestExampleRunFactLines(t *testing.T) {
	q := func(s string) facts.Query {
		x, err := facts.DecodeQuery([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	run := ExampleRun{Flipped: []facts.Kind{facts.KindRepoWikiOpen}, Report: Report{Facts: []facts.Entry{
		{Query: q(`{"kind": "repo.default-token-write"}`), RawAnswer: facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}},
		{Query: q(`{"kind": "action.runs-using", "repo": "actions/checkout", "ref": "v4"}`), RawAnswer: facts.RawAnswer{State: facts.StateFound, Value: []byte(`"node24"`)}},
		{Query: q(`{"kind": "repo.wiki-open"}`), RawAnswer: facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}},
		{Query: q(`{"kind": "repo.archived", "repo": "o/r"}`), RawAnswer: facts.RawAnswer{State: facts.StateAbsent}},
		{Query: q(`{"kind": "repo.public"}`), RawAnswer: facts.RawAnswer{State: facts.StateUnknown, Reason: "the example does not answer it"}},
	}}}
	want := []string{
		"repo.default-token-write = true",
		`action.runs-using repo=actions/checkout ref=v4 = "node24"`,
		"repo.wiki-open = false (the answer that removes the finding)",
		"repo.archived repo=o/r = absent",
		"repo.public = unknown",
	}
	if got := run.FactLines(); !slices.Equal(got, want) {
		t.Errorf("FactLines =\n%q\nwant\n%q", got, want)
	}
	if got := (ExampleRun{}).FactLines(); got == nil || len(got) != 0 {
		t.Errorf("FactLines of no facts = %#v, want an empty slice", got)
	}
}

// TestTrueNegativeTextShared: the text of a true negative of several kinds
// says what a finding of each would say, after the same head.
func TestTrueNegativeTextShared(t *testing.T) {
	a := FindingText{ID: MustFindingKindID("r.a"), Detected: "A is so"}
	b := FindingText{ID: MustFindingKindID("r.b"), Detected: "B is so"}
	want := "the rule reports no finding on the input of the example; a finding of r.a would say: A is so; a finding of r.b would say: B is so"
	if got := TrueNegativeText(a, b); got != want {
		t.Errorf("TrueNegativeText = %q, want %q", got, want)
	}
}

// TestCheckExamplesUndetectedKinds: the example of an undetected form with
// FindingKinds holds when the rule reports no finding of those kinds on
// it, though it reports a finding of another of its kinds; the example of
// a form without FindingKinds holds only when the rule reports nothing.
func TestCheckExamplesUndetectedKinds(t *testing.T) {
	step := withCause(exampleOf("l.yml"))
	step.Text = "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n"
	for _, c := range []struct {
		name  string
		kinds []FindingKindID
		holds bool
	}{
		{"another kind reported", []FindingKindID{otherKind}, true},
		{"the kind reported", []FindingKindID{saidKind}, false},
		{"every kind", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := meta("test")
			m.FindingKinds = append(m.FindingKinds, saidOf(otherKind))
			m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "l", FindingKinds: c.kinds, Disposition: Todo(NeedFact), Examples: []Example{step}}}
			reg, err := NewRegistry([]Rule{testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
				for _, s := range steps(c) {
					c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base)})
				}
				return nil
			}}})
			if err != nil {
				t.Fatal(err)
			}
			var got []ExampleCheck
			for _, x := range reg.CheckExamples(context.Background()) {
				if x.What == ExampleUndetected {
					got = append(got, x)
				}
			}
			if len(got) != 1 {
				t.Fatalf("undetected checks %+v", got)
			}
			if got[0].Holds != c.holds {
				t.Errorf("holds %v, want %v (why %q)", got[0].Holds, c.holds, got[0].Why)
			}
		})
	}
}

// TestCheckExamplesEachOfADeclaration: each example of a declaration has
// its own check, in the order of Examples, and is held to the declaration
// alone.
func TestCheckExamplesEachOfADeclaration(t *testing.T) {
	step := withCause(exampleOf("l.yml"))
	step.Text = "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n"
	other := withCause(exampleOf("l.label.yml"))
	other.Text = step.Text
	m := gapMeta("test")
	m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "l", Disposition: NoAddedGain(), Examples: []Example{step, other}}}
	m.InconclusiveKinds[0].Examples = append(m.InconclusiveKinds[0].Examples, other)
	reg, err := NewRegistry([]Rule{everyStepGap(m)})
	if err != nil {
		t.Fatal(err)
	}
	got := map[ExampleWhat][]string{}
	for _, x := range reg.CheckExamples(context.Background()) {
		got[x.What] = append(got[x.What], x.Example.Name.String())
		if x.What == ExampleUndetected && x.Holds {
			t.Errorf("%s holds; an inconclusive place is on it", x.Example.Name)
		}
		if x.What == ExampleInconclusive && x.Example.Name.String() == "l.label.yml" && !x.Holds {
			t.Errorf("%s: %s", x.Example.Name, x.Why)
		}
	}
	if !slices.Equal(got[ExampleUndetected], []string{"l.yml", "l.label.yml"}) || len(got[ExampleInconclusive]) != 2 || got[ExampleInconclusive][1] != "l.label.yml" {
		t.Errorf("checks %v", got)
	}
}

// TestCheckExamplesAddedTruePositive: a true positive whose notes name an
// added attacker holds when the run that adds no attacker reports no
// finding of the rule on it, and the run that adds the attacker alone
// reports a finding of its kind marked with the attacker; it does not
// hold when the run that adds no attacker reports one, or when the added
// run reports none.
func TestCheckExamplesAddedTruePositive(t *testing.T) {
	for _, c := range []struct {
		name  string
		when  func(analysis.BarrierPasses) bool
		holds bool
		why   string
	}{
		{"only with the attacker added", func(g analysis.BarrierPasses) bool { return g.Passes(analysis.BarrierAssociationMember) }, true, ""},
		{"also with no attacker added", func(analysis.BarrierPasses) bool { return true }, false, "adds no attacker"},
		{"never", func(analysis.BarrierPasses) bool { return false }, false, "adding read-member"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := meta("added")
			e := m.FindingKinds[0].TruePositives[0]
			e.Notes.AddedAttackers = []AddedAttacker{AddedAttackerReadMember}
			m.FindingKinds[0].TruePositives = []Example{e}
			rule := testRule{meta: m, check: func(_ context.Context, rc *RuleContext) error {
				if c.when(rc.Barriers()) {
					rc.Report(FindingDraft{Args: said("x"), Location: At(rc.input, rc.workflow.Base)})
				}
				return nil
			}}
			reg, err := newRegistry([]Rule{rule}, true)
			if err != nil {
				t.Fatal(err)
			}
			reg = reg.WithBarriers(addedBarriers)
			var got []ExampleCheck
			for _, x := range reg.CheckExamples(context.Background()) {
				if x.What == ExampleTruePositive {
					got = append(got, x)
				}
			}
			if len(got) != 1 {
				t.Fatalf("true positive checks %+v", got)
			}
			if got[0].Holds != c.holds || !strings.Contains(got[0].Why, c.why) {
				t.Errorf("holds %v (why %q), want %v (why with %q)", got[0].Holds, got[0].Why, c.holds, c.why)
			}
			if c.holds && (len(got[0].Runs) != 2 || got[0].Runs[0].Added != nil || !slices.Equal(got[0].Runs[1].Added, []AddedAttacker{AddedAttackerReadMember})) {
				t.Errorf("runs %+v, want the run that adds none and the run that adds read-member", got[0].Runs)
			}
		})
	}
}

// TestAddedTruePositiveJSONAndExplain: the JSON of the registry gives the
// added attackers of a true positive whose notes name them, in each form,
// and none of an example without them; --explain writes them under the
// example.
func TestAddedTruePositiveJSONAndExplain(t *testing.T) {
	m := meta("added")
	e := m.FindingKinds[0].TruePositives[0]
	e.Notes.AddedAttackers = []AddedAttacker{AddedAttackerReadMember}
	m.FindingKinds[0].TruePositives = []Example{e}
	reg, err := newRegistry([]Rule{testRule{meta: m}}, true)
	if err != nil {
		t.Fatal(err)
	}
	for name, marshal := range map[string]func() ([]byte, error){"default": reg.MarshalJSON, "full": reg.MarshalJSONFull} {
		b, err := marshal()
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(b), `"added_attackers":["read-member"]`); n != 1 {
			t.Errorf("%s: %d examples with the added attackers, want 1", name, n)
		}
	}
	out, err := reg.Explain(nil, "c")
	if err != nil {
		t.Fatal(err)
	}
	if want := nAddedAttackers.is("read-member"); !strings.Contains(string(out), want) {
		t.Errorf("no %q in\n%s", want, out)
	}
}

// TestExplainAddedFindingFiles: under a true positive of several files
// whose notes name an added attacker, --explain gives the files of the
// findings of the run that adds the attacker; the run that adds none has
// none.
func TestExplainAddedFindingFiles(t *testing.T) {
	m := meta("added")
	e := m.FindingKinds[0].TruePositives[0]
	e.Name = facts.MustCleanInputPath(".github/workflows/main.yml")
	e.Others = []ExampleFile{{InputKind: InputKindWorkflow, Name: facts.MustCleanInputPath(".github/workflows/other.yml"), Text: "on: push\n"}}
	e.Notes.AddedAttackers = []AddedAttacker{AddedAttackerReadMember}
	m.FindingKinds[0].TruePositives = []Example{e}
	rule := testRule{meta: m, check: func(_ context.Context, rc *RuleContext) error {
		if rc.Barriers().Passes(analysis.BarrierAssociationMember) {
			rc.Report(FindingDraft{Args: said("x"), Location: At(rc.input, rc.workflow.Base)})
		}
		return nil
	}}
	reg, err := newRegistry([]Rule{rule}, true)
	if err != nil {
		t.Fatal(err)
	}
	reg = reg.WithBarriers(addedBarriers)
	out, err := reg.Explain(nil, "c")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), nFindingOn.is(md(".github/workflows/main.yml")+", "+md(".github/workflows/other.yml"))) {
		t.Errorf("no %q line in\n%s", nFindingOn.name, out)
	}
}
