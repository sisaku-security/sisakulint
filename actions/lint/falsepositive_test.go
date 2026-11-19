package lint

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// exampleOf is an example of a workflow named name, for the tests.
func exampleOf(name string) Example {
	return Example{InputKind: InputKindWorkflow, Name: facts.MustCleanInputPath(name), Text: "on: push\n", Notes: ExampleNotes{Situation: "s", Reason: "r", Attack: "a", AttackRunBehavior: "b"}}
}

// withCause is e with the cause a false positive form's or an undetected
// form's example needs.
func withCause(e Example) Example {
	e.Notes.Cause = "c"
	return e
}

// examplesTargeting gives the examples of m's kinds the first of m.Targets: for a
// rule of the tests that reads no workflow.
func examplesTargeting(m Meta) Meta {
	m.FindingKinds = slices.Clone(m.FindingKinds)
	for i, k := range m.FindingKinds {
		for _, es := range [][]Example{k.TruePositives, k.TrueNegatives} {
			for j := range es {
				es[j].InputKind = m.Targets[0]
			}
		}
		m.FindingKinds[i] = k
	}
	return m
}

// TestFalsePositiveFormChecks: NewRegistry takes a false positive form
// with a Disposition of a limitation or a todo, or with FactKinds of an
// assumed boolean value, and refuses the rest.
func TestFalsePositiveFormChecks(t *testing.T) {
	kind := ruleOf("a-rule").FindingKinds[0].ID
	form := func(f func(*FalsePositiveForm)) Meta {
		m := ruleOf("a-rule")
		fp := FalsePositiveForm{ID: MustFalsePositiveFormID("if-guard"), Text: "an if that stops it", FindingKinds: []FindingKindID{kind}, Disposition: Todo(NeedSameFile), Examples: []Example{withCause(exampleOf("if-guard.yml"))}}
		f(&fp)
		m.FalsePositiveForms = []FalsePositiveForm{fp}
		return m
	}
	for _, c := range []struct {
		name string
		m    Meta
		err  string // "" for none
	}{
		{"todo", form(func(*FalsePositiveForm) {}), ""},
		{"limitation", form(func(f *FalsePositiveForm) { f.Disposition = Limitation(DeciderRunTime) }), ""},
		{"fact kinds", form(func(f *FalsePositiveForm) {
			f.Disposition = Disposition{}
			f.FactKinds = []facts.Kind{facts.KindRepoPublic}
		}), ""},
		{"both", form(func(f *FalsePositiveForm) { f.FactKinds = []facts.Kind{facts.KindRepoPublic} }), "one of"},
		{"neither", form(func(f *FalsePositiveForm) { f.Disposition = Disposition{} }), "one of"},
		{"no-added-gain", form(func(f *FalsePositiveForm) { f.Disposition = NoAddedGain() }), "limitation or a todo"},
		{"other-rule", form(func(f *FalsePositiveForm) { f.Disposition = OtherRule(MustRuleID("b-rule")) }), "limitation or a todo"},
		{"no assumed value", form(func(f *FalsePositiveForm) {
			f.Disposition = Disposition{}
			f.FactKinds = []facts.Kind{facts.KindGitRefCommit}
		}), "assumed boolean"},
		{"fact kind twice", form(func(f *FalsePositiveForm) {
			f.Disposition = Disposition{}
			f.FactKinds = []facts.Kind{facts.KindRepoPublic, facts.KindRepoPublic}
		}), "twice"},
		{"no kind", form(func(f *FalsePositiveForm) { f.FindingKinds = nil }), "names no kind"},
		{"another rule's kind", form(func(f *FalsePositiveForm) { f.FindingKinds = []FindingKindID{MustFindingKindID("b-rule.said")} }), "not a kind of the rule"},
		{"kind twice", form(func(f *FalsePositiveForm) { f.FindingKinds = []FindingKindID{kind, kind} }), "twice"},
		{"no text", form(func(f *FalsePositiveForm) { f.Text = " " }), "an ID and a Text"},
		{"no ID", form(func(f *FalsePositiveForm) { f.ID = FalsePositiveFormID{} }), "an ID and a Text"},
		{"line break", form(func(f *FalsePositiveForm) { f.Text = "a\nb" }), "line break"},
		{"example of another input kind", form(func(f *FalsePositiveForm) { f.Examples[0].InputKind = InputKindActionMetadata }), "not a target"},
		{"example without text", form(func(f *FalsePositiveForm) { f.Examples[0].Text = "" }), "no text"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewRegistry([]Rule{testRule{meta: c.m}})
			switch {
			case c.err == "" && err != nil:
				t.Errorf("refused: %v", err)
			case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
				t.Errorf("err = %v, want one that says %q", err, c.err)
			}
		})
	}
	two := form(func(*FalsePositiveForm) {})
	two.FalsePositiveForms = append(two.FalsePositiveForms, two.FalsePositiveForms[0])
	if _, err := NewRegistry([]Rule{testRule{meta: two}}); err == nil || !strings.Contains(err.Error(), "declared twice") {
		t.Errorf("a form declared twice: %v", err)
	}
}

// TestUndetectedFormKindChecks: NewRegistry takes an undetected form that
// names some of the kinds of the rule, each once, and refuses one that
// names another rule's kind, a kind twice, or every kind of the rule
// (which is a form without FindingKinds).
func TestUndetectedFormKindChecks(t *testing.T) {
	kind := ruleOf("a-rule").FindingKinds[0].ID
	second := saidOf(MustFindingKindID("a-rule.other"))
	form := func(kinds ...FindingKindID) Meta {
		m := ruleOf("a-rule")
		m.FindingKinds = append(m.FindingKinds, second)
		m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "l", FindingKinds: kinds, Disposition: Todo(NeedFact), Examples: []Example{withCause(exampleOf("l.yml"))}}}
		return m
	}
	for _, c := range []struct {
		name string
		m    Meta
		err  string // "" for none
	}{
		{"none", form(), ""},
		{"one kind", form(kind), ""},
		{"another rule's kind", form(MustFindingKindID("b-rule.said")), "not a kind of the rule"},
		{"kind twice", form(kind, kind), "twice"},
		{"every kind", form(kind, second.ID), "every kind"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewRegistry([]Rule{testRule{meta: c.m}})
			switch {
			case c.err == "" && err != nil:
				t.Errorf("refused: %v", err)
			case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
				t.Errorf("err = %v, want one that says %q", err, c.err)
			}
		})
	}
}

// TestExampleChecks: an example given to a kind of finding, an undetected
// form or an inconclusive kind is of an input kind the rule targets, with a
// name and a text; the zero Example is taken while examples are not
// required.
func TestExampleChecks(t *testing.T) {
	ok := ruleOf("a-rule")
	ok.FindingKinds[0].TruePositives = []Example{exampleOf("said.yml")}
	ok.FindingKinds[0].TrueNegatives = []Example{exampleOf("said.yml")}
	ok.UndetectedForms = []UndetectedForm{{ID: formL, Text: "l", Disposition: Todo(NeedFact), Examples: []Example{withCause(exampleOf("l.yml"))}}}
	ok.InconclusiveKinds = []InconclusiveKind{{ID: kindG, Text: "g", Disposition: Todo(NeedFact), Examples: []Example{exampleOf("g.yml")}}}
	if _, err := NewRegistry([]Rule{testRule{meta: ok}}); err != nil {
		t.Fatalf("refused: %v", err)
	}
	bad := ruleOf("a-rule")
	e := exampleOf("said.yml")
	e.InputKind = InputKindActionMetadata
	bad.FindingKinds[0].TruePositives = []Example{e}
	if _, err := NewRegistry([]Rule{testRule{meta: bad}}); err == nil || !strings.Contains(err.Error(), "not a target") {
		t.Errorf("an example of an input kind the rule does not target: %v", err)
	}
	none := ruleOf("a-rule")
	none.FindingKinds[0].TruePositives = nil
	if err := checkExamples(none, true, false); err == nil || !strings.Contains(err.Error(), "no true positive") {
		t.Errorf("required, a kind without examples: %v", err)
	}
}

// TestExampleOthers: an example of several files has the others in the
// registry's JSON, which fits $defs/example, and each other has a name and
// a text.
func TestExampleOthers(t *testing.T) {
	m := ruleOf("a-rule")
	e := exampleOf(".github/workflows/called.yml")
	e.Others = []ExampleFile{{InputKind: InputKindWorkflow, Name: facts.MustCleanInputPath(".github/workflows/ci.yml"), Text: "on: push\n"}}
	m.FindingKinds[0].TruePositives = []Example{e}
	reg, err := NewRegistry([]Rule{testRule{meta: m}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"others":[{"input_kind":"workflow","name":".github/workflows/ci.yml","text":"on: push\n"}]`) {
		t.Fatalf("no others in %s", b)
	}
	if err := schemas(t).Validate("registry-v0.json", "#", b); err != nil {
		t.Fatalf("the registry does not fit its schema: %v", err)
	}
	e.Others[0].Text = ""
	m.FindingKinds[0].TruePositives = []Example{e}
	if _, err := NewRegistry([]Rule{testRule{meta: m}}); err == nil || !strings.Contains(err.Error(), "no name or no text") {
		t.Errorf("an other file without a text: %v", err)
	}
}
