package lint

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// exampledRule is a rule of the tests whose examples are read apart from
// its Meta (ExampledRule); reads counts the calls of ExampledMeta.
type exampledRule struct {
	testRule
	full  Meta
	reads *int
}

func (r exampledRule) ExampledMeta() Meta {
	*r.reads++
	return r.full
}

// formsMeta is meta("test") with an undetected form and an inconclusive
// kind, each with its example.
func formsMeta() Meta {
	m := meta("test")
	m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "l", Disposition: Todo(NeedFact), Examples: []Example{withCause(exampleOf("l.yml"))}}}
	m.InconclusiveKinds = []InconclusiveKind{{ID: kindG, Text: "g", Disposition: Todo(NeedFact), Examples: []Example{exampleOf("g.yml")}}}
	return m
}

// exampledOf is a rule that reports every step, whose Meta is full
// without examples and whose ExampledMeta is full, and the count of its
// reads.
func exampledOf(full Meta) (exampledRule, *int) {
	reads := new(int)
	r := everyStep(full.withoutExamples(), func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base)}
	}).(testRule)
	return exampledRule{r, full, reads}, reads
}

// TestExampledRuleRun: making a registry, selecting from it, running it,
// Registry.Meta and MetaJSON read no example of an ExampledRule;
// MarshalJSON, MarshalJSONFull, Explain and CheckExamples read them, and
// show what they show of a rule whose Meta has them.
func TestExampledRuleRun(t *testing.T) {
	full := formsMeta()
	r, reads := exampledOf(full)
	reg, err := NewRegistry([]Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	one, err := reg.Select(Only(Selector{full.ID}), FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	in, err := Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n")}})
	if err != nil {
		t.Fatal(err)
	}
	if rep := Run(context.Background(), in, one, mapResolver{}); len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 {
		t.Fatalf("findings %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional))
	}
	if _, err := reg.MetaJSON(); err != nil {
		t.Fatal(err)
	}
	if m, _ := reg.Meta(full.ID); !reflect.DeepEqual(m, full.withoutExamples()) {
		t.Errorf("Registry.Meta of an ExampledRule is not its Meta without examples: %+v", m)
	}
	if *reads != 0 {
		t.Fatalf("ExampledMeta read %d times before anything showed the examples", *reads)
	}
	plain, err := NewRegistry([]Rule{testRule{meta: full}})
	if err != nil {
		t.Fatal(err)
	}
	for _, show := range []func(*Registry) ([]byte, error){
		(*Registry).MarshalJSON,
		(*Registry).MarshalJSONFull,
		func(r *Registry) ([]byte, error) { return r.Explain(nil, "c") },
	} {
		got, err := show(one)
		if err != nil {
			t.Fatal(err)
		}
		want, err := show(plain)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("an ExampledRule shows\n%s\nnot\n%s", got, want)
		}
	}
	if checks := one.CheckExamples(context.Background()); len(checks) == 0 {
		t.Error("CheckExamples checked no example")
	}
	if *reads == 0 {
		t.Error("nothing read ExampledMeta")
	}
}

// TestExampledRuleOnly: Explain and CheckExamples of another rule read no
// example of an ExampledRule.
func TestExampledRuleOnly(t *testing.T) {
	a, reads := exampledOf(meta("test"))
	b := testRule{meta: ruleOf("b-rule")}
	reg, err := NewRegistry([]Rule{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Explain([]RuleID{b.meta.ID}, "c"); err != nil {
		t.Fatal(err)
	}
	reg.CheckExamples(context.Background(), b.meta.ID)
	if *reads != 0 {
		t.Errorf("ExampledMeta read %d times for another rule", *reads)
	}
}

// TestExampledRuleChecked: the registry checks the examples of an
// ExampledRule when it shows them, not before: MarshalJSON and Explain
// give the error, CheckExamples panics with it. An ExampledMeta that is
// not the Meta with examples (of another ID, or another text: a type that
// embeds the rule and changes its Meta) is an error.
func TestExampledRuleChecked(t *testing.T) {
	noTP := meta("test")
	noTP.FindingKinds = slices.Clone(noTP.FindingKinds)
	noTP.FindingKinds[0].TruePositives = nil
	otherID := meta("test")
	otherID.ID = MustRuleID("b-rule")
	otherText := meta("test")
	otherText.Problem = "another problem"
	for name, full := range map[string]Meta{"no true positive": noTP, "another ID": otherID, "another text": otherText} {
		t.Run(name, func(t *testing.T) {
			r, _ := exampledOf(full)
			r.testRule.meta = meta("test").withoutExamples()
			reg, err := NewRegistry([]Rule{r})
			if err != nil {
				t.Fatalf("NewRegistry checked the examples of an ExampledRule: %v", err)
			}
			if _, err := reg.MarshalJSON(); err == nil {
				t.Error("MarshalJSON took the examples")
			}
			if _, err := reg.Explain(nil, "c"); err == nil {
				t.Error("Explain took the examples")
			}
			defer func() {
				if recover() == nil {
					t.Error("CheckExamples took the examples")
				}
			}()
			reg.CheckExamples(context.Background())
		})
	}
}
