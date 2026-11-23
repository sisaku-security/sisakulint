package lint

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"
)

func TestFixInput(t *testing.T) {
	fsys := fstest.MapFS{
		wfPath:                        {Data: []byte(twoSteps)},
		".github/workflows/clean.yml": {Data: []byte("on: push\njobs: {}\n")},
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := newRegistry([]Rule{marker("mark", "m", SafetySafe)}, true)
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), in, reg, mapResolver{})
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) == 0 {
		t.Fatal("no finding")
	}
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		got, ok := f.FixInput(in)
		if !ok || got.Name.String() != wfPath {
			t.Errorf("FixInput = %s, %t; want %s", got.Name, ok, wfPath)
		}
		other := in
		other.List = nil
		if _, ok := f.FixInput(other); ok {
			t.Error("FixInput finds an input among none")
		}
		f.Fix = nil
		if _, ok := f.FixInput(in); ok {
			t.Error("FixInput of a finding without a fix is true")
		}
	}
	if _, ok := (Finding{FindingDraft: FindingDraft{Fix: &Fix{}}}).FixInput(in); ok {
		t.Error("FixInput of a Finding not made by Run is true")
	}
}

// TestExplainRule: the section of a rule or a quality rule in Explain
// without its examples and without the head of the document, what a review
// document of the rule is; a rule not registered is an error.
func TestExplainRule(t *testing.T) {
	m := ruleOf("a-rule")
	m.UndetectedForms = []UndetectedForm{{ID: MustUndetectedFormID("o"), Text: "not an attack*", Disposition: NoAddedGain(), Examples: []Example{withCause(exampleOf("o.yml"))}}}
	reg, err := newRegistry([]Rule{testRule{meta: m}}, false, testQuality{m: goodQualityMeta()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.ExplainRule(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.HasPrefix(got, "## a-rule\n\n- problem: a rule a-rule detects\n") {
		t.Errorf("ExplainRule starts\n%s", got)
	}
	for _, no := range []string{"commit:", "terms:", "true positives:", "true negatives:", "example:", "```", "o.yml"} {
		if strings.Contains(got, no) {
			t.Errorf("ExplainRule has %q:\n%s", no, got)
		}
	}
	for _, want := range []string{"### undetected forms\n\n- o: not an attack\\*\n  - finding kinds: a-rule.said\n  - disposition: no-added-gain\n\n### threat", "  - preconditions: p\n\n### undetected forms", "### citations\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("no\n%s\nin\n%s", want, got)
		}
	}
	q, err := reg.ExplainRule(MustRuleID("test"))
	if err != nil {
		t.Fatal(err)
	}
	if s := string(q); !strings.HasPrefix(s, "## test\n") || !strings.Contains(s, "- quality rule: ") {
		t.Errorf("ExplainRule of the quality rule:\n%s", s)
	}
	for _, no := range []string{"commit:", "terms:", "true positives:", "true negatives:", "example:", "```"} {
		if strings.Contains(string(q), no) {
			t.Errorf("ExplainRule of the quality rule has %q:\n%s", no, q)
		}
	}
	if _, err := reg.ExplainRule(MustRuleID("no-rule")); err == nil {
		t.Error("ExplainRule(no-rule) is no error")
	}
}
