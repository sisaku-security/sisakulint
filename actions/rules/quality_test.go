package rules

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// qualityReport runs the quality rule id alone on src, the workflow
// .github/workflows/w.yml, with r answering the facts (nil: none known).
func qualityReport(t *testing.T, id lint.RuleID, src string, r facts.Resolver) lint.Report {
	t.Helper()
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	all, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := lint.ParseSelector(id.String())
	if err != nil {
		t.Fatal(err)
	}
	reg, err := all.Select(lint.Only(sel), lint.FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		r = &refs{}
	}
	rep := lint.Run(context.Background(), in, reg, r)
	for _, e := range rep.Errors {
		t.Errorf("internal error: %+v", e)
	}
	return rep
}

// qualityKinds are the quality findings of the quality rule id on src, as
// "<kind>: <detected>".
func qualityKinds(t *testing.T, id lint.RuleID, src string) []string {
	t.Helper()
	var out []string
	for _, f := range qualityReport(t, id, src, nil).QualityFindings {
		out = append(out, f.Args.KindID().String()+": "+f.Detected())
	}
	return out
}

// allMetas are the Metas of every rule, then of every quality rule as a
// Meta without a threat (lint.QualityMeta.AsMeta): what the tests of the
// examples and of the kinds read of both.
func allMetas() []lint.Meta {
	var out []lint.Meta
	for _, r := range All() {
		out = append(out, exampledMeta(r))
	}
	for _, q := range Quality() {
		out = append(out, q.(lint.ExampledQualityRule).ExampledQualityMeta().AsMeta())
	}
	return out
}

// runQualityWith runs the quality rule q alone on in, r answering the facts.
func runQualityWith(t *testing.T, q lint.QualityRule, in lint.Inputs, r facts.Resolver) lint.Report {
	t.Helper()
	reg, err := lint.NewRegistry(nil, q)
	if err != nil {
		t.Fatal(err)
	}
	return lint.Run(context.Background(), in, reg, r)
}

// TestExampledQualityRules: every quality rule is a
// lint.ExampledQualityRule whose QualityMeta has no example, as every rule
// is a lint.ExampledRule (TestExampledRules): a start of the command reads
// no example.
func TestExampledQualityRules(t *testing.T) {
	for _, q := range Quality() {
		e, ok := q.(lint.ExampledQualityRule)
		if !ok {
			t.Errorf("%s is not a lint.ExampledQualityRule", q.QualityMeta().ID)
			continue
		}
		e.ExampledQualityMeta()
		m := q.QualityMeta().AsMeta()
		if missing := missingExamples(m); len(missing) != declarations(m) {
			t.Errorf("%s: the QualityMeta has examples: only %v lack one", m.ID, missing)
		}
		if missing := missingExamples(e.ExampledQualityMeta().AsMeta()); len(missing) != 0 {
			t.Errorf("%s: no example for %v", m.ID, missing)
		}
	}
}
