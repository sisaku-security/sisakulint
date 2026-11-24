package rules

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// exampleDir is the example that gives every kind of finding of every rule,
// and fixes of several rules in one step (the README of the all-rules example says how to run it).
var exampleDir = filepath.Join("testdata", "all-rules")

// TestAllRulesExample keeps the example up to date: run with its file of
// facts, as the CLI answers, and again with the repository private, its
// readers forking it and the workflows of pull requests from forks
// running (privateRepo), the two runs give every kind of finding of All,
// each confirmed or conditional (a finding whose condition depends on a
// fact the file does not answer is conditional).
// A rule or a kind added without the example fails here. Every finding of
// a kind that declares fixes has a fix, and the fixes to review apply
// together: the fixes of rules that report in one step do not collide.
func TestAllRulesExample(t *testing.T) {
	in, err := lint.Enumerate(os.DirFS(exampleDir))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(exampleDir, "facts.json"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := facts.LoadStore(b)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i, r := range []facts.Resolver{store, privateRepo{store}} {
		rep := lint.Run(context.Background(), in, reg, r)
		if len(rep.Errors) != 0 {
			t.Fatalf("errors %+v", rep.Errors)
		}
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			got = append(got, f.Args.KindID().String())
			m, _ := reg.Meta(f.Rule)
			k := slices.IndexFunc(m.FindingKinds, func(k lint.FindingKind) bool { return k.ID == f.Args.KindID() })
			if k < 0 {
				t.Fatalf("%s is of a kind its rule does not declare", f.Detected())
			}
			if f.Fix == nil && len(m.FindingKinds[k].Fixes) > 0 {
				t.Errorf("%s has no fix, and its kind declares fixes", f.Detected())
			}
		}
		for _, f := range rep.QualityFindings {
			got = append(got, f.Args.KindID().String())
		}
		if i > 0 {
			continue
		}
		if _, err := lint.ApplyFixes(context.Background(), in, reg, r, rep, lint.SafetyReview); err != nil {
			t.Errorf("the fixes to review do not apply together: %v", err)
		}
	}
	for _, k := range allFindingKinds {
		if !slices.Contains(got, k.String()) {
			t.Errorf("the example gives no finding of %s", k)
		}
	}
}

// privateRepo answers a private repository that its readers fork and that
// runs the workflows of pull requests from forks, as --fact
// repo.public=false --fact repo.allow-forking=true --fact
// repo.fork-pr-run-workflows=true, and the rest as r.
type privateRepo struct{ r facts.Resolver }

func (p privateRepo) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	switch q.(type) {
	case facts.RepoPublic:
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}
	case facts.RepoAllowForking, facts.RepoForkPRRunWorkflows:
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
	}
	return p.r.Resolve(ctx, q)
}
