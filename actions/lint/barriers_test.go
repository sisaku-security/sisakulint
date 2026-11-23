package lint

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
)

// barrierRecorder is a rule that records the barriers each check reads,
// and whether the check was of a remote called workflow.
func barrierRecorder(seen *[]analysis.BarrierPasses, remote *int) Rule {
	return testRule{meta: meta("barriers"), check: func(_ context.Context, c *RuleContext) error {
		*seen = append(*seen, c.Barriers())
		if c.remoteQuery != nil {
			*remote++
		}
		return nil
	}}
}

// barrierInputs are a workflow that calls a reusable workflow of another
// repository, and the answer of the reusable workflow.
func barrierInputs(t *testing.T) (Inputs, facts.Resolver) {
	t.Helper()
	in, err := Enumerate(fstest.MapFS{".github/workflows/ci.yml": {Data: []byte("on: pull_request_target\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n    with:\n      t: ${{ github.event.pull_request.title }}\n")}})
	if err != nil {
		t.Fatal(err)
	}
	in.Repo = mustRepo("me/app")
	return in, workflowAnswers{"o/wf/.github/workflows/w.yml": remoteEcho}
}

// TestBarriersReachRules: the barriers a run lets its attacker past reach
// each rule, on the input and on the remote called workflow; a run that
// adds no attacker passes none.
func TestBarriersReachRules(t *testing.T) {
	g := analysis.BarrierPasses{}.With(analysis.BarrierAgentGate)
	for _, c := range []struct {
		name string
		run  func(context.Context, Inputs, *Registry, facts.Resolver) Report
		want analysis.BarrierPasses
	}{
		{"Run", Run, analysis.BarrierPasses{}},
		{"RunWithBarriers", func(ctx context.Context, in Inputs, reg *Registry, r facts.Resolver) Report {
			return RunWithBarriers(ctx, in, reg, r, g)
		}, g},
	} {
		var seen []analysis.BarrierPasses
		remote := 0
		reg, err := newRegistry([]Rule{barrierRecorder(&seen, &remote)}, true)
		if err != nil {
			t.Fatal(err)
		}
		in, r := barrierInputs(t)
		c.run(context.Background(), in, reg, r)
		if len(seen) < 2 || remote == 0 {
			t.Fatalf("%s: %d checks, %d of a remote called workflow", c.name, len(seen), remote)
		}
		for _, p := range seen {
			if p != c.want {
				t.Errorf("%s: a check read %q, want %q", c.name, p, c.want)
			}
		}
	}
}

// TestRegistryBarriersOf: a registry reads the barriers of added attackers
// from what WithBarriers gives it, and Select keeps it; a registry without
// it passes none for no added attacker.
func TestRegistryBarriersOf(t *testing.T) {
	reg, err := newRegistry([]Rule{testRule{meta: meta("a-rule")}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if p := reg.barriersOf(nil); !p.IsZero() {
		t.Errorf("no added attacker: %s", p)
	}
	want := analysis.BarrierPasses{}.With(analysis.BarrierLabelApproval)
	reg = reg.WithBarriers(func(vs []AddedAttacker) analysis.BarrierPasses {
		if len(vs) == 1 && vs[0] == AddedAttackerTriageAccount {
			return want
		}
		return analysis.BarrierPasses{}
	})
	sel, err := reg.Select(Selection{}, FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []*Registry{reg, sel} {
		if p := r.barriersOf([]AddedAttacker{AddedAttackerTriageAccount}); p != want {
			t.Errorf("barriersOf(triage-account) = %s, want %s", p, want)
		}
	}
}

// TestOutsiderRulesSkipped: a run whose attacker gets past a barrier does
// not run the rules that read an attacker outside the repository alone;
// a run that adds no attacker runs them.
func TestOutsiderRulesSkipped(t *testing.T) {
	ran := 0
	outsider := testRule{meta: meta("outsider"), check: func(context.Context, *RuleContext) error { ran++; return nil }}
	reg, err := newRegistry([]Rule{outsider}, true)
	if err != nil {
		t.Fatal(err)
	}
	reg = reg.WithBarriers(func([]AddedAttacker) analysis.BarrierPasses { return analysis.BarrierPasses{} }, MustRuleID("outsider"))
	in, r := barrierInputs(t)
	RunWithBarriers(context.Background(), in, reg, r, analysis.BarrierPasses{}.With(analysis.BarrierAgentGate))
	if ran != 0 {
		t.Errorf("the rule ran %d times in a run with barriers", ran)
	}
	Run(context.Background(), in, reg, r)
	if ran == 0 {
		t.Error("the rule did not run in a run without barriers")
	}
}
