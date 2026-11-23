package lint

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
)

// barrierRule reports, at the workflow, a finding for each anchor whose
// barriers the attacker of the run gets past: base always; gone only when
// the run adds none; member past BarrierAssociationMember; label past
// BarrierLabelApproval; both past the two; either past one of the two;
// env on the condition test.flag env, which BarrierEnvironmentApproval
// drops.
func barrierRule() Rule {
	m := asking(meta("barrier"), facts.KindTestFlag)
	env, _ := FactEq(facts.TestFlag{Name: "env"}, true)
	return testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		g := c.Barriers()
		report := func(anchor string, cond *Condition) {
			c.Report(FindingDraft{Args: said(anchor), Location: At(c.input, c.workflow.Base), Anchor: anchor, Condition: cond})
		}
		report("base", nil)
		if g.IsZero() {
			report("gone", nil)
		}
		if g.Passes(analysis.BarrierAssociationMember) {
			report("member", nil)
		}
		if g.Passes(analysis.BarrierLabelApproval) {
			report("label", nil)
		}
		if g.Passes(analysis.BarrierAssociationMember) && g.Passes(analysis.BarrierLabelApproval) {
			report("both", nil)
		}
		if g.Passes(analysis.BarrierAssociationMember) || g.Passes(analysis.BarrierLabelApproval) {
			report("either", nil)
		}
		if g.Passes(analysis.BarrierEnvironmentApproval) {
			report("env", nil)
		} else {
			report("env", &env)
		}
		return nil
	}}
}

// addedBarriers are the barriers of the added attackers of the tests.
func addedBarriers(vs []AddedAttacker) analysis.BarrierPasses {
	var p analysis.BarrierPasses
	for _, v := range vs {
		switch v {
		case AddedAttackerReadMember:
			p = p.With(analysis.BarrierAssociationMember)
		case AddedAttackerTriageAccount:
			p = p.With(analysis.BarrierLabelApproval)
		case AddedAttackerRequiredReviewer:
			p = p.With(analysis.BarrierEnvironmentApproval)
		}
	}
	return p
}

// runAdded runs barrierRule on one workflow, adding vs, and gives the
// findings by anchor.
func runAdded(t *testing.T, vs ...AddedAttacker) (Report, map[string][]Finding) {
	t.Helper()
	reg, err := newRegistry([]Rule{barrierRule()}, true)
	if err != nil {
		t.Fatal(err)
	}
	reg = reg.WithBarriers(addedBarriers)
	in, r := barrierInputs(t)
	rep := RunAdded(context.Background(), in, reg, r, vs)
	by := map[string][]Finding{}
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		if f.Rule.String() == "barrier" {
			by[f.Anchor] = append(by[f.Anchor], f)
		}
	}
	return rep, by
}

func wantMarks(t *testing.T, by map[string][]Finding, anchor string, want ...AddedAttacker) {
	t.Helper()
	fs := by[anchor]
	if len(fs) != 1 {
		t.Fatalf("%s: %d findings, want 1", anchor, len(fs))
	}
	if !slices.Equal(fs[0].AddedAttackers, want) {
		t.Errorf("%s: added attackers %v, want %v", anchor, fs[0].AddedAttackers, want)
	}
}

// TestAddedOneValue: a place that one added attacker alone gives is
// marked with it; the places of the run that adds none are not marked.
func TestAddedOneValue(t *testing.T) {
	rep, by := runAdded(t, AddedAttackerReadMember)
	wantMarks(t, by, "member", AddedAttackerReadMember)
	wantMarks(t, by, "base")
	if !slices.Equal(rep.AddedAttackers, []AddedAttacker{AddedAttackerReadMember}) {
		t.Errorf("the report's added attackers: %v", rep.AddedAttackers)
	}
}

// TestAddedTwoValues: the places of each value are marked with it, a
// place that each of the two alone gives with both, and a place only the
// two together give is not reported: each value is a separate attacker.
func TestAddedTwoValues(t *testing.T) {
	rep, by := runAdded(t, AddedAttackerTriageAccount, AddedAttackerReadMember)
	wantMarks(t, by, "member", AddedAttackerReadMember)
	wantMarks(t, by, "label", AddedAttackerTriageAccount)
	wantMarks(t, by, "either", AddedAttackerReadMember, AddedAttackerTriageAccount)
	if fs := by["both"]; len(fs) != 0 {
		t.Errorf("both: %d findings, want none (only the two together give the place)", len(fs))
	}
	if !slices.Equal(rep.AddedAttackers, []AddedAttacker{AddedAttackerReadMember, AddedAttackerTriageAccount}) {
		t.Errorf("the report's added attackers: %v, want them in their order", rep.AddedAttackers)
	}
}

// TestAddedKeepsDefault: a place of the run that adds none stays, not
// marked, when the added runs do not give it.
func TestAddedKeepsDefault(t *testing.T) {
	_, by := runAdded(t, AddedAttackerReadMember)
	wantMarks(t, by, "gone")
}

// TestAddedConditionDropped: a place whose condition an added attacker
// drops is reported once, as the added run gives it, marked.
func TestAddedConditionDropped(t *testing.T) {
	_, by := runAdded(t, AddedAttackerRequiredReviewer)
	wantMarks(t, by, "env", AddedAttackerRequiredReviewer)
	if f := by["env"][0]; f.Condition != nil || f.Certainty != CertaintyConfirmed {
		t.Errorf("env: condition %v, certainty %v", f.Condition, f.Certainty)
	}
	_, by = runAdded(t, AddedAttackerReadMember)
	wantMarks(t, by, "env")
	if by["env"][0].Condition == nil {
		t.Error("env without required-reviewer: no condition")
	}
}

// TestAddedDuplicates: a value given twice is added once.
func TestAddedDuplicates(t *testing.T) {
	rep, by := runAdded(t, AddedAttackerReadMember, AddedAttackerReadMember)
	wantMarks(t, by, "member", AddedAttackerReadMember)
	if len(rep.AddedAttackers) != 1 {
		t.Errorf("the report's added attackers: %v", rep.AddedAttackers)
	}
}

// TestAddedNoneIsRun: a run that adds no attacker is Run, to the byte.
func TestAddedNoneIsRun(t *testing.T) {
	reg, err := newRegistry([]Rule{barrierRule()}, true)
	if err != nil {
		t.Fatal(err)
	}
	in, r := barrierInputs(t)
	a, err := json.Marshal(RunAdded(context.Background(), in, reg, r, nil))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(Run(context.Background(), in, reg, r))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("RunAdded with none:\n%s\nRun:\n%s", a, b)
	}
}

// TestAddedReportSchema: a report of added attackers, with marked findings
// and the attackers at its top level, fits the schema of reports.
func TestAddedReportSchema(t *testing.T) {
	rep, _ := runAdded(t, AddedAttackerReadMember, AddedAttackerTriageAccount)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas(t).Validate("report-v0.json", "#", b); err != nil {
		t.Errorf("the report: %v\n%s", err, b)
	}
	var top struct {
		Added []string `json:"added_attackers"`
	}
	if err := json.Unmarshal(b, &top); err != nil || !slices.Equal(top.Added, []string{"read-member", "triage-account"}) {
		t.Errorf("added_attackers %v (%v)", top.Added, err)
	}
}

// TestSchemaOrder: the registry writes the added attackers of a form each
// once, in the order of $defs/added-attacker, whatever the order of the
// Meta; none stays none.
func TestSchemaOrder(t *testing.T) {
	got := schemaOrder([]AddedAttacker{AddedAttackerSecretsWriter, AddedAttackerReadMember, AddedAttackerSecretsWriter})
	if want := []AddedAttacker{AddedAttackerReadMember, AddedAttackerSecretsWriter}; !slices.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
	if got := schemaOrder(nil); got != nil {
		t.Errorf("none: %v", got)
	}
}
