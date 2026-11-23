package lint

import (
	"context"
	"encoding/json"
	"github.com/gh-intel/sisakulint/actions/ir"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

func TestClassify(t *testing.T) {
	read := Input{Name: facts.MustCleanInputPath("a.yml"), InputKind: InputKindWorkflow, State: InputStateRead}
	found := func(sev Severity, c Certainty) Finding {
		return Finding{FindingDraft: FindingDraft{Rule: MustRuleID("r")}, Severity: sev, Certainty: c}
	}
	gap := func(rule string) Finding {
		return Finding{FindingDraft: FindingDraft{Rule: MustRuleID(rule)}, Certainty: CertaintyInconclusive, InconclusiveKind: kindG}
	}
	accepted := func(g Finding) Finding {
		g.Acceptance = &Acceptance{Rule: g.Rule, KindID: g.InconclusiveKind, Reason: "a reason"}
		return g
	}
	high := []RuleRef{{ID: MustRuleID("r"), Severity: SeverityHigh}}
	for _, c := range []struct {
		name string
		rep  Report
		min  Severity
		want uint8
	}{
		{"nothing found", Report{Inputs: []Input{read}}, SeverityInfo, 0},
		{"no inputs", Report{}, SeverityInfo, 2},
		{"a confirmed finding", Report{Inputs: []Input{read}, Findings: []Finding{found(SeverityHigh, CertaintyConfirmed)}}, SeverityInfo, 1},
		{"a conditional finding", Report{Inputs: []Input{read}, Findings: []Finding{found(SeverityHigh, CertaintyConditional)}}, SeverityInfo, 2},
		{"both", Report{Inputs: []Input{read}, Findings: []Finding{found(SeverityHigh, CertaintyConfirmed), found(SeverityLow, CertaintyConditional)}}, SeverityInfo, 3},
		{"below the threshold", Report{Inputs: []Input{read}, Findings: []Finding{found(SeverityLow, CertaintyConfirmed), found(SeverityLow, CertaintyConditional)}}, SeverityMedium, 0},
		{"at the threshold", Report{Inputs: []Input{read}, Findings: []Finding{found(SeverityMedium, CertaintyConfirmed)}}, SeverityMedium, 1},
		{"info is every severity", Report{Inputs: []Input{read}, Findings: []Finding{found(SeverityInfo, CertaintyConfirmed)}}, SeverityInfo, 1},
		{"an invalid input", Report{Inputs: []Input{read, {Name: facts.MustCleanInputPath("b.yml"), State: InputStateInvalid}}}, SeverityInfo, 16},
		{"an unreadable input", Report{Inputs: []Input{{Name: facts.MustCleanInputPath("b.yml"), State: InputStateUnreadable}}}, SeverityInfo, 16},
		{"an internal error", Report{Inputs: []Input{read}, Errors: []RunError{{Message: "x"}}}, SeverityInfo, 4},
		{"everything", Report{Inputs: []Input{{State: InputStateInvalid}}, Findings: []Finding{found(SeverityHigh, CertaintyConfirmed)}, Errors: []RunError{{Message: "x"}}}, SeverityInfo, 21},
		{"an inconclusive place", Report{Inputs: []Input{read}, Rules: high, Findings: []Finding{gap("r")}}, SeverityInfo, 8},
		{"an inconclusive place of a rule below the threshold", Report{Inputs: []Input{read}, Rules: high, Findings: []Finding{gap("r")}}, SeverityCritical, 0},
		{"an inconclusive place of a rule at the threshold", Report{Inputs: []Input{read}, Rules: high, Findings: []Finding{gap("r")}}, SeverityHigh, 8},
		{"an inconclusive place of a rule the report does not have", Report{Inputs: []Input{read}, Findings: []Finding{gap("r")}}, SeverityCritical, 8},
		{"an inconclusive place and a confirmed finding", Report{Inputs: []Input{read}, Rules: high, Findings: []Finding{found(SeverityHigh, CertaintyConfirmed), gap("r")}}, SeverityInfo, 9},
		{"an inconclusive place below the threshold, then one at it", Report{Inputs: []Input{read},
			Rules:    []RuleRef{{ID: MustRuleID("low"), Severity: SeverityLow}, {ID: MustRuleID("r"), Severity: SeverityHigh}},
			Findings: []Finding{gap("low"), gap("r")}}, SeverityMedium, 8},
		{"an accepted inconclusive place", Report{Inputs: []Input{read}, Rules: high, Findings: []Finding{accepted(gap("r"))}}, SeverityInfo, 0},
		{"an accepted inconclusive place and one not accepted", Report{Inputs: []Input{read}, Rules: high, Findings: []Finding{accepted(gap("r")), gap("r")}}, SeverityInfo, 8},
		{"an accepted inconclusive place, and one not accepted below the threshold", Report{Inputs: []Input{read},
			Rules:    []RuleRef{{ID: MustRuleID("low"), Severity: SeverityLow}, {ID: MustRuleID("r"), Severity: SeverityHigh}},
			Findings: []Finding{gap("low"), accepted(gap("r"))}}, SeverityMedium, 0},
		{"every bit", Report{Inputs: []Input{{State: InputStateInvalid}}, Rules: high, Findings: []Finding{found(SeverityHigh, CertaintyConfirmed), found(SeverityHigh, CertaintyConditional), gap("r")}, Errors: []RunError{{Message: "x"}}}, SeverityInfo, 31},
		{"no fix does not count", Report{Inputs: []Input{read}, Findings: []Finding{{FindingDraft: FindingDraft{NoFix: &NoFix{Reason: ir.NoFixReasonFact}}, Severity: SeverityInfo, Certainty: CertaintyConfirmed}}}, SeverityCritical, 0},
	} {
		if got := Classify(c.rep, c.min); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// TestClassifyNeedsAThreshold: a threshold that is not a severity is the
// caller's mistake; every severity is SeverityInfo.
func TestClassifyNeedsAThreshold(t *testing.T) {
	for _, th := range []Severity{SeverityUnset, Severity(99)} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Classify(r, %v) did not panic", th)
				}
			}()
			Classify(Report{}, th)
		}()
	}
}

func TestClassifyRun(t *testing.T) {
	m := meta("cond")
	m = asking(m, facts.KindTestFlag)
	rule := everyStep(m, func(c *RuleContext, s workflow.Step) FindingDraft {
		cond, _ := FactEq(facts.TestFlag{Name: "f"}, true)
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Condition: &cond}
	})
	unknown := run(t, wf(twoSteps), nil, rule)
	if got := Classify(unknown, SeverityInfo); got != 2 {
		t.Errorf("without the fact: %d, want 2", got)
	}
	known := run(t, wf(twoSteps), mapResolver{facts.TestFlag{Name: "f"}: {State: facts.StateFound, Value: json.RawMessage(`true`)}}, rule)
	if got := Classify(known, SeverityInfo); got != 1 {
		t.Errorf("with the fact: %d, want 1", got)
	}
	reg, _ := newRegistry([]Rule{rule}, true)
	if got := Classify(Run(context.Background(), Inputs{Complete: true}, reg, mapResolver{}), SeverityInfo); got != 2 {
		t.Errorf("an empty repository: %d, want 2", got)
	}
}
