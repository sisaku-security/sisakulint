package lint

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/gh-intel/sisakulint/actions/facts"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// ownSaid is the args of a finding of the kind <rule>.said.
type ownSaid struct {
	kind FindingKindID
	text string
}

func (a ownSaid) KindID() FindingKindID { return a.kind }
func (a ownSaid) Detected() string      { return a.text }
func (a ownSaid) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Kind string `json:"kind_id"`
		Text string `json:"text"`
	}{a.kind.String(), a.text})
}

// bumper reports each step whose uses is at @v4, and fixes it to @v5: its
// fix changes uses.ref of the summary of that uses.
func bumper() Rule {
	m := fixing(ruleOf("bumper"), FixKind{ID: fixF, Title: "bump", Safety: SafetySafe})
	return testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			if s.Uses.Status != workflow.Present {
				continue
			}
			sp := s.Uses.Value.Base.Node.ContentSpan()
			i := bytes.Index(c.tree.Bytes()[sp.Start:sp.End], []byte("@v4"))
			if i < 0 {
				continue
			}
			at := sp.Start + i + 1
			c.Report(FindingDraft{Args: ownSaid{MustFindingKindID("bumper.said"), "x"}, Location: At(c.input, s.Base),
				Fix: &Fix{KindID: fixF, Title: "bump", Edits: []edit.Edit{{Span: cst.Span{Start: at, End: at + 2}, New: []byte("v5")}}}})
		}
		return nil
	}}
}

// reader is a rule that reads fields of the IR and reports nothing: what
// the engine compares for it when it is skipped.
func reader(id string, kinds []InputKind, fields ...ir.SummaryField) Rule {
	m := ruleOf(id)
	m.Targets = kinds
	m = examplesTargeting(m)
	m.ViewFields = fields
	return testRule{meta: m}
}

// uncheckedAfter runs the rules on src, but those skip, and applies the
// fixes that are safe.
func uncheckedAfter(t *testing.T, files map[string]string, rules []Rule, skip ...string) (Applied, error) {
	t.Helper()
	reg, err := newRegistry(rules, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(skip) > 0 {
		if reg, err = reg.Select(Skip(sel(t, skip...)...), FactSources{}); err != nil {
			t.Fatal(err)
		}
	}
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), in, reg, mapResolver{})
	if len(rep.Errors) != 0 {
		t.Fatalf("errors %+v", rep.Errors)
	}
	return ApplyFixes(context.Background(), in, reg, mapResolver{}, rep, SafetySafe)
}

var workflowOnly = []InputKind{InputKindWorkflow}

func equalUnchecked(a, b []Unchecked) bool {
	return slices.EqualFunc(a, b, func(x, y Unchecked) bool {
		return x.Rule == y.Rule && slices.EqualFunc(x.Changed, y.Changed, func(p, q Changed) bool {
			return p.Input == q.Input && p.Path == q.Path && slices.Equal(p.Fields, q.Fields) && slices.Equal(p.By, q.By)
		})
	})
}

// TestUncheckedByTheFields: a rule skipped is said when the fixes change
// a field it reads, with where and by which fix; not one that reads fields
// the fixes do not change.
func TestUncheckedByTheFields(t *testing.T) {
	a, err := uncheckedAfter(t, map[string]string{wfPath: twoSteps},
		[]Rule{bumper(), reader("uses-reader", workflowOnly, ir.FieldUsesRef), reader("sink-reader", workflowOnly, ir.FieldSinkRefs)},
		"uses-reader", "sink-reader")
	if err != nil {
		t.Fatal(err)
	}
	want := []Unchecked{{Rule: MustRuleID("uses-reader"), Changed: []Changed{{Input: facts.MustCleanInputPath(wfPath), Path: "jobs.build.steps[checkout].uses",
		Fields: []ir.SummaryField{ir.FieldUsesRef}, By: []FixBy{{Rule: MustRuleID("bumper"), Fix: fixF}}}}}}
	if !equalUnchecked(a.Unchecked, want) {
		t.Errorf("got %+v, want %+v", a.Unchecked, want)
	}
	if len(a.Files) != 1 {
		t.Errorf("files %d", len(a.Files))
	}
}

// TestUncheckedNotWhenNoFieldChanges: a fix that changes no field a rule
// skipped reads says nothing (the pin of commit-sha on an action that is
// not a checkout).
func TestUncheckedNotWhenNoFieldChanges(t *testing.T) {
	a, err := uncheckedAfter(t, map[string]string{wfPath: twoSteps},
		[]Rule{marker("mark", "m", SafetySafe), reader("uses-reader", workflowOnly, ir.FieldUsesRef, ir.FieldUsesRepo)}, "uses-reader")
	if err != nil || len(a.Unchecked) != 0 || len(a.Files) != 1 {
		t.Errorf("unchecked %+v, files %d, %v", a.Unchecked, len(a.Files), err)
	}
}

// TestUncheckedNotComparedWhenEveryRuleRuns: with no rule skipped, no
// summary is made to compare (the run again checks every rule).
func TestUncheckedNotComparedWhenEveryRuleRuns(t *testing.T) {
	var made []*ir.IR
	newIR = func(input string, t *cst.Tree, w *workflow.Workflow, a *workflow.ActionMetadata) *ir.IR {
		x := ir.New(input, t, w, a)
		made = append(made, x)
		return x
	}
	t.Cleanup(func() { newIR = ir.New })
	a, err := uncheckedAfter(t, map[string]string{wfPath: twoSteps}, []Rule{bumper(), reader("uses-reader", workflowOnly, ir.FieldUsesRef)})
	if err != nil || len(a.Unchecked) != 0 {
		t.Fatalf("unchecked %+v, %v", a.Unchecked, err)
	}
	for _, x := range made {
		if x.Made(ir.SummaryUses) != 0 {
			t.Error("a summary made with no rule skipped")
		}
	}
}

// TestUncheckedByTargets: a rule skipped that does not
// check the kind of the input fixed is not said.
func TestUncheckedByTargets(t *testing.T) {
	a, err := uncheckedAfter(t, map[string]string{wfPath: twoSteps},
		[]Rule{bumper(), reader("action-reader", []InputKind{InputKindActionMetadata}, ir.FieldUsesRef)}, "action-reader")
	if err != nil || len(a.Unchecked) != 0 {
		t.Errorf("unchecked %+v, %v", a.Unchecked, err)
	}
}

// TestUncheckedAfterTwoSelects: a rule skipped by the
// first of two selections is compared too.
func TestUncheckedAfterTwoSelects(t *testing.T) {
	reg, err := newRegistry([]Rule{bumper(), reader("uses-reader", workflowOnly, ir.FieldUsesRef), reader("other", workflowOnly)}, true)
	if err != nil {
		t.Fatal(err)
	}
	if reg, err = reg.Select(Skip(sel(t, "uses-reader")...), FactSources{}); err != nil {
		t.Fatal(err)
	}
	if reg, err = reg.Select(Skip(sel(t, "other")...), FactSources{}); err != nil {
		t.Fatal(err)
	}
	in, _ := Enumerate(fstest.MapFS{wfPath: {Data: []byte(twoSteps)}})
	rep := Run(context.Background(), in, reg, mapResolver{})
	a, err := ApplyFixes(context.Background(), in, reg, mapResolver{}, rep, SafetySafe)
	if err != nil || len(a.Unchecked) != 1 || a.Unchecked[0].Rule != MustRuleID("uses-reader") {
		t.Errorf("unchecked %+v, %v", a.Unchecked, err)
	}
}

// TestUncheckedPanicIsAnError: a making of summaries that
// panics while they are compared is an error of ApplyFixes, and nothing
// is given.
func TestUncheckedPanicIsAnError(t *testing.T) {
	reg, _ := newRegistry([]Rule{bumper(), reader("uses-reader", workflowOnly, ir.FieldUsesRef)}, true)
	reg, _ = reg.Select(Skip(sel(t, "uses-reader")...), FactSources{})
	in, _ := Enumerate(fstest.MapFS{wfPath: {Data: []byte(twoSteps)}})
	rep := Run(context.Background(), in, reg, mapResolver{})
	newIR = func(string, *cst.Tree, *workflow.Workflow, *workflow.ActionMetadata) *ir.IR {
		panic("the analysis failed")
	}
	t.Cleanup(func() { newIR = ir.New })
	a, err := ApplyFixes(context.Background(), in, reg, mapResolver{}, rep, SafetySafe)
	if err == nil || a.Files != nil {
		t.Errorf("files %v, err %v", a.Files, err)
	}
}

// TestFixResultJSON: unchecked_rules is in the fix of the report, the IDs
// of the rules; [] when there is none.
func TestFixResultJSON(t *testing.T) {
	rep := Report{Fix: &FixResult{Safety: SafetySafe, Error: "it failed", UncheckedRules: []Unchecked{{Rule: MustRuleID("watcher")}}}}
	b, err := rep.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"unchecked_rules":["watcher"]`) {
		t.Errorf("no unchecked_rules in %s", b)
	}
	if err := schemas(t).Validate("report-v0.json", "#", b); err != nil {
		t.Errorf("the report does not fit report-v0.json: %v", err)
	}
	rep.Fix = &FixResult{Safety: SafetySafe}
	b, _ = rep.MarshalJSON()
	if !strings.Contains(string(b), `"unchecked_rules":[]`) {
		t.Errorf("unchecked_rules is required: %s", b)
	}
}

// TestUncheckedEmptyOnAnError: when
// the run again refuses the fixes, nothing is given, the rules unchecked
// neither, though the comparison found one.
func TestUncheckedEmptyOnAnError(t *testing.T) {
	v5 := testRule{meta: ruleOf("v5"), check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			if s.Uses.Status == workflow.Present && strings.HasSuffix(s.Uses.Value.Text(), "@v5") {
				c.Report(FindingDraft{Args: ownSaid{MustFindingKindID("v5.said"), "x"}, Location: At(c.input, s.Base)})
			}
		}
		return nil
	}}
	a, err := uncheckedAfter(t, map[string]string{wfPath: twoSteps}, []Rule{bumper(), v5, reader("uses-reader", workflowOnly, ir.FieldUsesRef)}, "uses-reader")
	if err == nil || a.Files != nil || a.Unchecked != nil {
		t.Errorf("files %v, unchecked %+v, err %v; want an error and nothing", a.Files, a.Unchecked, err)
	}
}

// retarget reports a workflow on pull_request_target and fixes it to run
// on push: its edit is in on, out of the summary of the checkout, which is
// gone after it (its events are none).
func retarget() Rule {
	m := fixing(ruleOf("retarget"), FixKind{ID: fixF, Title: "push", Safety: SafetySafe})
	return testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		i := bytes.Index(c.tree.Bytes(), []byte("on: pull_request_target"))
		if i < 0 || len(steps(c)) == 0 {
			return nil
		}
		at := i + len("on: ")
		c.Report(FindingDraft{Args: ownSaid{MustFindingKindID("retarget.said"), "x"}, Location: At(c.input, steps(c)[0].Base),
			Fix: &Fix{KindID: fixF, Title: "push", Edits: []edit.Edit{{Span: cst.Span{Start: at, End: at + len("pull_request_target")}, New: []byte("push")}}}})
		return nil
	}}
}

// TestUncheckedByNoFix: a summary
// the fixes change with no edit in it says no fix.
func TestUncheckedByNoFix(t *testing.T) {
	src := "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm ci\n"
	a, err := uncheckedAfter(t, map[string]string{wfPath: src}, []Rule{retarget(), reader("site-reader", workflowOnly, ir.FieldCheckoutSitePRCodeOn)}, "site-reader")
	if err != nil {
		t.Fatal(err)
	}
	want := []Unchecked{{Rule: MustRuleID("site-reader"), Changed: []Changed{{Input: facts.MustCleanInputPath(wfPath), Path: "jobs.build.steps[0]", Fields: []ir.SummaryField{ir.FieldCheckoutSitePRCodeOn}}}}}
	if !equalUnchecked(a.Unchecked, want) {
		t.Errorf("got %+v, want %+v", a.Unchecked, want)
	}
}
