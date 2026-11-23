package lint

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

var qualityKind = MustFindingKindID("test.slow")

// testQuality is a quality rule of the tests: its description, and what
// its Check reports.
type testQuality struct {
	m      QualityMeta
	report func(c *RuleContext)
}

func (q testQuality) QualityMeta() QualityMeta { return q.m }

func (q testQuality) Check(_ context.Context, c *RuleContext) error {
	if q.report != nil {
		q.report(c)
	}
	return nil
}

func qualityExample(text string) Example {
	return Example{InputKind: InputKindWorkflow, Name: facts.MustCleanInputPath("w.yml"), Text: text,
		Notes: ExampleNotes{Situation: "a job", Reason: "it runs long"}}
}

func goodQualityMeta() QualityMeta {
	return QualityMeta{
		ID: MustRuleID("test"), Problem: "a job may run long", Expected: "a job has an end",
		Citations: []Citation{MustCitation("https://example.com/q")},
		Targets:   []InputKind{InputKindWorkflow},
		FindingKinds: []QualityFindingKind{{
			FindingText:   FindingText{ID: qualityKind, Detected: "slow", Consequence: "it runs long", Remedy: "end it"},
			TruePositives: []Example{qualityExample("on: push\n")},
			TrueNegatives: []Example{qualityExample("on: pull_request\n")},
		}},
	}
}

func TestNewRegistryQuality(t *testing.T) {
	reg, err := newRegistry(nil, false, testQuality{m: goodQualityMeta()})
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Rules()) != 0 || len(reg.QualityRules()) != 1 || !reg.IsQuality(MustRuleID("test")) {
		t.Errorf("rules %d, quality %d", len(reg.Rules()), len(reg.QualityRules()))
	}
	if _, ok := reg.Meta(MustRuleID("test")); ok {
		t.Error("Meta gives a quality rule")
	}
	if _, ok := reg.QualityMeta(MustRuleID("test")); !ok {
		t.Error("QualityMeta does not give the quality rule")
	}
}

func TestNewRegistryQualityRefuses(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(m *QualityMeta)
		want string
	}{
		{"no kind", func(m *QualityMeta) { m.FindingKinds = nil }, "no FindingKinds"},
		{"no problem", func(m *QualityMeta) { m.Problem = "" }, "Problem"},
		{"no citation", func(m *QualityMeta) { m.Citations = nil }, "Citations"},
		{"kind of another rule", func(m *QualityMeta) { m.FindingKinds[0].ID = MustFindingKindID("other.slow") }, "not of the rule"},
		{"no true negative", func(m *QualityMeta) { m.FindingKinds[0].TrueNegatives = nil }, "no true negative"},
		{"no added gain", func(m *QualityMeta) {
			m.UndetectedForms = []UndetectedForm{{ID: MustUndetectedFormID("u"), Text: "u", Disposition: NoAddedGain(), Examples: []Example{qualityExample("on: push\n")}}}
		}, "no-added-gain"},
		{"attack in notes", func(m *QualityMeta) { m.FindingKinds[0].TruePositives[0].Notes.Attack = "they push" }, "attack"},
		{"line break", func(m *QualityMeta) { m.FindingKinds[0].Remedy = "a\nb" }, "line break"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := goodQualityMeta()
			c.edit(&m)
			if _, err := newRegistry(nil, false, testQuality{m: m}); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want an error with %q", err, c.want)
			}
		})
	}
}

func TestNewRegistryQualityIDOfRule(t *testing.T) {
	if _, err := newRegistry([]Rule{testRule{meta: meta("test")}}, true, testQuality{m: goodQualityMeta()}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("got %v, want the ID twice", err)
	}
}

// slow is the args of a finding of qualityKind.
type slow struct{}

func (slow) KindID() FindingKindID { return qualityKind }
func (slow) Detected() string      { return "slow" }
func (slow) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind_id":"test.slow"}`), nil
}

func runQuality(t *testing.T, report func(c *RuleContext)) Report {
	t.Helper()
	reg, err := newRegistry(nil, false, testQuality{m: goodQualityMeta(), report: report})
	if err != nil {
		t.Fatal(err)
	}
	in, err := Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: make\n")}})
	if err != nil {
		t.Fatal(err)
	}
	return Run(context.Background(), in, reg, mapResolver{})
}

// wholeAt is the location of the whole workflow of c.
func wholeAt(c *RuleContext) Location { return At(c.input, c.workflow.Base) }

func TestRunQuality(t *testing.T) {
	rep := runQuality(t, func(c *RuleContext) {
		c.Report(FindingDraft{Location: wholeAt(c), Args: slow{}})
	})
	if len(rep.Errors) != 0 {
		t.Fatalf("errors %+v", rep.Errors)
	}
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 0 || len(rep.QualityFindings) != 1 {
		t.Fatalf("findings %d, quality %d", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)), len(rep.QualityFindings))
	}
	q := rep.QualityFindings[0]
	if q.Certainty != CertaintyConfirmed || q.Consequence != "it runs long" || q.Remedy != "end it" || q.Fingerprint.String() == "" {
		t.Errorf("%+v", q)
	}
	if len(rep.Rules) != 0 || len(rep.QualityRules) != 1 || rep.QualityRules[0] != MustRuleID("test") {
		t.Errorf("rules %v, quality rules %v", rep.Rules, rep.QualityRules)
	}
	if c := Classify(rep, SeverityInfo); c != 0 {
		t.Errorf("Classify is %d: a quality finding counts for nothing", c)
	}
	b, err := rep.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"quality_findings":[{"rule":"test","certainty":"confirmed"`) || strings.Contains(string(b), `"severity":"unset"`) {
		t.Errorf("%s", b)
	}
}

func TestRunQualityRefuses(t *testing.T) {
	for name, report := range map[string]func(c *RuleContext){
		"fix": func(c *RuleContext) {
			c.Report(FindingDraft{Location: wholeAt(c), Args: slow{}, Fix: &Fix{KindID: MustFixKindID("f")}})
		},
		"no fix": func(c *RuleContext) {
			c.Report(FindingDraft{Location: wholeAt(c), Args: slow{}, NoFix: &NoFix{Reason: ir.NoFixReasonManual}})
		},
		"inconclusive": func(c *RuleContext) {
			c.Inconclusive(InconclusiveDraft{KindID: MustInconclusiveKindID("x"), Location: wholeAt(c)})
		},
		"twice": func(c *RuleContext) {
			c.Report(FindingDraft{Location: wholeAt(c), Args: slow{}})
			c.Report(FindingDraft{Location: wholeAt(c), Args: slow{}})
		},
		"no location": func(c *RuleContext) { c.Report(FindingDraft{Args: slow{}}) },
	} {
		t.Run(name, func(t *testing.T) {
			rep := runQuality(t, report)
			if len(rep.Errors) == 0 {
				t.Errorf("no error: %+v", rep.QualityFindings)
			}
			if _, err := rep.MarshalJSON(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestRegistryJSONQuality(t *testing.T) {
	m := goodQualityMeta()
	ex := qualityExample("on: push\n")
	ex.Notes.Cause = "the rule reads no file"
	m.UndetectedForms = []UndetectedForm{{ID: MustUndetectedFormID("u"), Text: "u form", Disposition: Todo(NeedSameFile), Examples: []Example{ex}}}
	m.FalsePositiveForms = []FalsePositiveForm{{ID: MustFalsePositiveFormID("f"), Text: "f form", FindingKinds: []FindingKindID{qualityKind}, Disposition: Limitation(DeciderRunTime), Examples: []Example{ex}}}
	reg, err := newRegistry(nil, false, testQuality{m: m})
	if err != nil {
		t.Fatal(err)
	}
	s := schemas(t)
	for _, full := range []bool{false, true} {
		b, err := reg.MarshalJSON()
		if full {
			b, err = reg.MarshalJSONFull()
		}
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules   []json.RawMessage `json:"rules"`
			Quality []struct {
				ID           string `json:"id"`
				FindingKinds []struct {
					ID string `json:"id"`
				} `json:"finding_kinds"`
			} `json:"quality_rules"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Rules) != 0 || len(doc.Quality) != 1 || doc.Quality[0].FindingKinds[0].ID != "test.slow" {
			t.Errorf("%s", b)
		}
		if err := s.Validate("registry-v0.json", "#", b); err != nil {
			t.Errorf("full %v: %v\n%s", full, err, b)
		}
	}
	out, err := reg.Explain(nil, "c")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"quality rule", md("test.slow"), "u form", "f form"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	for _, not := range []string{"CVSS", "severity", "threat"} {
		if strings.Contains(strings.ToLower(string(out)), strings.ToLower(not)) {
			t.Errorf("%q in\n%s", not, out)
		}
	}
}

func TestSelectQuality(t *testing.T) {
	reg, err := newRegistry([]Rule{testRule{meta: meta("a-rule")}}, true, testQuality{m: goodQualityMeta(), report: func(c *RuleContext) {
		c.Report(FindingDraft{Location: wholeAt(c), Args: slow{}})
	}})
	if err != nil {
		t.Fatal(err)
	}
	only, err := reg.Select(Only(Selector{MustRuleID("test")}), FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	in, err := Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: make\n")}})
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), in, only, mapResolver{})
	if len(rep.Rules) != 0 || len(rep.QualityFindings) != 1 || len(rep.SkippedRules) != 1 || rep.SkippedRules[0] != MustRuleID("a-rule") || Classify(rep, SeverityInfo) != 0 {
		t.Errorf("rules %v, quality %d, skipped %v", rep.Rules, len(rep.QualityFindings), rep.SkippedRules)
	}
	skip, err := reg.Select(Skip(Selector{MustRuleID("test")}), FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	if rep := Run(context.Background(), in, skip, mapResolver{}); len(rep.QualityRules) != 0 || len(rep.QualityFindings) != 0 {
		t.Errorf("%+v", rep.QualityRules)
	}
}

// TestSelectQualityMeta: a quality rule Select leaves out is no quality
// rule of what it gives, as a rule left out has no Meta there.
func TestSelectQualityMeta(t *testing.T) {
	reg, err := newRegistry([]Rule{testRule{meta: meta("a-rule")}}, true, testQuality{m: goodQualityMeta()})
	if err != nil {
		t.Fatal(err)
	}
	skip, err := reg.Select(Skip(Selector{MustRuleID("test")}), FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	if skip.IsQuality(MustRuleID("test")) {
		t.Error("the quality rule left out is still one")
	}
	if _, ok := skip.QualityMeta(MustRuleID("test")); ok {
		t.Error("QualityMeta gives the quality rule left out")
	}
}

// TestReportSchemaQuality: a report with a quality finding, conditional and
// with a related place, fits report-v0.json.
func TestReportSchemaQuality(t *testing.T) {
	m := goodQualityMeta()
	m.FindingKinds[0].FactKinds = []facts.Kind{facts.KindTestFlag}
	reg, err := newRegistry(nil, false, testQuality{m: m, report: func(c *RuleContext) {
		cond, err := FactEq(facts.TestFlag{Name: "q"}, true)
		if err != nil {
			panic(err)
		}
		c.Report(FindingDraft{Location: wholeAt(c), Args: slow{}, Condition: &cond,
			Related: []Related{{Location: At(c.input, c.workflow.Jobs.Value.Entries[0].Value.Value.Base), Note: "the job"}}})
	}})
	if err != nil {
		t.Fatal(err)
	}
	in, err := Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: make\n")}})
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), in, reg, mapResolver{})
	if len(rep.QualityFindings) != 1 || rep.QualityFindings[0].Certainty != CertaintyConditional || len(rep.Errors) != 0 {
		t.Fatalf("%+v %+v", rep.QualityFindings, rep.Errors)
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas(t).Validate("report-v0.json", "#", b); err != nil {
		t.Errorf("%v\n%s", err, b)
	}
}

// exampledQuality is a quality rule of the tests whose examples are read
// apart from its QualityMeta (ExampledQualityRule); reads counts the calls
// of ExampledQualityMeta.
type exampledQuality struct {
	testQuality
	full  QualityMeta
	reads *int
}

func (q exampledQuality) ExampledQualityMeta() QualityMeta {
	*q.reads++
	return q.full
}

// TestExampledQualityRule: making a registry, selecting from it and
// running it read no example of an ExampledQualityRule, as of an
// ExampledRule; MarshalJSONFull, Explain and CheckExamples read them.
func TestExampledQualityRule(t *testing.T) {
	full := goodQualityMeta()
	reads := new(int)
	q := exampledQuality{testQuality{m: full.withoutExamples(), report: func(c *RuleContext) {
		if _, push := c.workflow.On.Value.Event(workflow.EventNamePush); push {
			c.Report(FindingDraft{Location: wholeAt(c), Args: slow{}})
		}
	}}, full, reads}
	reg, err := newRegistry([]Rule{testRule{meta: meta("a-rule")}}, true, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Select(Selection{}, FactSources{}); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.MetaJSON(); err != nil {
		t.Fatal(err)
	}
	if *reads != 0 {
		t.Fatalf("ExampledQualityMeta read %d times before anything showed the examples", *reads)
	}
	b, err := reg.MarshalJSONFull()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"on: pull_request\n"`) {
		t.Errorf("the registry has no example of the quality rule:\n%s", b)
	}
	if err := schemas(t).Validate("registry-v0.json", "#", b); err != nil {
		t.Error(err)
	}
	out, err := reg.Explain([]RuleID{full.ID}, "c")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "pull_request") {
		t.Errorf("Explain has no example of the quality rule:\n%s", out)
	}
	checks := reg.CheckExamples(context.Background(), full.ID)
	if len(checks) != 2 {
		t.Fatalf("checks %+v", checks)
	}
	for _, c := range checks {
		if !c.Holds {
			t.Errorf("%s: %s", c.What, c.Why)
		}
	}
	if *reads == 0 {
		t.Error("nothing read the examples")
	}
}

// TestExampledQualityRuleChecked: the examples of an ExampledQualityRule
// are checked when shown, as NewRegistry checks those of a QualityMeta.
func TestExampledQualityRuleChecked(t *testing.T) {
	bad := goodQualityMeta()
	bad.FindingKinds[0].TrueNegatives = nil
	reg, err := newRegistry(nil, true, exampledQuality{testQuality{m: bad.withoutExamples()}, bad, new(int)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.MarshalJSON(); err == nil {
		t.Error("MarshalJSON took a kind without a true negative")
	}
	if _, err := reg.Explain(nil, "c"); err == nil {
		t.Error("Explain took a kind without a true negative")
	}
}

// TestMetaJSONQuality: MetaJSON has the object of a quality rule of the
// registry's JSON, by its ID, without its examples.
func TestMetaJSONQuality(t *testing.T) {
	reg, err := newRegistry([]Rule{testRule{meta: meta("a-rule")}}, true, testQuality{m: goodQualityMeta()})
	if err != nil {
		t.Fatal(err)
	}
	metas, err := reg.MetaJSON()
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		ID           string                       `json:"id"`
		FindingKinds []map[string]json.RawMessage `json:"finding_kinds"`
	}
	if err := json.Unmarshal(metas[MustRuleID("test")], &m); err != nil || m.ID != "test" || len(m.FindingKinds) != 1 {
		t.Fatalf("the meta of the quality rule: %s (%v)", metas[MustRuleID("test")], err)
	}
	for _, k := range []string{"true_positives", "true_negatives"} {
		if _, ok := m.FindingKinds[0][k]; ok {
			t.Errorf("the kind has %s", k)
		}
	}
	if _, ok := metas[MustRuleID("a-rule")]; !ok {
		t.Error("no meta of the rule")
	}
}
