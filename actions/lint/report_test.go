package lint

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"github.com/gh-intel/sisakulint/actions/ir"
	"os"
	"regexp"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/jsonschema"
	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

var update = flag.Bool("update", false, "write the golden files of testdata")

// schemas are the three schemas, by the names their $ref use.
func schemas(t *testing.T) *jsonschema.Set {
	t.Helper()
	files := map[string][]byte{}
	for name, p := range map[string]string{
		facts.SchemaName:   "../facts/schema/facts-v0.json",
		"report-v0.json":   "schema/report-v0.json",
		"registry-v0.json": "schema/registry-v0.json",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = b
	}
	s, err := jsonschema.Load(files, jsonschema.Options{SchemaAnnotations: []string{"x-value"}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// golden is a run with every part of a report: a confirmed finding with a
// fix, a conditional one with a reason for no fix, facts of all three
// states, an input with diagnostics, one that cannot be read, an alias and
// an internal error.
func golden(t *testing.T, r facts.Resolver) (Report, *Registry) {
	t.Helper()
	files := fstest.MapFS{
		".github/workflows/a.yml": {Data: []byte(`on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - &checkout
        id: checkout
        uses: actions/checkout@v4
      - name: "<script>"
        run: echo hi
  again:
    runs-on: ubuntu-latest
    steps:
      - *checkout
`)},
		".github/workflows/bad.yml":   {Data: []byte("on: push\n")},
		".github/workflows/latin.yml": {Data: []byte("on: caf\xe9\n")},
		"action.yml":                  {Data: []byte(okAction)},
	}
	pin := meta("pin-step")
	pin = asking(pin, facts.KindTestFlag, facts.KindTestText)
	same := MustFixKindID("same") // a name of its own in the golden report
	pin = fixing(pin, FixKind{ID: same, Title: "mark it", FactKinds: []facts.Kind{facts.KindTestFlag}, Safety: SafetyReview, PossibleSideEffects: []ir.SideEffect{ir.SideEffectUnquotedOneWord}})
	pinRule := unmarkedStep(pin, func(c *RuleContext, s workflow.Step) FindingDraft {
		f := FindingDraft{Args: said("a step of " + c.input.Name.String()), Location: At(c.input, s.Base),
			Related: []Related{{Location: At(c.input, c.workflow.Base), Note: "the workflow"}}}
		if s.Uses.Status == workflow.Present {
			f.Evidence = []Related{{Location: At(c.input, s.Uses.Value.Base), Note: "uses"}}
			f.Fix = &Fix{KindID: same, Title: "mark it", Edits: []edit.Edit{markEdit(c, s, "same")}, SideEffects: []ir.SideEffect{ir.SideEffectUnquotedOneWord}}
			return f
		}
		cond, _ := FactEq(facts.TestText{Name: "mode"}, "strict")
		cond = Any(cond, FactAbsent(facts.TestFlag{Name: "gone"}), InputPresent(facts.MustCleanInputPath(".github/workflows/other.yml")))
		f.Condition = &cond
		f.NoFix = &NoFix{Reason: ir.NoFixReasonFact, Queries: []facts.Query{facts.TestFlag{Name: "gone"}}, Note: "set it by hand"}
		return f
	})
	fails := testRule{meta: meta("fails"), check: func(context.Context, *RuleContext) error { panic("boom") }}
	in, err := Enumerate(files)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := newRegistry([]Rule{pinRule, fails}, true)
	if err != nil {
		t.Fatal(err)
	}
	return Run(context.Background(), in, reg, r), reg
}

var goldenFacts = mapResolver{
	facts.TestText{Name: "mode"}: {State: facts.StateUnknown, Reason: "no token"},
	facts.TestFlag{Name: "gone"}: {State: facts.StateFound, Value: json.RawMessage(`true`)},
}

func TestReportGolden(t *testing.T) {
	rep, _ := golden(t, goldenFacts)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	pretty.WriteByte('\n')
	if *update {
		if err := os.WriteFile("testdata/report.golden.json", pretty.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/report.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pretty.Bytes(), want) {
		t.Errorf("the report differs from testdata/report.golden.json (go test -run TestReportGolden -update):\n%s", pretty.Bytes())
	}
	again, _ := golden(t, goldenFacts)
	b2, _ := json.Marshal(again)
	if !bytes.Equal(b, b2) {
		t.Error("two runs wrote two reports")
	}
}

// TestCitationSchema: the schema refuses what ParseCitation refuses of <, >
// and spaces, which an autolink of --explain cannot hold.
func TestCitationSchema(t *testing.T) {
	s := schemas(t)
	if err := s.Validate("registry-v0.json", "#/$defs/citation", []byte(`"https://example.com/a?b#c"`)); err != nil {
		t.Errorf("a citation: %v", err)
	}
	for _, c := range []string{`"https://x.com/<a>"`, `"https://x.com/a>"`, `"https://<x>.com/"`, `"https://x.com/a b"`} {
		if err := s.Validate("registry-v0.json", "#/$defs/citation", []byte(c)); err == nil {
			t.Errorf("%s fits the citation of the schema", c)
		}
	}
}

func TestReportSchemas(t *testing.T) {
	s := schemas(t)
	rep, reg := golden(t, goldenFacts)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate("report-v0.json", "#", b); err != nil {
		t.Errorf("the report does not fit report-v0.json: %v", err)
	}
	rb, _ := json.Marshal(reg)
	if err := s.Validate("registry-v0.json", "#", rb); err != nil {
		t.Errorf("the registry does not fit registry-v0.json: %v", err)
	}
	empty, _ := json.Marshal(Run(context.Background(), Inputs{}, reg, mapResolver{}))
	if err := s.Validate("report-v0.json", "#", empty); err != nil {
		t.Errorf("an empty report does not fit: %v\n%s", err, empty)
	}
}

func TestReportPositions(t *testing.T) {
	rep, _ := golden(t, goldenFacts)
	var doc struct {
		Findings []struct {
			Location struct {
				Start, Line, Column int
				Via                 []struct{ Line int }
			}
		}
	}
	b, _ := json.Marshal(rep)
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	tree := rep.Inputs[0].Tree
	for _, f := range doc.Findings {
		p := tree.Position(f.Location.Start)
		if p.Line != f.Location.Line || p.Column != f.Location.Column {
			t.Errorf("start %d: line %d column %d, want %d %d", f.Location.Start, f.Location.Line, f.Location.Column, p.Line, p.Column)
		}
	}
	if len(doc.Findings) != 3 || len(doc.Findings[2].Location.Via) != 1 || doc.Findings[2].Location.Via[0].Line != 14 {
		t.Errorf("the alias's finding: %+v", doc.Findings)
	}
}

func TestReportReplay(t *testing.T) {
	rec := facts.NewRecorder(goldenFacts)
	online, _ := golden(t, rec)
	file, err := rec.WriteFile()
	if err != nil {
		t.Fatal(err)
	}
	store, err := facts.LoadStore(file)
	if err != nil {
		t.Fatal(err)
	}
	offline, _ := golden(t, store)
	a, _ := json.Marshal(online)
	b, _ := json.Marshal(offline)
	// the same answers; where they come from is the file now
	source := regexp.MustCompile(`,"source":"[a-z]+"`)
	if !bytes.Contains(b, []byte(`"source":"file"`)) {
		t.Errorf("the replay does not say its answers come from the file:\n%s", b)
	}
	if a, b := source.ReplaceAll(a, nil), source.ReplaceAll(b, nil); !bytes.Equal(a, b) {
		t.Errorf("the replay from the file of facts wrote another report:\n%s\n%s", a, b)
	}
}

func TestReportFix(t *testing.T) {
	s := schemas(t)
	rep, _ := golden(t, goldenFacts)
	plain, _ := json.Marshal(rep)
	for _, c := range []struct {
		fix  FixResult
		want string
	}{
		{FixResult{Safety: SafetySafe}, `,"fix":{"safety":"safe","written":[],"unchecked_rules":[]}}`},
		{FixResult{Safety: SafetyReview, Written: []facts.InputPath{facts.MustCleanInputPath("a.yml"), facts.MustCleanInputPath("b/action.yml")}},
			`,"fix":{"safety":"review","written":["a.yml","b/action.yml"],"unchecked_rules":[]}}`},
		{FixResult{Safety: SafetySafe, Written: []facts.InputPath{facts.MustCleanInputPath("a.yml")}, Error: "b/action.yml: a symlink"},
			`,"fix":{"safety":"safe","written":["a.yml"],"error":"b/action.yml: a symlink","unchecked_rules":[]}}`},
	} {
		rep.Fix = &c.fix
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if want := string(plain[:len(plain)-1]) + c.want; string(b) != want {
			t.Errorf("%+v:\n%s\nwant the report without fix, then%s", c.fix, b, c.want)
		}
		if err := s.Validate("report-v0.json", "#", b); err != nil {
			t.Errorf("%+v does not fit report-v0.json: %v", c.fix, err)
		}
	}
	rep.Fix = &FixResult{}
	if b, err := json.Marshal(rep); err == nil {
		t.Errorf("a FixResult without a Safety is written: %s", b)
	}
	emptyError := string(plain[:len(plain)-1]) + `,"fix":{"safety":"safe","written":[],"error":"","unchecked_rules":[]}}`
	if err := s.Validate("report-v0.json", "#", []byte(emptyError)); err == nil {
		t.Error("report-v0.json takes an empty fix.error")
	}
}

func TestReportExcluded(t *testing.T) {
	in, err := EnumerateExcept(fstest.MapFS{"x/action.yml": {Data: []byte(okAction)}, "y/action.yml": {Data: []byte(okAction)}}, excludes(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := newRegistry(nil, true)
	rep := Run(context.Background(), in, reg, mapResolver{})
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas(t).Validate("report-v0.json", "#", b); err != nil {
		t.Errorf("does not fit report-v0.json: %v\n%s", err, b)
	}
	for _, s := range []string{`"excluded":["x"]`, `{"name":"x/action.yml","input_kind":"action-metadata","state":"excluded","reason":"--exclude x","diagnostics":[]}`} {
		if !bytes.Contains(b, []byte(s)) {
			t.Errorf("no %s in\n%s", s, b)
		}
	}
	none, _ := json.Marshal(Run(context.Background(), Inputs{}, reg, mapResolver{}))
	if !bytes.Contains(none, []byte(`"excluded":[]`)) {
		t.Errorf("no empty excluded in\n%s", none)
	}
}

func TestClassifyExcluded(t *testing.T) {
	reg, _ := newRegistry(nil, true)
	only, _ := EnumerateExcept(fstest.MapFS{"x/action.yml": {Data: []byte(okAction)}}, excludes(t, "x"))
	if got := Classify(Run(context.Background(), only, reg, mapResolver{}), SeverityInfo); got != UndecidedBit {
		t.Errorf("every input excluded: %d, want %d (nothing checked)", got, UndecidedBit)
	}
	mixed, _ := EnumerateExcept(fstest.MapFS{"x/action.yml": {Data: []byte(okAction)}, "y/action.yml": {Data: []byte(okAction)}}, excludes(t, "x"))
	if got := Classify(Run(context.Background(), mixed, reg, mapResolver{}), SeverityInfo); got != 0 {
		t.Errorf("an input read and one excluded: %d, want 0", got)
	}
}
