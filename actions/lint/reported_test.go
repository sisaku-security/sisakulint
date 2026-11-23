package lint

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
)

func TestWithReported(t *testing.T) {
	in, err := EnumerateExcept(fstest.MapFS{"x/action.yml": {Data: []byte(okAction)}, "y/action.yml": {Data: []byte(okAction)}}, excludes(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	y := facts.MustCleanInputPath("y/action.yml")
	got, err := in.WithReported([]facts.InputPath{y})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Reported, []facts.InputPath{y}) || len(got.List) != len(in.List) {
		t.Errorf("WithReported = %v of %d inputs, want [y/action.yml] of %d", got.Reported, len(got.List), len(in.List))
	}
	for _, c := range []struct {
		name  string
		names []string
		says  string
	}{
		{"not an input", []string{"z/action.yml"}, "not a workflow"},
		{"excluded", []string{"x/action.yml"}, "a path left out"},
		{"twice", []string{"y/action.yml", "y/action.yml"}, "twice"},
		{"none", nil, "no input"},
	} {
		var names []facts.InputPath
		for _, n := range c.names {
			names = append(names, facts.MustCleanInputPath(n))
		}
		if _, err := in.WithReported(names); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v, want an error that says %q", c.name, err, c.says)
		}
	}
}

func TestNarrow(t *testing.T) {
	a, b := facts.MustCleanInputPath("a.yml"), facts.MustCleanInputPath("b.yml")
	at := func(p facts.InputPath) Location { return Location{File: File{Input: p}} }
	rel := func(p facts.InputPath) []Related { return []Related{{Location: at(p)}} }
	draft := func(rule string, loc facts.InputPath, evidence, related []Related) FindingDraft {
		return FindingDraft{Rule: MustRuleID(rule), Location: at(loc), Evidence: evidence, Related: related}
	}
	findings := []Finding{
		{FindingDraft: draft("at-a", a, nil, nil)},
		{FindingDraft: draft("evidence-in-a", b, rel(a), nil)},
		{FindingDraft: draft("related-in-a", b, nil, rel(a))},
		{FindingDraft: draft("b-only", b, rel(b), nil)},
		{FindingDraft: draft("fact-file", b, []Related{{Location: Location{}}}, nil)},
	}
	quality := []QualityFinding{{FindingDraft: draft("q-evidence-in-a", b, rel(a), nil)}, {FindingDraft: draft("q-b-only", b, nil, nil)}}
	gap := func(loc facts.InputPath, related []Related) Finding {
		return Finding{FindingDraft: draft("r", loc, nil, related), Certainty: CertaintyInconclusive, InconclusiveKind: kindG}
	}
	findings = append(findings, gap(a, nil), gap(b, nil), gap(b, rel(a)))
	rep := Report{Findings: findings, QualityFindings: quality}

	all := rep.Narrow()
	if len(all.Findings) != 8 || len(all.QualityFindings) != 2 || len(all.FindingsWith(CertaintyInconclusive)) != 3 {
		t.Errorf("Narrow without Reported dropped places: %d, %d, %d", len(all.Findings), len(all.QualityFindings), len(all.FindingsWith(CertaintyInconclusive)))
	}
	rep.Reported = []facts.InputPath{a}
	got := rep.Narrow()
	var rules []string
	for _, f := range got.FindingsWith(CertaintyConfirmed, CertaintyConditional, CertaintyUnset) {
		rules = append(rules, f.Rule.String())
	}
	for _, f := range got.QualityFindings {
		rules = append(rules, f.Rule.String())
	}
	if want := []string{"at-a", "evidence-in-a", "related-in-a", "q-evidence-in-a"}; !slices.Equal(rules, want) {
		t.Errorf("kept %v, want %v", rules, want)
	}
	// an inconclusive finding is kept as the other findings are: by its
	// location, or by a related place in a reported input
	if g := got.FindingsWith(CertaintyInconclusive); len(g) != 2 || g[0].Location.File.Input != a || g[1].Location.File.Input != b {
		t.Errorf("inconclusive %v, want the one at a and the one at b related to a", g)
	}
	if again := got.Narrow(); len(again.Findings) != len(got.Findings) {
		t.Errorf("Narrow twice kept %d, once %d", len(again.Findings), len(got.Findings))
	}
}

func TestClassifyReported(t *testing.T) {
	a, b := facts.MustCleanInputPath("a.yml"), facts.MustCleanInputPath("b.yml")
	rep := Report{Inputs: []Input{{Name: a, State: InputStateRead}, {Name: b, State: InputStateInvalid}}}
	if got := Classify(rep, SeverityInfo); got != UnreadBit {
		t.Errorf("an invalid input, every input reported: %d, want %d", got, UnreadBit)
	}
	rep.Reported = []facts.InputPath{a}
	if got := Classify(rep, SeverityInfo); got != 0 {
		t.Errorf("an invalid input not reported: %d, want 0", got)
	}
	notNarrowed := rep
	notNarrowed.Findings = []Finding{{FindingDraft: FindingDraft{Rule: MustRuleID("r"), Location: Location{File: File{Input: b}}}, Severity: SeverityHigh, Certainty: CertaintyConfirmed}}
	if got := Classify(notNarrowed, SeverityInfo); got != 0 {
		t.Errorf("a finding in an input not reported, before Narrow: %d, want 0", got)
	}
	if got := rep.ReportedInputs(); len(got) != 1 || got[0].Name != a {
		t.Errorf("ReportedInputs = %v, want a.yml", got)
	}
	rep.Reported = []facts.InputPath{b}
	if got := Classify(rep, SeverityInfo); got != UnreadBit {
		t.Errorf("the invalid input reported: %d, want %d", got, UnreadBit)
	}
}

func TestReportReportedJSON(t *testing.T) {
	s := schemas(t)
	reg, _ := newRegistry(nil, true)
	in, err := Enumerate(fstest.MapFS{"x/action.yml": {Data: []byte(okAction)}, "y/action.yml": {Data: []byte(okAction)}})
	if err != nil {
		t.Fatal(err)
	}
	all, _ := json.Marshal(Run(context.Background(), in, reg, mapResolver{}))
	if !bytes.Contains(all, []byte(`"reported_inputs":["x/action.yml","y/action.yml"]`)) {
		t.Errorf("not every input in reported_inputs in\n%s", all)
	}
	in, err = in.WithReported([]facts.InputPath{facts.MustCleanInputPath("y/action.yml")})
	if err != nil {
		t.Fatal(err)
	}
	some, _ := json.Marshal(Run(context.Background(), in, reg, mapResolver{}))
	if !bytes.Contains(some, []byte(`"reported_inputs":["y/action.yml"]`)) {
		t.Errorf("no reported_inputs in\n%s", some)
	}
	unnarrowed := Report{Inputs: in.List, Reported: in.Reported, Findings: []Finding{{FindingDraft: FindingDraft{Rule: MustRuleID("r"), Location: Location{File: File{Input: facts.MustCleanInputPath("x/action.yml")}}}}}}
	if b, err := unnarrowed.MarshalJSON(); err != nil || !bytes.Contains(b, []byte(`"findings":[]`)) {
		t.Errorf("a finding in an input not reported is in the JSON (%v):\n%s", err, b)
	}
	for _, b := range [][]byte{all, some} {
		if err := s.Validate("report-v0.json", "#", b); err != nil {
			t.Errorf("does not fit report-v0.json: %v\n%s", err, b)
		}
	}
}
