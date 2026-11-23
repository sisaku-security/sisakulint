package lint

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// TestClassifyUnreadBit: an input of the run not read or not valid is bit
// 16, not bit 2.
func TestClassifyUnreadBit(t *testing.T) {
	a, b := facts.MustCleanInputPath("a.yml"), facts.MustCleanInputPath("b.yml")
	for _, s := range []InputState{InputStateUnreadable, InputStateInvalid} {
		rep := Report{Inputs: []Input{{Name: a, State: InputStateRead}, {Name: b, State: s}}}
		if got := Classify(rep, SeverityInfo); got != UnreadBit {
			t.Errorf("%s input: %d, want %d", s, got, UnreadBit)
		}
	}
}

// TestClassifyNoInput: bit 2 for no input is no input read at all; an
// empty reported list with inputs read sets nothing.
func TestClassifyNoInput(t *testing.T) {
	a, x := facts.MustCleanInputPath("a.yml"), facts.MustCleanInputPath("x/action.yml")
	read := Input{Name: a, State: InputStateRead}
	excluded := Input{Name: x, State: InputStateExcluded}
	for _, c := range []struct {
		name string
		rep  Report
		want uint8
	}{
		{"no input", Report{}, UndecidedBit},
		{"only excluded inputs", Report{Inputs: []Input{excluded}}, UndecidedBit},
		{"inputs read, none reported (a pull request that changes no input)", Report{Inputs: []Input{read}, Reported: []facts.InputPath{}}, 0},
		{"reported only an excluded one (--read-all)", Report{Inputs: []Input{read, excluded}, Reported: []facts.InputPath{x}}, UndecidedBit},
	} {
		if got := Classify(c.rep, SeverityInfo); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// TestClassifyCounted: the exit code counts the counted inputs, wider than
// the reported ones: a finding outside the PATHs sets bit 1.
func TestClassifyCounted(t *testing.T) {
	a, b := facts.MustCleanInputPath("a.yml"), facts.MustCleanInputPath("b.yml")
	rep := Report{
		Inputs:   []Input{{Name: a, State: InputStateRead}, {Name: b, State: InputStateRead}},
		Reported: []facts.InputPath{a},
		Counted:  []facts.InputPath{a, b},
		Findings: []Finding{{FindingDraft: FindingDraft{Rule: MustRuleID("r"), Location: Location{File: File{Input: b}}}, Severity: SeverityHigh, Certainty: CertaintyConfirmed}},
	}
	if got := Classify(rep, SeverityInfo); got != ConfirmedBit {
		t.Errorf("a finding in a counted input not reported: %d, want %d", got, ConfirmedBit)
	}
	if got := rep.Narrow(); len(got.Findings) != 0 {
		t.Errorf("Narrow kept %d findings outside the reported inputs", len(got.Findings))
	}
	if got := rep.CountedInputs(); len(got) != 2 {
		t.Errorf("CountedInputs = %v", got)
	}
}

// TestClassifyUnreadCallee: a counted input that calls an input not read
// sets bit 16, though the callee is not counted.
func TestClassifyUnreadCallee(t *testing.T) {
	fsys := fstest.MapFS{
		".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./x\n")},
		"x/action.yml":            {Data: []byte("\xff\xfe")},
		"y/action.yml":            {Data: []byte(okAction)},
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := newRegistry(nil, true)
	w := facts.MustCleanInputPath(".github/workflows/w.yml")
	reported, err := in.WithReported([]facts.InputPath{w})
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), reported, reg, mapResolver{})
	if got := Classify(rep, SeverityInfo); got&UnreadBit == 0 {
		t.Errorf("w.yml calls x, not read: %d, want bit %d", got, UnreadBit)
	}
	other, _ := in.WithReported([]facts.InputPath{facts.MustCleanInputPath("y/action.yml")})
	if got := Classify(Run(context.Background(), other, reg, mapResolver{}), SeverityInfo); got&UnreadBit != 0 {
		t.Errorf("y calls nothing: %d, want no bit %d", got, UnreadBit)
	}
}

// TestClassifyUnreadCalleeDeep: an input not read that a callee of a
// callee calls sets bit 16 too.
func TestClassifyUnreadCalleeDeep(t *testing.T) {
	fsys := fstest.MapFS{
		".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./x\n")},
		"x/action.yml":            {Data: []byte("runs:\n  using: composite\n  steps:\n    - uses: $/y\n")},
		"y/action.yml":            {Data: []byte("\xff\xfe")},
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := newRegistry(nil, true)
	reported, err := in.WithReported([]facts.InputPath{facts.MustCleanInputPath(".github/workflows/w.yml")})
	if err != nil {
		t.Fatal(err)
	}
	if got := Classify(Run(context.Background(), reported, reg, mapResolver{}), SeverityInfo); got&UnreadBit == 0 {
		t.Errorf("w.yml calls x, which calls y, not read: %d, want bit %d", got, UnreadBit)
	}
}

// TestReportedInputsNotNull: reported_inputs is always the names.
func TestReportedInputsNotNull(t *testing.T) {
	reg, _ := newRegistry(nil, true)
	in, err := Enumerate(fstest.MapFS{"x/action.yml": {Data: []byte(okAction)}, "y/action.yml": {Data: []byte(okAction)}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(Run(context.Background(), in, reg, mapResolver{}))
	if !bytes.Contains(b, []byte(`"reported_inputs":["x/action.yml","y/action.yml"]`)) {
		t.Errorf("reported_inputs not every name in\n%s", b)
	}
	s := schemas(t)
	null := bytes.Replace(b, []byte(`"reported_inputs":["x/action.yml","y/action.yml"]`), []byte(`"reported_inputs":null`), 1)
	if err := s.Validate("report-v0.json", "#", null); err == nil {
		t.Error("the schema takes a null reported_inputs")
	}
	if !slices.Contains(ClassifyReasons(Report{Inputs: []Input{{Name: facts.MustCleanInputPath("a.yml"), State: InputStateUnreadable}}}, SeverityInfo)[UnreadBit], "inputs not read") {
		t.Error("no reason for bit 16")
	}
}

// TestNarrowKeepsCountedPlaces: Narrow drops the places of the counted
// inputs not reported from the arrays, and Classify and Unreported still
// count them.
func TestNarrowKeepsCountedPlaces(t *testing.T) {
	a, b := facts.MustCleanInputPath("a.yml"), facts.MustCleanInputPath("b.yml")
	at := func(p facts.InputPath) Location { return Location{File: File{Input: p}} }
	rep := Report{
		Inputs:   []Input{{Name: a, State: InputStateRead}, {Name: b, State: InputStateRead}},
		Reported: []facts.InputPath{a},
		Counted:  []facts.InputPath{a, b},
		Rules:    []RuleRef{{ID: MustRuleID("r"), Severity: SeverityHigh}},
		Findings: []Finding{{FindingDraft: FindingDraft{Rule: MustRuleID("r"), Location: at(b)}, Severity: SeverityHigh, Certainty: CertaintyConfirmed},
			{FindingDraft: FindingDraft{Rule: MustRuleID("r"), Location: at(b)}, Severity: SeverityHigh, Certainty: CertaintyInconclusive}},
		QualityFindings: []QualityFinding{{FindingDraft: FindingDraft{Rule: MustRuleID("q"), Location: at(b)}}},
	}
	n := rep.Narrow().Narrow()
	if len(n.Findings)+len(n.QualityFindings) != 0 {
		t.Errorf("Narrow kept places of b: %+v", n)
	}
	if got := Classify(n, SeverityInfo); got != ConfirmedBit|InconclusiveBit {
		t.Errorf("Classify after Narrow = %d, want %d", got, ConfirmedBit|InconclusiveBit)
	}
	if got := n.Unreported(); got != (UnreportedCount{Findings: 2, QualityFindings: 1, Inconclusive: 1}) {
		t.Errorf("Unreported = %+v", got)
	}
	if got := rep.Unreported(); got != (UnreportedCount{}) {
		t.Errorf("Unreported before Narrow = %+v, want zero", got)
	}
}

// TestClassifyPullRequestBits: in a pull request run, a change of the base
// after the merge base and a changed input under --exclude set bit 16, and
// a changed input under --exclude alone is not bit 2.
func TestClassifyPullRequestBits(t *testing.T) {
	a, x := facts.MustCleanInputPath("a.yml"), facts.MustCleanInputPath("x/action.yml")
	base := Report{Inputs: []Input{{Name: a, State: InputStateRead}, {Name: x, State: InputStateExcluded}}, Reported: []facts.InputPath{}}
	pr := func(p PullRequestRevision) Report {
		r := base
		r.Remote = &RemoteRevision{PullRequest: &p}
		return r
	}
	if got := Classify(pr(PullRequestRevision{}), SeverityInfo); got != 0 {
		t.Errorf("a pull request that changes nothing: %d", got)
	}
	if got := Classify(pr(PullRequestRevision{BaseChangeCount: 2}), SeverityInfo); got != UnreadBit {
		t.Errorf("the base changed: %d, want %d", got, UnreadBit)
	}
	excluded := pr(PullRequestRevision{ChangedInputs: []facts.InputPath{x}})
	excluded.Counted = []facts.InputPath{x}
	if got := Classify(excluded, SeverityInfo); got != UnreadBit {
		t.Errorf("an excluded changed input: %d, want %d", got, UnreadBit)
	}
}

// TestRemoteRevisionSchema: a report of a remote run, with and without a
// pull request, fits report-v0.json.
func TestRemoteRevisionSchema(t *testing.T) {
	s := schemas(t)
	repo, _ := facts.ParseRepo("o/r")
	sha, _ := facts.ParseSHA("0123456789abcdef0123456789abcdef01234567")
	a := facts.MustCleanInputPath("a.yml")
	rev := &RemoteRevision{Repository: repo, Commit: sha, Tree: sha, ReadFiles: []RemoteFile{{Path: a, Blob: sha, Mode: "100644"}}}
	for _, pr := range []*PullRequestRevision{nil, {Number: 3, Base: sha, MergeBase: sha, BehindBy: 2, ChangedInputs: []facts.InputPath{a}, UnreportedCount: UnreportedCount{Findings: 1}, BaseChangeCount: 1, AcceptedCount: 1}} {
		rev.PullRequest = pr
		b, err := json.Marshal(Report{Inputs: []Input{{Name: a, InputKind: InputKindWorkflow, State: InputStateRead}}, Remote: rev})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Validate("report-v0.json", "#", b); err != nil {
			t.Errorf("does not fit report-v0.json: %v\n%s", err, b)
		}
	}
}
