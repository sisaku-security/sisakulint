package reportview

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/rules"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// offline answers every fact Unknown, as the command does by default.
type offline struct{}

func (offline) Resolve(context.Context, facts.Query) facts.RawAnswer {
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "offline"}
}

// runOn runs every rule on the files, offline, as the command does by default.
func runOn(t *testing.T, files map[string]string) (lint.Report, lint.Inputs) {
	t.Helper()
	m := fstest.MapFS{}
	for p, s := range files {
		m[p] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := lint.Enumerate(m)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(context.Background(), in, reg, offline{})
	if len(rep.Errors) != 0 {
		t.Fatalf("errors %+v", rep.Errors)
	}
	return rep, in
}

func inputPath(t *testing.T, s string) facts.InputPath {
	t.Helper()
	n, err := facts.CleanInputPath(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

const aliased = `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - &s
        name: Shared
        run: echo a
  b:
    runs-on: ubuntu-latest
    steps:
      - run: echo first
      - *s
`

func TestLocate(t *testing.T) {
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(aliased)}})
	if err != nil {
		t.Fatal(err)
	}
	w := in.List[0].Workflow
	a, b := w.Jobs.Value.Entries[0].Value.Value, w.Jobs.Value.Entries[1].Value.Value
	for _, c := range []struct {
		name string
		at   lint.Location
		want place
		via  bool
	}{
		{"the step in a", lint.At(in.List[0], a.Steps.Value.Items[0].Base), place{"a", "Shared"}, false},
		{"the first step of b, with no name", lint.At(in.List[0], b.Steps.Value.Items[0].Base), place{"b", "#1"}, false},
		{"the alias in b", lint.At(in.List[0], b.Steps.Value.Items[1].Base), place{"b", "Shared"}, true},
		{"the job b", lint.At(in.List[0], b.Base), place{"b", ""}, false},
		{"a file of a fact", lint.Location{File: lint.File{Query: facts.RepoPublic{}}}, place{}, false},
	} {
		if got := locate(in, c.at); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
		n, err := nodeOf(in, RoleEvidence, c.at, "")
		if err != nil {
			t.Fatal(err)
		}
		if n.Via != c.via {
			t.Errorf("%s: via %v", c.name, n.Via)
		}
	}
}

const injected = `on: issues
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Greet
        run: echo "${{ github.event.issue.title }}"
`

func TestBuildPath(t *testing.T) {
	rep, in := runOn(t, map[string]string{".github/workflows/w.yml": injected})
	p, err := Build(rep, in, testRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(p.Findings, func(f Finding) bool { return f.Rule.String() == "code-injection" })
	if i < 0 {
		t.Fatalf("no code-injection in %+v", p.Findings)
	}
	path := p.Findings[i].Path
	if path[0].Role != RoleEvent || !slices.Equal(path[0].Events, []workflow.EventName{workflow.EventNameIssues}) {
		t.Errorf("the first node %+v", path[0])
	}
	last := path[len(path)-1]
	if last.Role != RoleFinding || last.Job != "build" || last.Step != "Greet" || last.Line != 8 {
		t.Errorf("the last node %+v", last)
	}
	if last.Source != `        run: echo "${{ github.event.issue.title }}"` {
		t.Errorf("source %q", last.Source)
	}
	if last.KeyPath != "jobs.build.steps[0].run" {
		t.Errorf("key path %q", last.KeyPath)
	}
}

func TestBuildMergesLastEvidence(t *testing.T) {
	rep, in := runOn(t, map[string]string{".github/workflows/w.yml": injected})
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		n := len(f.Evidence)
		if n == 0 || !sameSpot(f.Evidence[n-1].Location, f.Location) {
			continue
		}
		p, err := Build(lint.Report{Findings: []lint.Finding{f}}, in, testRegistry(t))
		if err != nil {
			t.Fatal(err)
		}
		path := p.Findings[0].Path
		roles := 0
		for _, x := range path {
			if x.Role == RoleFinding {
				roles++
			}
		}
		if roles != 1 || path[len(path)-1].Note != f.Evidence[n-1].Note {
			t.Errorf("%s: %+v", f.Detected(), path)
		}
		return
	}
	// Make one: the evidence ends where the finding is.
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	f.Evidence = append(f.Evidence, lint.Related{Location: f.Location, Note: "used here"})
	p, err := Build(lint.Report{Findings: []lint.Finding{f}}, in, testRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	path := p.Findings[0].Path
	if last := path[len(path)-1]; last.Role != RoleFinding || last.Note != "used here" || path[len(path)-2].Role == RoleFinding {
		t.Errorf("%+v", path)
	}
}

func TestConditionOf(t *testing.T) {
	q := facts.RepoPublic{}
	eq, err := lint.FactEq(q, true)
	if err != nil {
		t.Fatal(err)
	}
	c := lint.All(eq, lint.InputPresent(inputPath(t, "x.yml")))
	answer := answers([]facts.Entry{{Query: q, RawAnswer: facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage("true"), Source: facts.SourceFile}}})
	look := func(facts.InputPath) lint.LookupState { return lint.LookupUnknown }
	id := 0
	got, err := conditionOf(c, answer, look, &id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Op != op(lint.ConditionOpAll) || got.ID != 0 || len(got.Parts) != 2 {
		t.Fatalf("%+v", got)
	}
	l0, l1 := got.Parts[0], got.Parts[1]
	if l0.ID != 1 || l0.Truth != truth(expr.TruthTrue) || l0.Text == "" {
		t.Errorf("the fact leaf %+v", l0)
	}
	if l1.ID != 2 || l1.Truth != truth(expr.TruthUnknown) {
		t.Errorf("the input leaf %+v", l1)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Op    string `json:"op"`
		Parts []struct {
			Op    string `json:"op"`
			Truth string `json:"truth"`
		} `json:"parts"`
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Op != "all" || back.Parts[0].Op != "leaf" || back.Parts[0].Truth != "true" || back.Parts[1].Truth != "unknown" {
		t.Errorf("%s", b)
	}
}

const aliasedInjection = `on: issues
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - &s
        name: Shared
        run: echo "${{ github.event.issue.title }}"
  b:
    runs-on: ubuntu-latest
    steps:
      - run: echo first
      - *s
`

// A place inside a value reached through an alias (AtSpan) is in the job
// and the step of the outermost alias, not of the anchor.
func TestLocateAtSpanThroughAlias(t *testing.T) {
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(aliasedInjection)}})
	if err != nil {
		t.Fatal(err)
	}
	b := in.List[0].Workflow.Jobs.Value.Entries[1].Value.Value
	run := b.Steps.Value.Items[1].Run.Value
	l := lint.AtSpan(in.List[0], run.Base, run.Node.ContentSpan(), true)
	if got, want := locate(in, l), (place{"b", "Shared"}); got != want {
		t.Errorf("%+v, want %+v", got, want)
	}
}

// Two keys under one alias have the same Span (the alias's); they are two
// places, not one.
func TestSameSpotKeysUnderAlias(t *testing.T) {
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(aliasedInjection)}})
	if err != nil {
		t.Fatal(err)
	}
	s := in.List[0].Workflow.Jobs.Value.Entries[1].Value.Value.Steps.Value.Items[1]
	name, run := lint.At(in.List[0], s.Name.Value.Base), lint.At(in.List[0], s.Run.Value.Base)
	if name.Span != run.Span {
		t.Fatalf("the spans differ: %v %v", name.Span, run.Span)
	}
	if sameSpot(name, run) {
		t.Error("the name and the run of an aliased step are one spot")
	}
	if !sameSpot(run, run) {
		t.Error("a place is not its own spot")
	}
}

// When a list of steps or a whole job is reached through an alias, every
// step has the alias's span; the step is the one the element is in.
func TestLocateAliasedListAndJob(t *testing.T) {
	for name, src := range map[string]string{
		"job": `on: issues
permissions: {}
jobs:
  a: &job
    runs-on: ubuntu-latest
    steps:
      - name: First
        run: echo hi
      - name: Second
        run: echo "${{ github.event.issue.title }}"
  b: *job
`,
		"steps": `on: issues
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps: &list
      - name: First
        run: echo hi
      - name: Second
        run: echo "${{ github.event.issue.title }}"
  b:
    runs-on: ubuntu-latest
    steps: *list
`,
	} {
		in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(src)}})
		if err != nil {
			t.Fatal(err)
		}
		b := in.List[0].Workflow.Jobs.Value.Entries[1].Value.Value
		run := b.Steps.Value.Items[1].Run.Value
		for _, l := range []lint.Location{lint.At(in.List[0], run.Base), lint.AtSpan(in.List[0], run.Base, run.Node.ContentSpan(), true)} {
			if got, want := locate(in, l), (place{"b", "Second"}); got != want {
				t.Errorf("%s: %+v, want %+v", name, got, want)
			}
		}
	}
}

const twoSteps = `on: issues
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
      - name: Later
        run: echo done
`

// Evidence in a later step of the job than the finding runs after it (a
// checkout or a download, then the step that runs what it brings): the
// finding comes before it in the path, in the order the steps run.
func TestBuildOrdersByStep(t *testing.T) {
	rep, in := runOn(t, map[string]string{".github/workflows/w.yml": twoSteps})
	i := slices.IndexFunc(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), func(f lint.Finding) bool { return f.Rule.String() == "code-injection" })
	if i < 0 {
		t.Fatal("no code-injection")
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[i]
	later := in.List[0].Workflow.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[1]
	f.Evidence = []lint.Related{{Location: lint.At(in.List[0], later.Base), Note: "runs it"}}
	p, err := Build(lint.Report{Findings: []lint.Finding{f}}, in, testRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range p.Findings[0].Path {
		got = append(got, roleNames[n.Role]+" "+n.Step)
	}
	if want := []string{"event ", "finding #1", "evidence Later"}; !slices.Equal(got, want) {
		t.Errorf("%q, want %q", got, want)
	}
}

// qualityRun is the run of the example id that shows what of the quality
// rule rule, with every rule and quality rule, and the first quality
// finding of rule on it.
func qualityRun(t *testing.T, rule string, what lint.ExampleWhat, id string) (lint.ExampleRun, lint.QualityFinding, *lint.Registry) {
	t.Helper()
	reg, err := lint.NewRegistry(rules.All(), rules.Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range rules.Examples() {
		if x.Rule.String() != rule || x.What != what || x.ID != id {
			continue
		}
		run, err := reg.RunExample(context.Background(), x.Example, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range run.Report.QualityFindings {
			if f.Rule.String() == rule {
				return run, f, reg
			}
		}
		t.Fatalf("no quality finding of %s on %s", rule, id)
	}
	t.Fatalf("no example %s %s", rule, id)
	return lint.ExampleRun{}, lint.QualityFinding{}, nil
}

// TestBuildQuality: a quality finding is drawn as a finding is: its place
// in its job and step, its related places with their notes, and its
// condition with the truth of each leaf by the answers; one in a file of a
// fact has no input.
func TestBuildQuality(t *testing.T) {
	run, f, reg := qualityRun(t, "cache-bloat", lint.ExampleTruePositive, "partial-restore.split")
	p, err := Build(lint.Report{QualityFindings: []lint.QualityFinding{f}}, run.Inputs, reg)
	if err != nil {
		t.Fatal(err)
	}
	q := p.QualityFindings[0]
	if q.KindID.String() != "cache-bloat.partial-restore" || q.Detected == "" || q.Remedy == "" || q.Consequence == "" {
		t.Errorf("%+v", q)
	}
	if len(q.Path) != 1 || q.Path[0].Role != RoleFinding || q.Path[0].Job != "build" || q.Path[0].Input == nil || len(q.Path[0].Snippet) == 0 {
		t.Errorf("the path %+v", q.Path)
	}
	if len(q.Related) != 1 || q.Related[0].Role != RoleRelated || q.Related[0].Note != "restores with restore-keys" {
		t.Errorf("the related places %+v", q.Related)
	}
	all, err := Build(run.Report, run.Inputs, reg)
	if err != nil || len(all.QualityFindings) != len(run.Report.QualityFindings) {
		t.Errorf("%d quality findings of %d (%v)", len(all.QualityFindings), len(run.Report.QualityFindings), err)
	}

	run, f, reg = qualityRun(t, "archived-uses", lint.ExampleTruePositive, "archived-repository")
	p, err = Build(lint.Report{QualityFindings: []lint.QualityFinding{f}, Facts: run.Report.Facts}, run.Inputs, reg)
	if err != nil {
		t.Fatal(err)
	}
	c := p.QualityFindings[0].Condition
	if c == nil || c.Op != op(lint.ConditionOpLeaf) || c.Truth != truth(expr.TruthTrue) {
		t.Errorf("the condition %+v", c)
	}

	f.Location = lint.Location{File: lint.File{Query: facts.RepoPublic{}}}
	p, err = Build(lint.Report{QualityFindings: []lint.QualityFinding{f}}, run.Inputs, reg)
	if err != nil {
		t.Fatal(err)
	}
	if n := p.QualityFindings[0].Path[0]; n.Query == nil || n.Input != nil {
		t.Errorf("the place in a file of a fact %+v", n)
	}
}

// TestBuildQualityOnly: a report of quality findings alone has the files
// they are in, and no finding.
func TestBuildQualityOnly(t *testing.T) {
	run, f, reg := qualityRun(t, "cache-bloat", lint.ExampleTruePositive, "partial-restore.split")
	p, err := Build(lint.Report{QualityFindings: []lint.QualityFinding{f}}, run.Inputs, reg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Findings == nil || len(p.Findings) != 0 || len(p.Files) != 1 {
		t.Errorf("findings %v, files %d", p.Findings, len(p.Files))
	}
}
