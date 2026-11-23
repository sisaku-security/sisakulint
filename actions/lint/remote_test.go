package lint

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/taint"
)

// workflowAnswers answers workflow.definition from files by repo/path, at
// the commit of 40 times the digit; anything else has no answer.
type workflowAnswers map[string]string

func (a workflowAnswers) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	w, ok := q.(facts.WorkflowDefinition)
	if !ok {
		return facts.RawAnswer{}
	}
	content, ok := a[w.Repo.String()+"/"+w.Path.String()]
	if !ok {
		return facts.RawAnswer{}
	}
	b, err := json.Marshal(facts.WorkflowFile{Commit: mustSHA(strings.Repeat("e", 40)), Content: content})
	if err != nil {
		panic(err)
	}
	return facts.RawAnswer{State: facts.StateFound, Value: b, Source: facts.SourceFile}
}

// remoteCallers are the callers of the workflows files, with the remote
// called workflows a answers.
func remoteCallers(t *testing.T, a workflowAnswers, files map[string]string) (*taint.Callers, []*calls.RemoteCalled) {
	t.Helper()
	fs := fstest.MapFS{}
	for n, src := range files {
		fs[n] = &fstest.MapFile{Data: []byte(src)}
	}
	in, err := Enumerate(fs)
	if err != nil {
		t.Fatal(err)
	}
	in.Repo = mustRepo("me/app")
	c := callersOf(context.Background(), in, compositeReader(in, a))
	return c, c.Graph().Remotes()
}

const remoteEcho = "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"

// TestRemoteCalledEvents: a remote called workflow runs on the events of
// the job that calls it, which is its one caller.
func TestRemoteCalledEvents(t *testing.T) {
	c, rs := remoteCallers(t, workflowAnswers{"o/wf/.github/workflows/w.yml": remoteEcho}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n    with:\n      t: ${{ github.event.pull_request.title }}\n",
	})
	if len(rs) != 1 {
		t.Fatalf("%d remote called workflows, want 1", len(rs))
	}
	n := calls.RemoteNode(rs[0])
	evs, cov := c.Events(n, taint.TableEvents(), false)
	if cov != analysis.CallerCoverageAll || len(evs) == 0 || slices.ContainsFunc(evs, func(e analysis.EventActivity) bool { return e.Name().String() != "pull_request_target" }) {
		t.Fatalf("events %v, coverage %v", evs, cov)
	}
	r, _ := c.Input(n, "t", evs, nil)
	if len(r.With) != 1 || r.With[0].Node != calls.InputNode(facts.MustCleanInputPath(".github/workflows/ci.yml")) {
		t.Fatalf("with %+v, want the with of the job of ci.yml", r.With)
	}
	if r.Verdict != analysis.Controlled {
		t.Errorf("inputs.t is not an attacker's value: %+v", r)
	}
	if rs[0].Top.String() != ".github/workflows/ci.yml" || rs[0].TopJob.ID.AsString() != "c" {
		t.Errorf("top %v, job %v", rs[0].Top, rs[0].TopJob.ID.AsString())
	}
}

// TestRemoteCalledNested: the inputs of a remote called workflow at depth
// 2 are read from the with of the job of the one at depth 1, and through
// its inputs from the input.
func TestRemoteCalledNested(t *testing.T) {
	mid := "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  m:\n    uses: o/leaf/.github/workflows/l.yml@v1\n    with:\n      t: ${{ inputs.t }}\n"
	c, rs := remoteCallers(t, workflowAnswers{"o/mid/.github/workflows/m.yml": mid, "o/leaf/.github/workflows/l.yml": remoteEcho}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\njobs:\n  c:\n    uses: o/mid/.github/workflows/m.yml@v1\n    with:\n      t: ${{ github.event.pull_request.title }}\n",
	})
	if len(rs) != 2 {
		t.Fatalf("%d remote called workflows, want 2", len(rs))
	}
	leaf := calls.RemoteNode(rs[1])
	evs, _ := c.Events(leaf, taint.TableEvents(), false)
	r, _ := c.Input(leaf, "t", evs, nil)
	if r.Verdict != analysis.Controlled || len(r.With) != 2 || r.With[1].Node != calls.RemoteNode(rs[0]) || r.With[0].Node != calls.InputNode(facts.MustCleanInputPath(".github/workflows/ci.yml")) {
		t.Fatalf("depth 2: %+v, want the attacker's value through the with of m.yml and of ci.yml", r)
	}
	if rs[1].Top.String() != ".github/workflows/ci.yml" {
		t.Errorf("top %v", rs[1].Top)
	}
}

// TestRemoteCalledNotOwnRepository: a remote called workflow that names
// the repository of the run calls another version of an input, not the
// input itself.
func TestRemoteCalledNotOwnRepository(t *testing.T) {
	back := "on: workflow_call\njobs:\n  b:\n    uses: me/app/.github/workflows/called.yml@v2\n"
	c, _ := remoteCallers(t, workflowAnswers{"o/wf/.github/workflows/w.yml": back}, map[string]string{
		".github/workflows/ci.yml":     "on: push\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
		".github/workflows/called.yml": remoteEcho,
	})
	if cs := c.Graph().CallsOf(calls.InputNode(facts.MustCleanInputPath(".github/workflows/called.yml"))); len(cs) != 0 {
		t.Fatalf("calls of the input called.yml: %+v, want none", cs)
	}
}

// TestRemoteCalledTwoJobs: two jobs that call one file make two remote
// called workflows, one for each.
func TestRemoteCalledTwoJobs(t *testing.T) {
	_, rs := remoteCallers(t, workflowAnswers{"o/wf/.github/workflows/w.yml": remoteEcho}, map[string]string{
		".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    uses: o/wf/.github/workflows/w.yml@v1\n  b:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
	})
	if len(rs) != 2 || rs[0].TopJob.ID.AsString() != "a" || rs[1].TopJob.ID.AsString() != "b" {
		t.Fatalf("%d remote called workflows: %+v", len(rs), rs)
	}
}

// TestRemoteCalledInvalid: a file the model rejects is not read.
func TestRemoteCalledInvalid(t *testing.T) {
	_, rs := remoteCallers(t, workflowAnswers{"o/wf/.github/workflows/w.yml": "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: 3\n"}, map[string]string{
		".github/workflows/ci.yml": "on: push\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
	})
	if len(rs) != 0 {
		t.Fatalf("%d remote called workflows, want none", len(rs))
	}
}

func mustSHA(s string) facts.SHA {
	v, err := facts.ParseSHA(s)
	if err != nil {
		panic(err)
	}
	return v
}

func mustRepo(s string) facts.Repo {
	v, err := facts.ParseRepo(s)
	if err != nil {
		panic(err)
	}
	return v
}

// TestRemoteCalledOwnEventsLeftOut: a remote called workflow runs on the
// events of its caller only; its own on starts runs in its repository.
func TestRemoteCalledOwnEventsLeftOut(t *testing.T) {
	own := "on:\n  pull_request_target:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	c, rs := remoteCallers(t, workflowAnswers{"o/wf/.github/workflows/w.yml": own, "o/notcall/.github/workflows/n.yml": "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"}, map[string]string{
		".github/workflows/ci.yml": "on: push\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n  d:\n    uses: o/notcall/.github/workflows/n.yml@v1\n",
	})
	if len(rs) != 1 {
		t.Fatalf("%d remote called workflows, want 1 (a workflow without workflow_call is not called)", len(rs))
	}
	evs, _ := c.Events(calls.RemoteNode(rs[0]), taint.TableEvents(), false)
	if slices.ContainsFunc(evs, func(e analysis.EventActivity) bool { return e.Name().String() != "push" }) {
		t.Fatalf("events %v, want push alone", evs)
	}
}

// TestRemoteCalledOwnRepositoryByName: a job that calls a workflow of the
// repository of the run by its name calls the input, not a remote called
// workflow.
func TestRemoteCalledOwnRepositoryByName(t *testing.T) {
	_, rs := remoteCallers(t, workflowAnswers{"me/app/.github/workflows/called.yml": remoteEcho}, map[string]string{
		".github/workflows/ci.yml":     "on: push\njobs:\n  c:\n    uses: me/app/.github/workflows/called.yml@v2\n",
		".github/workflows/called.yml": remoteEcho,
	})
	if len(rs) != 0 {
		t.Fatalf("%d remote called workflows, want none", len(rs))
	}
}

// TestRemoteCalledTwoJobsOfOneWorkflow: two jobs of a remote called
// workflow that call one workflow make two, each with the with of its own
// job.
func TestRemoteCalledTwoJobsOfOneWorkflow(t *testing.T) {
	mid := "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  a:\n    uses: o/leaf/.github/workflows/l.yml@v1\n    with:\n      t: constant\n  b:\n    uses: o/leaf/.github/workflows/l.yml@v1\n    with:\n      t: ${{ inputs.t }}\n"
	c, rs := remoteCallers(t, workflowAnswers{"o/mid/.github/workflows/m.yml": mid, "o/leaf/.github/workflows/l.yml": remoteEcho}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\njobs:\n  c:\n    uses: o/mid/.github/workflows/m.yml@v1\n    with:\n      t: ${{ github.event.pull_request.title }}\n",
	})
	if len(rs) != 3 {
		t.Fatalf("%d remote called workflows, want 3", len(rs))
	}
	controlled := 0
	for _, r := range rs[1:] {
		n := calls.RemoteNode(r)
		evs, _ := c.Events(n, taint.TableEvents(), false)
		if ref, _ := c.Input(n, "t", evs, nil); ref.Verdict == analysis.Controlled {
			controlled++
		}
	}
	if controlled != 1 {
		t.Fatalf("%d of the two calls of l.yml have an attacker's inputs.t, want 1", controlled)
	}
}

// TestRelocateGapRelated: an inconclusive place in a remote called
// workflow is moved to the uses of the job of the input, with where it was
// and the uses of the jobs of the chain between in Related, and a detected
// text without the line; a place of the input stays where it is, with no
// related place added.
func TestRelocateGapRelated(t *testing.T) {
	mid := "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  m:\n    uses: o/leaf/.github/workflows/l.yml@v1\n    with:\n      t: ${{ inputs.t }}\n"
	in, err := Enumerate(fstest.MapFS{".github/workflows/ci.yml": {Data: []byte("on: pull_request_target\njobs:\n  c:\n    uses: o/mid/.github/workflows/m.yml@v1\n    with:\n      t: ${{ github.event.pull_request.title }}\n")}})
	if err != nil {
		t.Fatal(err)
	}
	in.Repo = mustRepo("me/app")
	m := gapMeta("remote-gaps")
	rule := testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		if c.remoteQuery == nil {
			return nil
		}
		for _, s := range steps(c) {
			c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: factAt(c.remoteQuery, c.tree, s.Base), Note: "a step"})
		}
		j := &c.input.Workflow.Jobs.Value.Entries[0].Value.Value
		c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, j.With.Value.Base), Note: "the with"})
		return nil
	}}
	reg, err := newRegistry([]Rule{rule}, true)
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), in, reg, workflowAnswers{"o/mid/.github/workflows/m.yml": mid, "o/leaf/.github/workflows/l.yml": remoteEcho})
	if len(rep.Errors) != 0 {
		t.Fatalf("errors: %+v", rep.Errors)
	}
	var moved, stayed []Finding
	for _, f := range rep.FindingsWith(CertaintyInconclusive) {
		if f.Note == "the with" {
			stayed = append(stayed, f)
		} else {
			moved = append(moved, f)
		}
	}
	if len(moved) != 1 || len(stayed) != 2 {
		t.Fatalf("moved %d, stayed %d; want 1 (the step of l.yml) and 2 (the with, once for each remote called workflow)", len(moved), len(stayed))
	}
	f := moved[0]
	if f.Location.File.Query != nil || f.Location.File.Input.String() != ".github/workflows/ci.yml" {
		t.Errorf("location %+v, want the uses of the job of ci.yml", f.Location.File)
	}
	if f.Note != "a step" || strings.Contains(f.Detected(), "line") {
		t.Errorf("note %q, detected %q: want the note of the rule, without the line", f.Note, f.Detected())
	}
	if len(f.Related) != 2 {
		t.Fatalf("related %+v, want where it was and the uses of the job of m.yml", f.Related)
	}
	if q, ok := f.Related[0].Location.File.Query.(facts.WorkflowDefinition); !ok || q.Path.String() != ".github/workflows/l.yml" || !strings.HasPrefix(f.Related[0].Note, "the place is in the reusable workflow ") {
		t.Errorf("related[0] %+v, want the step of l.yml", f.Related[0])
	}
	if q, ok := f.Related[1].Location.File.Query.(facts.WorkflowDefinition); !ok || q.Path.String() != ".github/workflows/m.yml" {
		t.Errorf("related[1] %+v, want the uses of the job of m.yml", f.Related[1])
	}
	for _, g := range stayed {
		if len(g.Related) != 0 {
			t.Errorf("a place of the input has related places %+v", g.Related)
		}
	}
}
