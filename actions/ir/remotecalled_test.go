package ir

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
	"github.com/gh-intel/sisakulint/actions/taint"
)

// TestRemoteIRHandles: the places of the IR of a remote called workflow
// are in the value of workflow.definition, and the with of its caller is
// in the input of the caller.
func TestRemoteIRHandles(t *testing.T) {
	g := callerstest.Graph(t, true, false, [2]string{".github/workflows/ci.yml",
		"on: issues\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n    with:\n      t: ${{ github.event.issue.title }}\n"})
	ci, _ := g.File(calls.InputNode(facts.MustCleanInputPath(".github/workflows/ci.yml")))
	job := &ci.Workflow.Jobs.Value.Entries[0].Value.Value
	called := callerstest.File(t, ".github/workflows/w.yml", calledEcho)
	repo, err := facts.ParseRepo("o/wf")
	if err != nil {
		t.Fatal(err)
	}
	path, err := facts.ParseUsesPath(".github/workflows/w.yml")
	if err != nil {
		t.Fatal(err)
	}
	q := facts.WorkflowDefinition{Repo: repo, Path: path, Ref: "v1"}
	r := &calls.RemoteCalled{Called: composite.Called{Workflow: called.Workflow, Origin: composite.Origin{Query: q, Tree: called.Tree}, By: job, Parent: -1}, Top: ci.Name, TopJob: job}
	g.AddRemote(r, calls.Call{Caller: ci.Node(), Job: job, StepIndex: -1, With: job.With, Resolved: true})
	c := taint.NewCallers(g)
	x := NewRemote(r).WithCallers(func() *taint.Callers { return c })
	sinks := x.allSinks()
	if len(sinks) != 1 || len(sinks[0].refs) != 1 {
		t.Fatalf("sinks %+v", sinks)
	}
	ref := sinks[0].refs[0]
	if got, _ := ref.At.Fact(); got != facts.Query(q) || ref.At.InputName() != "" {
		t.Errorf("the reference is at %v %q, want in the value of %v", got, ref.At.InputName(), q)
	}
	if len(ref.With) != 1 || ref.With[0].InputName() != ".github/workflows/ci.yml" {
		t.Errorf("with %+v, want the with of the job of ci.yml", ref.With)
	}
	if ref.Verdict != analysis.Controlled {
		t.Errorf("verdict %v", ref.Verdict)
	}
}
