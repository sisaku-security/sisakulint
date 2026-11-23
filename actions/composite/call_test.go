package composite

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

func workflowQuery(t *testing.T, repo, path, ref string) facts.WorkflowDefinition {
	t.Helper()
	r, err := facts.ParseRepo(repo)
	if err != nil {
		t.Fatal(err)
	}
	p, err := facts.ParseUsesPath(path)
	if err != nil {
		t.Fatal(err)
	}
	return facts.WorkflowDefinition{Repo: r, Path: p, Ref: ref}
}

// defineWorkflow makes the answer of repo/path@ref the workflow content at
// the commit of c.
func (a *answers) defineWorkflow(t *testing.T, repo, path, ref string, c byte, content string) facts.WorkflowDefinition {
	t.Helper()
	q := workflowQuery(t, repo, path, ref)
	b, err := json.Marshal(facts.WorkflowFile{Commit: sha(t, c), Content: content})
	if err != nil {
		t.Fatal(err)
	}
	a.m[q] = facts.RawAnswer{State: facts.StateFound, Value: b, Source: facts.SourceGitHub}
	return q
}

// callJob is the first job of a workflow whose job a calls uses.
func callJob(t *testing.T, uses string) *workflow.Job {
	t.Helper()
	w, _ := workflow.Parse(cst.Parse([]byte("on: push\njobs:\n  a:\n    uses: " + uses + "\n")))
	if w == nil || len(w.Jobs.Value.Entries) == 0 {
		t.Fatal("no job")
	}
	j := w.Jobs.Value.Entries[0].Value.Value
	return &j
}

func calling(uses string) string {
	return "on: workflow_call\njobs:\n  c:\n    uses: " + uses + "\n"
}

const leaf = "on: workflow_call\njobs:\n  b:\n    runs-on: self-hosted\n    steps:\n      - run: echo hi\n"

// TestExpandCall: ExpandCall reads the reusable workflows of other
// repositories a job calls to MaxCallDepth (the one the job calls at depth
// 1), each repository, path and commit once; ./ and $/ in a called
// workflow are the same commit of its repository; a call with no answer
// is Unanswered, asked or not.
func TestExpandCall(t *testing.T) {
	a := newAnswers()
	a.defineWorkflow(t, "o/one", ".github/workflows/one.yml", "v1", '1', calling("o/two/.github/workflows/two.yml@v1"))
	a.defineWorkflow(t, "o/two", ".github/workflows/two.yml", "v1", '2', calling("./.github/workflows/three.yml"))
	a.defineWorkflow(t, "o/two", ".github/workflows/three.yml", "2222222222222222222222222222222222222222", '2', calling("o/four/.github/workflows/four.yml@v1"))
	a.defineWorkflow(t, "o/four", ".github/workflows/four.yml", "v1", '4', leaf)
	r := NewReader(nil, a)
	e := r.ExpandCall(context.Background(), callJob(t, "o/one/.github/workflows/one.yml@v1"))
	if len(e.Workflows) != MaxCallDepth {
		t.Fatalf("read %d workflows, want %d (depth 4 not read): %+v", len(e.Workflows), MaxCallDepth, e.Workflows)
	}
	last := e.Workflows[2]
	if len(last.Chain) != 3 || last.Chain[2].Uses != "./.github/workflows/three.yml" || last.Chain[2].Commit != sha(t, '2') || last.Workflow == nil {
		t.Errorf("depth 3: %+v", last)
	}
	if q, ok := last.Origin.Query.(facts.WorkflowDefinition); !ok || q.Ref != "2222222222222222222222222222222222222222" {
		t.Errorf("./ in a called workflow: %+v, want the commit of its repository", last.Origin.Query)
	}
	if n := a.asked[workflowQuery(t, "o/four", ".github/workflows/four.yml", "v1")]; n != 0 {
		t.Errorf("depth 4 asked %d times, want 0", n)
	}

	b := newAnswers()
	b.m[workflowQuery(t, "o/gone", ".github/workflows/x.yml", "v1")] = facts.RawAnswer{State: facts.StateUnknown, Reason: "403", Source: facts.SourceGitHub}
	e = NewReader(nil, b).ExpandCall(context.Background(), callJob(t, "o/gone/.github/workflows/x.yml@v1"))
	if len(e.Unanswered) != 1 || !e.Unanswered[0].Asked || e.Unanswered[0].Reason != "403" {
		t.Errorf("an unknown answer: %+v", e)
	}
	e = NewReader(nil, newAnswers()).ExpandCall(context.Background(), callJob(t, "o/unasked/.github/workflows/x.yml@v1"))
	if len(e.Unanswered) != 1 || e.Unanswered[0].Asked {
		t.Errorf("no answer: %+v", e)
	}
	if e := NewReader(nil, newAnswers()).ExpandCall(context.Background(), callJob(t, "./.github/workflows/local.yml")); len(e.Workflows)+len(e.Unanswered) != 0 {
		t.Errorf("a call of the inputs: %+v, want nothing", e)
	}
}

// TestExpandCallBy: each workflow read has the job that calls it and the
// index of the workflow that job is in (-1: the job ExpandCall reads).
func TestExpandCallBy(t *testing.T) {
	a := newAnswers()
	a.defineWorkflow(t, "o/one", ".github/workflows/one.yml", "v1", '1', calling("o/two/.github/workflows/two.yml@v1"))
	a.defineWorkflow(t, "o/two", ".github/workflows/two.yml", "v1", '2', leaf)
	j := callJob(t, "o/one/.github/workflows/one.yml@v1")
	e := NewReader(nil, a).ExpandCall(context.Background(), j)
	if len(e.Workflows) != 2 {
		t.Fatalf("read %d workflows, want 2", len(e.Workflows))
	}
	if e.Workflows[0].Parent != -1 || e.Workflows[0].By != j {
		t.Errorf("depth 1: Parent %d, By %p, want -1 and the job %p", e.Workflows[0].Parent, e.Workflows[0].By, j)
	}
	if e.Workflows[1].Parent != 0 || e.Workflows[1].By == nil || e.Workflows[1].By.ID.AsString() != "c" {
		t.Errorf("depth 2: Parent %d, By %+v, want 0 and the job c of one.yml", e.Workflows[1].Parent, e.Workflows[1].By)
	}
	if e.Workflows[1].By != &e.Workflows[0].Workflow.Jobs.Value.Entries[0].Value.Value {
		t.Error("depth 2: By is not the job of the workflow read at depth 1")
	}
}
