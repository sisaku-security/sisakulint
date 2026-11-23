package ir

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/composite"
	"github.com/sisaku-security/sisakulint/actions/facts"
)

// TestRemoteCalls: a job that calls a reusable workflow of another
// repository has its called jobs' runs-on labels and cache-mode, and their
// steps, with handles in the value of workflow.definition; a call with no
// answer is unanswered; a local call and a runner job are none.
func TestRemoteCalls(t *testing.T) {
	repo, _ := facts.ParseRepo("o/w")
	path, _ := facts.ParseUsesPath(".github/workflows/called.yml")
	q := facts.WorkflowDefinition{Repo: repo, Path: path, Ref: "v1"}
	sha, _ := facts.ParseSHA(strings.Repeat("1", 40))
	v, _ := json.Marshal(facts.WorkflowFile{Commit: sha, Content: "on: workflow_call\njobs:\n  b:\n    runs-on: [self-hosted, linux]\n    cache-mode: write\n    steps:\n      - uses: actions/cache@v4\n"})
	d := definitions{q: {State: facts.StateFound, Value: v, Source: facts.SourceGitHub}}
	r := composite.NewReader(nil, d)
	x := newIR(t, "on: push\njobs:\n  a:\n    uses: o/w/.github/workflows/called.yml@v1\n  gone:\n    uses: o/gone/.github/workflows/x.yml@v1\n  local:\n    uses: ./.github/workflows/local.yml\n  run:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n").WithComposite(context.Background(), r)
	cs := x.allRemoteCalls()
	if len(cs) != 2 {
		t.Fatalf("%d calls, want 2: %+v", len(cs), cs)
	}
	c := cs[0]
	if len(c.jobs) != 1 || c.jobs[0].ID != "b" || c.jobs[0].CacheModeText != "write" || len(c.jobs[0].RunnerLabels) != 2 || !c.jobs[0].RunnerLabels[0].HasSelfHostedLabel || c.jobs[0].Query != q {
		t.Fatalf("jobs %+v", c.jobs)
	}
	if fq, tree := c.jobs[0].CacheModeAt.Fact(); fq != q || tree == nil {
		t.Errorf("the handle of the cache-mode is not in the value of the fact: %v", fq)
	}
	if len(c.steps) != 1 || c.steps[0].Repo != "actions/cache" || c.steps[0].Ref != "v4" || c.steps[0].Chain[0].Commit != sha {
		t.Errorf("steps %+v", c.steps)
	}
	if u := cs[1].unanswered; len(u) != 1 || u[0].Asked || u[0].Chain[0].Uses != "o/gone/.github/workflows/x.yml@v1" {
		t.Errorf("unanswered %+v", u)
	}
	if cs := newIR(t, "on: push\njobs:\n  a:\n    uses: o/w/.github/workflows/called.yml@v1\n").allRemoteCalls(); len(cs) != 0 {
		t.Errorf("without a reader: %d calls", len(cs))
	}
}
