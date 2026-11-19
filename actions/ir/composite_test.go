package ir

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/composite"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// definitions answers action.definition from a map, as a file of facts.
type definitions map[facts.Query]facts.RawAnswer

func (d definitions) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	if r, ok := d[q]; ok {
		return r
	}
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "nothing to ask"}
}

const compositeWorkflow = `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: o/a@v1
      - uses: ./local
      - run: echo hi
`

// TestCompositeCalls: a step that runs a remote composite action and one
// that runs a local one are summaries; the steps inside have handles in
// the file they are written in: the value of action.definition, or the
// input.
func TestCompositeCalls(t *testing.T) {
	repo, _ := facts.ParseRepo("o/a")
	q := facts.ActionDefinition{Repo: repo, Ref: "v1"}
	sha, _ := facts.ParseSHA(strings.Repeat("1", 40))
	v, _ := json.Marshal(facts.ActionFile{Commit: sha, File: facts.ActionFileYML, Content: "runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n      with:\n        path: x\n"})
	d := definitions{q: {State: facts.StateFound, Value: v, Source: facts.SourceGitHub}}
	localTree, local := parseAction(t, "runs:\n  using: composite\n  steps:\n    - run: echo local\n      shell: bash\n")
	localName := facts.MustCleanInputPath("local/action.yml")
	r := composite.NewReader(func(target string) (facts.InputPath, *cst.Tree, *workflow.ActionMetadata, bool) {
		if target == "local" {
			return localName, localTree, local, true
		}
		return facts.InputPath{}, nil, nil, false
	}, d)
	x := newIR(t, compositeWorkflow).WithComposite(context.Background(), r)
	cs := x.allCompositeCalls()
	var got []string
	for _, c := range cs {
		got = append(got, c.usesText+"@"+c.key.Path())
	}
	// actions/checkout@v4 has no answer: no one answered it
	if want := "actions/checkout@v4@jobs.j.steps[0].uses o/a@v1@jobs.j.steps[1].uses ./local@jobs.j.steps[2].uses"; strings.Join(got, " ") != want {
		t.Fatalf("calls %q, want %q", strings.Join(got, " "), want)
	}
	if u := cs[0].unanswered; len(u) != 1 || u[0].Asked || u[0].Chain[0].Uses != "actions/checkout@v4" {
		t.Errorf("unanswered %+v", u)
	}
	remote := cs[1]
	if len(remote.steps) != 1 || remote.steps[0].Repo != "actions/cache" || remote.steps[0].Ref != "v4" || remote.steps[0].Query != q {
		t.Fatalf("steps %+v", remote.steps)
	}
	fq, tree := remote.steps[0].At.Fact()
	if fq != q || tree == nil || remote.steps[0].At.InputName() != "" {
		t.Errorf("the handle of a remote step is not in the value of the fact: %v %v %q", fq, tree, remote.steps[0].At.InputName())
	}
	if b, _, _, _ := remote.steps[0].At.Locate(); !strings.HasPrefix(string(tree.Bytes()[b.Node.ContentSpan().Start:]), "uses: actions/cache@v4") {
		t.Errorf("the handle is not on the step")
	}
	if a := remote.actions; len(a) != 1 || a[0].File != facts.ActionFileYML || a[0].Chain[0].Commit != sha {
		t.Errorf("actions %+v", a)
	}
	l := cs[2]
	if len(l.steps) != 1 || l.steps[0].Input != localName || l.steps[0].At.InputName() != "local/action.yml" {
		t.Errorf("local steps %+v", l.steps)
	}
	if fq, _ := l.steps[0].At.Fact(); fq != nil {
		t.Errorf("a local step has a fact: %v", fq)
	}
}

// TestCompositeCallsWithoutReader: an IR without a reader has none.
func TestCompositeCallsWithoutReader(t *testing.T) {
	if cs := newIR(t, compositeWorkflow).allCompositeCalls(); len(cs) != 0 {
		t.Errorf("%d calls", len(cs))
	}
}
