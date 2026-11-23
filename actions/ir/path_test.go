package ir

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

func parse(t *testing.T, src string) (*cst.Tree, *workflow.Workflow) {
	t.Helper()
	tree := cst.Parse([]byte(src))
	w, _ := workflow.Parse(tree)
	return tree, w
}

func parseAction(t *testing.T, src string) (*cst.Tree, *workflow.ActionMetadata) {
	t.Helper()
	tree := cst.Parse([]byte(src))
	a, _ := workflow.ParseActionMetadata(tree)
	return tree, a
}

// TestPathsOfSteps: a step is [id] when its id is unique in the steps,
// else its index; keys are joined by dots, and a key that is not plain is
// a JSON string in brackets.
func TestPathsOfSteps(t *testing.T) {
	tree, w := parse(t, `on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - id: a
        run: echo
      - id: b
        run: echo
      - id: b
        run: echo
  "odd name":
    steps:
      - run: echo
`)
	p := NewPaths()
	var got []string
	for _, j := range w.Jobs.Value.Entries {
		for _, s := range j.Value.Value.Steps.Value.Items {
			got = append(got, p.Of(tree, s.Base.Node, s.Base.Via))
		}
	}
	want := []string{"jobs.build.steps[0]", "jobs.build.steps[a]", "jobs.build.steps[2]", "jobs.build.steps[3]", `jobs["odd name"].steps[0]`}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("step %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestKeyOfAliasedStep: a step reached through an alias has the path of
// the alias.
func TestKeyOfAliasedStep(t *testing.T) {
	tree, w := parse(t, `on: push
jobs:
  a:
    steps:
      - &s
        run: echo
  b:
    steps:
      - *s
`)
	s := w.Jobs.Value.Entries[1].Value.Value.Steps.Value.Items[0]
	k := keyOf(NewPaths(), ".github/workflows/w.yml", tree, s.Base)
	if k.Path() != "jobs.b.steps[0]" || k.Input() != ".github/workflows/w.yml" {
		t.Errorf("got %s", k)
	}
}

// TestPathsOfParallelSteps: a step of a parallel group is [id] in its group
// too, so that its path, and the fingerprint of a finding on it, do not
// change with its place in the group.
func TestPathsOfParallelSteps(t *testing.T) {
	tree, w := parse(t, `on: push
jobs:
  build:
    steps:
      - parallel:
          - run: echo
          - id: lint
            run: echo
`)
	p := NewPaths()
	var got []string
	for _, s := range w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items {
		got = append(got, p.Of(tree, s.Base.Node, s.Base.Via))
	}
	if want := []string{"jobs.build.steps[0].parallel[0]", "jobs.build.steps[0].parallel[lint]"}; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %q, want %q", got, want)
	}
}
