package lint

import (
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

func TestLocationPositionLineText(t *testing.T) {
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo a\n      - name: Second\n        run: echo b\n"
	in, err := Enumerate(fstest.MapFS{".github/workflows/a.yml": {Data: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	job := in.List[0].Workflow.Jobs.Value.Entries[0].Value.Value
	l := At(in.List[0], job.Steps.Value.Items[1].Base)
	if got, want := l.Position(), (cst.Position{Line: 7, Column: 9}); got != want {
		t.Errorf("Position %+v, want %+v", got, want)
	}
	if got, want := l.LineText(), "      - name: Second"; got != want {
		t.Errorf("LineText %q, want %q", got, want)
	}
	run := job.Steps.Value.Items[1].Run.Value
	if got, want := At(in.List[0], run.Base).KeyPath().String(), "jobs.build.steps[1].run"; got != want {
		t.Errorf("KeyPath %q, want %q", got, want)
	}
	var zero Location
	if zero.Position() != (cst.Position{}) || zero.LineText() != "" || zero.KeyPath() != (KeyPath{}) || zero.NodeSpan() != (cst.Span{}) {
		t.Errorf("a zero Location: %+v %q %q", zero.Position(), zero.LineText(), zero.KeyPath())
	}
}

func TestConditionOpParts(t *testing.T) {
	name := func(s string) facts.InputPath {
		n, err := facts.CleanInputPath(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	leaf := InputPresent(name("a.yml"))
	c := All(leaf, Any(InputPresent(name("b.yml"))))
	if c.Op() != ConditionOpAll || leaf.Op() != ConditionOpLeaf || c.Parts()[1].Op() != ConditionOpAny {
		t.Fatalf("ops %v %v %v", c.Op(), leaf.Op(), c.Parts()[1].Op())
	}
	if len(leaf.Parts()) != 0 || len(c.Parts()) != 2 || len(c.Parts()[1].Parts()) != 1 {
		t.Fatalf("parts %d %d", len(leaf.Parts()), len(c.Parts()))
	}
	ps := c.Parts()
	ps[1] = leaf
	if c.Parts()[1].Op() != ConditionOpAny {
		t.Error("Parts is not a copy")
	}
}
