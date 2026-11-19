package attacker

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// stepIf is the if cond of the one step of a workflow on push, written as
// a double-quoted YAML string; with no cond the step has no if.
func stepIf(t *testing.T, cond string) workflow.Field[workflow.If] {
	t.Helper()
	src := "on: push\njobs:\n  a:\n    runs-on: u\n    steps:\n      - run: x\n"
	if cond != "" {
		src += "        if: \"" + cond + "\"\n"
	}
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	if w == nil {
		t.Fatalf("no workflow of %q", src)
	}
	e, _ := w.Jobs.Value.Lookup("a")
	return e.Value.Value.Steps.Value.Items[0].If
}

func TestStatusFunctions(t *testing.T) {
	n, err := expr.Parse("always () && (failure() || always()) && contains(x, 'success()')")
	if err != nil {
		t.Fatal(err)
	}
	if got := StatusFunctions(n, nil); !slices.Equal(got, []analysis.StatusFunction{analysis.StatusFunctionAlways, analysis.StatusFunctionFailure}) {
		t.Errorf("got %v", got)
	}
}

// TestHasStatusFunction: a call read in the syntax tree, in each ${{ }} of
// a mixed if, and in the string of a folded literal.
func TestHasStatusFunction(t *testing.T) {
	for _, c := range []struct {
		cond string
		want bool
	}{
		{"", false},
		{"${{ always() }}", true},
		{"${{ always () }}", true},
		{"ALWAYS()", true},
		{"failure() || github.event_name == 'push'", true},
		{"${{ !contains(github.event.pull_request.title, 'always()') }}", false},
		{"steps.success.outputs.x == 'y'", false},
		{"${{ always( }}", false},
		{"${{ always() }} && true", true},
		{"${{ 'always()' }}", true},
		{"'always()'", false},
		{"${{ 'github.event_name == ''push''' }}", false},
		{"${{ github.event_name }} == push", false},
	} {
		if got := HasStatusFunction(stepIf(t, c.cond)); got != c.want {
			t.Errorf("%q: got %v, want %v", c.cond, got, c.want)
		}
	}
}

// TestIfTree: the tree GitHub evaluates, with ${{ 'x' }} read as the
// expression x by the model; none for a mixed if, no if, or a syntax error.
func TestIfTree(t *testing.T) {
	call := func(name string) func(expr.Node) bool {
		return func(n expr.Node) bool { c, ok := n.(*expr.Call); return ok && c.Name == name }
	}
	compare := func(n expr.Node) bool { _, ok := n.(*expr.Compare); return ok }
	for _, c := range []struct {
		cond string
		want func(expr.Node) bool // nil for no tree
	}{
		{"always()", call("always")},
		{"${{ 'success()' }}", call("success")},
		{"${{ github.event_name == 'push' }}", compare},
		{"a ${{ always() }}", nil},
		{"", nil},
		{"${{ always( }}", nil},
	} {
		got, ok := IfTree(stepIf(t, c.cond))
		if c.want == nil {
			if ok {
				t.Errorf("%q: got a tree %T, want none", c.cond, got)
			}
			continue
		}
		if !ok || !c.want(got) {
			t.Errorf("%q: got %T (%v)", c.cond, got, ok)
		}
	}
}

// TestTrueOnlyOnSuccess: an if is true only when success() is true when it
// calls no status function, or when it is false with success() false and
// always() true.
func TestTrueOnlyOnSuccess(t *testing.T) {
	for _, c := range []struct {
		cond string
		want bool
	}{
		{"needs.build.result == 'failure'", true},
		{"${{ success() && needs.build.result == 'failure' }}", true},
		{"${{ success() }}", true},
		{"${{ always() && success() }}", true},
		{"${{ !cancelled() && needs.build.result == 'failure' }}", false},
		{"${{ always() && needs.build.result == 'failure' }}", false},
		{"${{ failure() }}", false},
		{"${{ success() || failure() }}", false},
		{"${{ !success() }}", false},
	} {
		if got := TrueOnlyOnSuccess(stepIfOn(t, "push", c.cond)); got != c.want {
			t.Errorf("%q: got %v, want %v", c.cond, got, c.want)
		}
	}
}
