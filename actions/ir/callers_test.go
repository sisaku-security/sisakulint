package ir

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/internal/callerstest"
	"github.com/sisaku-security/sisakulint/actions/taint"
)

const calledEcho = "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"

// calledIR is the IR of the called workflow among files, read with their
// callers.
func calledIR(t *testing.T, files ...[2]string) *IR {
	t.Helper()
	c := taint.NewCallers(callerstest.Graph(t, true, false, files...))
	f, ok := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(".github/workflows/called.yml")))
	if !ok {
		t.Fatal("no called.yml")
	}
	return New(f.Name.String(), f.Tree, f.Workflow, f.Action).WithCallers(func() *taint.Callers { return c })
}

func TestSinkWithOfCaller(t *testing.T) {
	x := calledIR(t, [2]string{".github/workflows/called.yml", calledEcho},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n"})
	r := x.allSinks()[0].refs[0]
	if len(r.With) != 1 || r.With[0].InputName() != ".github/workflows/ci.yml" || r.At.InputName() != ".github/workflows/called.yml" {
		t.Fatalf("ref = %+v", r)
	}
	b, sp, _, spanned := r.With[0].Locate()
	if !spanned || sp.Start >= sp.End || b.Node.Kind() == 0 {
		t.Fatalf("with at %v %v", b, sp)
	}
}

func TestCheckoutSiteOfCaller(t *testing.T) {
	called := "on:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v1\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	for _, tc := range []struct {
		on   string
		want bool
	}{{"push", false}, {"pull_request_target", true}} {
		x := calledIR(t, [2]string{".github/workflows/called.yml", called},
			[2]string{".github/workflows/ci.yml", "on: " + tc.on + "\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"})
		s := x.allCheckoutSites()
		if got := len(s) == 1 && len(s[0].prCodeOn) > 0; got != tc.want {
			t.Fatalf("%s: %+v", tc.on, s)
		}
	}
}

func TestIfSiteOfCaller(t *testing.T) {
	called := "on:\n  workflow_call:\njobs:\n  j:\n    if: github.actor == 'dependabot[bot]'\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	for _, tc := range []struct {
		on   string
		want int
	}{{"push", 0}, {"pull_request_target", 1}} {
		x := calledIR(t, [2]string{".github/workflows/called.yml", called},
			[2]string{".github/workflows/ci.yml", "on: " + tc.on + "\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"})
		if got := len(x.allIfSites()); got != tc.want {
			t.Fatalf("%s: %d if sites", tc.on, got)
		}
	}
}

// calledIRPartial is calledIR on inputs that are not the whole repository.
func calledIRPartial(t *testing.T, files ...[2]string) *IR {
	t.Helper()
	c := taint.NewCallers(callerstest.Graph(t, false, false, files...))
	f, ok := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(".github/workflows/called.yml")))
	if !ok {
		t.Fatal("no called.yml")
	}
	return New(f.Name.String(), f.Tree, f.Workflow, f.Action).WithCallers(func() *taint.Callers { return c })
}
