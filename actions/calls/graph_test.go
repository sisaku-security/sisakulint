package calls_test

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
)

const called = `on:
  workflow_call:
    inputs:
      t: {type: string}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.t }}"
`

const composite = "runs:\n  using: composite\n  steps:\n    - run: echo \"${{ inputs.t }}\"\n      shell: bash\n"

func name(s string) calls.Node { return calls.InputNode(facts.MustCleanInputPath(s)) }

func TestJobCall(t *testing.T) {
	for _, uses := range []string{"./.github/workflows/called.yml", "$/.github/workflows/called.yml"} {
		g := callerstest.Graph(t, true, false,
			[2]string{".github/workflows/called.yml", called},
			[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: " + uses + "\n    with:\n      t: x\n"})
		cs := g.CallsOf(name(".github/workflows/called.yml"))
		if len(cs) != 1 || cs[0].Caller.String() != ".github/workflows/ci.yml" || cs[0].StepIndex != -1 || !cs[0].Resolved || cs[0].Job == nil {
			t.Fatalf("%s: calls = %+v", uses, cs)
		}
		if c := g.Coverage(name(".github/workflows/called.yml")); c != analysis.CallerCoverageAll {
			t.Fatalf("%s: coverage = %v", uses, c)
		}
	}
}

func TestCoverageNotComplete(t *testing.T) {
	g := callerstest.Graph(t, false, false,
		[2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"})
	if c := g.Coverage(name(".github/workflows/called.yml")); c != analysis.CallerCoveragePartial {
		t.Fatalf("coverage = %v", c)
	}
}

func TestCoverageNone(t *testing.T) {
	g := callerstest.Graph(t, true, false, [2]string{".github/workflows/called.yml", called})
	if c := g.Coverage(name(".github/workflows/called.yml")); c != analysis.CallerCoverageNone {
		t.Fatalf("coverage = %v", c)
	}
}

func TestStepCallC1(t *testing.T) {
	for _, tc := range []struct {
		name, checkout string
		resolved       bool
	}{
		{"plain", "      - uses: actions/checkout@v4\n", true},
		{"ref", "      - uses: actions/checkout@v4\n        with: {ref: main}\n", false},
		{"repository", "      - uses: actions/checkout@v4\n        with: {repository: o/r}\n", false},
		{"path", "      - uses: actions/checkout@v4\n        with: {path: sub}\n", false},
		{"other input", "      - uses: actions/checkout@v4\n        with: {fetch-depth: 0}\n", true},
		{"none", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ci := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + tc.checkout + "      - uses: ./x\n        with: {t: y}\n"
			g := callerstest.Graph(t, true, false, [2]string{"x/action.yml", composite}, [2]string{".github/workflows/ci.yml", ci})
			cs := g.CallsOf(name("x/action.yml"))
			if len(cs) != 1 || cs[0].Resolved != tc.resolved || cs[0].Step == nil {
				t.Fatalf("calls = %+v", cs)
			}
			want := analysis.CallerCoverageAll
			if !tc.resolved {
				want = analysis.CallerCoveragePartial
			}
			if c := g.Coverage(name("x/action.yml")); c != want {
				t.Fatalf("coverage = %v", c)
			}
		})
	}
}

func TestActionYaml(t *testing.T) {
	ci := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./x/\n"
	g := callerstest.Graph(t, true, false, [2]string{"x/action.yaml", composite}, [2]string{".github/workflows/ci.yml", ci})
	if cs := g.CallsOf(name("x/action.yaml")); len(cs) != 1 {
		t.Fatalf("calls = %+v", cs)
	}
}

// TestResolvedLocalPath: ./ is resolved as GitHub resolves it, and one
// above the workspace calls no input.
func TestResolvedLocalPath(t *testing.T) {
	for _, tc := range []struct {
		uses  string
		calls int
	}{
		{"./acts/b/../../x", 1},
		{"./acts/../x/.", 1},
		{"./../x", 0},
	} {
		ci := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: " + tc.uses + "\n"
		g := callerstest.Graph(t, true, false, [2]string{"x/action.yml", composite}, [2]string{".github/workflows/ci.yml", ci})
		if cs := g.CallsOf(name("x/action.yml")); len(cs) != tc.calls {
			t.Errorf("%s: calls = %+v", tc.uses, cs)
		}
	}
}

func TestInComposite(t *testing.T) {
	for _, tc := range []struct {
		uses     string
		resolved bool
	}{{"$/x", true}, {"./x", false}} {
		outer := "runs:\n  using: composite\n  steps:\n    - uses: " + tc.uses + "\n      with: {t: y}\n"
		g := callerstest.Graph(t, true, false, [2]string{"x/action.yml", composite}, [2]string{"o/action.yml", outer})
		cs := g.CallsOf(name("x/action.yml"))
		if len(cs) != 1 || cs[0].Resolved != tc.resolved || cs[0].Job != nil {
			t.Fatalf("%s: calls = %+v", tc.uses, cs)
		}
	}
}

func TestCoverageExcluded(t *testing.T) {
	ci := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./x\n"
	g := callerstest.Graph(t, true, true, [2]string{"x/action.yml", composite}, [2]string{".github/workflows/ci.yml", ci})
	if c := g.Coverage(name("x/action.yml")); c != analysis.CallerCoveragePartial {
		t.Fatalf("coverage = %v", c)
	}
	// a workflow's callers are in .github/workflows, which is never left out
	g = callerstest.Graph(t, true, true,
		[2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"})
	if c := g.Coverage(name(".github/workflows/called.yml")); c != analysis.CallerCoverageAll {
		t.Fatalf("workflow: coverage = %v", c)
	}
}

func TestCallsOrder(t *testing.T) {
	caller := "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/called.yml\n  b:\n    uses: ./.github/workflows/called.yml\n"
	g := callerstest.Graph(t, true, false,
		[2]string{".github/workflows/z.yml", caller},
		[2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/a.yml", caller})
	cs := g.CallsOf(name(".github/workflows/called.yml"))
	var got []string
	for _, c := range cs {
		got = append(got, c.Caller.String()+"#"+c.Job.ID.AsString())
	}
	want := []string{".github/workflows/a.yml#a", ".github/workflows/a.yml#b", ".github/workflows/z.yml#a", ".github/workflows/z.yml#b"}
	if len(got) != len(want) {
		t.Fatalf("calls = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("calls = %v", got)
		}
	}
}

func TestDependents(t *testing.T) {
	mid := "on:\n  workflow_call:\njobs:\n  n:\n    uses: ./.github/workflows/called.yml\n"
	g := callerstest.Graph(t, true, false,
		[2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/mid.yml", mid},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/mid.yml\n"})
	got := g.Dependents(name(".github/workflows/ci.yml"))
	if len(got) != 2 || got[0].String() != ".github/workflows/called.yml" || got[1].String() != ".github/workflows/mid.yml" {
		t.Fatalf("dependents = %v", got)
	}
	if got := g.Dependents(name(".github/workflows/called.yml")); len(got) != 0 {
		t.Fatalf("dependents of a leaf = %v", got)
	}
}

func TestFile(t *testing.T) {
	g := callerstest.Graph(t, true, false, [2]string{".github/workflows/called.yml", called})
	if f, ok := g.File(name(".github/workflows/called.yml")); !ok || f.Workflow == nil {
		t.Fatalf("file = %+v", f)
	}
	if _, ok := g.File(name("nope.yml")); ok {
		t.Fatal("found a file not given")
	}
}

func TestIsCheckout(t *testing.T) {
	for _, c := range []struct {
		uses string
		want bool
	}{
		{"actions/checkout@v4", true},
		{"actions/checkout@0123456789012345678901234567890123456789", true},
		{"Actions/Checkout@v7", true},
		{"actions/checkout/sub@v4", false},
		{"actions/checkout-x@v4", false},
		{"./.github/actions/checkout", false},
		{"docker://actions/checkout", false},
		{"${{ 'actions/checkout@v4' }}", true},
		// GitHub reads the path past . and empty parts
		{"actions/checkout/.@v4", true},
		{"actions/checkout/@v4", true},
		{"actions/checkout/x/..@v4", true},
		{"actions/checkout/..@v4", false},
	} {
		src := "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + c.uses + "\n"
		u := callerstest.File(t, ".github/workflows/w.yml", src).Workflow.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[0].Uses.Value
		if got := calls.IsCheckout(u); got != c.want {
			t.Errorf("IsCheckout(%s) = %v", c.uses, got)
		}
	}
}

// TestRootAction: uses: ./ names the action.yml at the root.
func TestRootAction(t *testing.T) {
	ci := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./\n"
	g := callerstest.Graph(t, true, false, [2]string{"action.yml", composite}, [2]string{".github/workflows/ci.yml", ci})
	if cs := g.CallsOf(name("action.yml")); len(cs) != 1 || !cs[0].Resolved {
		t.Fatalf("calls = %+v", cs)
	}
}

// TestInvalidEdges: a job calls a workflow that can be called, a step an
// action; GitHub refuses the rest.
func TestInvalidEdges(t *testing.T) {
	dispatch := "on: workflow_dispatch\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	g := callerstest.Graph(t, true, false,
		[2]string{".github/workflows/d.yml", dispatch},
		[2]string{"x/action.yml", composite},
		[2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/d.yml\n  b:\n    uses: ./x\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/workflows/called.yml\n"})
	for _, n := range []string{".github/workflows/d.yml", "x/action.yml", ".github/workflows/called.yml"} {
		if cs := g.CallsOf(name(n)); len(cs) != 0 {
			t.Errorf("%s: calls = %+v", n, cs)
		}
	}
}

// TestRemoteFormSelfCall: a caller that names a workflow or action of the
// repository by owner/repo/path@ref runs it as another version, so the
// called one's callers are not all resolved: by the repository's name, or,
// when it is not known, by a
// path that is an input.
func TestRemoteFormSelfCall(t *testing.T) {
	prt := "on: pull_request_target\njobs:\n  c:\n    uses: me/repo/.github/workflows/called.yml@main\n    with:\n      t: x\n"
	ci := "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"
	for _, tc := range []struct {
		name string
		repo facts.Repo
		want analysis.CallerCoverage
	}{
		{"named", mustRepo(t, "me/repo"), analysis.CallerCoveragePartial},
		{"name in another case", mustRepo(t, "Me/Repo"), analysis.CallerCoveragePartial},
		{"not known", facts.Repo{}, analysis.CallerCoveragePartial},
		{"another repository", mustRepo(t, "other/repo"), analysis.CallerCoverageAll},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := calls.New([]calls.File{
				callerstest.File(t, ".github/workflows/called.yml", called),
				callerstest.File(t, ".github/workflows/ci.yml", ci),
				callerstest.File(t, ".github/workflows/prt.yml", prt),
			}, true, false, tc.repo)
			if c := g.Coverage(name(".github/workflows/called.yml")); c != tc.want {
				t.Fatalf("coverage = %v", c)
			}
		})
	}
}

func mustRepo(t *testing.T, s string) facts.Repo {
	t.Helper()
	r, err := facts.ParseRepo(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestStepCallParallel: the checkouts a local action may see are those it
// may run after, those of its parallel group too; one that a later
// checkout covers, done before the step, is not.
func TestStepCallParallel(t *testing.T) {
	for _, tc := range []struct {
		name, steps string
		resolved    bool
	}{
		{"a ref checkout alongside, written after", "      - uses: actions/checkout@v4\n      - parallel:\n          - uses: ./x\n            with: {t: y}\n          - uses: actions/checkout@v4\n            with: {ref: main}\n", false},
		{"a plain checkout in the group before", "      - parallel:\n          - uses: actions/checkout@v4\n          - run: make\n      - uses: ./x\n        with: {t: y}\n", true},
		{"a ref checkout covered after", "      - uses: actions/checkout@v4\n        with: {ref: main}\n      - parallel:\n          - uses: actions/checkout@v4\n      - uses: ./x\n        with: {t: y}\n", true},
		{"a background ref checkout waited after a plain one", "      - id: r\n        uses: actions/checkout@v4\n        with: {ref: main}\n        background: true\n      - uses: actions/checkout@v4\n      - wait: r\n      - uses: ./x\n        with: {t: y}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ci := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + tc.steps
			g := callerstest.Graph(t, true, false, [2]string{"x/action.yml", composite}, [2]string{".github/workflows/ci.yml", ci})
			cs := g.CallsOf(name("x/action.yml"))
			if len(cs) != 1 || cs[0].Resolved != tc.resolved {
				t.Fatalf("calls = %+v", cs)
			}
		})
	}
}

// TestCalledBy: the calls a caller makes, with the input each calls; a
// call of what is not among the inputs is not there.
func TestCalledBy(t *testing.T) {
	g := callerstest.Graph(t, true, false,
		[2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n  d:\n    uses: ./.github/workflows/none.yml\n  e:\n    uses: ./.github/workflows/called.yml\n"})
	cs := g.CalledBy(name(".github/workflows/ci.yml"))
	if len(cs) != 2 || cs[0].Called != name(".github/workflows/called.yml") || cs[0].Job == nil || cs[0].Job.ID.AsString() != "c" || cs[1].Job.ID.AsString() != "e" {
		t.Fatalf("CalledBy = %+v", cs)
	}
	if cs := g.CalledBy(name(".github/workflows/called.yml")); len(cs) != 0 {
		t.Fatalf("called calls: %+v", cs)
	}
}
