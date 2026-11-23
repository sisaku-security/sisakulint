package ir

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
	"github.com/gh-intel/sisakulint/actions/taint"
)

var useNames = map[analysis.ConfigurationVariableUse]string{
	analysis.ConfigurationVariableUseValue:    "value",
	analysis.ConfigurationVariableUseFromJSON: "from-json",
	analysis.ConfigurationVariableUseCompared: "compared",
}

// refsOf are the references of x, one line each: the name, the use and the
// environments.
func refsOf(x *IR) []string {
	var out []string
	for _, r := range x.allConfigurationVariableRefs() {
		var envs []string
		for _, e := range r.environments {
			envs = append(envs, e.String())
		}
		if r.environmentExpression {
			envs = append(envs, "${{}}")
		}
		line := fmt.Sprintf("%s %s [%s]", r.name, useNames[r.use], strings.Join(envs, ","))
		if r.remoteCallerOnly {
			line += " remote-caller-only"
		}
		out = append(out, line)
	}
	slices.Sort(out)
	return out
}

func wantRefs(t *testing.T, name string, x *IR, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := refsOf(x); !slices.Equal(got, want) {
		t.Errorf("%s:\n got %q\nwant %q", name, got, want)
	}
}

// TestConfigurationVariableRefUse: how a ${{ }} uses a reference, a node
// of the tree each.
func TestConfigurationVariableRefUse(t *testing.T) {
	step := func(run string) string {
		return "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: " + run + "\n"
	}
	for _, tc := range []struct {
		name, src string
		want      []string
	}{
		{"alone", step("echo ${{ vars.A }}"), []string{"A value []"}},
		{"index", step("echo ${{ vars['A'] }}"), []string{"A value []"}},
		{"or", step("echo ${{ vars.A || 'd' }}"), []string{"A compared []"}},
		{"or last", step("echo ${{ 'd' || vars.A }}"), []string{"A value []"}},
		{"and", step("echo ${{ vars.A && vars.B }}"), []string{"A compared []", "B value []"}},
		{"not", step("echo ${{ !vars.A }}"), []string{"A compared []"}},
		{"compare", step("echo ${{ vars.A == 'x' }}"), []string{"A compared []"}},
		{"contains", step("echo ${{ contains(vars.A, 'x') }}"), []string{"A compared []"}},
		{"case", step("echo ${{ case(vars.P, vars.V, vars.D) }}"), []string{"P compared []", "V value []", "D value []"}},
		{"format", step("echo ${{ format('{0}', vars.A, vars.B) }}"), []string{"A value []"}},
		{"fromJSON", step("echo ${{ fromJSON(vars.A).x }}"), []string{"A from-json []"}},
		{"join", step("echo ${{ join(vars.A, vars.S) }}"), []string{"A value []", "S value []"}},
		{"index by a name", step("echo ${{ vars[vars.N] }}"), []string{"N value []"}},
		{"not by name", step("echo ${{ vars[matrix.n] }} ${{ toJSON(vars) }}"), nil},
		{"two in a text", step("echo ${{ vars.A }}-${{ vars.B }}"), []string{"A value []", "B value []"}},
		{"if of a step", "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: a\n        if: vars.A\n      - run: b\n        if: ${{ fromJSON(vars.B) }}\n", []string{"A compared []", "B from-json []"}},
		{"format of a value", step("echo ${{ format(vars.F, vars.A) }}"), []string{"F value []", "A value []"}},
		{"case of two predicates", step("echo ${{ case(vars.P1, vars.V1, vars.P2, vars.V2, vars.D) }}"), []string{"P1 compared []", "V1 value []", "P2 compared []", "V2 value []", "D value []"}},
		{"if of or", "on: push\njobs:\n  j:\n    runs-on: x\n    if: vars.A || vars.B\n    steps: [{run: a}]\n", []string{"A compared []", "B compared []"}},
		{"matrix", "on: push\njobs:\n  j:\n    runs-on: x\n    strategy:\n      matrix:\n        os: ${{ fromJSON(vars.OSES) }}\n        v: [1, '${{ vars.V }}']\n    steps: [{run: a}]\n", []string{"V value []"}}, // os: the model has no values (the UndetectedForm unread-key)
		{"guarded fromJSON", step("echo ${{ vars.X && fromJSON(vars.X) }} ${{ vars.Y != '' && fromJSON(vars.Y) || 'd' }}"), []string{"X compared []", "X compared []", "Y compared []", "Y compared []"}},
		{"guard of another name", step("echo ${{ vars.A && fromJSON(vars.B) }}"), []string{"A compared []", "B from-json []"}},
		{"fromJSON of toJSON", step("echo ${{ fromJSON(toJSON(vars.X)) }} ${{ fromJSON(format('[{0}]', vars.Y)) }} ${{ fromJSON(format('{0}', vars.Z)) }}"), []string{"X value []", "Y value []", "Z from-json []"}},
		{"if of text", "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: a\n        if: ${{ vars.A }} == x\n", nil},
	} {
		wantRefs(t, tc.name, newIR(t, tc.src), tc.want...)
	}
}

// TestConfigurationVariableRefEnvironments: the environments of a key, by
// the run on GitHub of unseenKeys.
func TestConfigurationVariableRefEnvironments(t *testing.T) {
	src := `on: push
run-name: ${{ vars.RUN }}
env:
  W: ${{ vars.W }}
jobs:
  j:
    environment: prod
    name: ${{ vars.NAME }}
    if: vars.IF == 'x'
    runs-on: ${{ vars.RUNS_ON }}
    env:
      J: ${{ vars.J }}
    steps:
      - name: ${{ vars.STEP_NAME }}
        run: echo ${{ vars.RUN_STEP }}
    outputs:
      o: ${{ vars.OUT }}
  k:
    environment:
      name: staging
    runs-on: x
    steps: [{run: '${{ vars.K }}'}]
  e:
    environment: ${{ inputs.e }}
    runs-on: x
    steps: [{run: '${{ vars.E }}'}]
`
	wantRefs(t, "environments", newIR(t, src),
		"RUN value []", "W value [prod,staging,${{}}]", "NAME value []", "IF compared []", "RUNS_ON value [prod]", "J value [prod]",
		"STEP_NAME value [prod]", "RUN_STEP value [prod]", "OUT value [prod]", "K value [staging]", "E value [${{}}]")
}

// TestConfigurationVariableRefCaller: a workflow of workflow_call alone
// whose caller is among the inputs, or is not.
func TestConfigurationVariableRefCaller(t *testing.T) {
	called := "run-name: ${{ vars.R }}\non:\n  workflow_call:\njobs:\n  j:\n    runs-on: x\n    steps: [{run: '${{ vars.A }}'}]\n"
	both := "on:\n  workflow_call:\n  push:\njobs:\n  j:\n    runs-on: x\n    steps: [{run: '${{ vars.A }}'}]\n"
	caller := "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"
	irOf := func(name string, files ...[2]string) *IR {
		c := taint.NewCallers(callerstest.Graph(t, true, false, files...))
		f, ok := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(name)))
		if !ok {
			t.Fatal("no " + name)
		}
		return New(f.Name.String(), f.Tree, f.Workflow, f.Action).WithCallers(func() *taint.Callers { return c })
	}
	wantRefs(t, "no caller", irOf(".github/workflows/called.yml", [2]string{".github/workflows/called.yml", called}), "A value [] remote-caller-only")
	wantRefs(t, "a caller", irOf(".github/workflows/called.yml", [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", caller}), "A value []")
	wantRefs(t, "push too", irOf(".github/workflows/called.yml", [2]string{".github/workflows/called.yml", both}), "A value []")
}

// TestConfigurationVariableRefFolded: a reference in an if of ${{ '…' }}
// is at the whole value, with the whole value as its expression.
func TestConfigurationVariableRefFolded(t *testing.T) {
	const cond = "${{ 'vars.FOO == ''a''' }}"
	src := "on: push\njobs:\n  j:\n    if: " + cond + "\n    runs-on: x\n    steps: [{run: a}]\n"
	x := newIR(t, src)
	wantRefs(t, "folded", x, "FOO compared []")
	for _, r := range x.allConfigurationVariableRefs() {
		if r.expression != cond {
			t.Errorf("expression %q, want the whole value", r.expression)
		}
		if !wholeValue(r.at, src, cond) {
			t.Errorf("the reference is not at the whole value")
		}
	}
}
