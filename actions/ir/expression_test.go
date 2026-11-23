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

// mistakesOf are the mistakes of x, one line each: the key, the error,
// the types and the ${{ }}, or text and the types for objectText.
func mistakesOf(x *IR) []string {
	var out []string
	for _, m := range x.allExpressionMistakes() {
		var types []string
		for _, t := range m.valueTypes {
			b, _ := t.MarshalJSON()
			types = append(types, strings.Trim(string(b), `"`))
		}
		if m.objectText {
			out = append(out, fmt.Sprintf("text %s %s", strings.Join(types, "|"), m.expression))
			continue
		}
		k, _ := m.expressionKey.MarshalJSON()
		e, _ := m.error.MarshalJSON()
		out = append(out, strings.TrimSpace(fmt.Sprintf("%s %s %s %s", strings.Trim(string(k), `"`), strings.Trim(string(e), `"`), strings.Join(types, "|"), m.expression)))
	}
	slices.Sort(out)
	return out
}

func wantMistakes(t *testing.T, name string, x *IR, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := mistakesOf(x); !slices.Equal(got, want) {
		t.Errorf("%s:\n got %q\nwant %q", name, got, want)
	}
}

// TestExpressionMistakes: one key of each kind, the text of a ${{ }}, the
// calls that fail, and the forms the rule must not report.
func TestExpressionMistakes(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      []string
	}{
		{"job keys", "on: push\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: ${{ github.event_name }}\n    continue-on-error: ${{ format('{0}', 'true') }}\n    strategy:\n      fail-fast: ${{ vars.F }}\n      max-parallel: ${{ inputs.x }}\n      matrix: ${{ needs.a.outputs.m }}\n    steps: [{run: a}]\n",
			[]string{"job-timeout-minutes value-type string ${{ github.event_name }}", "job-continue-on-error value-type string ${{ format('{0}', 'true') }}", "strategy-fail-fast value-type string ${{ vars.F }}"}},
		{"types that fit", "on: push\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: ${{ fromJSON(vars.T) }}\n    continue-on-error: ${{ github.event_name == 'push' }}\n    strategy:\n      matrix: {t: [5], f: [true]}\n    concurrency: {group: g, cancel-in-progress: '${{ matrix.f }}'}\n    steps:\n      - run: echo\n        timeout-minutes: ${{ matrix.t }}\n        env: {X: '${{ null }}', Y: '${{ 1 }}'}\n",
			nil},
		{"runs-on and environment", "on: push\njobs:\n  j:\n    runs-on: ${{ github }}\n    environment: ${{ fromJSON('{\"name\":\"e\",\"x\":\"1\"}') }}\n    steps: [{run: a}]\n  k:\n    runs-on: ${{ github.event }}\n    environment: ${{ fromJSON('{\"name\":\"e\"}') }}\n    steps: [{run: a}]\n",
			[]string{"runs-on value-type object ${{ github }}", `environment value-type object ${{ fromJSON('{"name":"e","x":"1"}') }}`}},
		{"failed job", "on: push\nenv:\n  X: ${{ github.event }}\njobs:\n  j:\n    runs-on: x\n    env: ${{ format('{0}', 'a') }}\n    outputs:\n      o: ${{ steps.s.outputs }}\n    steps:\n      - id: s\n        run: a\n",
			[]string{"workflow-env value-type object ${{ github.event }}", "job-env value-type string ${{ format('{0}', 'a') }}", "job-outputs value-type object ${{ steps.s.outputs }}"}},
		{"failed step", "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: ${{ github.event }}\n        working-directory: ${{ github.event.commits.*.id }}\n        if: ${{ case(github.event_name, true, false) }}\n      - env:\n          X: ${{ fromJSON(github.event) }}\n        run: echo \"${{ format('{0} {1}', 'a') }}\"\n",
			[]string{"step-run value-type object ${{ github.event }}", "step-working-directory value-type array ${{ github.event.commits.*.id }}", "step-if case-predicate  ${{ case(github.event_name, true, false) }}", "step-env fromjson-argument  ${{ fromJSON(github.event) }}", "step-run format-arguments  ${{ format('{0} {1}', 'a') }}"}},
		{"ignored setting", "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: a\n        env: {T: 5}\n        timeout-minutes: ${{ env.T }}\n        continue-on-error: ${{ github.run_number }}\n",
			[]string{"step-timeout-minutes value-type string ${{ env.T }}", "step-continue-on-error value-type string ${{ github.run_number }}"}},
		{"text", "on: push\njobs:\n  j:\n    name: n ${{ github.event }}\n    runs-on: x\n    strategy:\n      matrix: {c: [{a: 1}]}\n    steps:\n      - name: test ${{ matrix.c }}\n        run: echo \"${{ github.event.commits.*.id }} ${{ toJSON(github.event) }} ${{ null }}\"\n        if: ${{ github.event }} == x\n",
			[]string{"text object ${{ github.event }}", "text object ${{ matrix.c }}", "text array ${{ github.event.commits.*.id }}"}},
		{"not known", "on: push\njobs:\n  j:\n    runs-on: x\n    timeout-minutes: ${{ inputs.t || 30 }}\n    environment: ${{ github.event }}\n    steps:\n      - run: echo ${{ steps.nope.outputs }} ${{ github.event.pull_request }} ${{ fromJSON(inputs.x) }}\n        name: ${{ github.event }}\n        if: false && fromJSON(github.event)\n",
			nil},
		{"input default", "on:\n  workflow_call:\n    inputs:\n      b: {type: boolean, default: '${{ format(''{0}'', ''true'') }}'}\n      n: {type: number, default: '${{ github.event_name }}'}\n      s: {type: string, default: '${{ github.event_name == ''x'' }}'}\n      ok: {type: boolean, default: '${{ github.event_name == ''x'' }}'}\njobs:\n  j:\n    runs-on: x\n    steps: [{run: a}]\n",
			[]string{"input-default value-type string ${{ format('{0}', 'true') }}", "input-default value-type string ${{ github.event_name }}"}},
		// a call that fails in a default is not read (UndetectedForm default-call)
		{"input default call", "on:\n  workflow_call:\n    inputs:\n      s: {type: string, default: '${{ format(''{0}{1}'', ''a'') }}'}\njobs:\n  j:\n    runs-on: x\n    steps: [{run: a}]\n",
			nil},
		{"alias", "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: a\n        timeout-minutes: &t ${{ github.sha }}\n      - run: b\n        timeout-minutes: *t\n",
			[]string{"step-timeout-minutes value-type string ${{ github.sha }}", "step-timeout-minutes value-type string ${{ github.sha }}"}},
	} {
		wantMistakes(t, tc.name, newIR(t, tc.src), tc.want...)
	}
}

// TestExpressionMistakesAction: the steps and the outputs of an action.yml.
func TestExpressionMistakesAction(t *testing.T) {
	tree, a := parseAction(t, "inputs:\n  c: {default: 'true'}\noutputs:\n  o: {value: '${{ steps.s.outputs }}'}\nruns:\n  using: composite\n  steps:\n    - id: s\n      run: exit 1\n      shell: bash\n      continue-on-error: ${{ inputs.c }}\n      env: {X: '${{ github.event }}'}\n")
	x := New("a/action.yml", tree, nil, a)
	wantMistakes(t, "action", x, "action-outputs value-type object ${{ steps.s.outputs }}", "step-continue-on-error value-type string ${{ inputs.c }}", "step-env value-type object ${{ github.event }}")
}

// TestExpressionMistakesCall: the with of a call of a workflow among the
// inputs, by the types of its inputs.
func TestExpressionMistakesCall(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs:\n      b: {type: boolean}\n      n: {type: number}\n      s: {type: string}\njobs:\n  j:\n    runs-on: x\n    steps: [{run: a}]\n"
	caller := "on: push\njobs:\n  c:\n    strategy:\n      matrix: {n: [3]}\n    uses: ./.github/workflows/called.yml\n    with:\n      b: ${{ format('{0}', 'true') }}\n      n: ${{ matrix.n }}\n      s: ${{ github.ref_protected }}\n"
	x := callerIR(t, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", caller})
	wantMistakes(t, "call", x, "call-with value-type string ${{ format('{0}', 'true') }}")
	if m := x.allExpressionMistakes(); len(m) != 1 || m[0].expressionKey != analysis.ExpressionKeyCallWith {
		t.Errorf("mistakes %+v", m)
	}
}

// callerIR is the IR of .github/workflows/ci.yml among files, with its
// callers and callees read.
func callerIR(t *testing.T, files ...[2]string) *IR {
	t.Helper()
	c := taint.NewCallers(callerstest.Graph(t, true, false, files...))
	f, ok := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(".github/workflows/ci.yml")))
	if !ok {
		t.Fatal("no ci.yml")
	}
	return New(f.Name.String(), f.Tree, f.Workflow, f.Action).WithCallers(func() *taint.Callers { return c })
}

// TestExpressionMistakesFolded: the mistake of an if of ${{ '…' }}, in a
// step of a workflow and of an action.yml, is at the whole value, with the
// whole value as its expression: the spans of the expression are in the
// folded string, not in the value.
func TestExpressionMistakesFolded(t *testing.T) {
	const cond = "${{ 'case(github.event, ''a'', ''b'') == ''a''' }}"
	action := "name: x\ndescription: x\nruns:\n  using: composite\n  steps:\n    - if: " + cond + "\n      run: echo\n      shell: bash\n"
	workflow := "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - if: " + cond + "\n        run: echo\n"
	tree, a := parseAction(t, action)
	for _, c := range []struct {
		name, src string
		x         *IR
	}{
		{"workflow", workflow, newIR(t, workflow)},
		{"action.yml", action, New("a/action.yml", tree, nil, a)},
	} {
		wantMistakes(t, c.name, c.x, "step-if case-predicate  "+cond)
		for _, m := range c.x.allExpressionMistakes() {
			if !wholeValue(m.at, c.src, cond) {
				t.Errorf("%s: the mistake is not at the whole value", c.name)
			}
		}
	}
}
