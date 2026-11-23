package job

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// TestDispatchInputs: a ${{ }} that refers to an input of workflow_dispatch
// anywhere in it, in a workflow with workflow_dispatch (with workflow_call
// too), is the dispatch's; the inputs of a workflow with workflow_call
// alone, github.event.inputs without workflow_dispatch, vars and matrix
// are not.
func TestDispatchInputs(t *testing.T) {
	const (
		dispatch = "on:\n  workflow_dispatch:\n    inputs:\n      x: {}\n"
		both     = "on:\n  workflow_call:\n    inputs:\n      x: {type: string}\n  workflow_dispatch:\n    inputs:\n      x: {}\n"
		call     = "on:\n  workflow_call:\n    inputs:\n      x: {type: string}\n"
		push     = "on: push\n"
	)
	for _, c := range []struct {
		on, value string
		want      bool
	}{
		{dispatch, "${{ inputs.x }}", true},
		{dispatch, "${{ github.event.inputs.x }}", true},
		{dispatch, "${{ inputs.big && 'self-hosted' || 'ubuntu-latest' }}", true},
		{dispatch, "${{ format('{0}-latest', inputs.x) }}", true},
		{dispatch, "x-${{ inputs.x }}", true},
		{dispatch, "${{ fromJSON(vars.R)[inputs.x] }}", true},
		{dispatch, "${{ matrix[inputs.x] }}", true},
		{dispatch, "${{ INPUTS.x }}", true},
		{both, "${{ inputs.x }}", true},
		{call, "${{ inputs.x }}", false},
		{push, "${{ github.event.inputs.x }}", false},
		{dispatch, "${{ fromJSON(vars.R) }}", false},
		{dispatch, "${{ matrix.os }}", false},
		{dispatch, "ubuntu-latest", false},
	} {
		w := parse(t, c.on+"jobs:\n  a:\n    runs-on: \""+c.value+"\"\n    steps:\n      - run: echo\n")
		if got := DispatchInputs(w, runsOnValue(w)); got != c.want {
			t.Errorf("%q in %q: %v, want %v", c.value, c.on, got, c.want)
		}
	}
	if DispatchInputs(nil, runsOnValue(parse(t, dispatch+"jobs:\n  a:\n    runs-on: '${{ inputs.x }}'\n    steps:\n      - run: echo\n"))) {
		t.Error("a nil workflow has inputs of a dispatch")
	}
}

// runsOnValue is the runs-on of the first job of w: the whole ${{ }}, or
// the first label.
func runsOnValue(w *workflow.Workflow) workflow.String {
	j := w.Jobs.Value.Entries[0].Value.Value
	if j.RunsOn.Status == workflow.Dynamic {
		return *j.RunsOn.Expr
	}
	return j.RunsOn.Value.Items[0]
}

// TestRunnerLabelsDispatch: a label of runs-on, or a value of the matrix
// it takes, that has an input of workflow_dispatch is marked Dispatch;
// another ${{ }} is not.
func TestRunnerLabelsDispatch(t *testing.T) {
	for _, c := range []struct {
		name, runsOn, strategy string
		want                   []bool
	}{
		{"input", "${{ inputs.runner }}", "", []bool{true}},
		{"list", "[self-hosted, '${{ inputs.runner }}']", "", []bool{true}},
		{"matrix value", "${{ matrix.os }}", "    strategy:\n      matrix: {os: ['${{ inputs.os }}', ubuntu-latest]}\n", []bool{true}},
		{"dynamic matrix", "${{ matrix.os }}", "    strategy:\n      matrix: {os: '${{ fromJSON(inputs.o) }}'}\n", []bool{false}},
		{"vars", "${{ vars.RUNNER }}", "", []bool{false}},
	} {
		j := one(t, "on:\n  workflow_dispatch:\n    inputs:\n      runner: {}\n      os: {}\n      o: {}\njobs:\n  a:\n    runs-on: "+c.runsOn+"\n"+c.strategy+"    steps:\n      - run: echo\n")
		var got []bool
		for _, g := range j.InconclusiveLabels {
			got = append(got, g.Dispatch)
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: %+v, want %v", c.name, j.InconclusiveLabels, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: %+v, want %v", c.name, j.InconclusiveLabels, c.want)
			}
		}
	}
}
