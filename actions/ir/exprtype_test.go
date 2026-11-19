package ir

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/expr"
)

// typeIn is the type of the expression src where c reads it; nil when it
// is not known.
func typeIn(t *testing.T, c contextTypes, src string) []expr.ValueType {
	t.Helper()
	n, errs := expr.Parse(src)
	if len(errs) > 0 {
		t.Fatalf("%s: %v", src, errs)
	}
	ty := expr.TypeOfExpr(n, c.lookup)
	if !ty.Known() {
		return nil
	}
	return ty.ValueTypes()
}

func wantTypes(t *testing.T, c contextTypes, tests map[string][]expr.ValueType) {
	t.Helper()
	for src, want := range tests {
		if got := typeIn(t, c, src); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", src, got, want)
		}
	}
}

var (
	tBoolean = []expr.ValueType{expr.ValueBoolean}
	tNumber  = []expr.ValueType{expr.ValueNumber}
	tString  = []expr.ValueType{expr.ValueString}
	tObject  = []expr.ValueType{expr.ValueObject}
)

// TestContextTypes: the types of the contexts, by contextTypes.
func TestContextTypes(t *testing.T) {
	src := "on:\n" +
		"  workflow_call:\n    inputs:\n      s: {type: string}\n      b: {type: boolean}\n      n: {type: number}\n      both: {type: number}\n" +
		"  workflow_dispatch:\n    inputs:\n      c: {type: choice, options: [a]}\n      e: {type: environment}\n      both: {type: string}\n      d: {type: boolean}\n" +
		"jobs:\n" +
		"  a:\n    runs-on: x\n    outputs: {o: x}\n    steps: [{run: a}]\n" +
		"  j:\n    needs: [a]\n    runs-on: x\n" +
		"    strategy:\n      matrix:\n        n: [5, 6]\n        s: ['5']\n        mixed: [5, '5']\n        o: [{a: 1}]\n        e: ['${{ github.x }}']\n        include: [{i: true}]\n        exclude: [{n: x}]\n" +
		"    steps:\n      - id: first\n        run: a\n      - id: second\n        run: b\n"
	_, w := parse(t, src)
	j := &w.Jobs.Value.Entries[1].Value.Value
	steps := j.Steps.Value.Items
	c := workflowContextTypes(w, j, steps[:1]) // as the second step reads them
	wantTypes(t, c, map[string][]expr.ValueType{
		"github":                tObject,
		"github.event":          tObject,
		"github.event.issue":    nil,
		"github.sha":            tString,
		"github.RUN_NUMBER":     tString,
		"github.ref_protected":  tBoolean,
		"github.nope":           nil,
		"env":                   tObject,
		"env.X":                 tString,
		"env[github.sha]":       tString,
		"vars.T":                tString,
		"secrets.T":             tString,
		"inputs":                tObject,
		"inputs.s":              tString,
		"inputs.B":              tBoolean,
		"inputs.n":              tNumber,
		"inputs.d":              tBoolean,
		"inputs.both":           nil,
		"inputs.c":              nil,
		"inputs.e":              nil,
		"inputs.none":           nil,
		"steps":                 tObject,
		"steps.first":           tObject,
		"steps.first.outputs":   tObject,
		"steps.first.outputs.x": tString,
		"steps.first.outcome":   tString,
		"steps.second.outputs":  nil,
		"steps.nope.outputs.x":  nil,
		"needs.a":               tObject,
		"needs.a.outputs":       tObject,
		"needs.a.outputs.o":     tString,
		"needs.a.result":        tString,
		"needs.x.outputs":       nil,
		"matrix":                tObject,
		"matrix.n":              tNumber,
		"matrix.s":              tString,
		"matrix.mixed":          {expr.ValueNumber, expr.ValueString},
		"matrix.o":              tObject,
		"matrix.e":              nil,
		"matrix.i":              tBoolean,
		"runner.os":             tString,
		"job.status":            tString,
		"job.check_run_id":      tNumber,
		"job.services":          tObject,
		"strategy.fail-fast":    tBoolean,
		"strategy.job-index":    tNumber,
	})
	// a job without a matrix: matrix is not known
	a := &w.Jobs.Value.Entries[0].Value.Value
	wantTypes(t, workflowContextTypes(w, a, nil), map[string][]expr.ValueType{"matrix": nil, "needs.a": nil, "steps.first": nil})
	// a key of the workflow: no job
	wantTypes(t, workflowContextTypes(w, nil, nil), map[string][]expr.ValueType{"inputs.s": tString, "jobs.a.outputs": tObject, "jobs.a.outputs.o": tString})
}

// TestContextTypesAction: an action.yml's inputs are strings, and its
// steps are those before.
func TestContextTypesAction(t *testing.T) {
	_, a := parseAction(t, "inputs:\n  b: {default: 'true'}\nruns:\n  using: composite\n  steps:\n    - id: s\n      run: a\n      shell: bash\n    - run: b\n      shell: bash\n")
	steps := a.Runs.Value.Steps.Value.Items
	wantTypes(t, actionContextTypes(a, steps[:1]), map[string][]expr.ValueType{
		"inputs.b":          tString,
		"inputs.nope":       nil,
		"steps.s.outputs":   tObject,
		"steps.s.outputs.x": tString,
		"github.event":      tObject,
		"matrix":            nil,
	})
}
