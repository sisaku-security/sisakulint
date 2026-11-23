package workflow

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// isExpr is whether f is a value written as one ${{ }}.
func isExpr(f Field[String]) bool { return f.Status == Present && f.Value.IsExpr() }

// TestExpressionKeys: the keys the quality rule expression reads, which
// the model read only to check them before.
func TestExpressionKeys(t *testing.T) {
	src := "on: push\n" +
		"concurrency: {group: g, cancel-in-progress: '${{ github.x }}'}\n" +
		"defaults: {run: {working-directory: d}}\n" +
		"jobs:\n  a:\n    runs-on: x\n" +
		"    continue-on-error: ${{ github.x }}\n" +
		"    cancel-timeout-minutes: ${{ github.x }}\n" +
		"    concurrency: ${{ github.x }}\n" +
		"    environment: {name: e, url: '${{ github.x }}'}\n" +
		"    defaults: {run: {working-directory: '${{ github.x }}'}}\n" +
		"    strategy: {fail-fast: '${{ github.x }}', max-parallel: '${{ github.x }}', matrix: {a: [1]}}\n" +
		"    steps:\n      - run: echo\n        timeout-minutes: ${{ github.x }}\n        continue-on-error: ${{ github.x }}\n        working-directory: ${{ github.x }}\n"
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	if !isExpr(w.Concurrency.Value.CancelInProgress) || w.Concurrency.Value.Group.Value.AsString() != "g" {
		t.Errorf("workflow concurrency: %+v", w.Concurrency)
	}
	if w.DefaultWorkingDirectory.Value.AsString() != "d" {
		t.Errorf("workflow defaults.run.working-directory: %+v", w.DefaultWorkingDirectory)
	}
	j := w.Jobs.Value.Entries[0].Value.Value
	for name, f := range map[string]Field[String]{
		"continue-on-error": j.ContinueOnError, "cancel-timeout-minutes": j.CancelTimeoutMinutes,
		"concurrency": j.Concurrency.Value.Group, "environment.url": j.EnvironmentURL,
		"defaults.run.working-directory": j.DefaultWorkingDirectory, "fail-fast": j.FailFast, "max-parallel": j.MaxParallel,
	} {
		if !isExpr(f) {
			t.Errorf("job %s: %+v", name, f)
		}
	}
	if j.Environment.Value.AsString() != "e" || len(j.MatrixVariables) != 1 {
		t.Errorf("environment %+v, matrix %+v", j.Environment, j.MatrixVariables)
	}
	s := j.Steps.Value.Items[0]
	for name, f := range map[string]Field[String]{"timeout-minutes": s.TimeoutMinutes, "continue-on-error": s.ContinueOnError, "working-directory": s.WorkingDirectory} {
		if !isExpr(f) {
			t.Errorf("step %s: %+v", name, f)
		}
	}
}

// TestExpressionKeysAction: a composite step of an action.yml has
// continue-on-error and working-directory, and no timeout-minutes.
func TestExpressionKeysAction(t *testing.T) {
	src := "runs:\n  using: composite\n  steps:\n    - run: echo\n      shell: bash\n      continue-on-error: ${{ inputs.c }}\n      working-directory: ${{ inputs.d }}\n"
	a, diags := ParseActionMetadata(cst.ParseMode([]byte(src), cst.ModeGitHub))
	wantCodes(t, src, diags)
	s := a.Runs.Value.Steps.Value.Items[0]
	if !isExpr(s.ContinueOnError) || !isExpr(s.WorkingDirectory) || s.TimeoutMinutes.Status != Absent {
		t.Errorf("composite step: %+v %+v %+v", s.ContinueOnError, s.WorkingDirectory, s.TimeoutMinutes)
	}
}

// TestMatrixTypes: the type of each value written for a name of the
// matrix, as GitHub keeps it in the matrix context: a plain
// scalar by YAML, a quoted one a string, a mapping an object, a sequence
// an array, a ${{ }} not known.
func TestMatrixTypes(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    strategy:\n      matrix:\n" +
		"        t: [5, '5', true, null, {a: 1}, [1], '${{ github.x }}']\n" +
		"        include: [{u: 1.5}, {u: [a]}]\n" +
		"        exclude: [{t: 5}]\n" +
		"    steps:\n      - run: echo\n"
	w, _, _ := parse(t, src)
	j := w.Jobs.Value.Entries[0].Value.Value
	want := map[string][]expr.ValueType{
		"t": {expr.ValueNumber, expr.ValueString, expr.ValueBoolean, expr.ValueNull, expr.ValueObject, expr.ValueArray, expr.ValueTypeUnset},
		"u": {expr.ValueNumber, expr.ValueArray},
	}
	for _, v := range j.MatrixVariables {
		if !slices.Equal(v.Types, want[v.Name]) {
			t.Errorf("%s: %v, want %v", v.Name, v.Types, want[v.Name])
		}
	}
	if len(j.MatrixVariables) != 2 {
		t.Errorf("variables: %+v", j.MatrixVariables)
	}
	src = "on: push\njobs:\n  a:\n    runs-on: x\n    strategy:\n      matrix:\n        t: [5]\n        include: '${{ fromJSON(github.x) }}'\n    steps:\n      - run: echo\n"
	w, _, _ = parse(t, src)
	if v := w.Jobs.Value.Entries[0].Value.Value.MatrixVariables; len(v) != 1 || v[0].Types != nil {
		t.Errorf("include of a ${{ }}: %+v", v)
	}
	// the values of a key written as a ${{ }} are not known, though include
	// adds one
	src = "on: push\njobs:\n  a:\n    runs-on: x\n    strategy:\n      matrix:\n        os: '${{ fromJSON(github.x) }}'\n        include: [{os: w}]\n    steps:\n      - run: echo\n"
	w, _, _ = parse(t, src)
	if v := w.Jobs.Value.Entries[0].Value.Value.MatrixVariables; len(v) != 1 || !slices.Contains(v[0].Types, expr.ValueTypeUnset) {
		t.Errorf("a key of a ${{ }}: %+v", v)
	}
}
