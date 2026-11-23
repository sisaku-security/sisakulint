package calls_test

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

const required = "on:\n  workflow_call:\n    inputs:\n      t: {type: string, required: true}\njobs:\n  j:\n    runs-on: x\n    steps: [{run: y}]\n"

// Diagnostics checks a job's ./ and $/ calls against the called input,
// and gives the diagnostics by the caller.
func TestDiagnostics(t *testing.T) {
	for _, uses := range []string{"./.github/workflows/called.yml", "$/.github/workflows/called.yml"} {
		files := []calls.File{
			callerstest.File(t, ".github/workflows/called.yml", required),
			callerstest.File(t, ".github/workflows/ci.yml", "on: push\njobs:\n  c:\n    uses: "+uses+"\n"),
		}
		ds := calls.Diagnostics(files)
		got := ds[facts.MustCleanInputPath(".github/workflows/ci.yml")]
		if len(ds) != 1 || len(got) != 1 || got[0].Code != workflow.MissingKey {
			t.Errorf("%s: %+v", uses, ds)
		}
	}
}

// What is not an input of the run, not a workflow, or another
// repository's is not checked; a call that gives what is required has
// nothing to report.
func TestDiagnosticsNotChecked(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []calls.File
	}{
		{"called not an input", []calls.File{
			callerstest.File(t, ".github/workflows/ci.yml", "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"),
		}},
		{"remote", []calls.File{
			callerstest.File(t, ".github/workflows/called.yml", required),
			callerstest.File(t, ".github/workflows/ci.yml", "on: push\njobs:\n  c:\n    uses: o/r/.github/workflows/called.yml@v1\n"),
		}},
		{"given", []calls.File{
			callerstest.File(t, ".github/workflows/called.yml", required),
			callerstest.File(t, ".github/workflows/ci.yml", "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      T: x\n"),
		}},
	} {
		if ds := calls.Diagnostics(tc.files); len(ds) != 0 {
			t.Errorf("%s: %+v", tc.name, ds)
		}
	}
}
