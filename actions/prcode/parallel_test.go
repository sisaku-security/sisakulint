package prcode

import (
	"github.com/sisaku-security/sisakulint/actions/workflow"
	"slices"
	"testing"
)

// TestCodeRunsParallel: the steps that may run after the step that brings
// the tree are read, those of its parallel group too; a checkout over it
// cleans it only when it is done after the step and before the one that
// runs.
func TestCodeRunsParallel(t *testing.T) {
	for _, c := range []struct {
		name  string
		steps string
		after int
		runs  []string
	}{
		{"a step of the group written before", "      - parallel:\n          - run: npm ci\n          - run: echo bring\n", 1, []string{"npm ci"}},
		{"a step of the group written after", "      - parallel:\n          - run: echo bring\n          - run: npm ci\n", 0, []string{"npm ci"}},
		{"a checkout alongside does not clean", "      - parallel:\n          - run: echo bring\n          - uses: actions/checkout@v4\n      - run: npm ci\n", 0, []string{"npm ci"}},
		{"a checkout in a group after cleans for the steps after it", "      - run: echo bring\n      - parallel:\n          - uses: actions/checkout@v4\n          - run: make\n      - run: npm ci\n", 0, []string{"make"}},
		{"a background step before its wait", "      - run: npm ci\n        background: true\n      - run: echo bring\n", 1, []string{"npm ci"}},
		{"a background step done before", "      - id: x\n        run: npm ci\n        background: true\n      - wait: x\n      - run: echo bring\n", 2, nil},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + c.steps
		w := mustWorkflow(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		var got []string
		for _, e := range codeRuns(w, &j, j.Steps.Value.Items, workflow.OrderOf(j.Steps.Value.Items), c.after, ws("."), nil) {
			got = append(got, e.Text)
		}
		if !slices.Equal(got, c.runs) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.runs)
		}
	}
}

// TestStepPathParallel: a checkout of a parallel group is named by its
// place in the group, as a file of facts names it.
func TestStepPathParallel(t *testing.T) {
	w := mustWorkflow(t, "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n      - parallel:\n          - run: echo\n          - uses: actions/checkout@v4\n")
	if s := Analyze(w, nil); len(s) != 1 || s[0].Path.String() != "jobs.build.steps[1].parallel[1]" {
		t.Errorf("sites = %+v", s)
	}
}
