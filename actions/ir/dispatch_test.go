package ir

import "testing"

// TestCheckoutSiteDispatchKept: a site that runs on no privileged event is
// kept when an input of workflow_dispatch gives its ref and it can run on
// workflow_dispatch, and dropped when it cannot.
func TestCheckoutSiteDispatchKept(t *testing.T) {
	for _, c := range []struct {
		name, src string
		kept      bool
	}{
		{"dispatch", "on: {workflow_dispatch: {inputs: {ref: {}}}}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with: {ref: '${{ inputs.ref }}'}\n", true},
		{"written ref", "on: workflow_dispatch\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with: {ref: main}\n", false},
		{"job if", "on: {workflow_dispatch: {inputs: {ref: {}}}}\njobs:\n  a:\n    if: github.event_name != 'workflow_dispatch'\n    steps:\n      - uses: actions/checkout@v4\n        with: {ref: '${{ inputs.ref }}'}\n", false},
	} {
		tree, w := parse(t, c.src)
		got := New(".github/workflows/w.yml", tree, w, nil).allCheckoutSites()
		if (len(got) == 1) != c.kept || c.kept && (!got[0].dispatchInput || len(got[0].dispatchOn) != 1 || len(got[0].prCodeOn) != 0) {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

// TestDownloadSiteDispatchKept: the same for a download whose run an input
// of workflow_dispatch gives.
func TestDownloadSiteDispatchKept(t *testing.T) {
	tree, w := parse(t, "on: {workflow_dispatch: {inputs: {run: {}}}}\njobs:\n  a:\n    steps:\n      - uses: dawidd6/action-download-artifact@v6\n        with: {run_id: '${{ inputs.run }}'}\n")
	got := New(".github/workflows/w.yml", tree, w, nil).allDownloadSites()
	if len(got) != 1 || !got[0].dispatchInput || len(got[0].dispatchOn) != 1 {
		t.Errorf("%+v", got)
	}
}
