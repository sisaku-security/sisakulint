package prcode

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/facts"
)

// TestCheckoutSiteDispatch: whether a checkout's ref or repository refers to
// an input of workflow_dispatch, and the runs of workflow_dispatch that the
// ifs of the job and the step let through, each on its own.
func TestCheckoutSiteDispatch(t *testing.T) {
	const dispatch = "{workflow_dispatch: {inputs: {ref: {}}}}"
	for _, c := range []struct {
		name, on, jobExtra, with, after string
		input                           bool
		on1                             []string
		approval                        analysis.Approval
	}{
		{name: "inputs", on: dispatch, with: "{ref: '${{ inputs.ref }}'}", input: true, on1: []string{"workflow_dispatch/"}},
		{name: "event inputs", on: dispatch, with: "{ref: '${{ github.event.inputs.ref }}'}", input: true, on1: []string{"workflow_dispatch/"}},
		{name: "repository", on: dispatch, with: "{repository: '${{ inputs.ref }}'}", input: true, on1: []string{"workflow_dispatch/"}},
		{name: "a written ref", on: dispatch, with: "{ref: main}", on1: []string{"workflow_dispatch/"}},
		{name: "no workflow_dispatch", on: "{workflow_call: {inputs: {ref: {type: string}}}}", with: "{ref: '${{ inputs.ref }}'}"},
		{name: "job if", on: dispatch, jobExtra: "    if: github.event_name != 'workflow_dispatch'\n", with: "{ref: '${{ inputs.ref }}'}", input: true},
		{name: "labeled", on: "{pull_request_target: {types: [labeled]}, workflow_dispatch: {inputs: {ref: {}}}}", with: "{ref: '${{ inputs.ref }}'}", input: true, on1: []string{"workflow_dispatch/"}, approval: analysis.ApprovalLabel},
	} {
		s := oneSite(t, c.on, c.jobExtra, "actions/checkout@v4", c.with, c.after)
		if s.DispatchInput != c.input || !slices.Equal(eventNames(s.DispatchOn), c.on1) {
			t.Errorf("%s: DispatchInput %v, DispatchOn %v; want %v, %v", c.name, s.DispatchInput, eventNames(s.DispatchOn), c.input, c.on1)
		}
		if s.Approval != c.approval {
			t.Errorf("%s: Approval %v, want %v", c.name, s.Approval, c.approval)
		}
		if s.CallFromPR {
			t.Errorf("%s: CallFromPR without a caller", c.name)
		}
	}
	// the if of the step
	w := mustWorkflow(t, "on: "+dispatch+"\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.event_name == 'push'\n        uses: actions/checkout@v4\n        with: {ref: '${{ inputs.ref }}'}\n")
	if s := Analyze(w, nil)[0]; !s.DispatchInput || len(s.DispatchOn) != 0 {
		t.Errorf("step if: DispatchInput %v, DispatchOn %v", s.DispatchInput, eventNames(s.DispatchOn))
	}
}

// TestCheckoutSiteDispatchCallFromPR: a workflow of workflow_call and
// workflow_dispatch that a caller on pull_request_target calls: the input
// is the dispatcher's on workflow_dispatch and the caller's on the call.
func TestCheckoutSiteDispatchCallFromPR(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs: {ref: {type: string}}\n  workflow_dispatch:\n    inputs: {ref: {}}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v1\n        with:\n          ref: ${{ inputs.ref }}\n"
	for _, tc := range []struct {
		on   string
		want bool
	}{{"push", false}, {"pull_request_target", true}} {
		c := callersOf(t, [2]string{calledName, called}, caller(tc.on))
		f, _ := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(calledName)))
		sites := AnalyzeIn(c, f.Node(), f.Workflow, nil, nil)
		if len(sites) != 1 || !sites[0].DispatchInput || sites[0].CallFromPR != tc.want {
			t.Errorf("%s: sites = %+v", tc.on, sites)
		}
	}
}

// TestDownloadSiteDispatch: a download whose run_id, run-id, repository,
// repo, token or allow_forks refers to an input of workflow_dispatch.
func TestDownloadSiteDispatch(t *testing.T) {
	const dispatch = "on: {workflow_dispatch: {inputs: {run: {}}}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
	for _, c := range []struct {
		name, src string
		input     bool
	}{
		{"run_id", dispatch + "    steps:\n      - uses: dawidd6/action-download-artifact@v6\n        with: {run_id: '${{ inputs.run }}'}\n", true},
		{"run-id", dispatch + "    steps:\n      - uses: actions/download-artifact@v4\n        with: {run-id: '${{ github.event.inputs.run }}', github-token: '${{ github.token }}'}\n", true},
		{"repo", dispatch + "    steps:\n      - uses: dawidd6/action-download-artifact@v6\n        with: {repo: '${{ inputs.run }}'}\n", true},
		{"written", dispatch + "    steps:\n      - uses: dawidd6/action-download-artifact@v6\n        with: {run_id: '123'}\n", false},
		{"current run", dispatch + "    steps:\n      - uses: actions/download-artifact@v4\n        with: {run-id: '${{ inputs.run }}'}\n", false},
		{"before v4", dispatch + "    steps:\n      - uses: actions/download-artifact@v3\n        with: {run-id: '${{ inputs.run }}', github-token: '${{ github.token }}'}\n", false},
		{"no workflow_dispatch", "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: dawidd6/action-download-artifact@v6\n        with: {run_id: '${{ inputs.run }}'}\n", false},
	} {
		sites := AnalyzeDownloads(mustWorkflow(t, c.src), nil, nil)
		if len(sites) != 1 || sites[0].DispatchInput != c.input {
			t.Errorf("%s: sites = %+v", c.name, sites)
		}
	}
}

// TestCheckoutSiteDispatchNotUnknown: an input of workflow_dispatch in a
// ref is the dispatcher's, which input-dispatch reports, and not a value the
// tables cannot tell; unless a caller on an event of a pull request may
// give it, or another value of the ref is unknown.
func TestCheckoutSiteDispatchNotUnknown(t *testing.T) {
	const on = "{pull_request_target: {}, workflow_dispatch: {inputs: {ref: {}}}}"
	for _, c := range []struct {
		name, with string
		code       analysis.CheckoutCode
		unknown    int
	}{
		{"input", "{ref: '${{ inputs.ref }}'}", analysis.CodeBase, 0},
		{"event input", "{ref: '${{ github.event.inputs.ref }}'}", analysis.CodeBase, 0},
		{"mixed", "{ref: '${{ inputs.ref || github.event.pull_request.head.sha }}'}", analysis.CodePR, 0},
		{"another unknown", "{ref: '${{ inputs.ref || steps.a.outputs.ref }}'}", analysis.CodeUnknown, 1},
	} {
		s := oneSite(t, on, "", "actions/checkout@v1", c.with, "")
		if s.CheckoutCode != c.code || len(s.InconclusiveValues) != c.unknown {
			t.Errorf("%s: %v, %d unknown", c.name, s.CheckoutCode, len(s.InconclusiveValues))
		}
	}
	called := "on:\n  workflow_call:\n    inputs: {ref: {type: string}}\n  workflow_dispatch:\n    inputs: {ref: {}}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v1\n        with:\n          ref: ${{ inputs.ref }}\n"
	c := callersOf(t, [2]string{calledName, called}, caller("pull_request_target"))
	f, _ := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(calledName)))
	if s := AnalyzeIn(c, f.Node(), f.Workflow, nil, nil)[0]; s.CheckoutCode != analysis.CodeUnknown {
		t.Errorf("called from a pull request: %v", s.CheckoutCode)
	}
}

// TestDownloadSiteDispatchNotUnknown: the same for the inputs that choose
// the run of a download.
func TestDownloadSiteDispatchNotUnknown(t *testing.T) {
	const head = "on: {pull_request_target: {}, workflow_dispatch: {inputs: {run: {}}}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
	for _, c := range []struct {
		name, step string
		unknown    int
	}{
		{"run_id", "      - uses: dawidd6/action-download-artifact@v6\n        with: {run_id: '${{ inputs.run }}'}\n", 0},
		{"repo", "      - uses: dawidd6/action-download-artifact@v6\n        with: {repo: '${{ inputs.run }}'}\n", 0},
		{"allow_forks", "      - uses: dawidd6/action-download-artifact@v6\n        with: {allow_forks: '${{ inputs.run }}'}\n", 0},
		{"token", "      - uses: actions/download-artifact@v4\n        with: {run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ inputs.run }}'}\n", 0},
		{"another unknown", "      - uses: dawidd6/action-download-artifact@v6\n        with: {run_id: '${{ inputs.run || steps.a.outputs.id }}'}\n", 1},
	} {
		sites := AnalyzeDownloads(mustWorkflow(t, head+c.step), nil, nil)
		if len(sites) != 1 || len(sites[0].InconclusiveValues) != c.unknown {
			t.Errorf("%s: sites = %+v", c.name, sites)
		}
	}
}
