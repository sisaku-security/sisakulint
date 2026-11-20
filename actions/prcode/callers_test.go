package prcode

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/internal/callerstest"
	"github.com/sisaku-security/sisakulint/actions/taint"
)

func callersOf(t *testing.T, files ...[2]string) *taint.Callers {
	t.Helper()
	return taint.NewCallers(callerstest.Graph(t, true, false, files...))
}

const calledName = ".github/workflows/called.yml"

func caller(on string) [2]string {
	return [2]string{".github/workflows/ci.yml", "on: " + on + "\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"}
}

func TestCheckoutSiteCallers(t *testing.T) {
	called := "on:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v1\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	for _, tc := range []struct {
		on   string
		want bool
	}{{"push", false}, {"pull_request_target", true}} {
		c := callersOf(t, [2]string{calledName, called}, caller(tc.on))
		f, _ := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(calledName)))
		sites := AnalyzeIn(c, f.Node(), f.Workflow, nil, nil)
		if got := len(sites) == 1 && len(sites[0].PRCodeOn) > 0; got != tc.want {
			t.Fatalf("%s: sites = %+v", tc.on, sites)
		}
	}
}

func TestDownloadSiteCallers(t *testing.T) {
	called := "on:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with: {run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ github.token }}'}\n"
	for _, tc := range []struct {
		on   string
		want bool
	}{{"push", false}, {"workflow_run:\n    workflows: [ci]", true}} {
		c := callersOf(t, [2]string{calledName, called}, caller(tc.on))
		f, _ := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(calledName)))
		sites := AnalyzeDownloadsIn(c, f.Node(), f.Workflow, nil, nil)
		if got := len(sites) == 1 && len(sites[0].PRCodeOn) > 0; got != tc.want {
			t.Fatalf("%s: sites = %+v", tc.on, sites)
		}
	}
}

// TestDownloadSiteNoCaller: a called workflow with no caller reads the
// events it read without callers.
func TestDownloadSiteNoCaller(t *testing.T) {
	called := "on:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: dawidd6/action-download-artifact@v3\n        with: {workflow: ci.yml}\n"
	c := callersOf(t, [2]string{calledName, called})
	f, _ := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(calledName)))
	got, want := AnalyzeDownloadsIn(c, f.Node(), f.Workflow, nil, nil), AnalyzeDownloads(f.Workflow, nil, nil)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// TestDownloadSiteForkSearchAnyEvent: a download that searches forks'
// runs holds on any event its callers run it on, also one outside the
// attacker's table.
func TestDownloadSiteForkSearchAnyEvent(t *testing.T) {
	step := "      - uses: dawidd6/action-download-artifact@v6\n        with: {workflow: build.yml, allow_forks: true}\n"
	called := "on:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + step
	c := callersOf(t, [2]string{calledName, called}, caller("[workflow_dispatch, schedule]"))
	f, _ := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(calledName)))
	if sites := AnalyzeDownloadsIn(c, f.Node(), f.Workflow, nil, nil); len(sites) != 1 || len(sites[0].PRCodeOn) == 0 {
		t.Fatalf("workflow: sites = %+v", sites)
	}
	action := "runs:\n  using: composite\n  steps:\n" + strings.ReplaceAll(step, "      ", "    ")
	ci := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./x\n"
	c = callersOf(t, [2]string{"x/action.yml", action}, [2]string{".github/workflows/ci.yml", ci})
	f, _ = c.Graph().File(calls.InputNode(facts.MustCleanInputPath("x/action.yml")))
	if sites := AnalyzeDownloadsIn(c, f.Node(), nil, f.Action, nil); len(sites) != 1 || len(sites[0].PRCodeOn) == 0 {
		t.Fatalf("action: sites = %+v", sites)
	}
}
