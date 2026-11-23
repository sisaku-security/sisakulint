package prcode

import (
	"github.com/gh-intel/sisakulint/actions/analysis"
	"testing"

	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

func mustWorkflow(t *testing.T, src string) *workflow.Workflow {
	t.Helper()
	w, diags := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	for _, d := range diags {
		t.Fatalf("%q: %v", src, d)
	}
	return w
}

// oneSite is the one checkout of a job of the workflow on on, whose
// checkout step has with and whose job has jobExtra, followed by after.
func oneSite(t *testing.T, on, jobExtra, uses, with, after string) CheckoutSite {
	t.Helper()
	src := "on: " + on + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + jobExtra + "    steps:\n      - uses: " + uses + "\n"
	if with != "" {
		src += "        with: " + with + "\n"
	}
	src += after
	sites := Analyze(mustWorkflow(t, src), nil)
	if len(sites) != 1 {
		t.Fatalf("%q: %d sites", src, len(sites))
	}
	return sites[0]
}

func eventNames(evs []analysis.EventActivity) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Name().String()+"/"+activityText(e.ActivityType()))
	}
	return out
}

func refTexts(rs []CheckoutRef) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Text)
	}
	return out
}

// activityText is a as eventTexts writes it: "" for none.
func activityText(a workflow.ActivityType) string {
	if a == workflow.ActivityTypeUnset {
		return ""
	}
	return a.String()
}

func mustAction(t *testing.T, src string) *workflow.ActionMetadata {
	t.Helper()
	a, diags := workflow.ParseActionMetadata(cst.ParseMode([]byte(src), cst.ModeGitHub))
	for _, d := range diags {
		t.Fatalf("%q: %v", src, d)
	}
	return a
}
