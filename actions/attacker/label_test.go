package attacker

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// labeledIf is the if of the one job of a workflow on pull_request_target
// labeled, and the event.
func labeledIf(t *testing.T, cond string) (workflow.Field[workflow.If], analysis.EventActivity) {
	t.Helper()
	src := "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  j:\n    if: " + cond + "\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	j := w.Jobs.Value.Entries[0].Value.Value
	e, err := analysis.NewEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeLabeled)
	if err != nil {
		t.Fatal(err)
	}
	return j.If, e
}

func TestLabelTruth(t *testing.T) {
	for _, c := range []struct {
		cond, label string
		want        expr.Truth
	}{
		{"github.event.label.name == 'safe'", "safe", expr.TruthTrue},
		{"github.event.label.name == 'safe'", "other", expr.TruthFalse},
		{"contains(github.event.pull_request.labels.*.name, 'safe')", "safe", expr.TruthTrue},
		{"contains(github.event.pull_request.labels.*.name, 'safe')", "other", expr.TruthFalse},
		{"!contains(github.event.pull_request.labels.*.name, 'blocked')", "safe", expr.TruthTrue},
		{"contains('safe-to-test', github.event.label.name)", "test", expr.TruthTrue},
		{"github.event.label.name == 'safe' && vars.X == 'y'", "safe", expr.TruthUnknown},
		{"github.event.action == 'labeled' && github.event.label.name == 'safe'", "safe", expr.TruthTrue},
	} {
		c0, e := labeledIf(t, c.cond)
		if got := Outsider.LabelTruth(StepIf(nil, nil, c0), e, c.label, []string{c.label}); got != c.want {
			t.Errorf("%s with %s: got %v, want %v", c.cond, c.label, got, c.want)
		}
	}
	c0, e := labeledIf(t, "contains(github.event.pull_request.labels.*.name, 'a') && contains(github.event.pull_request.labels.*.name, 'b')")
	if got := Outsider.LabelTruth(StepIf(nil, nil, c0), e, "a", []string{"a"}); got != expr.TruthFalse {
		t.Errorf("a alone: got %v, want false", got)
	}
	if got := Outsider.LabelTruth(StepIf(nil, nil, c0), e, "a", []string{"a", "b"}); got != expr.TruthTrue {
		t.Errorf("a and b: got %v, want true", got)
	}
}

func TestLabelNameCase(t *testing.T) {
	c0, e := labeledIf(t, "github.event.label.name == 'safe-to-test'")
	if got := Outsider.LabelTruth(StepIf(nil, nil, c0), e, "Safe-To-Test", []string{"Safe-To-Test"}); got != expr.TruthTrue {
		t.Errorf("got %v, want true: == ignores the case", got)
	}
}

func TestLabelBypasses(t *testing.T) {
	for _, c := range []struct {
		cond  string
		names []string
		want  int
	}{
		{"contains('safe-to-test', github.event.label.name)", []string{"test"}, 1},
		{"contains('safe-to-test', github.event.label.name)", []string{"safe-to-test", "test"}, 0}, // the whole label is the attacker's anyway
		{"contains(github.event.label.name, 'ok')", []string{"not-ok"}, 1},
		{"startsWith(github.event.label.name, 'ok')", []string{"OK-go"}, 1},
		{"github.event.label.name == 'safe'", []string{"safe"}, 0},
		{"contains(fromJSON('[\"safe\"]'), github.event.label.name)", []string{"safe"}, 0},
		{"contains('safe-to-test', github.event.label.name)", []string{"docs"}, 0},
	} {
		c0, _ := labeledIf(t, c.cond)
		if got := LabelBypasses(StepIf(nil, nil, c0), c.names); len(got) != c.want {
			t.Errorf("%s with %v: got %d, want %d", c.cond, c.names, len(got), c.want)
		}
	}
}
