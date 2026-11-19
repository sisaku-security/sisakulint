package taint

import (
	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/attacker"
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// TestEventsOf: the events of on among those named, each with its actions;
// a workflow that can be called runs on any of them.
func TestEventsOf(t *testing.T) {
	names := []workflow.EventName{workflow.EventNamePullRequestTarget, workflow.EventNameIssueComment}
	for _, c := range []struct {
		on   string
		want []string
	}{
		{"[push, pull_request_target]", []string{"pull_request_target/opened", "pull_request_target/reopened", "pull_request_target/synchronize"}},
		{"{issue_comment: {types: [created]}, push: {}}", []string{"issue_comment/created"}},
		{"push", nil},
		{"workflow_call", eventTexts(sortEvents(EventsAll(names)))},
	} {
		w, _ := workflow.Parse(cst.ParseMode([]byte("on: "+c.on+"\njobs:\n  a:\n    runs-on: x\n    steps: [{run: a}]\n"), cst.ModeGitHub))
		if got := eventTexts(EventsOf(w, names)); !slices.Equal(got, c.want) {
			t.Errorf("on %s: %v, want %v", c.on, got, c.want)
		}
	}
}

func eventTexts(evs []analysis.EventActivity) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Name().String()+"/"+activityText(e.ActivityType()))
	}
	return out
}

// TestEventsOn: the callers' events of workflow_call are not w's own.
func TestEventsOn(t *testing.T) {
	w, _ := workflow.Parse(cst.ParseMode([]byte("on: [workflow_call, issues]\njobs:\n  a:\n    runs-on: x\n    steps: [{run: a}]\n"), cst.ModeGitHub))
	names := []workflow.EventName{workflow.EventNameIssues, workflow.EventNamePullRequestTarget}
	for _, e := range EventsOn(w, names) {
		if e.Name() != workflow.EventNameIssues {
			t.Errorf("%+v", e)
		}
	}
	if len(EventsOn(w, names)) == 0 || !slices.ContainsFunc(EventsOf(w, names), func(e analysis.EventActivity) bool { return e.Name() == workflow.EventNamePullRequestTarget }) {
		t.Error("EventsOn has no issues, or EventsOf lost the callers' events")
	}
}

// activityText is a as eventTexts writes it: "" for none.
func activityText(a workflow.ActivityType) string {
	if a == workflow.ActivityTypeUnset {
		return ""
	}
	return a.String()
}

// TestEventsOfTypes: the pairs of an event and an activity type.
func TestEventsOfTypes(t *testing.T) {
	names := []workflow.EventName{workflow.EventNamePullRequestTarget, workflow.EventNameIssues, workflow.EventNameDiscussion, workflow.EventNamePush}
	for _, c := range []struct {
		on   string
		want []string // exactly these, when has is nil
		has  []string
	}{
		{on: "{issues: {types: [field_added]}}", want: []string{"issues/field_added"}},
		{on: "{issues: {types: [foo]}}", want: nil},
		{on: "{issues: {types: [opend]}}", want: nil},
		{on: "{issues: {types: [Opened]}}", want: nil},
		{on: "{issues: {types: [opened, foo]}}", want: []string{"issues/opened"}},
		{on: "{pull_request_target: {types: [stacked]}}", want: nil},
		{on: "{pull_request_target: {types: [opened, stacked]}}", want: []string{"pull_request_target/opened"}},
		{on: "{pull_request_target: {types: [labeled, opend]}}", want: []string{"pull_request_target/labeled"}},
		{on: "{push: {types: [opened]}}", want: nil},
		{on: "push", want: []string{"push/"}},
		{on: "discussion", has: []string{"discussion/closed", "discussion/reopened", "discussion/created"}},
		{on: "issues", has: []string{"issues/field_added", "issues/opened"}},
		{on: "pull_request_target", want: []string{"pull_request_target/opened", "pull_request_target/reopened", "pull_request_target/synchronize"}},
	} {
		w, _ := workflow.Parse(cst.ParseMode([]byte("on: "+c.on+"\njobs:\n  a:\n    runs-on: x\n    steps: [{run: a}]\n"), cst.ModeGitHub))
		got := eventTexts(EventsOf(w, names))
		if c.has == nil && !slices.Equal(got, c.want) {
			t.Errorf("on %s: %v, want %v", c.on, got, c.want)
		}
		for _, h := range c.has {
			if !slices.Contains(got, h) {
				t.Errorf("on %s: %v lacks %s", c.on, got, h)
			}
		}
	}
}

// TestEventsOfCheckSuiteCompleted: check_suite starts a run only on the
// activity type completed, whatever its types say: requested and
// rerequested are no event a job runs on.
func TestEventsOfCheckSuiteCompleted(t *testing.T) {
	names := []workflow.EventName{workflow.EventNameCheckSuite}
	for _, c := range []struct {
		on   string
		want []string
	}{
		{"check_suite", []string{"check_suite/completed"}},
		{"{check_suite: {types: [completed]}}", []string{"check_suite/completed"}},
		{"{check_suite: {types: [requested]}}", nil},
		{"{check_suite: {types: [requested, rerequested]}}", nil},
		{"{check_suite: {types: [requested, completed]}}", []string{"check_suite/completed"}},
	} {
		w, _ := workflow.Parse(cst.ParseMode([]byte("on: "+c.on+"\njobs:\n  a:\n    runs-on: x\n    steps: [{run: a}]\n"), cst.ModeGitHub))
		if got := eventTexts(EventsOf(w, names)); !slices.Equal(got, c.want) {
			t.Errorf("on %s: %v, want %v", c.on, got, c.want)
		}
	}
	if got := eventTexts(EventsAll(names)); !slices.Equal(got, []string{"check_suite/completed"}) {
		t.Errorf("EventsAll(check_suite) = %v", got)
	}
}

// TestEventsAllNoStacked: stacked is no attacker's on any event.
func TestEventsAllNoStacked(t *testing.T) {
	evs := EventsAll([]workflow.EventName{workflow.EventNamePullRequest, workflow.EventNamePullRequestTarget})
	if len(evs) == 0 {
		t.Fatal("no events")
	}
	for _, e := range evs {
		if e.ActivityType() == workflow.ActivityTypeStacked {
			t.Errorf("%+v", e)
		}
	}
}

// TestFilterAttackerRun: an if that keeps the attacker's pull request out
// keeps pull_request_target out; one Dependabot's push passes does not,
// nor one a pull request from a branch of the repository passes.
func TestFilterAttackerRun(t *testing.T) {
	syn := analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)
	for _, c := range []struct {
		cond string
		n    int
	}{
		{"github.event.pull_request.head.repo.full_name == github.repository", 1},
		{"github.actor == 'dependabot[bot]'", 1},
		{"github.event.pull_request.user.login == 'dependabot[bot]'", 0},
	} {
		w, _ := workflow.Parse(cst.ParseMode([]byte("on: pull_request_target\njobs:\n  a:\n    if: "+c.cond+"\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"), cst.ModeGitHub))
		if got := Filter(attacker.Outsider, []analysis.EventActivity{syn}, attacker.StepIf(w.Jobs.Value.Entries[0].Value.Value.If)); len(got) != c.n {
			t.Errorf("%s: %v", c.cond, got)
		}
	}
}

// TestFilterCode: the head's full name keeps the attacker's code out, not
// their values.
func TestFilterCode(t *testing.T) {
	syn := analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)
	w, _ := workflow.Parse(cst.ParseMode([]byte("on: pull_request_target\njobs:\n  a:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"), cst.ModeGitHub))
	c := w.Jobs.Value.Entries[0].Value.Value.If
	if len(Filter(attacker.Outsider, []analysis.EventActivity{syn}, attacker.StepIf(c))) != 1 || len(FilterCode(attacker.Outsider, []analysis.EventActivity{syn}, attacker.StepIf(c))) != 0 {
		t.Errorf("Filter %v, FilterCode %v", Filter(attacker.Outsider, []analysis.EventActivity{syn}, attacker.StepIf(c)), FilterCode(attacker.Outsider, []analysis.EventActivity{syn}, attacker.StepIf(c)))
	}
}
