package prcode

import (
	"slices"
	"testing"
)

// TestEvents: the privileged events an attacker triggers.
func TestEvents(t *testing.T) {
	// a ref with a value on each event (an inference, not an observation)
	const with = "{ref: 'refs/pull/${{ github.event.pull_request.number || github.event.issue.number || github.event.workflow_run.pull_requests[0].number }}/head'}"
	for _, c := range []struct {
		on   string
		want []string
	}{
		{"pull_request_target", []string{"pull_request_target/opened", "pull_request_target/reopened", "pull_request_target/synchronize"}},
		{"{pull_request_target: {types: [labeled]}}", []string{"pull_request_target/labeled"}},
		{"pull_request", nil},
		{"push", nil},
		{"{workflow_run: {workflows: [ci], types: [completed]}}", []string{"workflow_run/completed"}},
		{"{issue_comment: {types: [created]}}", []string{"issue_comment/created"}},
		// a pinned comment is never on a pull request (as observed on 2026-10-14)
		{"{issue_comment: {types: [pinned, unpinned, created]}}", []string{"issue_comment/created"}},
		{"{issue_comment: {types: [pinned]}}", nil},
		{"pull_request_review", nil},
		{"pull_request_review_comment", nil},
	} {
		if got := eventNames(oneSite(t, c.on, "", "actions/checkout@v4", with, "").PRCodeOn); !slices.Equal(got, c.want) {
			t.Errorf("on %s: %v; want %v", c.on, got, c.want)
		}
	}
	w := mustWorkflow(t, "on: [pull_request_target, push]\njobs:\n  a:\n    if: github.event_name == 'push'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with: "+with+"\n")
	if evs := Analyze(w, nil)[0].PRCodeOn; len(evs) != 0 {
		t.Errorf("job if push: %v", evs)
	}
	// a ref the comment shapes does not need the issue to be a pull request
	// pinned stays
	if got := eventNames(oneSite(t, "{issue_comment: {types: [pinned]}}", "", "actions/checkout@v4", "{repository: '${{ github.event.comment.body }}'}", "").PRCodeOn); !slices.Equal(got, []string{"issue_comment/pinned"}) {
		t.Errorf("a repository the comment names, on pinned: %v", got)
	}
	s := oneSite(t, "[pull_request_target, issue_comment]", "", "actions/checkout@v4.2.2", with, "")
	guarded, open := s.Split()
	if len(guarded) != 3 || !slices.Equal(eventNames(open), []string{"issue_comment/created", "issue_comment/deleted", "issue_comment/edited"}) {
		t.Errorf("Split = %v, %v", eventNames(guarded), eventNames(open))
	}
}

func TestStepPathAndActions(t *testing.T) {
	w := mustWorkflow(t, "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n      - uses: actions/checkout@v4\n")
	if s := Analyze(w, nil); len(s) != 1 || s[0].Path.String() != "jobs.build.steps[1]" || s[0].Job == nil || s[0].Job.ID.AsString() != "build" {
		t.Errorf("sites = %+v", s)
	}
}
