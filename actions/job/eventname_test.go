package job

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/workflow"
)

// TestAlwaysSkippedCalledEventName: github.event_name of a called run is
// its caller's event, never workflow_call.
func TestAlwaysSkippedCalledEventName(t *testing.T) {
	for _, c := range []struct {
		cond string
		want bool
	}{
		{"github.event_name == 'workflow_call'", true},
		{"github.event_name == 'push'", false},
		{"github.event_name != 'workflow_call'", false},
	} {
		w := parse(t, "on: workflow_call\njobs:\n  a:\n    if: "+c.cond+"\n    runs-on: x\n    steps:\n      - run: a\n")
		j := w.Jobs.Value.Entries[0].Value.Value
		if got := AlwaysSkipped(w, &j); got != c.want {
			t.Errorf("%s: %v, want %v", c.cond, got, c.want)
		}
	}
}

// TestAlwaysSkippedDefaultTypes: pull_request without types runs on opened,
// synchronize and reopened alone.
func TestAlwaysSkippedDefaultTypes(t *testing.T) {
	for _, c := range []struct {
		on   string
		want bool
	}{
		{"pull_request", true},
		{"{pull_request: {types: [closed]}}", false},
	} {
		w := parse(t, "on: "+c.on+"\njobs:\n  a:\n    if: github.event.action == 'closed'\n    runs-on: x\n    steps:\n      - run: a\n")
		j := w.Jobs.Value.Entries[0].Value.Value
		if got := AlwaysSkipped(w, &j); got != c.want {
			t.Errorf("on %s: %v, want %v", c.on, got, c.want)
		}
	}
}

func TestCacheSavesOn(t *testing.T) {
	for _, c := range []struct {
		wf, job string // the cache-modes written; empty for none
		e       workflow.EventName
		called  bool
		want    bool
	}{
		{"", "", workflow.EventNamePush, false, true},
		{"", "", workflow.EventNameSchedule, false, true},
		{"", "", workflow.EventNamePullRequest, false, true}, // the merge ref's scope
		{"", "", workflow.EventNameIssueComment, false, false},
		{"", "", workflow.EventNamePullRequestTarget, false, false},
		{"", "", workflow.EventNameIssueComment, true, true}, // the caller decides
		{"", "read", workflow.EventNameIssueComment, true, false},
		{"", "read", workflow.EventNamePush, false, false},
		{"none", "", workflow.EventNamePush, false, false},
		{"", "write", workflow.EventNameIssueComment, false, true},
		{"write-only", "", workflow.EventNamePullRequestTarget, false, true},
	} {
		src := "on: push\n"
		if c.wf != "" {
			src += "cache-mode: " + c.wf + "\n"
		}
		src += "jobs:\n  a:\n    runs-on: ubuntu-latest\n"
		if c.job != "" {
			src += "    cache-mode: " + c.job + "\n"
		}
		src += "    steps:\n      - run: echo\n"
		w := parse(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		if got := CacheSavesOn(j.CacheMode, w.CacheMode, c.e, c.called); got != c.want {
			t.Errorf("wf %q job %q on %v: %v, want %v", c.wf, c.job, c.e, got, c.want)
		}
	}
}
