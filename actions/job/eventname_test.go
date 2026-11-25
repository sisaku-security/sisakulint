package job

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/workflow"
)

func TestEventNamesOf(t *testing.T) {
	w := parse(t, "on: [push, pull_request, push]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n")
	want := []workflow.EventName{workflow.EventNamePullRequest, workflow.EventNamePush}
	if got := EventNamesOf(w); !slices.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
	// A called workflow ends with workflow_call, the mark of its callers' runs.
	called := EventNamesOf(parse(t, "on: [push, workflow_call]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n"))
	if want := []workflow.EventName{workflow.EventNamePush, workflow.EventNameWorkflowCall}; !slices.Equal(called, want) {
		t.Errorf("workflow_call: %v, want %v", called, want)
	}
	if got := EventNamesOf(parse(t, "jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n")); len(got) != 0 {
		t.Errorf("no on: %v", got)
	}
}

// TestCalledRunEventName checks that github.event_name of a called run
// evaluates to its caller's event, never workflow_call.
func TestCalledRunEventName(t *testing.T) {
	for _, c := range []struct {
		cond string
		want bool
	}{
		{"github.event_name == 'workflow_call'", true},
		{"github.event_name == 'issue_comment'", false},
		{"github.event_name == 'push'", false},
	} {
		w := parse(t, "on: workflow_call\njobs:\n  a:\n    if: ${{ "+c.cond+" }}\n    runs-on: x\n    steps:\n      - run: a\n")
		j := w.Jobs.Value.Entries[0].Value.Value
		if got := AlwaysSkipped(w, &j); got != c.want {
			t.Errorf("%s: skipped %v, want %v", c.cond, got, c.want)
		}
	}
	// pull_request without types runs on its default activity types alone.
	w := parse(t, "on: pull_request\njobs:\n  a:\n    if: ${{ github.event.action == 'closed' }}\n    runs-on: x\n    steps:\n      - run: a\n")
	j := w.Jobs.Value.Entries[0].Value.Value
	if !AlwaysSkipped(w, &j) {
		t.Errorf("pull_request closed: not skipped")
	}
}

func TestCacheSavesOn(t *testing.T) {
	for _, c := range []struct {
		wf, job string // the cache-modes written; empty for none
		e       workflow.EventName
		want    bool
	}{
		{"", "", workflow.EventNamePush, true},
		{"", "", workflow.EventNameSchedule, true},
		{"", "", workflow.EventNamePullRequest, true}, // the merge ref's scope
		{"", "", workflow.EventNameIssueComment, false},
		{"", "", workflow.EventNamePullRequestTarget, false},
		{"", "", workflow.EventNameWorkflowCall, true}, // the caller decides
		{"", "read", workflow.EventNamePush, false},
		{"none", "", workflow.EventNamePush, false},
		{"", "write", workflow.EventNameIssueComment, true},
		{"write-only", "", workflow.EventNamePullRequestTarget, true},
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
		if got := CacheSavesOn(j.CacheMode, w.CacheMode, c.e); got != c.want {
			t.Errorf("wf %q job %q on %v: %v, want %v", c.wf, c.job, c.e, got, c.want)
		}
	}
}
