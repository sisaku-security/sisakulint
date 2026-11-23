package job

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/workflow"
)

func TestEventNamesOf(t *testing.T) {
	w := parse(t, "on: [push, pull_request, workflow_call, push]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n")
	want := []workflow.EventName{workflow.EventNamePush, workflow.EventNamePullRequest, workflow.EventNameWorkflowCall}
	if got := EventNamesOf(w); !slices.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
	if got := EventNamesOf(parse(t, "jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n")); len(got) != 0 {
		t.Errorf("no on: %v", got)
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
