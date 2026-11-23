package analysis

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// TestGuarded: the guard of actions/checkout covers pull_request_target
// and workflow_run, and no other event.
func TestGuarded(t *testing.T) {
	for name, want := range map[workflow.EventName]bool{
		workflow.EventNamePullRequestTarget: true,
		workflow.EventNameWorkflowRun:       true,
		workflow.EventNameIssueComment:      false,
		workflow.EventNamePullRequest:       false,
	} {
		if got := Guarded(EventActivity{name: name}); got != want {
			t.Errorf("%s: %t, want %t", name, got, want)
		}
	}
}
