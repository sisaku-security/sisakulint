package job

import (
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// ForkPullRequestOnly is whether the job j of w runs only on pull_request,
// and there only for a pull request from a fork, in a repository that is
// not a fork: on every event and activity type of the on of w, an if that
// a run of j goes through (attacker.JobIfs) is false by the event alone,
// or the event is pull_request and that if is false in a run for a pull
// request from a branch of the repository (attacker.BranchPullRequestFalse).
// False when j is skipped on every event, or the events of w are not known.
func ForkPullRequestOnly(w *workflow.Workflow, j *workflow.Job) bool {
	evs, _, known := taint.WorkflowEvents(w)
	if !known {
		return false
	}
	ifs := attacker.JobIfs(w, j)
	runs := false
	for _, e := range evs {
		stopped, fork := false, false
		for _, p := range ifs {
			if attacker.EventOnly(p, e) == expr.TruthFalse {
				stopped = true
				break
			}
			fork = fork || attacker.BranchPullRequestFalse(p, e)
		}
		switch {
		case stopped:
		case fork:
			runs = true
		default:
			return false
		}
	}
	return runs
}
