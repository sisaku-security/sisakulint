package job

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// forkPullRequestEvents are the events of a pull request whose run for a
// pull request from a fork has no secret but GITHUB_TOKEN unless the
// settings of a private repository send them (repo.fork-pr-secrets), as
// the rows of actions/boundary for the head of a fork say (forkPRGrants).
// pull_request_target is not one: its run has the secrets.
var forkPullRequestEvents = []workflow.EventName{workflow.EventNamePullRequest, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment}

// ForkPullRequestOnly is whether the job j of w runs only on pull_request,
// pull_request_review and pull_request_review_comment
// (forkPullRequestEvents), and there only for a pull request from a fork,
// in a repository that is not a fork: on every event and activity type of
// the on of w, an if that a run of j goes through (JobReach) is false by
// the event alone, or the event is one of the three and that if is false
// in a run for a pull request from a branch of the repository
// (attacker.BranchPullRequestFalse). False when j is skipped on every
// event, or the events of w are not known.
func ForkPullRequestOnly(w *workflow.Workflow, j *workflow.Job) bool {
	evs, _, known := taint.WorkflowEvents(w)
	if !known {
		return false
	}
	ifs := JobReach(w, j).Ifs()
	runs := false
	for _, e := range evs {
		stopped, fork, pr := false, false, slices.Contains(forkPullRequestEvents, e.Name())
		for _, p := range ifs {
			if attacker.EventOnly(p, e) == expr.TruthFalse {
				stopped = true
				break
			}
			fork = fork || pr && attacker.BranchPullRequestFalse(p, e)
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
