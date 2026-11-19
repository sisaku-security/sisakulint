package job

import (
	"github.com/sisaku-security/sisakulint/actions/attacker"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// privileged are the attacker's privileged events: one without write
// access triggers them, and the run has the repository's secrets and a
// token that may write. pull_request_review and
// pull_request_review_comment are privileged as the review of a pull
// request from a branch of the repository, which anyone who may comment
// writes, and whose run has the secrets and the token the workflow asks
// for; the attacker run table (package attacker) reads their runs so. A
// review of a pull request from a fork gives the author of the pull request
// nothing more, as the run takes the workflow of the merge commit of the
// pull request, which the author can change; a review of another's pull
// request from a fork the rules declare as the undetected form
// fork-review. push and merge_group need write access; gollum needs a wiki
// anyone may edit (the limit gollum of dangerous-triggers); watch carries
// nothing the attacker writes (the limit watch of dangerous-triggers). A
// run of these events starts unless the Actions policies of the repository
// block it; the engine of the rules (package lint) asks whether they block
// it for pull_request_target alone (repo.pull-request-target-allowed).
// status, check_suite and check_run are privileged where an app outside
// GitHub Actions, such as an outside CI, makes a commit status or a check
// run for a commit whose message an attacker writes (a commit of a pull
// request from a fork, or a commit that merges a pull request): the run
// starts on the default branch with the SHA of the commit in the payload,
// and for status and check_suite with its message and names too; the engine
// asks repo.fork-pr-app-checks or repo.merge-commit-app-checks of a
// workflow whose on has no other event.
var privileged = []workflow.EventName{
	workflow.EventNameCheckRun,
	workflow.EventNameCheckSuite,
	workflow.EventNameDiscussion,
	workflow.EventNameDiscussionComment,
	workflow.EventNameFork,
	workflow.EventNameIssueComment,
	workflow.EventNameIssues,
	workflow.EventNamePullRequestReview,
	workflow.EventNamePullRequestReviewComment,
	workflow.EventNamePullRequestTarget,
	workflow.EventNameStatus,
	workflow.EventNameWorkflowRun,
}

// Privileged are the attacker's privileged events.
func Privileged() []workflow.EventName { return slices.Clone(privileged) }

// eventsOf are the attacker's privileged events of w's own on that the job
// j can run on: those its if is not known to be false on. A workflow that
// can be called runs on its callers' events, which its callers' jobs are
// read for.
func eventsOf(w *workflow.Workflow, j workflow.Job, t attacker.Table) []analysis.EventActivity {
	return taint.Filter(t, taint.EventsOn(w, privileged), attacker.JobIfs(w, &j)...)
}
