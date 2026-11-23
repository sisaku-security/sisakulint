package attacker

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// ifOf is the if of the first job of a workflow whose on is on.
func ifOf(t *testing.T, on, cond string) workflow.Field[workflow.If] {
	t.Helper()
	src := "on: " + on + "\njobs:\n  a:\n    if: " + cond + "\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
	w, _ := workflow.Parse(cst.Parse([]byte(src)))
	return w.Jobs.Value.Entries[0].Value.Value.If
}

func ev(e workflow.EventName, a workflow.ActivityType) analysis.EventActivity {
	return analysis.MustEventActivity(e, a)
}

func TestKept(t *testing.T) {
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)
	prtLabeled := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeLabeled)
	comment := ev(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	issues := ev(workflow.EventNameIssues, workflow.ActivityTypeOpened)
	wr := ev(workflow.EventNameWorkflowRun, workflow.ActivityTypeCompleted)
	push := ev(workflow.EventNamePush, workflow.ActivityTypeUnset)
	for _, c := range []struct {
		name, cond string
		e          analysis.EventActivity
		kept       bool
	}{
		{"fork full name: a pull request from a branch of the repository", "github.event.pull_request.head.repo.full_name == github.repository", prt, true},
		{"fork flag: null once the fork is deleted", "github.event.pull_request.head.repo.fork == false", prt, true},
		{"not a fork", "${{ !github.event.pull_request.head.repo.fork }}", prt, true},
		{"owner's comment on the attacker's issue", "github.event.comment.author_association == 'OWNER'", comment, true},
		{"members' comment on the attacker's issue", "contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association)", comment, true},
		{"owner's comment on the owner's issue", "github.event.comment.author_association == 'OWNER' && github.event.issue.author_association == 'OWNER'", comment, false},
		{"review by the owner of the attacker's pull request", "github.event.review.author_association == 'OWNER'", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), true},
		{"issue opened by owner", "github.event.issue.author_association == 'OWNER'", issues, false},
		{"comment's issue by owner", "github.event.issue.author_association == 'OWNER'", comment, true},
		{"contributor", "github.event.comment.author_association == 'CONTRIBUTOR'", comment, true},
		{"or a contributor", "github.event.comment.author_association == 'OWNER' || github.event.comment.author_association == 'NONE'", comment, true},
		{"workflow_run: the run before may be pull_request_target's", "github.event.workflow_run.head_repository.full_name == github.repository", wr, true},
		{"actor owner on opened", "github.actor == 'octocat'", ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened), false},
		{"actor owner on synchronize: a maintainer may push", "github.actor == 'octocat'", prt, true},
		{"actor owner on labeled", "github.actor == 'octocat'", prtLabeled, true},
		{"actor owner on issues closed", "github.actor == 'octocat'", ev(workflow.EventNameIssues, workflow.ActivityTypeClosed), true},
		{"sender owner on comment deleted", "github.event.sender.login == 'octocat'", ev(workflow.EventNameIssueComment, workflow.ActivityTypeDeleted), true},
		{"actor owner on comment created: the owner comments on the attacker's issue", "github.actor == 'octocat'", comment, true},
		{"an outsider's comment on the owner's issue", "github.event.comment.author_association == 'NONE' && github.event.issue.author_association == 'OWNER'", comment, true},
		{"actor on workflow_run", "github.actor == 'octocat'", wr, true},
		{"dependabot", "github.actor == 'dependabot[bot]'", prt, true},
		{"pr author dependabot", "github.event.pull_request.user.login == 'dependabot[bot]'", prt, false},
		{"actor id", "github.actor_id == 49699333", prt, true},
		{"head ref", "github.head_ref == 'main'", prt, true},
		{"push not a table event", "github.actor == 'octocat'", push, true},
		{"step output", "steps.x.outputs.ok == 'true'", prt, true},
		{"event name", "github.event_name == 'push'", prt, false},
		{"mixed", "x ${{ false }}", prt, true},
		{"review: a pull request from a branch of the repository", "github.event.pull_request.head.repo.full_name == github.repository", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), true},
		{"review: a pull request from a fork only", "github.event.pull_request.head.repo.full_name != github.repository", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), false},
		{"review comment: a pull request from a fork only", "github.event.pull_request.head.repo.full_name != github.repository", ev(workflow.EventNamePullRequestReviewComment, workflow.ActivityTypeCreated), false},
		{"review: the fork flag of the head is that of the repository, not known", "github.event.pull_request.head.repo.fork", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), true},
		{"review: the author of the pull request is the owner", "github.event.pull_request.user.login == 'octocat'", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), true},
	} {
		if got := Outsider.Kept(StepIf(nil, nil, ifOf(t, "pull_request_target", c.cond)), c.e); got != c.kept {
			t.Errorf("%s: kept %v, want %v", c.name, got, c.kept)
		}
	}
}

// TestKeptSyntax: an if that does not parse keeps the
// event, as before.
func TestKeptSyntax(t *testing.T) {
	e := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)
	if !Outsider.Kept(StepIf(nil, nil, ifOf(t, "pull_request_target", "github.actor == (")), e) {
		t.Error("an if that does not parse kept the event out")
	}
}

func TestEventOnly(t *testing.T) {
	e := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)
	if got := EventOnly(StepIf(nil, nil, ifOf(t, "pull_request_target", "github.event.pull_request.head.repo.fork == false")), e); got != expr.TruthUnknown {
		t.Errorf("EventOnly reads more than the event: %v", got)
	}
	if got := EventOnly(StepIf(nil, nil, ifOf(t, "pull_request_target", "github.event_name == 'push'")), e); got != expr.TruthFalse {
		t.Errorf("EventOnly: %v", got)
	}
}

// TestKeptCode: a pull request from a branch of the repository brings the
// code of those who can write, so a guard by the head's full name keeps
// the attacker's code out, but not their title.
func TestKeptCode(t *testing.T) {
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)
	for _, c := range []struct {
		cond       string
		kept, code bool
	}{
		{"github.event.pull_request.head.repo.full_name == github.repository", true, false},
		{"github.event.pull_request.head.repo.fork == false", true, true},
		{"github.event.pull_request.user.login == 'octocat'", false, false},
	} {
		w := ifOf(t, "pull_request_target", c.cond)
		if got := Outsider.Kept(StepIf(nil, nil, w), prt); got != c.kept {
			t.Errorf("%s: kept %v", c.cond, got)
		}
		if got := Outsider.KeptCode(StepIf(nil, nil, w), prt); got != c.code {
			t.Errorf("%s: kept for code %v", c.cond, got)
		}
	}
	// a review is of a pull request from a branch of the repository, whose
	// code is of those who can write
	for _, e := range []analysis.EventActivity{ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), ev(workflow.EventNamePullRequestReviewComment, workflow.ActivityTypeCreated)} {
		if Outsider.KeptCode(StepIf(nil, nil, workflow.Field[workflow.If]{}), e) {
			t.Errorf("%s: kept for code", e.Name())
		}
	}
}

// TestKeptEmpty: an empty if is success(), which is not known.
func TestKeptEmpty(t *testing.T) {
	e := ev(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	if !Outsider.Kept(StepIf(nil, nil, ifOf(t, "issue_comment", "''")), e) {
		t.Error("an empty if kept the event out")
	}
}

// TestKeptActor: the attacker triggers e themselves, as its actor, and c
// is not false then: not an activity type someone else triggers, not a
// comment of the owner; workflow_run's actor is that of the run before
// it, which may be theirs; a pull request from a branch of the repository
// is theirs to open, not to push to.
func TestKeptActor(t *testing.T) {
	issues := ev(workflow.EventNameIssues, workflow.ActivityTypeOpened)
	labeled := ev(workflow.EventNameIssues, workflow.ActivityTypeLabeled)
	comment := ev(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)
	wr := ev(workflow.EventNameWorkflowRun, workflow.ActivityTypeCompleted)
	for _, c := range []struct {
		name, cond string
		e          analysis.EventActivity
		kept       bool
	}{
		{"opened", "true", issues, true},
		{"labeled: a maintainer labels", "true", labeled, false},
		{"comment", "true", comment, true},
		{"owner's comment", "github.event.comment.author_association == 'OWNER'", comment, false},
		{"comment on the owner's issue", "github.event.issue.author_association == 'OWNER'", comment, true},
		{"actor owner on synchronize: the attacker pushes", "github.actor == 'octocat'", prt, false},
		{"synchronize", "true", prt, true},
		{"workflow_run: the run before is of the attacker's pull request or comment", "true", wr, true},
		{"workflow_run, actor owner", "github.actor == 'octocat'", wr, false},
		{"a branch of the repository: anyone who reads opens the pull request", "github.event.pull_request.head.repo.full_name == github.repository", ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened), true},
		{"a branch of the repository on synchronize: those who can write push", "github.event.pull_request.head.repo.full_name == github.repository", prt, false},
		{"dependabot", "github.actor == 'dependabot[bot]'", prt, false},
	} {
		if got := Outsider.KeptActor(StepIf(nil, nil, ifOf(t, "issues", c.cond)), c.e); got != c.kept {
			t.Errorf("%s: kept %v, want %v", c.name, got, c.kept)
		}
	}
	if !Outsider.KeptActor(StepIf(nil, nil, workflow.Field[workflow.If]{}), issues) {
		t.Error("no if: not kept")
	}
}

func path(names ...string) []expr.PathElem {
	var out []expr.PathElem
	for _, n := range names {
		out = append(out, expr.PathElem{Name: n})
	}
	return out
}

// TestKeptOthers: a run whose actor is not the
// attacker (a maintainer labels their issue, comments on it), in which the
// value is the attacker's, past the if.
func TestKeptOthers(t *testing.T) {
	opened := ev(workflow.EventNameIssues, workflow.ActivityTypeOpened)
	labeled := ev(workflow.EventNameIssues, workflow.ActivityTypeLabeled)
	comment := ev(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	fork := ev(workflow.EventNameFork, workflow.ActivityTypeUnset)
	title := path("github", "event", "issue", "title")
	body := path("github", "event", "comment", "body")
	for _, c := range []struct {
		name, cond string
		e          analysis.EventActivity
		p          []expr.PathElem
		kept       bool
	}{
		{"opened: only the author", "true", opened, title, false},
		{"labeled: a maintainer", "true", labeled, title, true},
		{"labeled, if the label", "github.event.label.name == 'triage'", labeled, title, true},
		{"labeled, if the attacker", "github.actor == 'mallory'", labeled, title, true},
		{"comment on the attacker's issue: its title", "true", comment, title, true},
		{"comment on the attacker's issue: the comment is the maintainer's", "true", comment, body, false},
		{"the owner's comment", "github.event.comment.author_association == 'OWNER'", comment, title, true},
		{"pull_request_target opened: only the author", "true", prt, path("github", "event", "pull_request", "title"), false},
		{"fork: only the attacker", "true", fork, path("github", "event", "forkee", "full_name"), false},
		{"env: read as the attacker's", "true", comment, path("env", "X"), true},
		{"another's review on the attacker's pull request: its title", "true", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), path("github", "event", "pull_request", "title"), true},
		{"another's review on the attacker's pull request: the review is the other's", "true", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), path("github", "event", "review", "body"), false},
		{"another's review, if the pull request is from a fork", "github.event.pull_request.head.repo.full_name != github.repository", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), path("github", "event", "pull_request", "title"), false},
	} {
		if got := Outsider.KeptOthers(StepIf(nil, nil, ifOf(t, "issues", c.cond)), c.e, c.p); got != c.kept {
			t.Errorf("%s: kept %v, want %v", c.name, got, c.kept)
		}
	}
}
