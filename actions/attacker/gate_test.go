package attacker

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// gateOf is the if of the job (none when cond is empty) and the value of
// the input x of the step of a workflow, written value.
func gateOf(t *testing.T, cond, value string) ([]PlacedIf, workflow.String) {
	t.Helper()
	src := "on: issues\njobs:\n  a:\n"
	if cond != "" {
		src += "    if: " + cond + "\n"
	}
	src += "    runs-on: x\n    steps:\n      - uses: o/r@v1\n        with:\n          x: " + value + "\n"
	w, _ := workflow.Parse(cst.Parse([]byte(src)))
	j := w.Jobs.Value.Entries[0].Value.Value
	e, ok := j.Steps.Value.Items[0].With.Value.Lookup("x")
	if !ok {
		t.Fatalf("no x in %q", src)
	}
	v := e.Value.Value
	if e.Value.Status == workflow.Dynamic {
		v = *e.Value.Expr
	}
	return []PlacedIf{StepIf(nil, nil, j.If)}, v
}

// TestActorListed: the reading of a gate's value: the attacker who
// triggers the event as its actor, past the if;
// '*' after a trim, or an element that is one ${{ }} of their login.
func TestActorListed(t *testing.T) {
	opened := ev(workflow.EventNameIssues, workflow.ActivityTypeOpened)
	labeled := ev(workflow.EventNameIssues, workflow.ActivityTypeLabeled)
	comment := ev(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	wr := ev(workflow.EventNameWorkflowRun, workflow.ActivityTypeCompleted)
	T, F, U := expr.TruthTrue, expr.TruthFalse, expr.TruthUnknown
	for _, c := range []struct {
		name, cond, value string
		e                 analysis.EventActivity
		listed            expr.Truth
		anyone            bool
	}{
		{"the issue's author on opened (nnUNet)", "", "${{ github.event.issue.user.login }}", opened, T, false},
		{"nnUNet's if", "github.actor != 'claude[bot]' && github.actor != 'github-actions[bot]' && github.event.issue.state != 'closed' && !github.event.issue.pull_request", "${{ github.event.issue.user.login }}", opened, T, false},
		{"the actor", "", "${{ github.actor }}", opened, T, false},
		{"the sender", "", "${{ github.event.sender.login }}", opened, T, false},
		{"in a list", "", "'alice, ${{ github.actor }}'", opened, T, false},
		{"a block scalar: trimmed", "", "|\n            ${{ github.actor }}", opened, T, false},
		{"with text: not the login", "", "'x${{ github.actor }}'", opened, F, false},
		{"'*' of an expression", "", "${{ '*' }}", opened, T, true},
		{"'*' on issues only", "", "${{ github.event_name == 'issues' && '*' || '' }}", opened, T, true},
		{"the repository's owner", "", "${{ github.repository_owner }}", opened, F, false},
		{"a list with the owner", "", "'alice,${{ github.repository_owner }}'", opened, F, false},
		{"the actor's ID", "", "${{ github.actor_id }}", opened, F, false},
		{"a variable", "", "${{ vars.USERS }}", opened, U, false},
		{"a function Partial does not read", "", "${{ join(github.event.issue.assignees.*.login, ',') }}", opened, U, false},
		{"a branch the attacker names", "", "${{ github.head_ref }}", prt, U, false},
		{"the author of their pull request", "", "${{ github.event.pull_request.user.login }}", prt, T, false},
		{"a comment on their own issue", "", "${{ github.event.issue.user.login }}", comment, T, false},
		{"a comment, if the issue is the owner's", "github.event.issue.author_association == 'OWNER'", "${{ github.event.issue.user.login }}", comment, F, false},
		{"a comment, if the actor wrote the issue", "github.event.issue.user.login == github.actor", "${{ github.event.issue.user.login }}", comment, T, false},
		{"a comment on the owner's issue, the actor", "github.event.issue.author_association == 'OWNER'", "${{ github.actor }}", comment, T, false},
		{"labeled: a maintainer is the actor", "", "${{ github.event.issue.user.login }}", labeled, F, false},
		{"workflow_run: the actor of the run before", "", "${{ github.actor }}", wr, T, false},
		{"an if the attacker does not pass", "github.event.issue.author_association == 'OWNER'", "${{ github.actor }}", opened, F, false},
		{"a comment on their own issue, if its author is not the actor", "github.event.issue.user.login != github.actor", "${{ github.event.issue.user.login }}", comment, F, false},
		{"a bool: 'false'", "", "${{ github.event_name == 'issue_comment' && github.actor }}", opened, F, false},
		{"null", "", "${{ null }}", opened, F, false},
		{"the owner of their fork", "", "${{ github.event.pull_request.head.repo.owner.login }}", prt, T, false},
		{"a review on a pull request the attacker opened from a branch of the repository", "", "${{ github.event.pull_request.user.login }}", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), T, false},
		{"a review: the owner of the head is the repository's", "", "${{ github.event.pull_request.head.repo.owner.login }}", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), F, false},
		// GitHub lets no author approve their own pull request
		{"an approved review on their own pull request", "github.event.review.state == 'approved'", "${{ github.event.pull_request.user.login }}", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), F, false},
		{"an approved review, in upper case", "github.event.review.state == 'APPROVED'", "${{ github.event.pull_request.user.login }}", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), F, false},
		{"a review that is not approved on their own pull request", "github.event.review.state != 'approved'", "${{ github.event.pull_request.user.login }}", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), T, false},
		{"a commented review on their own pull request", "github.event.review.state == 'commented'", "${{ github.event.pull_request.user.login }}", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), T, false},
		{"an approved review, the reviewer as the gate", "github.event.review.state == 'approved'", "${{ github.actor }}", ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted), T, false},
	} {
		ifs, v := gateOf(t, c.cond, c.value)
		if listed, anyone := Outsider.ActorListed(ifs, c.e, v); listed != c.listed || anyone != c.anyone {
			t.Errorf("%s: listed %v anyone %v, want %v %v", c.name, listed, anyone, c.listed, c.anyone)
		}
	}
}
