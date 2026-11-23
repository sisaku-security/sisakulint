package attacker

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

func passing(bs ...analysis.Barrier) Table { return TableOf(analysis.BarrierPasses{}.With(bs...)) }

// TestAssociationBarriers: an attacker who gets past an association
// barrier writes with that author_association; the outsider does not.
func TestAssociationBarriers(t *testing.T) {
	issues := ev(workflow.EventNameIssues, workflow.ActivityTypeOpened)
	comment := ev(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	member := passing(analysis.BarrierAssociationMember, analysis.BarrierAssociationCollaborator)
	owner := passing(analysis.BarrierAssociationOwner)
	for _, c := range []struct {
		name, cond string
		e          analysis.EventActivity
		tab        Table
		kept       bool
	}{
		{"outsider, MEMBER", "github.event.issue.author_association == 'MEMBER'", issues, Outsider, false},
		{"member, MEMBER", "github.event.issue.author_association == 'MEMBER'", issues, member, true},
		{"member, COLLABORATOR in a list", "contains(fromJSON('[\"MEMBER\",\"COLLABORATOR\"]'), github.event.issue.author_association)", issues, member, true},
		{"member, OWNER", "github.event.issue.author_association == 'OWNER'", issues, member, false},
		{"owner, OWNER", "github.event.issue.author_association == 'OWNER'", issues, owner, true},
		{"member, comment MEMBER on the owner's issue", "github.event.comment.author_association == 'MEMBER' && github.event.issue.author_association == 'OWNER'", comment, member, true},
		{"outsider, comment MEMBER on the owner's issue", "github.event.comment.author_association == 'MEMBER' && github.event.issue.author_association == 'OWNER'", comment, Outsider, false},
		{"member, comment and issue both MEMBER", "github.event.comment.author_association == 'MEMBER' && github.event.issue.author_association == 'MEMBER'", comment, member, true},
		{"outsider, comment and issue both MEMBER", "github.event.comment.author_association == 'MEMBER' && github.event.issue.author_association == 'MEMBER'", comment, Outsider, false},
	} {
		if got := c.tab.Kept(StepIf(nil, nil, ifOf(t, c.e.Name().String(), c.cond)), c.e); got != c.kept {
			t.Errorf("%s: Kept = %v, want %v", c.name, got, c.kept)
		}
	}
}

// TestActorNameBarrier: an attacker who gets past the actor-name barrier
// may be any account the workflow names, the actor and the author of what
// they write; the outsider is none of them.
func TestActorNameBarrier(t *testing.T) {
	opened := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	issues := ev(workflow.EventNameIssues, workflow.ActivityTypeOpened)
	named := passing(analysis.BarrierActorName)
	for _, c := range []struct {
		name, cond string
		e          analysis.EventActivity
		tab        Table
		kept       bool
	}{
		{"outsider, actor", "github.actor == 'maintainer'", opened, Outsider, false},
		{"named, actor", "github.actor == 'maintainer'", opened, named, true},
		{"named, a bot", "github.actor == 'renovate[bot]'", opened, named, true},
		{"named, a list of actors", "contains(fromJSON('[\"alice\",\"bob\"]'), github.triggering_actor)", opened, named, true},
		{"outsider, the author of the issue", "github.event.issue.user.login == 'maintainer'", issues, Outsider, false},
		{"named, the author of the issue", "github.event.issue.user.login == 'maintainer'", issues, named, true},
		{"named, the actor's id", "github.actor_id == 12345", opened, named, true},
		{"named, not the actor", "github.actor != 'maintainer'", opened, named, true},
	} {
		if got := c.tab.Kept(StepIf(nil, nil, ifOf(t, c.e.Name().String(), c.cond)), c.e); got != c.kept {
			t.Errorf("%s: Kept = %v, want %v", c.name, got, c.kept)
		}
	}
}

// TestWrittenObjects: an attacker whose credential writes only some
// objects starts only the runs of those: a token that writes comments on
// issues only does not start a run of a comment on a pull request, nor of
// a review; one that writes comments on pull requests only does not start
// a run of an issue.
func TestWrittenObjects(t *testing.T) {
	issueComment := ev(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	review := ev(workflow.EventNamePullRequestReview, workflow.ActivityTypeSubmitted)
	opened := ev(workflow.EventNameIssues, workflow.ActivityTypeOpened)
	issuesToken := TableOf(analysis.BarrierPasses{}.Limited(analysis.WrittenIssue, analysis.WrittenIssueComment))
	pullsToken := TableOf(analysis.BarrierPasses{}.Limited(analysis.WrittenPullRequestComment, analysis.WrittenPullRequestReview))
	for _, c := range []struct {
		name, cond string
		e          analysis.EventActivity
		tab        Table
		kept       bool
	}{
		{"outsider, a comment on a pull request", "github.event.issue.pull_request", issueComment, Outsider, true},
		{"outsider, a comment on an issue", "${{ !github.event.issue.pull_request }}", issueComment, Outsider, true},
		{"issues token, a comment on a pull request", "github.event.issue.pull_request", issueComment, issuesToken, false},
		{"issues token, a comment on an issue", "${{ !github.event.issue.pull_request }}", issueComment, issuesToken, true},
		{"pulls token, a comment on a pull request", "github.event.issue.pull_request", issueComment, pullsToken, true},
		{"pulls token, a comment on an issue", "${{ !github.event.issue.pull_request }}", issueComment, pullsToken, false},
		{"issues token, a review", "", review, issuesToken, false},
		{"pulls token, a review", "", review, pullsToken, true},
		{"pulls token, an issue", "", opened, pullsToken, false},
		{"issues token, an issue", "", opened, issuesToken, true},
	} {
		cond := c.cond
		if cond == "" {
			cond = "true"
		}
		if got := c.tab.Kept(StepIf(nil, nil, ifOf(t, c.e.Name().String(), cond)), c.e); got != c.kept {
			t.Errorf("%s: Kept = %v, want %v", c.name, got, c.kept)
		}
	}
}
