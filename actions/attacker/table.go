package attacker

import (
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// RunKind is a kind of run whose payload holds what an attacker wrote.
type RunKind uint8

const (
	// RunOwn is a run of what the attacker wrote: they trigger it, or one
	// who can write acts on it (labels, closes, edits it); its actor is the
	// attacker only for the activity types no one else triggers. Of a
	// review, it is the attacker's review of a pull request from a branch
	// of the repository.
	RunOwn RunKind = iota + 1
	// RunBaseBranch is pull_request_target of the attacker's pull request
	// from a branch of the repository, which anyone who reads it may open:
	// its head is no fork, and its code is of those who can write.
	RunBaseBranch
	// RunDependabot is the run of Dependabot's push to the attacker's pull
	// request from their fork.
	RunDependabot
	// RunOthersComment is a run of a comment or a review someone else
	// writes on the attacker's issue, pull request or discussion: one who
	// can write, too. Its comment is not the attacker's; what it is on is
	// Of a review, the pull request is one the
	// attacker opened from a branch of the repository.
	RunOthersComment
)

// row is a path below github, lowered, and its value in a run.
type row struct {
	path  string
	value expr.Value
}

var (
	ownLogin = expr.AbstractValue(own{form: formLogin})
	ownID    = expr.AbstractValue(own{form: formID})
	ownRepo  = expr.AbstractValue(own{form: formRepo})
	outsider = expr.AbstractValue(set(outsiderAssociations))
	null     = expr.Null()
)

// repositoryRows are the values of the repository the workflow runs in.
var repositoryRows = []row{
	{"repository", expr.AbstractValue(repository)},
	{"event.repository.full_name", expr.AbstractValue(repository)},
	{"repository_owner", expr.AbstractValue(repositoryOwner)},
	{"event.repository.owner.login", expr.AbstractValue(repositoryOwner)},
}

// actorRows are the actor of a run the attacker triggers.
var actorRows = []row{
	{"actor", ownLogin}, {"triggering_actor", ownLogin}, {"event.sender.login", ownLogin},
	{"actor_id", ownID}, {"triggering_actor_id", ownID}, {"event.sender.id", ownID},
}

// dependabotRows are the actor of a run Dependabot's push triggers
// (the ID is dependabot[bot]'s).
var dependabotRows = []row{
	{"actor", expr.String("dependabot[bot]")}, {"triggering_actor", expr.String("dependabot[bot]")}, {"event.sender.login", expr.String("dependabot[bot]")},
	{"actor_id", expr.Number(49699333)}, {"triggering_actor_id", expr.Number(49699333)}, {"event.sender.id", expr.Number(49699333)},
}

// pullRequestRows are the rows of the attacker's pull request, whatever
// its head.
var pullRequestRows = []row{
	{"event.pull_request.user.login", ownLogin},
	{"event.pull_request.user.id", ownID},
	{"event.pull_request.author_association", outsider},
}

// forkHeadRows are the head of a pull request from the attacker's fork:
// null once they delete the fork (GitHub compares null as 0, as false).
var forkHeadRows = []row{
	{"event.pull_request.head.repo.fork", expr.AbstractValue(oneOf{expr.Bool(true), null})},
	{"event.pull_request.head.repo.full_name", expr.AbstractValue(oneOf{ownRepo, null})},
	{"event.pull_request.head.repo.owner.login", expr.AbstractValue(oneOf{ownLogin, null})},
	{"head_ref", expr.AbstractValue(chosen{})},
	{"event.pull_request.head.ref", expr.AbstractValue(chosen{})},
}

// baseHeadRows are the head of a pull request from a branch of the
// repository: the repository itself, a fork or not.
var baseHeadRows = []row{
	{"event.pull_request.head.repo.full_name", expr.AbstractValue(repository)},
	{"event.pull_request.head.repo.owner.login", expr.AbstractValue(repositoryOwner)},
}

// object is what the attacker wrote of an event: its rows, and the
// activity types only its author triggers, whose actor is the attacker.
type object struct {
	rows     []row
	on       []row                   // the rows of what the comment or review is on, the attacker's in RunOthersComment
	actors   []workflow.ActivityType // only the author triggers them
	acts     []workflow.ActivityType // the attacker may trigger them themselves
	anyActor bool                    // an event without activity types only the attacker triggers (fork, gollum)
	// branchHead: the runs are of a pull request from a branch of the
	// repository. A review of a pull request from a fork gives the author
	// of the pull request nothing more, as the author can change the
	// workflow of the run (it runs the workflow of the merge commit of the
	// pull request); a review of another's pull request from a fork is the
	// undetected form fork-review of the rules.
	branchHead bool
}

func authored(prefix string) []row {
	return []row{
		{"event." + prefix + ".author_association", outsider},
		{"event." + prefix + ".user.login", ownLogin},
		{"event." + prefix + ".user.id", ownID},
	}
}

func types(ts ...workflow.ActivityType) []workflow.ActivityType { return ts }

// objects are the events of the table (not push, not merge_group).
// workflow_run has no row of its head repository: the run
// before it may be of pull_request_target or issue_comment, which the
// attacker triggers on the default branch of the repository.
var objects = map[workflow.EventName]object{
	workflow.EventNameIssues:                   {rows: authored("issue"), actors: types(workflow.ActivityTypeOpened), acts: types(workflow.ActivityTypeOpened, workflow.ActivityTypeEdited, workflow.ActivityTypeClosed, workflow.ActivityTypeReopened)},
	workflow.EventNameIssueComment:             {rows: authored("comment"), on: authored("issue"), actors: types(workflow.ActivityTypeCreated), acts: types(workflow.ActivityTypeCreated, workflow.ActivityTypeEdited, workflow.ActivityTypeDeleted)},
	workflow.EventNameDiscussion:               {rows: authored("discussion"), actors: types(workflow.ActivityTypeCreated), acts: types(workflow.ActivityTypeCreated, workflow.ActivityTypeEdited)},
	workflow.EventNameDiscussionComment:        {rows: authored("comment"), on: authored("discussion"), actors: types(workflow.ActivityTypeCreated), acts: types(workflow.ActivityTypeCreated, workflow.ActivityTypeEdited, workflow.ActivityTypeDeleted)},
	workflow.EventNamePullRequestReviewComment: {rows: authored("comment"), on: slices.Concat(pullRequestRows, baseHeadRows), actors: types(workflow.ActivityTypeCreated), acts: types(workflow.ActivityTypeCreated, workflow.ActivityTypeEdited, workflow.ActivityTypeDeleted), branchHead: true},
	workflow.EventNamePullRequestReview:        {rows: authored("review"), on: slices.Concat(pullRequestRows, baseHeadRows), actors: types(workflow.ActivityTypeSubmitted), acts: types(workflow.ActivityTypeSubmitted, workflow.ActivityTypeEdited), branchHead: true},
	workflow.EventNamePullRequestTarget:        {rows: pullRequestRows, actors: types(workflow.ActivityTypeOpened), acts: types(workflow.ActivityTypeOpened, workflow.ActivityTypeEdited, workflow.ActivityTypeClosed, workflow.ActivityTypeReopened, workflow.ActivityTypeSynchronize, workflow.ActivityTypeReadyForReview, workflow.ActivityTypeConvertedToDraft)},
	workflow.EventNameWorkflowRun:              {rows: []row{{"event.workflow_run.head_branch", expr.AbstractValue(chosen{})}}},
	workflow.EventNameFork:                     {rows: []row{{"event.forkee.full_name", ownRepo}, {"event.forkee.owner.login", ownLogin}}, anyActor: true},
	workflow.EventNameGollum:                   {anyActor: true},
}

// Runs are the kinds of runs of e: none for an event the table does not
// have.
func Runs(e analysis.EventActivity) []RunKind {
	if _, ok := objects[e.Name()]; !ok {
		return nil
	}
	if e.Name() != workflow.EventNamePullRequestTarget {
		if objects[e.Name()].on != nil {
			return []RunKind{RunOwn, RunOthersComment}
		}
		return []RunKind{RunOwn}
	}
	if e.ActivityType() == workflow.ActivityTypeSynchronize {
		return []RunKind{RunOwn, RunBaseBranch, RunDependabot}
	}
	return []RunKind{RunOwn, RunBaseBranch}
}

// rowsOf are the rows of the run k of e, besides event_name and action.
// actor puts the attacker as the actor whatever the activity type: the
// run as the attacker would trigger it.
func (t Table) rowsOf(e analysis.EventActivity, k RunKind, actor bool) []row {
	o := objects[e.Name()]
	if k == RunOthersComment {
		return t.added(e, k, slices.Concat(repositoryRows, o.on)) // the comment and the actor are someone else's
	}
	var out []row
	if k == RunDependabot {
		out = append(out, dependabotRows...)
	} else if actor || o.anyActor || slices.Contains(o.actors, e.ActivityType()) {
		out = append(out, actorRows...)
	}
	out = append(out, repositoryRows...)
	out = append(out, o.rows...)
	if o.branchHead {
		out = append(out, baseHeadRows...)
	}
	if e.Name() == workflow.EventNamePullRequestTarget {
		if k == RunBaseBranch {
			out = append(out, baseHeadRows...)
		} else {
			out = append(out, forkHeadRows...)
		}
	}
	return t.added(e, k, out)
}

// added are rows with the values of the attacker t adds: the
// author_association of what the attacker writes is also each value whose
// barrier they get past, and their login and ID, as the actor and as the
// author, are any account the workflow names when they get past the
// actor-name barrier.
func (t Table) added(e analysis.EventActivity, k RunKind, rows []row) []row {
	rows = t.pullRequestRow(e, k, rows)
	if !t.authors(e, k) {
		return rows // what the run is of, the attacker wrote with an account of their own, as an outsider
	}
	assoc := slices.Clone(outsiderAssociations)
	for _, x := range []struct {
		b analysis.Barrier
		v string
	}{{analysis.BarrierAssociationOwner, "OWNER"}, {analysis.BarrierAssociationMember, "MEMBER"}, {analysis.BarrierAssociationCollaborator, "COLLABORATOR"}} {
		if t.barriers.Passes(x.b) {
			assoc = append(assoc, x.v)
		}
	}
	name := t.barriers.Passes(analysis.BarrierActorName)
	if len(assoc) == len(outsiderAssociations) && !name {
		return rows
	}
	out := slices.Clone(rows)
	for i, r := range out {
		switch {
		case strings.HasSuffix(r.path, ".author_association") && len(assoc) > len(outsiderAssociations):
			out[i].value = expr.AbstractValue(set(assoc))
		case name && (sameValue(r.value, ownLogin) || sameValue(r.value, ownID)):
			out[i].value = namedName
		}
	}
	return out
}

// sameValue is whether v is the abstract value w: a value of the table.
func sameValue(v, w expr.Value) bool {
	a, ok := v.AbstractOf()
	b, ok2 := w.AbstractOf()
	return ok && ok2 && a == b
}

// acts is whether the attacker may trigger e themselves, as its actor.
func acts(e analysis.EventActivity) bool {
	o := objects[e.Name()]
	return o.anyActor || slices.Contains(o.acts, e.ActivityType())
}

// Table is the attacker run table as a run reads it: the rows of the runs
// of an attacker outside the repository, and, where the run adds an
// attacker (lint's AddedAttacker), the barriers that attacker gets past
// (BarrierPasses). Outsider is the table of a run that adds none.
type Table struct{ barriers analysis.BarrierPasses }

// Outsider is the table of a run that adds no attacker: the attacker is
// outside the repository and gets past no barrier.
var Outsider Table

// TableOf is the table of a run whose attacker gets past p.
func TableOf(p analysis.BarrierPasses) Table { return Table{barriers: p} }

// Barriers are the barriers the attacker of t gets past.
func (t Table) Barriers() analysis.BarrierPasses { return t.barriers }

// needs are the objects one of which the attacker writes for a run k of e
// to be theirs; accountOnly, that the run is of an act of an account
// (forking, editing the wiki), which no credential limited to some
// objects does.
func needs(e analysis.EventActivity, k RunKind) (objects []analysis.WrittenObject, accountOnly bool) {
	others := k == RunOthersComment
	switch e.Name() {
	case workflow.EventNameIssues:
		return []analysis.WrittenObject{analysis.WrittenIssue}, false
	case workflow.EventNameIssueComment:
		if others {
			return []analysis.WrittenObject{analysis.WrittenIssue, analysis.WrittenPullRequest}, false
		}
		return []analysis.WrittenObject{analysis.WrittenIssueComment, analysis.WrittenPullRequestComment}, false
	case workflow.EventNameDiscussion, workflow.EventNameDiscussionComment:
		return []analysis.WrittenObject{analysis.WrittenDiscussion}, false
	case workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment:
		if others {
			return []analysis.WrittenObject{analysis.WrittenPullRequest}, false
		}
		return []analysis.WrittenObject{analysis.WrittenPullRequestReview}, false
	case workflow.EventNamePullRequestTarget:
		return []analysis.WrittenObject{analysis.WrittenPullRequest}, false
	case workflow.EventNameWorkflowRun:
		return analysis.WrittenObjects(), false // a run of any of them may come before
	}
	return nil, true
}

// authors is whether the credential of the attacker of t writes what the
// run k of e is of: the object the run needs (needs). An attacker not
// limited to some objects writes every object.
func (t Table) authors(e analysis.EventActivity, k RunKind) bool {
	objects, accountOnly := needs(e, k)
	if accountOnly {
		return slices.IndexFunc(analysis.WrittenObjects(), func(o analysis.WrittenObject) bool { return !t.barriers.Writes(o) }) < 0 // only an attacker not limited to some objects
	}
	return slices.ContainsFunc(objects, t.barriers.Writes)
}

// writes is whether the attacker of t starts the run k of e: they write
// what it is of (authors), or, past the approval by a label, they add the
// label to a pull request they open from a fork with an account of their
// own, which their credential does not write (labeled, unlabeled).
func (t Table) writes(e analysis.EventActivity, k RunKind) bool {
	if t.authors(e, k) {
		return true
	}
	return e.Name() == workflow.EventNamePullRequestTarget && t.barriers.Passes(analysis.BarrierLabelApproval) &&
		(e.ActivityType() == workflow.ActivityTypeLabeled || e.ActivityType() == workflow.ActivityTypeUnlabeled)
}

// runs are the runs of e that the attacker of t starts: Runs, of what they
// write.
func (t Table) runs(e analysis.EventActivity) []RunKind {
	return slices.DeleteFunc(Runs(e), func(k RunKind) bool { return !t.writes(e, k) })
}

// pullRequestRow is rows with github.event.issue.pull_request fixed when
// the attacker of t writes on issues only, or on pull requests only: what
// they comment on (RunOwn), or what they wrote that another comments on
// (RunOthersComment), of issue_comment.
func (t Table) pullRequestRow(e analysis.EventActivity, k RunKind, rows []row) []row {
	if e.Name() != workflow.EventNameIssueComment {
		return rows
	}
	issue, pull := analysis.WrittenIssueComment, analysis.WrittenPullRequestComment
	if k == RunOthersComment {
		issue, pull = analysis.WrittenIssue, analysis.WrittenPullRequest
	}
	switch w := t.barriers; {
	case w.Writes(issue) && !w.Writes(pull):
		return append(slices.Clone(rows), row{"event.issue.pull_request", null})
	case w.Writes(pull) && !w.Writes(issue):
		return append(slices.Clone(rows), row{"event.issue.pull_request", expr.AbstractValue(present{})})
	}
	return rows
}
