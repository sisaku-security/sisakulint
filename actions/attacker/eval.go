package attacker

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// Truth is what the if p is in the run k of e. Without an if it is true;
// one GitHub reads as a string (IfMixed) is true; an empty one, or one that
// does not parse, is not known, as before. The if of a job reads the needs
// context (PlacedIf).
func (t Table) Truth(p PlacedIf, e analysis.EventActivity, k RunKind) expr.Truth {
	return p.truth(eventOf(e), t.lookupFor(e, k), nil)
}

// EventOnly is what c is when e triggers the run, of github.event_name and
// github.event.action alone: the reading of an if before the table.
func EventOnly(p PlacedIf, e analysis.EventActivity) expr.Truth {
	return p.truth(eventOf(e), eventLookup(e), nil)
}

// EventOnlyWith is EventOnly with the values of values first: a reader
// gives the values of other paths (the matrix of a job, for one).
func EventOnlyWith(p PlacedIf, e analysis.EventActivity, values func([]expr.PathElem) (expr.Value, bool)) expr.Truth {
	base := eventLookup(e)
	return p.truth(eventOf(e), func(path []expr.PathElem) (expr.Value, bool) {
		if v, ok := values(path); ok {
			return v, true
		}
		return base(path)
	}, nil)
}

// EventNameOnly is what p is on a run of the event e, of github.event_name
// alone: EventOnly for an event read without its activity type (not known
// on a run of a called workflow, eventNameOf). An if of
// text and ${{ }} is a string, which is true (workflow.IfMixed); an empty
// one is success(), which may be true.
func EventNameOnly(p PlacedIf, e workflow.EventName) expr.Truth {
	r := eventNameOf(e)
	return p.truth(r, r.lookup, nil)
}

// Kept is whether an attacker's value may reach what c guards on e: c is
// not false in some run of e. An event without runs is read by EventOnly.
func (t Table) Kept(p PlacedIf, e analysis.EventActivity) bool {
	return t.kept(p, e, t.runs(e))
}

// KeptValue is Kept with the value at path the string v: whether a run
// whose value at path is v may get past c.
func (t Table) KeptValue(p PlacedIf, e analysis.EventActivity, path []expr.PathElem, v string) bool {
	set := func(lookup func([]expr.PathElem) (expr.Value, bool)) func([]expr.PathElem) (expr.Value, bool) {
		return func(p []expr.PathElem) (expr.Value, bool) {
			if samePath(path, p) {
				return expr.String(v), true
			}
			return lookup(p)
		}
	}
	if len(Runs(e)) == 0 {
		return p.truth(eventOf(e), set(eventLookup(e)), nil) != expr.TruthFalse
	}
	runs := t.runs(e)
	for _, k := range runs {
		if p.truth(eventOf(e), set(t.lookupFor(e, k)), nil) != expr.TruthFalse {
			return true
		}
	}
	return false
}

// KeptCode is Kept for the attacker's code: the runs whose head is a branch
// of the repository bring the code of those who can write, as every run of
// a review does.
func (t Table) KeptCode(p PlacedIf, e analysis.EventActivity) bool {
	if objects[e.Name()].branchHead {
		return false
	}
	return t.kept(p, e, slices.DeleteFunc(t.runs(e), func(k RunKind) bool { return k == RunBaseBranch }))
}

// KeptActor is whether the attacker may trigger e themselves, as its
// actor, in a run in which c is not false: an activity type they trigger
// (acts), read with them as the actor, in a run of their own or of their
// pull request from a branch of the repository, which they open but do
// not push to. workflow_run's actor is that of the run before it, which
// may be theirs. A check of the actor, such as an agent action's, passes
// or stops them there.
func (t Table) KeptActor(p PlacedIf, e analysis.EventActivity) bool {
	for _, k := range t.actorRuns(e) {
		if p.truth(eventOf(e), lookupRows(e, t.rowsOf(e, k, true)), nil) != expr.TruthFalse {
			return true
		}
	}
	return false
}

// actorRuns are the runs of e the attacker of t triggers themselves, as
// its actor (KeptActor), of what they write: none when no activity type
// of e is theirs to trigger.
func (t Table) actorRuns(e analysis.EventActivity) []RunKind {
	return slices.DeleteFunc(actorRuns(e), func(k RunKind) bool { return !t.writes(e, k) })
}

// actorRuns are the runs of e an attacker who writes every object
// triggers themselves, as its actor.
func actorRuns(e analysis.EventActivity) []RunKind {
	runs := []RunKind{RunOwn}
	switch {
	case e.Name() == workflow.EventNameWorkflowRun:
	case !acts(e):
		return nil
	case slices.Contains(Runs(e), RunBaseBranch) && e.ActivityType() != workflow.ActivityTypeSynchronize:
		runs = append(runs, RunBaseBranch)
	}
	return runs
}

// KeptOthers is whether a run of e whose actor is not the attacker, in
// which the value at path is what they wrote, may get past c: a check of
// the actor, such as an agent action's, lets that actor in. Such a run is
// of an activity type someone else triggers too (a label, an edit), or of
// another's comment on what the attacker wrote, whose own rows are not
// theirs; not Dependabot's, whose bot the agent actions refuse (as read on
// 2026-10-10). A path not below github (env, inputs) is read as the
// attacker's in every run: where it came from is not followed.
func (t Table) KeptOthers(p PlacedIf, e analysis.EventActivity, path []expr.PathElem) bool {
	o, ok := objects[e.Name()]
	if !ok || o.anyActor {
		return false
	}
	key, isBelow := below("github", path)
	for _, k := range t.runs(e) {
		switch k {
		case RunDependabot:
			continue
		case RunOwn, RunBaseBranch:
			if slices.Contains(o.actors, e.ActivityType()) {
				continue // only the attacker triggers it
			}
		case RunOthersComment:
			if isBelow && !onObject(o.on, key) {
				continue // the comment's own: not the attacker's
			}
		}
		if t.Truth(p, e, k) != expr.TruthFalse {
			return true
		}
	}
	return false
}

// onObject is whether key is what a comment of RunOthersComment is on: a
// row of on (head_ref), or below the object of one (event.issue of
// event.issue.user.login).
func onObject(on []row, key string) bool {
	for _, r := range on {
		if key == r.path {
			return true
		}
		if p := strings.SplitN(r.path, ".", 3); len(p) == 3 && p[0] == "event" && strings.HasPrefix(key, p[0]+"."+p[1]+".") {
			return true
		}
	}
	return false
}

func (t Table) kept(p PlacedIf, e analysis.EventActivity, runs []RunKind) bool {
	if len(Runs(e)) == 0 {
		return EventOnly(p, e) != expr.TruthFalse
	}
	for _, k := range runs {
		if t.Truth(p, e, k) != expr.TruthFalse {
			return true
		}
	}
	return false
}

func truthWith(c workflow.Field[workflow.If], lookup func([]expr.PathElem) (expr.Value, bool), override func(expr.Node) (expr.Value, bool)) expr.Truth {
	if c.Status != workflow.Present {
		return expr.TruthTrue
	}
	switch c.Value.Form {
	case workflow.IfMixed:
		return expr.TruthTrue // a string of text and ${{ }}, which is not empty
	case workflow.IfEmpty:
		return expr.TruthUnknown // success()
	}
	if c.Value.Expr == nil || c.Value.Expr.Tree == nil {
		return expr.TruthUnknown
	}
	return expr.PartialWith(c.Value.Expr.Tree, lookup, override).Truthy()
}

// eventLookup knows github.event_name and github.event.action of e, as
// eventOf reads e: neither on a run of a called workflow.
func eventLookup(e analysis.EventActivity) func([]expr.PathElem) (expr.Value, bool) {
	return eventOf(e).lookup
}

// lookupFor knows, besides the event, the rows of the run k of e.
func (t Table) lookupFor(e analysis.EventActivity, k RunKind) func([]expr.PathElem) (expr.Value, bool) {
	return lookupRows(e, t.rowsOf(e, k, false))
}

// lookupRows knows, besides the event, the rows: the first of a path.
func lookupRows(e analysis.EventActivity, rows []row) func([]expr.PathElem) (expr.Value, bool) {
	base := eventLookup(e)
	return func(p []expr.PathElem) (expr.Value, bool) {
		if v, ok := base(p); ok {
			return v, true
		}
		key, ok := below("github", p)
		if !ok {
			return expr.Value{}, false
		}
		for _, r := range rows {
			if r.path == key {
				return r.value, true
			}
		}
		return expr.Value{}, false
	}
}

// below is p after its first name ctx, lowered and joined by dots; false
// when p is not below ctx or has a star or an index not a string.
func below(ctx string, p []expr.PathElem) (string, bool) {
	if len(p) < 2 || !expr.EqualName(p[0].Name, ctx) {
		return "", false
	}
	names := make([]string, 0, len(p)-1)
	for _, e := range p[1:] {
		if e.Star || e.Dynamic != nil {
			return "", false
		}
		names = append(names, strings.ToLower(e.Name))
	}
	return strings.Join(names, "."), true
}

// branchPullRequestRows are the head of a run of a pull request event for
// a pull request from a branch of the repository, in a repository that is
// not a fork: the head is the repository itself, which is no fork.
var branchPullRequestRows = slices.Concat(repositoryRows, baseHeadRows, []row{{"event.pull_request.head.repo.fork", expr.Bool(false)}})

// BranchPullRequestFalse is whether p is false in every run of e, an
// event whose payload has pull_request (hasPullRequest), for a pull
// request from a branch of the repository, in a repository that is not a
// fork: p lets in only the runs for a pull request from a fork. False for
// any other event.
func BranchPullRequestFalse(p PlacedIf, e analysis.EventActivity) bool {
	if !hasPullRequest(e.Name()) {
		return false
	}
	return p.truth(eventOf(e), lookupRows(e, branchPullRequestRows), nil) == expr.TruthFalse
}
