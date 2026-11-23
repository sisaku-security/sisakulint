package lint

import (
	"fmt"
	"slices"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// The runs of status, check_suite and check_run that an outside app, such
// as an outside CI, starts by a commit status or a check run for a commit
// whose message an attacker writes have that commit in their payload. Two
// kinds of fact say whether an outside app checks such commits:
// repo.fork-pr-app-checks for a commit of a pull request from a fork, whose
// author is fork-pr-author, and repo.merge-commit-app-checks for a commit
// that the merge of a pull request puts in a branch, whose author is
// merged-commit-author. A finding of a kind that declares one or both of
// them, in a workflow whose own on has no event other than these three,
// holds only when the declared fact is true, or one of the two is true when
// the kind declares both: the engine adds that to its condition when the
// rule reports it, as for repo.pull-request-target-allowed
// (eventpolicy.go). A reusable workflow and an action, which run on the
// events of their callers, do not get the condition.

// appChecksFacts are the kinds of fact of the runs of status, check_suite
// and check_run, with the attacker who writes the commit that each asks
// about.
var appChecksFacts = []struct {
	kind     facts.Kind
	attacker Attacker
}{
	{facts.KindRepoForkPRAppChecks, AttackerForkPRAuthor},
	{facts.KindRepoMergeCommitAppChecks, AttackerMergedCommitAuthor},
}

// AppChecksFact is the kind of fact that says whether an outside app makes
// a commit status or a check run for a commit that a writes, so that the
// runs of status, check_suite and check_run start with the commit; false
// when a writes no such commit.
func AppChecksFact(a Attacker) (facts.Kind, bool) {
	for _, f := range appChecksFacts {
		if f.attacker == a {
			return f.kind, true
		}
	}
	return 0, false
}

// appChecksDeclared are the kinds of fact of appChecksFacts that k
// declares, in the order of appChecksFacts.
func appChecksDeclared(k FindingKind) []facts.Kind {
	var out []facts.Kind
	for _, f := range appChecksFacts {
		if slices.Contains(k.FactKinds, f.kind) {
			out = append(out, f.kind)
		}
	}
	return out
}

// appCheckEvents are the events of a commit status or a check run.
var appCheckEvents = []workflow.EventName{workflow.EventNameStatus, workflow.EventNameCheckSuite, workflow.EventNameCheckRun}

// appChecksOnly is whether the events of w's own on are among status,
// check_suite and check_run, one at least. Any other event keeps the
// condition off, as in pullRequestTargetOnly; a name GitHub does not know
// is not counted.
func appChecksOnly(w *workflow.Workflow) bool {
	if w == nil || w.On.Status != workflow.Present {
		return false
	}
	some := false
	for _, ev := range w.On.Value.Events {
		n, err := workflow.ParseEventName(ev.Name.AsString())
		switch {
		case err != nil:
		case slices.Contains(appCheckEvents, n):
			some = true
		default:
			return false
		}
	}
	return some
}

// appChecksKinds are the kinds of fact of appChecksFacts that the findings
// of each kind of m in w get in their condition, by the kind: the kinds of
// fact that the kind declares, when the events of w's own on are among
// status, check_suite and check_run.
func appChecksKinds(m Meta, w *workflow.Workflow) map[FindingKindID][]facts.Kind {
	if !appChecksOnly(w) {
		return nil
	}
	out := map[FindingKindID][]facts.Kind{}
	for _, k := range m.FindingKinds {
		if ks := appChecksDeclared(k); len(ks) != 0 {
			out[k.ID] = ks
		}
	}
	return out
}

// withAppChecks is the condition of d with the kinds of fact that kinds
// gives for the kind of d, of the repository of c, added: the one fact, or
// any of the two.
func withAppChecks(c *RuleContext, kinds map[FindingKindID][]facts.Kind, d FindingDraft) *Condition {
	if d.Args == nil {
		return d.Condition
	}
	var parts []Condition
	for _, k := range kinds[d.Args.KindID()] {
		var q facts.Query
		switch k {
		case facts.KindRepoForkPRAppChecks:
			q = facts.RepoForkPRAppChecks{Repo: c.repo}
		case facts.KindRepoMergeCommitAppChecks:
			q = facts.RepoMergeCommitAppChecks{Repo: c.repo}
		default:
			panic("no query of the kind of fact " + k.String()) // appChecksFacts has a kind withAppChecks does not know
		}
		eq, err := FactEq(q, true)
		if err != nil {
			panic(err) // the kind's value is a boolean
		}
		parts = append(parts, eq)
	}
	var checks Condition
	switch len(parts) {
	case 0:
		return d.Condition
	case 1:
		checks = parts[0]
	default:
		checks = Any(parts...)
	}
	if d.Condition == nil {
		return &checks
	}
	all := All(*d.Condition, checks)
	return &all
}

// checkAppChecks is whether each kind of m that declares a kind of fact of
// appChecksFacts has the attacker of the fact among its attackers, with
// status, check_suite or check_run among the events of the attacker's
// actor. A kind may have those events without declaring the fact: a rule
// whose finding does not rest on the payload of the run, such as
// artifact-poisoning, whose search of the runs of forks takes the artifact
// of a run of a pull request from a fork whoever starts the run of the job.
func checkAppChecks(m Meta) error {
	for _, k := range m.FindingKinds {
		for _, f := range appChecksFacts {
			if !slices.Contains(k.FactKinds, f.kind) {
				continue
			}
			reached := slices.Contains(k.Attackers, f.attacker) && slices.ContainsFunc(m.Threat.Actors, func(a Actor) bool {
				return a.Attacker == f.attacker && slices.ContainsFunc(a.Events, func(e workflow.EventName) bool { return slices.Contains(appCheckEvents, e) })
			})
			if !reached {
				return fmt.Errorf("the kind %s declares %s, and none of status, check_suite and check_run is an event of its attacker %s", k.ID, f.kind, f.attacker)
			}
		}
	}
	return nil
}
