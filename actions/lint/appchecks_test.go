package lint

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// appChecksEvents are the events of the actors of appChecksMeta: status,
// check_suite and check_run, and issue_comment.
var appChecksEvents = []workflow.EventName{workflow.EventNameStatus, workflow.EventNameCheckSuite, workflow.EventNameCheckRun, workflow.EventNameIssueComment}

// appChecksActor is an actor of the tests: a, whose events are
// appChecksEvents, each started by the attacker.
func appChecksActor(a Attacker) Actor {
	starters := map[workflow.EventName]RunStarter{}
	for _, e := range appChecksEvents {
		starters[e] = RunStarterAttacker
	}
	return Actor{Attacker: a, Via: "writes a commit", Events: appChecksEvents, RunStarters: starters, Gains: []Gain{GainRunCode}}
}

// appChecksMeta is a rule of the tests whose one kind's attackers are
// attackers, each with appChecksActor, and whose kind declares the kinds of
// fact of appChecksFacts of the attackers.
func appChecksMeta(attackers ...Attacker) Meta {
	m := meta("app-checks")
	m.Threat.Actors = nil
	var ks []facts.Kind
	for _, a := range attackers {
		m.Threat.Actors = append(m.Threat.Actors, appChecksActor(a))
		k, ok := AppChecksFact(a)
		if !ok {
			panic(a.String() + " has no fact of the app checks")
		}
		ks = append(ks, k)
	}
	m.FindingKinds = slices.Clone(m.FindingKinds)
	m.FindingKinds[0].Attackers = attackers
	return asking(m, ks...)
}

// TestAppChecksFact: the author of a pull request from a fork and the
// author of a merged commit each have their fact; another attacker has
// none.
func TestAppChecksFact(t *testing.T) {
	for _, c := range []struct {
		a    Attacker
		want facts.Kind
		ok   bool
	}{
		{AttackerForkPRAuthor, facts.KindRepoForkPRAppChecks, true},
		{AttackerMergedCommitAuthor, facts.KindRepoMergeCommitAppChecks, true},
		{AttackerIssueAuthor, 0, false},
	} {
		if got, ok := AppChecksFact(c.a); got != c.want || ok != c.ok {
			t.Errorf("AppChecksFact(%s) = %v, %v; want %v, %v", c.a, got, ok, c.want, c.ok)
		}
	}
}

// TestAppChecksCondition: a finding of a kind that declares
// repo.fork-pr-app-checks, in a workflow whose own on has no event other
// than status, check_suite and check_run, holds only when an outside app
// checks the commits of the pull requests from forks. Any other event
// keeps the condition off, as for repo.pull-request-target-allowed.
func TestAppChecksCondition(t *testing.T) {
	asked := facts.RepoForkPRAppChecks{}
	plain := everyStep(appChecksMeta(AttackerForkPRAuthor), func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base)}
	})
	for _, c := range []struct {
		name, on string
		asked    bool
	}{
		{"status", "on: status\n", true},
		{"two of the three", "on: [status, check_run]\n", true},
		{"types", "on:\n  check_suite:\n    types: [completed]\n", true},
		{"another event of the attackers", "on: [status, issue_comment]\n", false},
		{"an event of no attacker of the kind", "on: [status, push]\n", false},
		{"workflow_call", "on: [status, workflow_call]\n", false},
		{"none of the three", "on: issue_comment\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := run(t, wf(c.on+prTargetSteps), mapResolver{}, plain)
			if len(rep.Errors) != 0 || len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 {
				t.Fatalf("findings %+v, errors %+v; want one", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
			}
			f := rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0]
			if got := f.Condition != nil && slices.Contains(f.Condition.Queries(), facts.Query(asked)); got != c.asked {
				t.Fatalf("the condition %+v asks %v: %v, want %v", f.Condition, asked, got, c.asked)
			}
			if f.Condition != nil && slices.Contains(f.Condition.Queries(), facts.Query(facts.RepoMergeCommitAppChecks{})) {
				t.Fatalf("the condition %+v asks repo.merge-commit-app-checks, which the kind does not declare", f.Condition)
			}
			if !c.asked {
				return
			}
			if rep := run(t, wf(c.on+prTargetSteps), facts.Assume(mapResolver{}), plain); len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 || rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Certainty != CertaintyConfirmed {
				t.Errorf("with the assumption: %+v, want one confirmed", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional))
			}
			if rep := run(t, wf(c.on+prTargetSteps), mapResolver{asked: foundJSON("false")}, plain); len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 0 || len(rep.Errors) != 0 {
				t.Errorf("with false: %+v, errors %+v; want none", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
			}
		})
	}
	if appChecksOnly(nil) || len(appChecksKinds(appChecksMeta(AttackerForkPRAuthor), nil)) != 0 {
		t.Error("an input without a workflow gets the condition")
	}
}

// TestAppChecksConditionBoth: a finding of a kind that declares both kinds
// of fact holds when either fact is true, and not when both are false: the
// condition is any of the two.
func TestAppChecksConditionBoth(t *testing.T) {
	fork, merge := facts.RepoForkPRAppChecks{}, facts.RepoMergeCommitAppChecks{}
	plain := everyStep(appChecksMeta(AttackerForkPRAuthor, AttackerMergedCommitAuthor), func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base)}
	})
	in := wf("on: status\n" + prTargetSteps)
	rep := run(t, in, mapResolver{}, plain)
	if len(rep.Errors) != 0 || len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 {
		t.Fatalf("findings %+v, errors %+v; want one", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
	}
	if c := rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Condition; c == nil || c.Op() != ConditionOpAny || !slices.Equal(c.Queries(), []facts.Query{fork, merge}) {
		t.Fatalf("the condition %+v is not any of %v and %v", c, fork, merge)
	}
	for _, c := range []struct {
		name        string
		fork, merge string
		want        int
	}{
		{"fork true", "true", "false", 1},
		{"merge true", "false", "true", 1},
		{"both false", "false", "false", 0},
	} {
		if rep := run(t, in, mapResolver{fork: foundJSON(c.fork), merge: foundJSON(c.merge)}, plain); len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != c.want || len(rep.Errors) != 0 {
			t.Errorf("%s: %+v, errors %+v; want %d", c.name, rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors, c.want)
		}
	}
}

// foundJSON is an answer of the value v.
func foundJSON(v string) facts.RawAnswer {
	return facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(v)}
}

// TestMetaDeclaresAppChecks: a kind that declares a kind of fact of
// appChecksFacts has the attacker of the fact among its attackers, with
// status, check_suite or check_run among the events of the attacker.
func TestMetaDeclaresAppChecks(t *testing.T) {
	noEvents := appChecksMeta(AttackerForkPRAuthor)
	noEvents.Threat.Actors = slices.Clone(noEvents.Threat.Actors)
	noEvents.Threat.Actors[0].Events = []workflow.EventName{workflow.EventNameIssueComment}
	noEvents.Threat.Actors[0].RunStarters = map[workflow.EventName]RunStarter{workflow.EventNameIssueComment: RunStarterAttacker}
	otherAttacker := asking(appChecksMeta(AttackerForkPRAuthor), facts.KindRepoMergeCommitAppChecks)
	for _, m := range []Meta{asking(meta("extra"), facts.KindRepoForkPRAppChecks), noEvents, otherAttacker} {
		_, err := newRegistry([]Rule{testRule{meta: m}}, true)
		if err == nil || !strings.Contains(err.Error(), "none of status, check_suite and check_run") {
			t.Errorf("%s %v: %v, want an error that none of the events is of its attacker", m.ID, m.FindingKinds[0].FactKinds, err)
		}
	}
	for _, m := range []Meta{appChecksMeta(AttackerForkPRAuthor), appChecksMeta(AttackerMergedCommitAuthor), appChecksMeta(AttackerForkPRAuthor, AttackerMergedCommitAuthor), asking(appChecksMeta(AttackerForkPRAuthor), facts.KindTestFlag)} {
		if _, err := newRegistry([]Rule{testRule{meta: m}}, true); err != nil {
			t.Errorf("%s %v: %v", m.ID, m.FindingKinds[0].FactKinds, err)
		}
	}
}
