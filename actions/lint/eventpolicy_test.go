package lint

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// prTargetMeta is a rule of the tests whose one kind's attacker opens a
// pull request from a fork, which runs pull_request_target and
// issue_comment, and that asks about ks besides
// repo.pull-request-target-allowed.
func prTargetMeta(ks ...facts.Kind) Meta {
	m := meta("pr-target")
	events := []workflow.EventName{workflow.EventNamePullRequestTarget, workflow.EventNameIssueComment}
	m.Threat.Actors = []Actor{{Attacker: AttackerForkPRAuthor, Via: "opens a pull request from a fork", Events: events,
		RunStarters: map[workflow.EventName]RunStarter{workflow.EventNamePullRequestTarget: RunStarterAttacker, workflow.EventNameIssueComment: RunStarterAttacker},
		Gains:       []Gain{GainRunCode}}}
	m.FindingKinds = slices.Clone(m.FindingKinds)
	m.FindingKinds[0].Attackers = []Attacker{AttackerForkPRAuthor}
	return asking(m, append([]facts.Kind{facts.KindRepoPullRequestTargetAllowed}, ks...)...)
}

const prTargetSteps = `jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`

// TestPullRequestTargetCondition: a finding of a kind that declares
// repo.pull-request-target-allowed, in a workflow whose own on has
// pull_request_target and no other event, holds only when the runs of the
// workflow on pull_request_target start. Any other event keeps the
// condition off, an event of no attacker of the kind too: a rule may
// report on it (gollum), and an attacker without events gets what its run
// holds.
func TestPullRequestTargetCondition(t *testing.T) {
	path, err := facts.ParseInputPath(".github/workflows/w.yml")
	if err != nil {
		t.Fatal(err)
	}
	allowed := facts.RepoPullRequestTargetAllowed{InputPath: path}
	found := func(v string) facts.RawAnswer {
		return facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(v)}
	}
	plain := everyStep(prTargetMeta(), func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base)}
	})
	for _, c := range []struct {
		name, on string
		asked    bool // whether the finding has the condition
	}{
		{"alone", "on: pull_request_target\n", true},
		{"types", "on:\n  pull_request_target:\n    types: [opened]\n", true},
		{"another event of the attackers", "on: [pull_request_target, issue_comment]\n", false},
		{"an event of no attacker of the kind", "on: [pull_request_target, push]\n", false},
		{"gollum", "on: [pull_request_target, gollum]\n", false},
		{"workflow_call", "on: [pull_request_target, workflow_call]\n", false},
		{"no pull_request_target", "on: issue_comment\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := run(t, wf(c.on+prTargetSteps), mapResolver{}, plain)
			if len(rep.Errors) != 0 || len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 {
				t.Fatalf("findings %+v, errors %+v; want one", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
			}
			f := rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0]
			if got := f.Condition != nil && slices.Contains(f.Condition.Queries(), facts.Query(allowed)); got != c.asked {
				t.Fatalf("the condition %+v asks %v: %v, want %v", f.Condition, allowed, got, c.asked)
			}
			if !c.asked {
				return
			}
			if f.Certainty != CertaintyConditional {
				t.Errorf("with no answer: %v, want conditional", f.Certainty)
			}
			if rep := run(t, wf(c.on+prTargetSteps), facts.Assume(mapResolver{}), plain); len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 || rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Certainty != CertaintyConfirmed {
				t.Errorf("with the assumption: %+v, want one confirmed", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional))
			}
			if rep := run(t, wf(c.on+prTargetSteps), mapResolver{allowed: found("false")}, plain); len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 0 || len(rep.Errors) != 0 {
				t.Errorf("with false: %+v, errors %+v; want none", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
			}
		})
	}

	// a condition the rule gives is kept: the finding holds when both do
	flag := facts.TestFlag{Name: "x"}
	both := everyStep(prTargetMeta(facts.KindTestFlag), func(c *RuleContext, s workflow.Step) FindingDraft {
		cond, err := FactEq(flag, true)
		if err != nil {
			panic(err)
		}
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Condition: &cond}
	})
	for _, c := range []struct {
		name          string
		flag, allowed string
		count         int
	}{
		{"both true", "true", "true", 1},
		{"the rule's false", "false", "true", 0},
		{"the policy's false", "true", "false", 0},
	} {
		rep := run(t, wf("on: pull_request_target\n"+prTargetSteps), mapResolver{flag: found(c.flag), allowed: found(c.allowed)}, both)
		if len(rep.Errors) != 0 || len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != c.count {
			t.Errorf("%s: findings %+v, errors %+v; want %d", c.name, rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors, c.count)
		}
	}

	// a kind that does not declare the fact gets no condition
	other := everyStep(asking(meta("other"), facts.KindTestFlag), func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base)}
	})
	if rep := run(t, wf("on: pull_request_target\n"+prTargetSteps), mapResolver{}, other); len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 || rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Condition != nil {
		t.Errorf("a kind without the fact: %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional))
	}

	// an action metadata file has no events
	if pullRequestTargetOnly(nil) || len(pullRequestTargetKinds(prTargetMeta(), nil)) != 0 {
		t.Error("an input without a workflow gets the condition")
	}
}

// TestMetaDeclaresPullRequestTarget: a kind declares
// repo.pull-request-target-allowed exactly when pull_request_target is an
// event of its attackers.
func TestMetaDeclaresPullRequestTarget(t *testing.T) {
	undeclared := prTargetMeta()
	undeclared = asking(undeclared, facts.KindTestFlag)
	extra := asking(meta("extra"), facts.KindRepoPullRequestTargetAllowed)
	for _, m := range []Meta{undeclared, extra} {
		_, err := newRegistry([]Rule{testRule{meta: m}}, true)
		if err == nil || !strings.Contains(err.Error(), "the two go together") {
			t.Errorf("%s: %v, want an error that the two go together", m.ID, err)
		}
	}
	if _, err := newRegistry([]Rule{testRule{meta: prTargetMeta()}}, true); err != nil {
		t.Errorf("a kind that declares it: %v", err)
	}
}

// TestPullRequestTargetFixCheck: the check of a fix reads the fixed input
// with the same condition (pass.runOn, identitiesOf), so that a finding
// whose runs the policies block is not counted there either.
func TestPullRequestTargetFixCheck(t *testing.T) {
	path, err := facts.ParseInputPath(".github/workflows/w.yml")
	if err != nil {
		t.Fatal(err)
	}
	allowed := facts.RepoPullRequestTargetAllowed{InputPath: path}
	m := prTargetMeta()
	rule := everyStep(m, func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base)}
	})
	in := inputsOf(t, wf("on: pull_request_target\n"+prTargetSteps))
	for _, c := range []struct {
		answer string
		want   int
	}{{"true", 1}, {"false", 0}} {
		rec := facts.NewRecorder(mapResolver{allowed: {State: facts.StateFound, Value: json.RawMessage(c.answer)}})
		p := pass{st: &runState{}, rule: rule, m: m, input: in.List[0], inputs: in, rec: rec, callers: lazyCallers(context.Background(), in, nil)}
		ids, err := p.runOn(context.Background(), in.List[0], in, p.callers)
		if err != nil || len(ids) != c.want {
			t.Errorf("answered %s: %d identities (%v), want %d", c.answer, len(ids), err, c.want)
		}
	}
}

// TestPullRequestTargetRepo: with the name of the repository (--repo), the
// condition names it, as the other facts of repo. do.
func TestPullRequestTargetRepo(t *testing.T) {
	repo, err := facts.ParseRepo("o/r")
	if err != nil {
		t.Fatal(err)
	}
	path, err := facts.ParseInputPath(".github/workflows/w.yml")
	if err != nil {
		t.Fatal(err)
	}
	rule := everyStep(prTargetMeta(), func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base)}
	})
	reg, err := newRegistry([]Rule{rule}, true)
	if err != nil {
		t.Fatal(err)
	}
	in := inputsOf(t, wf("on: pull_request_target\n"+prTargetSteps))
	in.Repo = repo
	rep := Run(context.Background(), in, reg, mapResolver{})
	want := facts.Query(facts.RepoPullRequestTargetAllowed{Repo: repo, InputPath: path})
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 || rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Condition == nil || !slices.Contains(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Condition.Queries(), want) {
		t.Fatalf("findings %+v, want one whose condition asks %v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), want)
	}
}
