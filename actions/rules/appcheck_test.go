package rules

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// TestWithAppChecks: a kind asks, for each of its attackers whose actor
// starts status, check_suite or check_run, the fact of the commits that
// the attacker writes; a kind whose attackers start none of them asks
// neither.
func TestWithAppChecks(t *testing.T) {
	fork := lint.MustFindingKindID("t.fork")
	merged := lint.MustFindingKindID("t.merged")
	both := lint.MustFindingKindID("t.both")
	issue := lint.MustFindingKindID("t.issue")
	m := lint.Meta{
		Threat: lint.Threat{Actors: []lint.Actor{
			{Attacker: lint.AttackerForkPRAuthor, Events: []workflow.EventName{workflow.EventNameCheckSuite}},
			{Attacker: lint.AttackerMergedCommitAuthor, Events: []workflow.EventName{workflow.EventNamePush, workflow.EventNameStatus}},
			{Attacker: lint.AttackerIssueAuthor, Events: []workflow.EventName{workflow.EventNameIssues}},
		}},
		FindingKinds: []lint.FindingKind{
			{FindingText: lint.FindingText{ID: fork}, Attackers: []lint.Attacker{lint.AttackerForkPRAuthor}},
			{FindingText: lint.FindingText{ID: merged}, Attackers: []lint.Attacker{lint.AttackerMergedCommitAuthor}},
			{FindingText: lint.FindingText{ID: both}, Attackers: []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerMergedCommitAuthor, lint.AttackerIssueAuthor}},
			{FindingText: lint.FindingText{ID: issue}, Attackers: []lint.Attacker{lint.AttackerIssueAuthor}},
		},
	}
	got := withAppChecks(m)
	for i, want := range [][]facts.Kind{
		{facts.KindRepoForkPRAppChecks},
		{facts.KindRepoMergeCommitAppChecks},
		{facts.KindRepoForkPRAppChecks, facts.KindRepoMergeCommitAppChecks},
		nil,
	} {
		if k := got.FindingKinds[i]; !slices.Equal(k.FactKinds, want) {
			t.Errorf("the kind %s asks %v, want %v", k.ID, k.FactKinds, want)
		}
	}
	if i := slices.IndexFunc(got.FalsePositiveForms, func(f lint.FalsePositiveForm) bool { return f.ID == appChecksUnasked }); i < 0 || !slices.Equal(got.FalsePositiveForms[i].FindingKinds, []lint.FindingKindID{fork, merged, both}) {
		t.Errorf("the false positive forms %+v have no app-checks-unasked of the kinds fork, merged and both alone", got.FalsePositiveForms)
	}
	if len(m.FindingKinds[0].FactKinds) != 0 {
		t.Error("withAppChecks changed the kinds of m")
	}
}

// TestWithAppChecksNotAsked: artifact-poisoning, whose finding does not rest
// on an app that checks the commits of the pull requests from forks, asks
// neither fact, though its attackers start status.
func TestWithAppChecksNotAsked(t *testing.T) {
	m := withAppChecks(artifactPoisoningMeta)
	for _, k := range m.FindingKinds {
		if slices.Contains(k.FactKinds, facts.KindRepoForkPRAppChecks) || slices.Contains(k.FactKinds, facts.KindRepoMergeCommitAppChecks) {
			t.Errorf("the kind %s asks %v", k.ID, k.FactKinds)
		}
	}
	if !slices.Contains(m.AttackerEvents(m.FindingKinds[0]), workflow.EventNameStatus) {
		t.Error("status is not an event of the attackers of artifact-poisoning")
	}
}

// TestAppChecksForkOnly: where an outside app checks only the commits that
// the merges of pull requests put in the branches of the repository
// (repo.fork-pr-app-checks false, repo.merge-commit-app-checks true), a
// kind whose finding on status needs the code of a commit of a pull request
// from a fork (untrusted-checkout) reports nothing, and a kind that reads
// the message of the commit (code-injection) still reports the finding.
func TestAppChecksForkOnly(t *testing.T) {
	r := worstCase(flipped{kinds: []facts.Kind{facts.KindRepoForkPRAppChecks}})
	for _, c := range []struct {
		rule lint.RuleID
		wf   string
		want int
	}{
		{UntrustedCheckoutID, `on: status
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.sha }}
      - run: npm ci
`, 0},
		{CodeInjectionID, `on: status
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.commit.commit.message }}"
`, 1},
	} {
		in, err := lint.Single(lint.InputBytes{Name: facts.MustCleanInputPath("w.yml"), InputKind: lint.InputKindWorkflow, Bytes: []byte(c.wf)})
		if err != nil {
			t.Fatal(err)
		}
		rule := ruleOf(t, c.rule)
		if rep := runWith(t, rule, in, worstCase(limitFacts{})); len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Fatalf("%s with the assumption: %+v, want one finding", c.rule, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
		if rep := runWith(t, rule, in, r); len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != c.want || len(rep.Errors) != 0 {
			t.Errorf("%s: %+v, errors %+v; want %d findings", c.rule, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.Errors, c.want)
		}
	}
}

// TestAppChecksKindsOfRules: of the rules that read the privileged events
// of a job, the kinds of a value that an attacker writes ask both facts,
// since the message of a commit that the merge of a pull request puts in a
// branch can hold what the author of the pull request writes; the kinds
// that need the code of a pull request from a fork, or the run of the job
// with that code, ask repo.fork-pr-app-checks alone.
func TestAppChecksKindsOfRules(t *testing.T) {
	fork := []facts.Kind{facts.KindRepoForkPRAppChecks}
	both := []facts.Kind{facts.KindRepoForkPRAppChecks, facts.KindRepoMergeCommitAppChecks}
	want := map[lint.FindingKindID][]facts.Kind{
		kindCachePoisoningAttackerKey:       both,
		kindCachePoisoningAttackerPath:      both,
		kindAIActionUnsafeSandboxCommands:   both,
		kindAIActionUnsafeSandboxPrivileges: both,
		kindCachePoisoningWritableJob:       fork,
		kindCachePoisoningSavedCheckout:     fork,
		kindDangerousTriggersSecrets:        fork,
		kindDangerousTriggersTokenWrite:     fork,
		kindUntrustedCheckoutExecuted:       fork,
		kindUntrustedCheckoutCheckout:       fork,
	}
	seen := 0
	for _, r := range All() {
		for _, k := range r.Meta().FindingKinds {
			w, ok := want[k.ID]
			if !ok {
				continue
			}
			seen++
			var got []facts.Kind
			for _, x := range k.FactKinds {
				if x == facts.KindRepoForkPRAppChecks || x == facts.KindRepoMergeCommitAppChecks {
					got = append(got, x)
				}
			}
			if !slices.Equal(got, w) {
				t.Errorf("the kind %s asks %v, want %v", k.ID, got, w)
			}
		}
	}
	if seen != len(want) {
		t.Errorf("%d of the %d kinds are kinds of All", seen, len(want))
	}
}
