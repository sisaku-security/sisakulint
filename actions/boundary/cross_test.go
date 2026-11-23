package boundary

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

func eq(t *testing.T, q facts.Query, v bool) lint.Condition {
	t.Helper()
	c, err := lint.FactEq(q, v)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// answers answers each kind by its value: true, false, or unknown when it
// is not there.
func answers(by map[facts.Kind]bool) Answer {
	return func(q facts.Query) facts.RawAnswer {
		v, ok := by[q.Kind()]
		if !ok {
			return facts.RawAnswer{State: facts.StateUnknown, Reason: "not given"}
		}
		b, _ := json.Marshal(v)
		return facts.RawAnswer{State: facts.StateFound, Value: b}
	}
}

func testTables(t *testing.T) tables {
	doc := func(g RunGrant) RunGrant { g.Basis, g.Quotes = BasisDocumented, []Quote{quote()}; return g }
	public, private := eq(t, facts.RepoPublic{}, true), eq(t, facts.RepoPublic{}, false)
	secretsOn := lint.All(private, eq(t, facts.RepoForkPRSecrets{}, true))
	secretsOff := lint.All(private, eq(t, facts.RepoForkPRSecrets{}, false))
	fork := RunRef{workflow.EventNamePullRequest, PRHeadFork}
	return tables{
		grants: []RunGrant{
			doc(RunGrant{Event: workflow.EventNamePullRequestTarget, Head: PRHeadFork, Token: AccessWrite, Secrets: SecretsAccessAll}),
			doc(RunGrant{Event: workflow.EventNameIssueComment, Head: PRHeadNone, Token: AccessWrite, Secrets: SecretsAccessAll}),
			doc(RunGrant{Event: workflow.EventNamePullRequest, Head: PRHeadFork, Condition: public, Token: AccessRead, Secrets: SecretsAccessNone}),
			doc(RunGrant{Event: workflow.EventNamePullRequest, Head: PRHeadFork, Condition: secretsOff, Token: AccessRead, Secrets: SecretsAccessNone}),
			doc(RunGrant{Event: workflow.EventNamePullRequest, Head: PRHeadFork, Condition: secretsOn, Token: AccessRead, Secrets: SecretsAccessAll}),
			doc(RunGrant{Event: workflow.EventNamePush, Head: PRHeadNone, Token: AccessWrite, Secrets: SecretsAccessAll}),
		},
		baselines: []RoleBaseline{
			{Role: RoleNone, Runs: []RunRef{fork}, SelfHostedRunner: expr.TruthTrue, Basis: BasisDocumented, Quotes: []Quote{quote()}},
			{Role: RoleRead, Runs: []RunRef{fork}, SelfHostedRunner: expr.TruthTrue, Basis: BasisDocumented, Quotes: []Quote{quote()}},
			{Role: RoleWrite, Runs: []RunRef{fork, {workflow.EventNamePush, PRHeadNone}}, SelfHostedRunner: expr.TruthTrue, Basis: BasisDocumented, Quotes: []Quote{quote()}},
		},
		channels: []Channel{
			{Attacker: lint.AttackerCommenter, Role: RoleNone, Condition: public, Writable: true, Basis: BasisDocumented, Quotes: []Quote{quote()}},
			{Attacker: lint.AttackerCommenter, Role: RoleNone, Condition: private, Writable: false, Basis: BasisDocumented, Quotes: []Quote{quote()}},
			{Attacker: lint.AttackerCommenter, Role: RoleRead, Writable: true, Basis: BasisDocumented, Quotes: []Quote{quote()}},
			{Attacker: lint.AttackerCommenter, Role: RoleWrite, Writable: true, Basis: BasisDocumented, Quotes: []Quote{quote()}},
			{Attacker: lint.AttackerForkPRAuthor, Role: RoleNone, Condition: public, Writable: true, Basis: BasisDocumented, Quotes: []Quote{quote()}},
			{Attacker: lint.AttackerForkPRAuthor, Role: RoleNone, Condition: private, Writable: false, Basis: BasisDocumented, Quotes: []Quote{quote()}},
		},
	}
}

func TestCross(t *testing.T) {
	tb := testTables(t)
	prt := RunRef{workflow.EventNamePullRequestTarget, PRHeadFork}
	pr := RunRef{workflow.EventNamePullRequest, PRHeadFork}
	comment := RunRef{workflow.EventNameIssueComment, PRHeadNone}
	public := map[facts.Kind]bool{facts.KindRepoPublic: true}
	privateSecrets := map[facts.Kind]bool{facts.KindRepoPublic: false, facts.KindRepoForkPRSecrets: true}
	privateNoSecrets := map[facts.Kind]bool{facts.KindRepoPublic: false, facts.KindRepoForkPRSecrets: false}
	for _, c := range []struct {
		name    string
		a       lint.Attacker
		role    Role
		ref     RunRef
		answers map[facts.Kind]bool
		channel expr.Truth
		want    map[lint.Gain]Crossing
	}{
		{"pull_request_target from a fork", lint.AttackerForkPRAuthor, RoleNone, prt, public, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingByWorkflow, lint.GainWriteWithToken: CrossingByWorkflow, lint.GainRunCode: CrossingByWorkflow, lint.GainPersistOnRunner: CrossingByBaseline}},
		{"pull_request from a fork, public", lint.AttackerForkPRAuthor, RoleNone, pr, public, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingNone, lint.GainWriteWithToken: CrossingNone, lint.GainRunCode: CrossingNone}},
		{"pull_request from a fork, private with secrets sent", lint.AttackerForkPRAuthor, RoleRead, pr, privateSecrets, expr.TruthUnknown, // no channel row of read
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingByBaseline, lint.GainWriteWithToken: CrossingNone}},
		{"pull_request from a fork, private without secrets", lint.AttackerForkPRAuthor, RoleRead, pr, privateNoSecrets, expr.TruthUnknown,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingNone}},
		{"whether the repository is public is not known", lint.AttackerForkPRAuthor, RoleRead, pr, map[facts.Kind]bool{}, expr.TruthUnknown,
			// every row of the run and of the role has a read token, so write is
			// known to be none; secrets differ by the fact that is not known
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingUnknown, lint.GainWriteWithToken: CrossingNone}},
		{"a comment of one who reads", lint.AttackerCommenter, RoleRead, comment, privateNoSecrets, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainWriteWithToken: CrossingByWorkflow, lint.GainReadSecrets: CrossingByWorkflow}},
		{"a comment of one who writes", lint.AttackerCommenter, RoleWrite, comment, privateNoSecrets, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainWriteWithToken: CrossingByBaseline, lint.GainReadSecrets: CrossingByBaseline}},
		{"a comment of one with no access to a private repository", lint.AttackerCommenter, RoleNone, comment, privateNoSecrets, expr.TruthFalse, nil},
		{"an event with no row", lint.AttackerIssueAuthor, RoleRead, RunRef{workflow.EventNameIssues, PRHeadNone}, public, expr.TruthUnknown,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingUnknown, lint.GainWriteWithToken: CrossingUnknown}},
		{"a role with no row", lint.AttackerCommenter, RoleTriage, comment, public, expr.TruthUnknown,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingUnknown}},
	} {
		got := tb.cross(c.a, c.role, c.ref, answers(c.answers))
		if got.Channel != c.channel {
			t.Errorf("%s: channel %v, want %v", c.name, got.Channel, c.channel)
		}
		if c.channel == expr.TruthFalse {
			if len(got.Crossings) != 0 {
				t.Errorf("%s: crossings %v without a channel", c.name, got.Crossings)
			}
			continue
		}
		for g, w := range c.want {
			if got.Crossings[g] != w {
				t.Errorf("%s: %s is %s, want %s", c.name, g, got.Crossings[g], w)
			}
		}
	}
}

func TestCrossingOf(t *testing.T) {
	T, F, U := expr.TruthTrue, expr.TruthFalse, expr.TruthUnknown
	for _, c := range []struct {
		run, held expr.Truth
		want      Crossing
	}{
		{T, T, CrossingByBaseline}, {F, T, CrossingByBaseline}, {U, T, CrossingByBaseline},
		{T, U, CrossingUnknown}, {F, U, CrossingUnknown}, {U, U, CrossingUnknown},
		{T, F, CrossingByWorkflow}, {U, F, CrossingUnknown}, {F, F, CrossingNone},
	} {
		if got := CrossingOf(c.run, c.held); got != c.want {
			t.Errorf("CrossingOf(%v, %v) = %s, want %s", c.run, c.held, got, c.want)
		}
	}
}

// TestBasisOfUsedRows: the basis of a result is the weakest of the rows it
// read, and a result with no row is unverified.
func TestBasisOfUsedRows(t *testing.T) {
	tb := testTables(t)
	tb.grants[0].Basis, tb.grants[0].Quotes, tb.grants[0].Uncertainty = BasisUnverified, nil, "x"
	got := tb.cross(lint.AttackerForkPRAuthor, RoleNone, RunRef{workflow.EventNamePullRequestTarget, PRHeadFork}, answers(map[facts.Kind]bool{facts.KindRepoPublic: true}))
	if got.Basis != BasisUnverified {
		t.Errorf("basis %s, want unverified", got.Basis)
	}
	if _, b := tb.runDims(RunRef{workflow.EventNameIssues, PRHeadNone}, answers(nil)); b != BasisUnverified {
		t.Errorf("no row: basis %s", b)
	}
}

func TestQueries(t *testing.T) {
	tb := testTables(t)
	var kinds []string
	for _, q := range tb.roleQueries(RoleRead) {
		kinds = append(kinds, q.Kind().String())
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []string{"repo.fork-pr-secrets", "repo.public"}) {
		t.Errorf("the queries of read: %v, want repo.fork-pr-secrets and repo.public, once each", kinds)
	}
}
