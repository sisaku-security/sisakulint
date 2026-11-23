package boundary

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// TestRows: every row fits its basis (rows panics otherwise), and the
// cases of a public and of two private repositories come out of the real
// tables.
func TestRows(t *testing.T) {
	_ = rows()
	public := answers(map[facts.Kind]bool{facts.KindRepoPublic: true, facts.KindRepoAllowForking: true, facts.KindRepoWikiOpen: false})
	privateSecrets := answers(map[facts.Kind]bool{facts.KindRepoPublic: false, facts.KindRepoAllowForking: true, facts.KindRepoWikiOpen: false,
		facts.KindRepoForkPRRunWorkflows: true, facts.KindRepoForkPRWriteTokens: false, facts.KindRepoForkPRSecrets: true})
	privateClosed := answers(map[facts.Kind]bool{facts.KindRepoPublic: false, facts.KindRepoAllowForking: false, facts.KindRepoWikiOpen: false,
		facts.KindRepoForkPRRunWorkflows: false, facts.KindRepoForkPRWriteTokens: false, facts.KindRepoForkPRSecrets: false})
	prt := RunRef{workflow.EventNamePullRequestTarget, PRHeadFork}
	pr := RunRef{workflow.EventNamePullRequest, PRHeadFork}
	comment := RunRef{workflow.EventNameIssueComment, PRHeadNone}
	for _, c := range []struct {
		name    string
		a       lint.Attacker
		role    Role
		ref     RunRef
		answer  Answer
		channel expr.Truth
		want    map[lint.Gain]Crossing
	}{
		{"pull_request_target from a fork", lint.AttackerForkPRAuthor, RoleNone, prt, public, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingByWorkflow, lint.GainWriteWithToken: CrossingByWorkflow}},
		{"pull_request from a fork, public", lint.AttackerForkPRAuthor, RoleNone, pr, public, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingNone, lint.GainWriteWithToken: CrossingNone, lint.GainRunCode: CrossingNone, lint.GainPersistOnRunner: CrossingByBaseline}},
		{"pull_request from a fork, private with secrets sent", lint.AttackerForkPRAuthor, RoleRead, pr, privateSecrets, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingByBaseline, lint.GainWriteWithToken: CrossingNone}},
		{"a comment of one who reads", lint.AttackerCommenter, RoleRead, comment, privateClosed, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainWriteWithToken: CrossingByWorkflow, lint.GainReadSecrets: CrossingByWorkflow}},
		{"a comment of one who writes", lint.AttackerCommenter, RoleWrite, comment, privateClosed, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainWriteWithToken: CrossingByBaseline, lint.GainReadSecrets: CrossingByBaseline}},
		{"an issue of one with no access to a private repository", lint.AttackerIssueAuthor, RoleNone, RunRef{workflow.EventNameIssues, PRHeadNone}, privateClosed, expr.TruthFalse, nil},
		{"a pull request of one who triages", lint.AttackerForkPRAuthor, RoleTriage, prt, public, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingByWorkflow}},
	} {
		got := Cross(c.a, c.role, c.ref, c.answer)
		if got.Channel != c.channel {
			t.Errorf("%s: channel %v, want %v", c.name, got.Channel, c.channel)
		}
		for g, w := range c.want {
			if got.Crossings[g] != w {
				t.Errorf("%s: %s is %s, want %s", c.name, g, got.Crossings[g], w)
			}
		}
	}
}

// TestRowsCover: every pull request event has rows of both heads, every
// role has a baseline, every attacker of an event has a channel row of
// every role, and every attacker with no event a pathway row of every role.
func TestRowsCover(t *testing.T) {
	tb := rows()
	for _, e := range []workflow.EventName{workflow.EventNamePullRequest, workflow.EventNamePullRequestTarget, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment} {
		for _, h := range []PRHead{PRHeadFork, PRHeadRepository} {
			if len(tb.runConditions(RunRef{e, h})) == 0 {
				t.Errorf("no row of %s %s", e, h)
			}
		}
	}
	for _, r := range Roles() {
		if !slices.ContainsFunc(tb.baselines, func(b RoleBaseline) bool { return b.Role == r }) {
			t.Errorf("no baseline of %s", r)
		}
	}
	for _, a := range []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerMergedCommitAuthor, lint.AttackerAnyoneWhoForks, lint.AttackerWikiEditor} {
		for _, r := range Roles() {
			if !slices.ContainsFunc(tb.channels, func(c Channel) bool { return c.Attacker == a && c.Role == r }) {
				t.Errorf("no channel of %s %s", a, r)
			}
		}
	}
	for _, a := range []lint.Attacker{lint.AttackerArtifactReader, lint.AttackerLogReader, lint.AttackerMaintainerOfCalled, lint.AttackerForkerOfCalled, lint.AttackerImagePublisher, lint.AttackerDestinationHolder, lint.AttackerAdvisoryAttacker} {
		for _, r := range Roles() {
			if !slices.ContainsFunc(tb.pathways, func(p Pathway) bool { return p.Attacker == a && p.Role == r }) {
				t.Errorf("no pathway of %s %s", a, r)
			}
		}
	}
}
