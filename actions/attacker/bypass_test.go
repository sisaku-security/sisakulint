package attacker

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

func TestBypasses(t *testing.T) {
	syn := []analysis.EventActivity{analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)}
	comment := []analysis.EventActivity{analysis.MustEventActivity(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)}
	for _, c := range []struct {
		name, cond         string
		evs                []analysis.EventActivity
		dependabot, others int
		substring          int
	}{
		{"actor", "github.actor == 'dependabot[bot]'", syn, 1, 0, 0},
		{"actor ne", "github.actor != 'dependabot[bot]'", syn, 0, 0, 0},
		{"actor case", "GitHub.Actor == 'Dependabot[bot]'", syn, 1, 0, 0},
		{"actor id", "github.actor_id == '49699333'", syn, 1, 0, 0},
		{"trpc", "github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]'", syn, 1, 0, 0},
		{"renovate", "github.actor == 'renovate[bot]'", syn, 0, 1, 0},
		{"author", "github.event.pull_request.user.login == 'dependabot[bot]'", syn, 0, 0, 0},
		{"array", "contains(fromJSON('[\"dependabot[bot]\"]'), github.actor)", syn, 1, 0, 0},
		{"and repo", "github.actor == 'dependabot[bot]' && github.repository == 'o/r'", syn, 1, 0, 0},
		{"on comment", "github.actor == 'dependabot[bot]'", comment, 0, 1, 0},
		{"substring", "contains('alice bob', github.actor)", comment, 0, 0, 1},
		{"array of names", "contains(fromJSON('[\"alice\",\"bob\"]'), github.actor)", comment, 0, 0, 0},
		{"head ref", "contains('main', github.head_ref)", syn, 0, 0, 0},
		{"association", "contains('OWNER MEMBER', github.event.comment.author_association)", comment, 0, 0, 0},
		{"starts", "startsWith('alice', github.actor)", comment, 0, 0, 1},
		{"reference first", "contains(github.event.comment.user.login, 'alice')", comment, 0, 0, 1},
		{"reference starts", "startsWith(github.actor, 'Alice')", comment, 0, 0, 1},
		{"reference ends", "endsWith(github.actor, '-alice')", comment, 0, 0, 1},
		{"reference no login", "contains(github.actor, 'alice bob')", comment, 0, 0, 0},
		{"reference association", "contains(github.event.comment.author_association, 'MEMBER')", comment, 0, 0, 0},
		{"reference contributor", "contains(github.event.comment.author_association, 'CONTRIBUTOR')", comment, 0, 0, 0},
		{"reference body", "contains(github.event.comment.body, '/deploy')", comment, 0, 0, 0},
		{"reference bot", "endsWith(github.actor, '[bot]')", syn, 0, 0, 0},
		{"reference dependabot", "contains(github.actor, 'dependabot')", syn, 0, 0, 1},
		{"reference head ref", "contains(github.head_ref, 'release')", syn, 0, 0, 0},
		{"reference no slash in login", "contains(github.event.comment.user.login, 'my-org/')", comment, 0, 0, 0},
		{"reference id", "contains(github.event.comment.user.id, '4969')", comment, 0, 0, 0},
		{"id in a string", "contains('4969 1234', github.event.comment.user.id)", comment, 0, 0, 0},
	} {
		w := ifOf(t, "pull_request_target", c.cond)
		if got := len(DependabotBypasses(StepIf(nil, nil, w), c.evs)); got != c.dependabot {
			t.Errorf("%s: %d dependabot bypasses, want %d", c.name, got, c.dependabot)
		}
		if got := len(OtherBots(StepIf(nil, nil, w), c.evs)); got != c.others {
			t.Errorf("%s: %d other bots, want %d", c.name, got, c.others)
		}
		if got := len(SubstringBypasses(StepIf(nil, nil, w), c.evs)); got != c.substring {
			t.Errorf("%s: %d substring bypasses, want %d", c.name, got, c.substring)
		}
	}
}

// TestOtherBotsAllEvents: other bots on every activity type of
// pull_request_target: opened has no run of Dependabot, but synchronize
// lets the if through, so no comparison is inconclusive.
func TestOtherBotsAllEvents(t *testing.T) {
	evs := []analysis.EventActivity{
		analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened),
		analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize),
	}
	w := ifOf(t, "pull_request_target", "github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]'")
	if got := OtherBots(StepIf(nil, nil, w), evs); len(got) != 0 {
		t.Errorf("%d other bots", len(got))
	}
	if got := DependabotBypasses(StepIf(nil, nil, w), evs); len(got) != 1 {
		t.Errorf("%d dependabot bypasses", len(got))
	}
}

// TestBypassesBotNameString: a string of bot
// names compared by contains is both a run of Dependabot and a part of a
// name; a number written first is compared too; the literal of an array is
// its elements.
func TestBypassesBotNameString(t *testing.T) {
	syn := []analysis.EventActivity{analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)}
	for _, c := range []struct {
		cond               string
		dependabot, substr int
		literal            string
	}{
		{"contains('dependabot[bot]', github.actor)", 1, 1, "dependabot[bot]"},
		{"contains('dependabot[bot] renovate[bot]', github.actor)", 1, 1, "dependabot[bot] renovate[bot]"},
		{"49699333 == github.actor_id", 1, 0, "49699333"},
		{"contains(fromJSON('[\"dependabot[bot]\"]'), github.actor)", 1, 0, "dependabot[bot]"},
	} {
		w := ifOf(t, "pull_request_target", c.cond)
		d := DependabotBypasses(StepIf(nil, nil, w), syn)
		if len(d) != c.dependabot || len(d) > 0 && d[0].Literal != c.literal {
			t.Errorf("%s: dependabot %+v", c.cond, d)
		}
		if got := len(SubstringBypasses(StepIf(nil, nil, w), syn)); got != c.substr {
			t.Errorf("%s: %d substring bypasses, want %d", c.cond, got, c.substr)
		}
	}
}

// TestReferenceFirstFits: == of the reference and the
// string is the fix only when the string has the form of the attacker's
// value of the reference.
func TestReferenceFirstFits(t *testing.T) {
	fork := []analysis.EventActivity{analysis.MustEventActivity(workflow.EventNameFork, workflow.ActivityTypeUnset)}
	comment := []analysis.EventActivity{analysis.MustEventActivity(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)}
	for _, c := range []struct {
		cond string
		evs  []analysis.EventActivity
		fits bool
	}{
		{"contains(github.event.comment.user.login, 'alice')", comment, true},
		{"contains(github.actor, 'alice')", comment, true},
		{"contains(github.event.forkee.full_name, 'myorg/')", fork, false},
		{"contains(github.event.forkee.full_name, 'myorg/r')", fork, true},
		{"contains(github.actor, 'a-')", comment, false},
		{"contains(github.event.forkee.full_name, 'myorg')", fork, false},
		{"endsWith(github.event.forkee.full_name, '-tools')", fork, false},
	} {
		got := SubstringBypasses(StepIf(nil, nil, ifOf(t, "pull_request_target", c.cond)), c.evs)
		if len(got) != 1 || !got[0].ReferenceFirst || got[0].Fits != c.fits {
			t.Errorf("%s: %+v, want one with Fits %v", c.cond, got, c.fits)
		}
	}
}
