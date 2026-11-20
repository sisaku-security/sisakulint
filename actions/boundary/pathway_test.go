package boundary

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// TestCrossByPathway: what one of each role gets by the pathway of an
// attacker with no event, in a run of the workflow.
func TestCrossByPathway(t *testing.T) {
	public := answers(map[facts.Kind]bool{facts.KindRepoPublic: true})
	closed := answers(map[facts.Kind]bool{facts.KindRepoPublic: false})
	push := RunRef{workflow.EventNamePush, PRHeadNone}
	forkPR := RunRef{workflow.EventNamePullRequest, PRHeadFork}
	for _, c := range []struct {
		name    string
		a       lint.Attacker
		role    Role
		ref     RunRef
		answer  Answer
		pathway expr.Truth
		want    map[lint.Gain]Crossing
		basis   Basis // BasisUnset: not checked
	}{
		{"artifact of a fork's pull request", lint.AttackerArtifactReader, RoleNone, forkPR, public, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingNone, lint.GainWriteWithToken: CrossingNone}, BasisUnset},
		{"artifact of a push", lint.AttackerArtifactReader, RoleNone, push, public, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingByWorkflow, lint.GainWriteWithToken: CrossingByWorkflow}, BasisDocumented},
		{"artifact of a push, one who writes", lint.AttackerArtifactReader, RoleWrite, push, public, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingByBaseline, lint.GainWriteWithToken: CrossingByBaseline}, BasisUnset},
		{"artifact of a private repository", lint.AttackerArtifactReader, RoleNone, push, closed, expr.TruthFalse, nil, BasisUnset},
		{"log of a private repository", lint.AttackerLogReader, RoleNone, push, closed, expr.TruthFalse, nil, BasisUnset},
		{"log of a push, one who writes", lint.AttackerLogReader, RoleWrite, push, closed, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainReadSecrets: CrossingByBaseline}, BasisUnset},
		{"code of the called", lint.AttackerMaintainerOfCalled, RoleNone, push, public, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainRunCode: CrossingByWorkflow}, BasisUnset},
		{"code of the called, one who administers", lint.AttackerMaintainerOfCalled, RoleAdmin, push, public, expr.TruthTrue,
			map[lint.Gain]Crossing{lint.GainRunCode: CrossingByBaseline}, BasisUnset},
		// not known: what one gets if they can, marked so by the viewer
		{"an advisory's attacker", lint.AttackerAdvisoryAttacker, RoleNone, push, public, expr.TruthUnknown,
			map[lint.Gain]Crossing{lint.GainRunCode: CrossingByWorkflow}, BasisUnverified},
		{"an attacker of no pathway row", lint.AttackerIssueAuthor, RoleNone, push, public, expr.TruthUnknown, nil, BasisUnverified},
	} {
		r := CrossByPathway(c.a, c.role, c.ref, c.answer)
		if r.Usable != c.pathway {
			t.Errorf("%s: pathway %v, want %v", c.name, r.Usable, c.pathway)
		}
		if c.pathway == expr.TruthFalse && r.Crossings != nil {
			t.Errorf("%s: crossings %v where the pathway is not usable", c.name, r.Crossings)
		}
		if c.basis != BasisUnset && r.Basis != c.basis {
			t.Errorf("%s: basis %s, want %s", c.name, r.Basis, c.basis)
		}
		for g, want := range c.want {
			if got := r.Crossings[g]; got != want {
				t.Errorf("%s: %s is %s, want %s", c.name, g, got, want)
			}
		}
	}
}

// TestPathwayCheck: a row whose Usable is not known needs the basis
// unverified, and a row needs an attacker.
func TestPathwayCheck(t *testing.T) {
	bad := []Pathway{
		{Attacker: lint.AttackerAdvisoryAttacker, Role: RoleNone, Usable: expr.TruthUnknown, Basis: BasisDocumented, Quotes: []Quote{doc("a.md", "x")}},
		{Role: RoleNone, Usable: expr.TruthTrue, Basis: BasisDocumented, Quotes: []Quote{doc("a.md", "x")}},
		{Attacker: lint.AttackerImagePublisher, Role: RoleNone, Usable: expr.TruthTrue, Basis: BasisDocumented},
		{Attacker: lint.AttackerAdvisoryAttacker, Role: RoleNone, Usable: expr.TruthUnknown, Basis: BasisUnverified},
	}
	for i, p := range bad {
		if p.check() == nil {
			t.Errorf("the row %d is taken", i)
		}
	}
	for _, p := range Pathways() {
		if err := p.check(); err != nil {
			t.Errorf("%s %s: %v", p.Attacker, p.Role, err)
		}
	}
}

// TestPathwayBases: the bases the owner chose: unverified for the attacker
// of an advisory, documented for the
// others; the row of the forker of the called keeps the observation. The
// rows of the artifact and the log that the accounts of no role (in a
// public repository), of the role read and of the role triage were seen
// to use are observed.
func TestPathwayBases(t *testing.T) {
	for _, p := range Pathways() {
		want := BasisDocumented
		switch {
		case p.Attacker == lint.AttackerAdvisoryAttacker:
			want = BasisUnverified
		case p.Attacker == lint.AttackerArtifactReader || p.Attacker == lint.AttackerLogReader:
			if p.Role == RoleRead || p.Role == RoleTriage || (p.Role == RoleNone && p.Usable == expr.TruthTrue) {
				want = BasisObserved
			}
		}
		if p.Basis != want {
			t.Errorf("%s %s: basis %s, want %s", p.Attacker, p.Role, p.Basis, want)
		}
		if p.Attacker == lint.AttackerForkerOfCalled && len(p.Observed) == 0 {
			t.Errorf("%s %s: no observation", p.Attacker, p.Role)
		}
	}
}

// TestPathwayOutsiders: one of any role can be one outside the repository
// (as the owner chose), and one who reads the repository views
// its logs.
func TestPathwayOutsiders(t *testing.T) {
	a := answers(map[facts.Kind]bool{facts.KindRepoPublic: false})
	for _, at := range []lint.Attacker{lint.AttackerMaintainerOfCalled, lint.AttackerForkerOfCalled, lint.AttackerImagePublisher, lint.AttackerDestinationHolder} {
		for _, r := range Roles() {
			if u, _ := PathwayUsable(at, r, a); u != expr.TruthTrue {
				t.Errorf("%s %s: %v, want true", at, r, u)
			}
		}
	}
	for _, at := range []lint.Attacker{lint.AttackerArtifactReader, lint.AttackerLogReader} {
		for _, r := range []Role{RoleRead, RoleTriage, RoleWrite, RoleMaintain, RoleAdmin} {
			if u, _ := PathwayUsable(at, r, a); u != expr.TruthTrue {
				t.Errorf("%s %s of a private repository: %v, want true", at, r, u)
			}
		}
	}
}
