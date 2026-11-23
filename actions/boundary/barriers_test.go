package boundary

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// TestBarrierPassCheck: a barrier pass row needs an added attacker, a
// barrier and grounds that fit its basis, and an unverified row lets no
// attacker past.
func TestBarrierPassCheck(t *testing.T) {
	q := doc("data/tables/repository-roles.yml", "  - action: 'Apply/dismiss labels'")
	ok := BarrierPass{AddedAttacker: lint.AddedAttackerTriageAccount, Barrier: analysis.BarrierLabelApproval, Passes: true, Basis: BasisDocumented, Quotes: []Quote{q}}
	if err := ok.check(); err != nil {
		t.Errorf("a documented row: %v", err)
	}
	for _, c := range []struct {
		name string
		edit func(*BarrierPass)
		want string
	}{
		{"no added attacker", func(r *BarrierPass) { r.AddedAttacker = lint.AddedAttackerUnset }, "no added attacker"},
		{"no barrier", func(r *BarrierPass) { r.Barrier = analysis.BarrierUnset }, "no barrier"},
		{"documented without a quote", func(r *BarrierPass) { r.Quotes = nil }, "documented without a quote"},
		{"a JSON pointer in a file not JSON", func(r *BarrierPass) {
			x := q
			x.JSONPointer = MustJSONPointer("/a")
			r.Quotes = []Quote{x}
		}, "the file is not JSON"},
		{"unverified and passes", func(r *BarrierPass) { r.Basis, r.Uncertainty = BasisUnverified, "not seen" }, "unverified"},
	} {
		r := ok
		c.edit(&r)
		if err := r.check(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", c.name, err, c.want)
		}
	}
}

// TestBarrierPassesOfNone: a run that adds no attacker passes no barrier.
func TestBarrierPassesOfNone(t *testing.T) {
	if p := BarrierPassesOf(nil); !p.IsZero() {
		t.Errorf("BarrierPassesOf(nil) = %s", p)
	}
}

// passing are the barriers the rows of v let past, in their order.
func passing(v lint.AddedAttacker) []analysis.Barrier {
	var out []analysis.Barrier
	for _, b := range analysis.Barriers() {
		for _, r := range BarrierRows() {
			if r.AddedAttacker == v && r.Barrier == b && r.Passes {
				out = append(out, b)
			}
		}
	}
	return out
}

// TestBarrierRowsByValue: each added attacker gets past the barriers that
// the table of the values of the added attackers says, and no other.
func TestBarrierRowsByValue(t *testing.T) {
	owner, member, collaborator := analysis.BarrierAssociationOwner, analysis.BarrierAssociationMember, analysis.BarrierAssociationCollaborator
	for _, c := range []struct {
		v    lint.AddedAttacker
		want []analysis.Barrier
	}{
		{lint.AddedAttackerReadMember, []analysis.Barrier{member, collaborator}},
		{lint.AddedAttackerTriageAccount, []analysis.Barrier{member, collaborator, analysis.BarrierLabelApproval}},
		{lint.AddedAttackerWriterPullRequestsToken, []analysis.Barrier{owner, member, collaborator, analysis.BarrierActorName, analysis.BarrierLabelApproval, analysis.BarrierAgentGate}},
		{lint.AddedAttackerWriterIssuesToken, []analysis.Barrier{owner, member, collaborator, analysis.BarrierActorName, analysis.BarrierAgentGate}},
		{lint.AddedAttackerRequiredReviewer, []analysis.Barrier{member, collaborator, analysis.BarrierEnvironmentApproval}},
		{lint.AddedAttackerAppInstallationToken, []analysis.Barrier{analysis.BarrierActorName, analysis.BarrierLabelApproval}},
		{lint.AddedAttackerVariablesWriter, []analysis.Barrier{analysis.BarrierVariableValue}},
		{lint.AddedAttackerSecretsWriter, []analysis.Barrier{analysis.BarrierSecretValue}},
	} {
		if got := passing(c.v); !slices.Equal(got, c.want) {
			t.Errorf("%s passes %v, want %v", c.v, got, c.want)
		}
	}
}

// TestBarrierRowsCover: every added attacker has one row of each barrier.
func TestBarrierRowsCover(t *testing.T) {
	for _, v := range lint.AddedAttackers() {
		for _, b := range analysis.Barriers() {
			n := 0
			for _, r := range BarrierRows() {
				if r.AddedAttacker == v && r.Barrier == b {
					n++
				}
			}
			if n != 1 {
				t.Errorf("%s %s: %d rows, want 1", v, b, n)
			}
		}
	}
}

// TestBarrierPassesOfRows: BarrierPassesOf of one value is what its rows
// let past.
func TestBarrierPassesOfRows(t *testing.T) {
	for _, v := range lint.AddedAttackers() {
		p := BarrierPassesOf([]lint.AddedAttacker{v})
		for _, b := range analysis.Barriers() {
			if p.Passes(b) != slices.Contains(passing(v), b) {
				t.Errorf("%s: BarrierPassesOf passes %s: %v", v, b, p.Passes(b))
			}
		}
	}
}

// TestWriteRows: every added attacker has one row of each object; the
// accounts write every object, the tokens of a writer only those of their
// permission, the token of an App comments and opens issues and reviews
// but no pull request, and the writers of values write none.
func TestWriteRows(t *testing.T) {
	writes := func(v lint.AddedAttacker) []analysis.WrittenObject {
		var out []analysis.WrittenObject
		for _, o := range analysis.WrittenObjects() {
			n := 0
			for _, r := range WriteRows() {
				if r.AddedAttacker == v && r.Object == o {
					n++
					if r.Writes {
						out = append(out, o)
					}
				}
			}
			if n != 1 {
				t.Errorf("%s %s: %d rows, want 1", v, o, n)
			}
		}
		return out
	}
	all := analysis.WrittenObjects()
	for _, c := range []struct {
		v    lint.AddedAttacker
		want []analysis.WrittenObject
	}{
		{lint.AddedAttackerReadMember, all},
		{lint.AddedAttackerTriageAccount, all},
		{lint.AddedAttackerRequiredReviewer, all},
		{lint.AddedAttackerWriterIssuesToken, []analysis.WrittenObject{analysis.WrittenIssue, analysis.WrittenIssueComment}},
		{lint.AddedAttackerWriterPullRequestsToken, []analysis.WrittenObject{analysis.WrittenPullRequestComment, analysis.WrittenPullRequestReview}},
		{lint.AddedAttackerAppInstallationToken, []analysis.WrittenObject{analysis.WrittenIssue, analysis.WrittenIssueComment, analysis.WrittenPullRequestComment, analysis.WrittenPullRequestReview}},
		{lint.AddedAttackerVariablesWriter, nil},
		{lint.AddedAttackerSecretsWriter, nil},
	} {
		if got := writes(c.v); !slices.Equal(got, c.want) {
			t.Errorf("%s writes %v, want %v", c.v, got, c.want)
		}
		p := BarrierPassesOf([]lint.AddedAttacker{c.v})
		for _, o := range all {
			if p.Writes(o) != slices.Contains(c.want, o) {
				t.Errorf("%s: BarrierPassesOf writes %s: %v", c.v, o, p.Writes(o))
			}
		}
	}
}
