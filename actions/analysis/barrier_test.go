package analysis

import (
	"slices"
	"testing"
)

// TestZeroBarrierPassesPassesNone: the barriers of a run that adds no
// attacker let no attacker past any barrier.
func TestZeroBarrierPassesPassesNone(t *testing.T) {
	var p BarrierPasses
	if !p.IsZero() {
		t.Error("the zero BarrierPasses is not zero")
	}
	for _, g := range Barriers() {
		if p.Passes(g) {
			t.Errorf("the zero BarrierPasses passes %s", g)
		}
	}
}

// TestBarrierPassesWithUnion: With and Union pass what they are given and
// nothing else.
func TestBarrierPassesWithUnion(t *testing.T) {
	p := BarrierPasses{}.With(BarrierLabelApproval).Union(BarrierPasses{}.With(BarrierAgentGate))
	for _, g := range Barriers() {
		want := g == BarrierLabelApproval || g == BarrierAgentGate
		if p.Passes(g) != want {
			t.Errorf("Passes(%s) = %v, want %v", g, p.Passes(g), want)
		}
	}
	if got, want := p.String(), "label-approval,agent-gate"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestBarrierNames: the barriers and their names, in their order.
func TestBarrierNames(t *testing.T) {
	var got []string
	for _, g := range Barriers() {
		got = append(got, g.String())
	}
	want := []string{"association-owner", "association-member", "association-collaborator", "actor-name", "label-approval", "environment-approval", "agent-gate", "variable-value", "secret-value"}
	if !slices.Equal(got, want) {
		t.Errorf("Barriers() = %v, want %v", got, want)
	}
}

// TestBarrierPassesWrites: the zero BarrierPasses writes every object; one
// limited to some writes those only; the union writes what either writes.
func TestBarrierPassesWrites(t *testing.T) {
	var p BarrierPasses
	for _, o := range WrittenObjects() {
		if !p.Writes(o) {
			t.Errorf("the zero BarrierPasses does not write %s", o)
		}
	}
	issues := BarrierPasses{}.Limited(WrittenIssue, WrittenIssueComment)
	if !issues.Writes(WrittenIssueComment) || issues.Writes(WrittenPullRequestComment) || issues.IsZero() {
		t.Errorf("limited to issues: %s", issues)
	}
	pulls := BarrierPasses{}.Limited(WrittenPullRequestComment)
	u := issues.Union(pulls)
	if !u.Writes(WrittenIssueComment) || !u.Writes(WrittenPullRequestComment) || u.Writes(WrittenDiscussion) {
		t.Errorf("the union: %s", u)
	}
	if !issues.Union(BarrierPasses{}).Writes(WrittenDiscussion) {
		t.Error("a union with the unlimited is limited")
	}
	none := BarrierPasses{}.Limited()
	if none.Writes(WrittenIssue) || none.IsZero() {
		t.Errorf("limited to none: %s", none)
	}
}
