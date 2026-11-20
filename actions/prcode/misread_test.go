package prcode

import (
	"github.com/sisaku-security/sisakulint/actions/analysis"
	"slices"
	"testing"
)

// Forms of a checkout of a pull request's code that prcode once read
// wrongly, each with what it reads now.

// TestMisreadPullRefForms: a number of a pull request in a ref of another form is not dropped.
func TestMisreadPullRefForms(t *testing.T) {
	for _, c := range []struct {
		on, ref string
		tree    analysis.CheckoutCode
		guard   analysis.Guard
	}{
		{"issue_comment", "${{ format('refs/pull/{0}/head', github.event.issue.number) }}", analysis.CodeUnknown, analysis.GuardStatic},
		{"issue_comment", "REFS/PULL/${{ github.event.issue.number }}/head", analysis.CodePR, analysis.GuardNone},
		// the guard's pattern does not match capitals: it lets it through
		{"pull_request_target", "Refs/Pull/${{ github.event.pull_request.number }}/head", analysis.CodePR, analysis.GuardNone},
		{"pull_request_target", "refs/pull/${{ github.event.pull_request.number }}/head", analysis.CodePR, analysis.GuardStatic},
	} {
		s := oneSite(t, c.on, "", "actions/checkout@v4", "{ref: \""+c.ref+"\"}", "")
		if s.CheckoutCode != c.tree || s.Guard != c.guard {
			t.Errorf("%s: %v %v, want %v %v", c.ref, s.CheckoutCode, s.Guard, c.tree, c.guard)
		}
	}
}

// TestMisreadUnknownContexts: what an attacker shapes in a ref, and a repository other than the
// base's, are not known.
func TestMisreadUnknownContexts(t *testing.T) {
	for _, c := range []struct {
		on, with string
		tree     analysis.CheckoutCode
	}{
		{"issue_comment", "{ref: '${{ github.event.comment.body }}'}", analysis.CodeUnknown},
		{"pull_request_target", "{repository: '${{ github.event.pull_request.head.repo.owner.login }}/x', ref: '${{ github.head_ref }}'}", analysis.CodeUnknown},
		{"pull_request_target", "{repository: '${{ github.event.pull_request.head.repo.clone_url }}'}", analysis.CodeUnknown},
		{"pull_request_target", "{repository: '${{ github.repository }}', ref: '${{ github.sha }}'}", analysis.CodeBase},
		{"pull_request_target", "{repository: '${{ github.event.pull_request.base.repo.full_name }}'}", analysis.CodeBase},
		{"pull_request_target", "{ref: '${{ github.event.pull_request.base.ref }}'}", analysis.CodeBase},
	} {
		if s := oneSite(t, c.on, "", "actions/checkout@v4", c.with, ""); s.CheckoutCode != c.tree {
			t.Errorf("on %s with %s: %v, want %v", c.on, c.with, s.CheckoutCode, c.tree)
		}
	}
}

// TestMisreadForkMutable: a fork's checkout moves unless its ref is a commit.
func TestMisreadForkMutable(t *testing.T) {
	const fork = "repository: '${{ github.event.pull_request.head.repo.full_name }}'"
	for _, c := range []struct {
		ref     string
		mutable bool
	}{
		{"", true},
		{", ref: ''", true},
		{", ref: main", true},
		{", ref: '${{ github.ref }}'", true},
		{", ref: '${{ github.event.pull_request.head.sha }}'", false},
	} {
		if s := oneSite(t, "pull_request_target", "", "actions/checkout@v4", "{"+fork+c.ref+"}", ""); !s.Fork || s.Mutable() != c.mutable {
			t.Errorf("ref %q: fork=%v mutable=%v, want %v", c.ref, s.Fork, s.Mutable(), c.mutable)
		}
	}
}

// TestMisreadRefEvents: a reference counts on the events whose payload has it.
func TestMisreadRefEvents(t *testing.T) {
	for _, c := range []struct {
		on, ref string
		want    []string
	}{
		{"[pull_request_target, issue_comment]", "${{ github.event.pull_request.head.sha }}", []string{"pull_request_target"}},
		{"[pull_request_target, issue_comment]", "refs/pull/${{ github.event.issue.number }}/head", []string{"issue_comment"}},
		{"[pull_request_target, workflow_run]", "${{ github.event.workflow_run.head_sha }}", []string{"workflow_run"}},
		{"issue_comment", "${{ github.event.pull_request.head.sha }}", nil},
	} {
		s := oneSite(t, c.on, "", "actions/checkout@v4.2.2", "{ref: '"+c.ref+"'}", "")
		var names []string
		for _, e := range s.PRCodeOn {
			if !slices.Contains(names, e.Name().String()) {
				names = append(names, e.Name().String())
			}
		}
		if !slices.Equal(names, c.want) || (c.want == nil) != (s.CheckoutCode == analysis.CodeBase) {
			t.Errorf("on %s ref %s: %v %v, want %v", c.on, c.ref, names, s.CheckoutCode, c.want)
		}
	}
}

// TestMisreadLaterCheckout: a later checkout of the same place takes away what the first one
// brought.
func TestMisreadLaterCheckout(t *testing.T) {
	for _, c := range []struct {
		after string
		runs  int
	}{
		{"      - uses: actions/checkout@v4\n      - run: npm ci\n", 0},
		{"      - uses: actions/checkout@v4\n        with: {path: base}\n      - run: npm ci\n", 1},
		{"      - run: make\n      - uses: actions/checkout@v4\n      - run: npm ci\n", 1},
	} {
		w := mustWorkflow(t, "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with: {ref: '${{ github.event.pull_request.head.sha }}'}\n"+c.after)
		if s := Analyze(w, nil)[0]; len(s.CodeRunSteps) != c.runs {
			t.Errorf("%q: %d runs, want %d", c.after, len(s.CodeRunSteps), c.runs)
		}
	}
}

// TestMisreadAllowEmpty: allow-unsafe-pr-checkout empty is false, as the checkout reads it.
func TestMisreadAllowEmpty(t *testing.T) {
	for _, allow := range []string{"''", "null"} {
		if s := oneSite(t, "pull_request_target", "", "actions/checkout@v4", "{ref: '${{ github.event.pull_request.head.sha }}', allow-unsafe-pr-checkout: "+allow+"}", ""); s.Guard != analysis.GuardStatic {
			t.Errorf("allow %s: %v", allow, s.Guard)
		}
	}
}
