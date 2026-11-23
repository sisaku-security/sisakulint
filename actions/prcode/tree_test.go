package prcode

import (
	"github.com/gh-intel/sisakulint/actions/analysis"
	"slices"
	"testing"
)

// TestTree: a branch's name alone, with the base repository, does not bring a fork's
// code; the fork as the repository does, whatever the ref.
func TestTree(t *testing.T) {
	for _, c := range []struct {
		with    string
		tree    analysis.CheckoutCode
		refs    []string
		fork    bool
		mutable bool
	}{
		{"", analysis.CodeBase, nil, false, false},
		{"{ref: main}", analysis.CodeBase, nil, false, false},
		{"{ref: '${{ github.event.pull_request.head.sha }}'}", analysis.CodePR, []string{"github.event.pull_request.head.sha"}, false, false},
		{"{ref: '${{ github.event.pull_request.merge_commit_sha }}'}", analysis.CodePR, []string{"github.event.pull_request.merge_commit_sha"}, false, false},
		{"{ref: '${{ github.event.pull_request.head.ref }}'}", analysis.CodeBase, nil, false, false},
		{"{ref: '${{ github.head_ref }}'}", analysis.CodeBase, nil, false, false},
		{"{repository: '${{ github.event.pull_request.head.repo.full_name }}'}", analysis.CodePR, []string{"github.event.pull_request.head.repo.full_name"}, true, true},
		{"{repository: '${{ github.event.pull_request.head.repo.full_name }}', ref: '${{ github.head_ref }}'}", analysis.CodePR, []string{"github.event.pull_request.head.repo.full_name", "github.head_ref"}, true, true},
		{"{repository: '${{ github.event.pull_request.head.repo.full_name }}', ref: '${{ github.event.pull_request.head.sha }}'}", analysis.CodePR, []string{"github.event.pull_request.head.repo.full_name", "github.event.pull_request.head.sha"}, true, false},
		{"{ref: '${{ github.sha }}'}", analysis.CodeBase, nil, false, false},
		{"{ref: '${{ github.event.pull_request.base.sha }}'}", analysis.CodeBase, nil, false, false},
		{"{ref: '${{ steps.pr.outputs.sha }}'}", analysis.CodeUnknown, nil, false, false},
		{"{ref: '${{ inputs.ref }}'}", analysis.CodeUnknown, nil, false, false},
		{"'${{ fromJSON(inputs.with) }}'", analysis.CodeUnknown, nil, false, false},
		{"{ref: '${{ github.event.pull_request.head.sha || github.sha }}'}", analysis.CodePR, []string{"github.event.pull_request.head.sha"}, false, false},
		{"{ref: '${{ GitHub.Event.Pull_Request.Head.SHA }}'}", analysis.CodePR, []string{"GitHub.Event.Pull_Request.Head.SHA"}, false, false},
	} {
		s := oneSite(t, "pull_request_target", "", "actions/checkout@v4", c.with, "")
		if s.CheckoutCode != c.tree || !slices.Equal(refTexts(s.Refs), c.refs) || s.Fork != c.fork || s.Mutable() != c.mutable {
			t.Errorf("with %s: %v %v fork=%v mutable=%v; want %v %v %v %v", c.with, s.CheckoutCode, refTexts(s.Refs), s.Fork, s.Mutable(), c.tree, c.refs, c.fork, c.mutable)
		}
	}
	// the references of workflow_run, on workflow_run
	for _, c := range []struct {
		with string
		refs []string
		fork bool
	}{
		{"{ref: '${{ github.event.workflow_run.head_sha }}'}", []string{"github.event.workflow_run.head_sha"}, false},
		{"{repository: '${{ github.event.workflow_run.head_repository.full_name }}', ref: '${{ github.event.workflow_run.head_branch }}'}", []string{"github.event.workflow_run.head_repository.full_name", "github.event.workflow_run.head_branch"}, true},
	} {
		s := oneSite(t, "{workflow_run: {workflows: [ci], types: [completed]}}", "", "actions/checkout@v4", c.with, "")
		if s.CheckoutCode != analysis.CodePR || !slices.Equal(refTexts(s.Refs), c.refs) || s.Fork != c.fork {
			t.Errorf("with %s: %v %v fork=%v", c.with, s.CheckoutCode, refTexts(s.Refs), s.Fork)
		}
	}
}

// TestTreeRefPullNumber: refs/pull/<n>/… is read with the literal around the
// number.
func TestTreeRefPullNumber(t *testing.T) {
	for _, c := range []struct {
		ref  string
		tree analysis.CheckoutCode
	}{
		{"refs/pull/${{ github.event.pull_request.number }}/merge", analysis.CodePR},
		{"refs/pull/${{ github.event.number }}/head", analysis.CodePR},
		// the number of a pull request in another form is not known: not
		// dropped
		{"refs/heads/${{ github.event.pull_request.number }}", analysis.CodeUnknown},
		{"${{ github.event.pull_request.number }}", analysis.CodeUnknown},
		{"refs/pull/${{ github.event.pull_request.number }}/merge-x", analysis.CodeUnknown},
		{"x/refs/pull/${{ github.event.pull_request.number }}/head", analysis.CodeUnknown},
	} {
		s := oneSite(t, "pull_request_target", "", "actions/checkout@v4", "{ref: '"+c.ref+"'}", "")
		if s.CheckoutCode != c.tree || c.tree == analysis.CodePR && (len(s.Refs) != 1 || !s.Refs[0].Mutable || s.Refs[0].Text != c.ref || !s.Mutable()) {
			t.Errorf("ref %s: %v %+v", c.ref, s.CheckoutCode, s.Refs)
		}
	}
}

// The releases of actions/checkout that refuse a fork's code.
func TestGuard(t *testing.T) {
	sha := "0123456789012345678901234567890123456789"
	for _, c := range []struct {
		ref, allow string
		want       analysis.Guard
	}{
		{"v4", "", analysis.GuardStatic},
		{"v7", "", analysis.GuardStatic},
		{"v2", "", analysis.GuardStatic},
		{"v1", "", analysis.GuardNone},
		{"v8", "", analysis.GuardStatic},
		{"v4.4.0", "", analysis.GuardStatic},
		{"v4.4", "", analysis.GuardStatic},
		{"v4.3.1", "", analysis.GuardNone},
		{"v4.3", "", analysis.GuardNone},
		{"v4.2.2", "", analysis.GuardNone},
		{"v7.0.0", "", analysis.GuardStatic},
		{"v6.0.3", "", analysis.GuardNone},
		{"v6.1.0", "", analysis.GuardStatic},
		{"v2.8.0", "", analysis.GuardStatic},
		{"v1.2.0", "", analysis.GuardNone},
		{"main", "", analysis.GuardNone},
		{sha, "", analysis.GuardSHA},
		{"v4", "true", analysis.GuardNone},
		{"v4", "TRUE", analysis.GuardNone},
		{"v4", "false", analysis.GuardStatic},
		{"v4", "'${{ inputs.allow }}'", analysis.GuardNone},
	} {
		with := "{ref: '${{ github.event.pull_request.head.sha }}'"
		if c.allow != "" {
			with += ", allow-unsafe-pr-checkout: " + c.allow
		}
		s := oneSite(t, "pull_request_target", "", "actions/checkout@"+c.ref, with+"}", "")
		if s.Guard != c.want || c.want == analysis.GuardSHA && s.SHA.String() != sha {
			t.Errorf("@%s allow %q: %v %v, want %v", c.ref, c.allow, s.Guard, s.SHA, c.want)
		}
	}
	if n := len(GuardCommits()); n != 6 {
		t.Errorf("%d commits of the guard, want 6", n)
	}
}

// TestTreeRefsAppCommitEvents: on status, check_suite and check_run, the
// fields that held the SHA of the commit of a pull request from a fork
// (seen on GitHub on 2026-11-06) name the code of the pull request;
// check_suite.after, which was null for that commit, does not.
func TestTreeRefsAppCommitEvents(t *testing.T) {
	for _, c := range []struct {
		on, ref string
		tree    analysis.CheckoutCode
	}{
		{"status", "github.event.sha", analysis.CodePR},
		{"status", "github.event.commit.sha", analysis.CodePR},
		{"{check_suite: {types: [completed]}}", "github.event.check_suite.head_sha", analysis.CodePR},
		{"{check_suite: {types: [completed]}}", "github.event.check_suite.head_commit.id", analysis.CodePR},
		{"check_run", "github.event.check_run.head_sha", analysis.CodePR},
		{"check_run", "github.event.check_run.check_suite.head_sha", analysis.CodePR},
	} {
		s := oneSite(t, c.on, "", "actions/checkout@v4", "{ref: '${{ "+c.ref+" }}'}", "")
		if s.CheckoutCode != c.tree || !slices.Equal(refTexts(s.Refs), []string{c.ref}) || s.Fork || s.Mutable() {
			t.Errorf("on %s, ref %s: %v %v fork=%v mutable=%v", c.on, c.ref, s.CheckoutCode, refTexts(s.Refs), s.Fork, s.Mutable())
		}
	}
	s := oneSite(t, "{check_suite: {types: [completed]}}", "", "actions/checkout@v4", "{ref: '${{ github.event.check_suite.after }}'}", "")
	if s.CheckoutCode == analysis.CodePR {
		t.Errorf("check_suite.after: %v %v, want no code of a pull request", s.CheckoutCode, refTexts(s.Refs))
	}
}
