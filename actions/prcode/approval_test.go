package prcode

import (
	"github.com/gh-intel/sisakulint/actions/analysis"
	"testing"
)

// TestApproval: a run on pull_request_target labeled
// alone is approved by who adds the label (triage and above); a label read
// by an if on other types is not, as a push after it runs again; an
// environment is, if it has required reviewers (a fact the rules ask).
func TestApproval(t *testing.T) {
	const with = "{repository: '${{ github.event.pull_request.head.repo.full_name }}', ref: '${{ github.event.pull_request.head.ref }}'}"
	for _, c := range []struct {
		name, on, jobExtra string
		want               analysis.Approval
		env                string
	}{
		{"labeled only", "{pull_request_target: {types: [labeled]}}", "", analysis.ApprovalLabel, ""},
		{"labeled and synchronize", "{pull_request_target: {types: [labeled, synchronize]}}", "    if: contains(github.event.pull_request.labels.*.name, 'ok')\n", analysis.ApprovalNone, ""},
		{"if narrows to labeled", "{pull_request_target: {types: [labeled, opened]}}", "    if: github.event.action == 'labeled'\n", analysis.ApprovalLabel, ""},
		{"environment", "pull_request_target", "    environment: prod\n", analysis.ApprovalEnvironment, "prod"},
		{"environment mapping", "pull_request_target", "    environment: {name: Prod}\n", analysis.ApprovalEnvironment, "prod"},
		{"environment by expression", "pull_request_target", "    environment: ${{ github.event.pull_request.head.ref }}\n", analysis.ApprovalNone, ""},
		{"label and environment", "{pull_request_target: {types: [labeled]}}", "    environment: prod\n", analysis.ApprovalLabel, ""},
		{"none", "pull_request_target", "", analysis.ApprovalNone, ""},
		// the fork's head.ref has no value on issue_comment, so only the
		// labeled run brings the pull request's code
		{"labeled and issue_comment", "{pull_request_target: {types: [labeled]}, issue_comment: {}}", "", analysis.ApprovalLabel, ""},
		{"workflow_run with an environment", "{workflow_run: {workflows: [ci], types: [completed]}}", "    environment: prod\n", analysis.ApprovalEnvironment, "prod"},
		{"no privileged event", "push", "    environment: prod\n", analysis.ApprovalEnvironment, "prod"},
	} {
		s := oneSite(t, c.on, c.jobExtra, "actions/checkout@v4", with, "")
		if s.Approval != c.want || s.Environment.String() != c.env {
			t.Errorf("%s: %v %q; want %v %q", c.name, s.Approval, s.Environment.String(), c.want, c.env)
		}
	}
}
