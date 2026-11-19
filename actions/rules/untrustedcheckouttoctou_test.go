package rules

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

const forkHeadRef = "{repository: '${{ github.event.pull_request.head.repo.full_name }}', ref: '${{ github.event.pull_request.head.ref }}', allow-unsafe-pr-checkout: true}"

func TestUntrustedCheckoutToctou(t *testing.T) {
	const labeled = "{pull_request_target: {types: [labeled]}}"
	for _, c := range []struct {
		name, on, jobExtra, uses, with string
		want                           bool
		ref, approval, cond            string
	}{
		{"label, fork's branch", labeled, "", "actions/checkout@v4", forkHeadRef, true, "github.event.pull_request.head.ref", "label", ""},
		{"label, refs/pull head", labeled, "", "actions/checkout@v4.2.2", "{ref: 'refs/pull/${{ github.event.pull_request.number }}/head'}", true, "refs/pull/${{ github.event.pull_request.number }}/head", "label", ""},
		{"label, the fork alone", labeled, "", "actions/checkout@v4.2.2", "{repository: '${{ github.event.pull_request.head.repo.full_name }}'}", true, "github.event.pull_request.head.repo.full_name", "label", ""},
		{"label, head sha", labeled, "", "actions/checkout@v4.2.2", "{ref: '${{ github.event.pull_request.head.sha }}'}", false, "", "", ""},
		{"label, guarded", labeled, "", "actions/checkout@v4", "{ref: 'refs/pull/${{ github.event.pull_request.number }}/head'}", false, "", "", ""},
		{"environment", "pull_request_target", "    environment: prod\n", "actions/checkout@v4", forkHeadRef, true, "github.event.pull_request.head.ref", "environment", `{"query":{"kind":"repo.environment-protected","environment":"prod"},"eq":true}`},
		{"no approval", "pull_request_target", "", "actions/checkout@v4", forkHeadRef, false, "", "", ""},
	} {
		src := checkoutJob(c.on, c.jobExtra, c.uses, c.with, "      - run: npm ci\n")
		rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckoutToctou}, wfFile(src), checkoutFacts{})
		if !c.want {
			if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
				t.Errorf("%s: %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			}
			continue
		}
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Errorf("%s: %d findings %+v", c.name, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			continue
		}
		a, ok := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.(UntrustedCheckoutToctouMutableRef)
		if !ok || a.CheckoutRef != c.ref || approvalJSON(t, a.Approval) != c.approval || condJSON(t, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]) != c.cond {
			t.Errorf("%s: %+v %s", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args, condJSON(t, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]))
		}
	}
}

// TestCheckoutDivision: with the
// facts answered, the two rules never both hold on one step.
func TestCheckoutDivision(t *testing.T) {
	ons := []string{"pull_request_target", "{pull_request_target: {types: [labeled]}}", "{pull_request_target: {types: [labeled, synchronize]}}", "{workflow_run: {workflows: [ci], types: [completed]}}", "{issue_comment: {types: [created]}}"}
	envs := []string{"", "    environment: prod\n"}
	withs := []string{
		forkHeadRef,
		"{ref: '${{ github.event.pull_request.head.sha }}', allow-unsafe-pr-checkout: true}",
		"{ref: 'refs/pull/${{ github.event.pull_request.number || github.event.issue.number }}/head'}",
		"{repository: '${{ github.event.workflow_run.head_repository.full_name }}', ref: '${{ github.event.workflow_run.head_branch }}', allow-unsafe-pr-checkout: true}",
	}
	for _, protected := range []bool{false, true} {
		for _, on := range ons {
			for _, env := range envs {
				for _, with := range withs {
					src := checkoutJob(on, env, "actions/checkout@v4", with, "      - run: npm ci\n")
					r := checkoutFacts{protected: ptr(protected), executed: ptr(true), guarded: ptr(false)}
					a, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, wfFile(src), r)
					b, _, _ := checkRules(t, []lint.Rule{UntrustedCheckoutToctou}, wfFile(src), r)
					if confirmed(a) > 0 && confirmed(b) > 0 {
						t.Errorf("both hold on %s %q %s protected=%v", on, env, with, protected)
					}
				}
			}
		}
	}
}

func confirmed(rep lint.Report) int {
	n := 0
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Certainty == lint.CertaintyConfirmed {
			n++
		}
	}
	return n
}

var _ = fmt.Sprintf

// approvalJSON is a as the args of a finding write it, without its quotes.
func approvalJSON(t *testing.T, a analysis.Approval) string {
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Trim(string(b), `"`)
}
