package rules

import (
	"github.com/gh-intel/sisakulint/actions/ir"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// Forms of untrusted-checkout and untrusted-checkout-toctou that the rules
// once read wrongly, each with what the rules read now.

// TestCheckoutFormAfterBefore: github.event.after and before on synchronize are commits of the
// pull request; before is not what the guard of actions/checkout compares.
func TestCheckoutFormAfterBefore(t *testing.T) {
	for _, c := range []struct {
		uses, ref string
		want      int
	}{
		{"actions/checkout@v3.6.0", "${{ github.event.after }}", 1},
		{"actions/checkout@v3.6.0", "${{ github.event.before }}", 1},
		{"actions/checkout@v4", "${{ github.event.before }}", 1},
		{"actions/checkout@v4", "${{ github.event.after }}", 0}, // the head's SHA, which the guard refuses
	} {
		src := checkoutJob("{pull_request_target: {types: [synchronize]}}", "", c.uses, "{ref: '"+c.ref+"'}", "      - run: make\n")
		rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, wfFile(src), checkoutFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != c.want {
			t.Errorf("%s %s: %d findings, want %d", c.uses, c.ref, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), c.want)
		}
	}
}

// TestCheckoutFormToolOutsidePath: a tool run at the root does not run the tree a checkout put in pr/.
func TestCheckoutFormToolOutsidePath(t *testing.T) {
	src := "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n      - uses: actions/checkout@v4.2.2\n        with: {ref: '${{ github.event.pull_request.head.sha }}', path: pr}\n      - run: npm ci && npm test\n"
	rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, wfFile(src), checkoutFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != "untrusted-checkout.checkout" {
		t.Errorf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestCheckoutFormPinWholeOnly: the safe fix replaces a branch's name only when it is the whole ref.
func TestCheckoutFormPinWholeOnly(t *testing.T) {
	for _, ref := range []string{"refs/heads/${{ github.head_ref }}", "${{ github.head_ref || 'main' }}"} {
		src := checkoutJob("{pull_request_target: {types: [labeled]}}", "", "actions/checkout@v4.2.2", "{repository: '${{ github.event.pull_request.head.repo.full_name }}', ref: \""+ref+"\"}", "      - run: npm ci\n")
		rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckoutToctou}, wfFile(src), checkoutFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix != nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix == nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix.Reason != ir.NoFixReasonManual {
			t.Errorf("%s: %+v", ref, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
	}
}

// A checkout whose ref is not known is a place not
// examined even with a release that has the guard, which refuses only some
// values.
func TestCheckoutFormGuardedUnknown(t *testing.T) {
	src := checkoutJob("pull_request_target", "", "actions/checkout@v4", "{ref: '${{ steps.pr.outputs.sha }}'}", "      - run: npm ci\n")
	rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, wfFile(src), checkoutFacts{})
	if len(rep.FindingsWith(lint.CertaintyInconclusive)) != 1 {
		t.Errorf("unexamined %+v", rep.FindingsWith(lint.CertaintyInconclusive))
	}
}
