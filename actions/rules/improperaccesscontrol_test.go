package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestImproperAccessControl: the forms the upstream rule
// improper-access-control reports (sisakulint
// 17c2d82151a966e6e388a17619b060ae2919712e,
// pkg/core/improper_access_control.go), and what untrusted-checkout and
// untrusted-checkout-toctou report of them.
func TestImproperAccessControl(t *testing.T) {
	const fork = "          ref: ${{ github.event.pull_request.head.ref }}\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
	wf := func(on, jobIf, stepIf, uses, with string) string {
		return "on:\n  pull_request_target:\n" + on + "jobs:\n  test:\n    runs-on: ubuntu-latest\n" + jobIf +
			"    steps:\n      - uses: " + uses + "\n" + stepIf + "        with:\n" + with + "      - run: make test\n"
	}
	const label = "contains(github.event.pull_request.labels.*.name, 'safe to test')"
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		// synchronize and a label read in the step's if, which approves
		// nothing: the push after the label runs the job too.
		{"label in the step", wf("    types: [opened, synchronize]\n", "", "        if: "+label+"\n", "actions/checkout@v4.2.2", fork), []string{"untrusted-checkout.executed"}},
		// the name of the fork's branch in the base repository: no code of
		// the fork is fetched (as observed on GitHub).
		{"head_ref only", wf("    types: [opened, synchronize]\n", "", "", "actions/checkout@v4.2.2", "          ref: ${{ github.head_ref }}\n"), nil},
		// labeled alone, which upstream does not report: a push after the
		// label changes what the job checks out.
		{"labeled", wf("    types: [labeled]\n", "    if: "+label+"\n", "", "actions/checkout@v4.2.2", fork), []string{"untrusted-checkout-toctou.mutable-ref"}},
		// the floating v4 refuses to fetch a fork's code on
		// pull_request_target since 2026-07-20.
		{"floating v4", wf("    types: [opened, synchronize]\n", "", "        if: "+label+"\n", "actions/checkout@v4", fork), nil},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout, UntrustedCheckoutToctou}, wfFile(c.src), noFacts{})
		var got []string
		for _, k := range kindsOf(rep) {
			got = append(got, k.String())
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %s, want %s", c.name, strings.Join(got, ","), strings.Join(c.want, ","))
		}
	}
}
