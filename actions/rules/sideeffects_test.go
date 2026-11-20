package rules

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// sideEffectInputs are workflows whose fixes make the side effects the
// examples of the rules do not, by the rules that fix them.
var sideEffectInputs = []struct {
	rules []lint.Rule
	src   string
	facts facts.Resolver
}{
	{[]lint.Rule{CodeInjection}, injStep(`echo ${{ github.event.issue.body }}; [[ x == ${{ github.event.issue.title }} ]]`), nil},
	{[]lint.Rule{CodeInjection}, "on: issues\njobs:\n  j:\n    runs-on: windows-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n", nil},
	{[]lint.Rule{CodeInjection}, "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: console.log('${{ github.event.issue.title }}')\n", nil},
	{[]lint.Rule{CodeInjection}, injStep(`echo "t=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"`), nil},
	{[]lint.Rule{CodeInjection}, injStep(`'{ echo "t<<EOF"; echo "${{ github.event.issue.title }}"; echo EOF; } >> "$GITHUB_OUTPUT"'`), nil},
	// the example of the rule checks out refs/pull/<n>/head
	{[]lint.Rule{UntrustedCheckoutToctou}, "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: refs/pull/${{ github.event.pull_request.number }}/merge\n          allow-unsafe-pr-checkout: true\n      - run: npm ci\n", checkoutFacts{}},
}

// TestSideEffectsAppear: each side effect a fix kind declares is made by a
// fix of that kind, in the examples of the rules or in sideEffectInputs:
// a side effect declared and never made is not known to hold. It reads the
// shared checks (sharedChecks) of the rules of All, as
// TestAdvisoryExampleResults does.
func TestSideEffectsAppear(t *testing.T) {
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	type pair struct {
		kind   lint.FixKindID
		effect ir.SideEffect
	}
	made := map[pair]bool{}
	note := func(rep lint.Report) {
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Fix != nil {
				for _, e := range f.Fix.SideEffects {
					made[pair{f.Fix.KindID, e}] = true
				}
			}
		}
	}
	for _, c := range sharedChecks(t).Of(securityRuleIDs()...) {
		for _, run := range c.Runs {
			note(run.Report)
		}
	}
	for _, in := range sideEffectInputs {
		rep, _, _ := checkRules(t, in.rules, wfFile(in.src), in.facts)
		note(rep)
	}
	for _, r := range reg.Rules() {
		for _, k := range r.Meta().FixKinds {
			for _, e := range k.PossibleSideEffects {
				if !made[pair{k.ID, e}] {
					t.Errorf("%s: the fix %s declares %s, which no fix makes", r.Meta().ID, k.ID, e)
				}
			}
		}
	}
}
