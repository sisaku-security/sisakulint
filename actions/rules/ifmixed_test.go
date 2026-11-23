package rules

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// An if with text outside its ${{ }} is a string, which is true: written
// as a gate, it lets the attacker's run through, and the rules report what
// the job then does. The same gate as one expression keeps it out. The
// case is the owner's decision.
func TestIfMixedGate(t *testing.T) {
	src := func(cond string) string {
		return "on: [issue_comment, workflow_dispatch]\npermissions:\n  issues: write\njobs:\n  j:\n    runs-on: ubuntu-latest\n    if: " + cond + "\n    steps:\n      - run: echo \"${{ github.event.comment.body }}\"\n"
	}
	kinds := func(cond string) []string {
		rep, _, _ := checkRules(t, All(), map[string]string{".github/workflows/w.yml": src(cond)}, nil)
		var ks []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Certainty == lint.CertaintyConfirmed {
				ks = append(ks, f.Args.KindID().String())
			}
		}
		slices.Sort(ks)
		return ks
	}
	if got := kinds("${{ github.event_name }} == 'workflow_dispatch'"); !slices.Equal(got, []string{"code-injection.controlled", "dangerous-triggers.token-write"}) {
		t.Errorf("mixed: %v", got)
	}
	if got := kinds("${{ github.event_name == 'workflow_dispatch' }}"); len(got) != 0 {
		t.Errorf("one expression: %v", got)
	}
}
