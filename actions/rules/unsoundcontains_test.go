package rules

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestUnsoundContains: the findings and the fixes of unsound-contains on
// the forms of a condition.
func TestUnsoundContains(t *testing.T) {
	for _, c := range []struct {
		name, cond string
		n          int
		fix        bool
	}{
		{"names", "contains('alice bob', github.actor)", 1, true},
		{"array", "contains(fromJSON('[\"alice\",\"bob\"]'), github.actor)", 0, false},
		{"head ref", "contains('main', github.head_ref)", 0, false},
		{"members", "contains('OWNER MEMBER COLLABORATOR', github.event.comment.author_association)", 0, false},
		{"starts", "startsWith('alice', github.actor)", 1, false},
	} {
		src := "on: issue_comment\njobs:\n  a:\n    if: ${{ " + c.cond + " }}\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
		rep, _, _ := checkRules(t, []lint.Rule{UnsoundContains}, wfFile(src), nil)
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != c.n {
			t.Errorf("%s: %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			continue
		}
		if c.n > 0 && (rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix != nil) != c.fix {
			t.Errorf("%s: fix %+v, no fix %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix)
		}
	}
}
