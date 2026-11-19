package rules

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// missingCond is the condition that the commit sha of actions/upload-artifact
// lacks the commit lacked, and its key.
func missingCond(t *testing.T, sha, lacked string) (*lint.Condition, string) {
	t.Helper()
	repo, err := facts.ParseRepo("actions/upload-artifact")
	if err != nil {
		t.Fatal(err)
	}
	s, err := facts.ParseSHA(strings.Repeat(sha, 40))
	if err != nil {
		t.Fatal(err)
	}
	l, err := facts.ParseSHA(strings.Repeat(lacked, 40))
	if err != nil {
		t.Fatal(err)
	}
	c := unlessCond([]ir.MissingCommit{{Repo: repo, SHA: s, Commit: l}})
	return c, condKey(c)
}

// TestAnyCondNil: a condition that always holds (nil) makes the
// disjunction always hold, whether it comes first or last.
func TestAnyCondNil(t *testing.T) {
	c1, k1 := missingCond(t, "a", "b")
	c2, k2 := missingCond(t, "c", "d")
	for _, order := range [][]int{{1, 0, 2}, {0, 1, 2}, {1, 2, 0}} {
		var a anyCond
		for _, i := range order {
			switch i {
			case 0:
				a.add(nil, "")
			case 1:
				a.add(c1, k1)
			case 2:
				a.add(c2, k2)
			}
		}
		if c, some := a.cond(); c != nil || !some {
			t.Errorf("%v: %v %v", order, c, some)
		}
	}
}

// TestAnyCondDedup: the same condition added three times is one leaf.
func TestAnyCondDedup(t *testing.T) {
	c1, k1 := missingCond(t, "a", "b")
	var a anyCond
	for range 3 {
		a.add(c1, k1)
	}
	c, some := a.cond()
	if !some || c == nil || condKey(c) != k1 {
		t.Errorf("%v %v, want %s", c, some, k1)
	}
}

// TestAnyCondTwo: two conditions are their disjunction.
func TestAnyCondTwo(t *testing.T) {
	c1, k1 := missingCond(t, "a", "b")
	c2, k2 := missingCond(t, "c", "d")
	var a anyCond
	a.add(c1, k1)
	a.add(c2, k2)
	c, some := a.cond()
	if want := condKey(new(lint.Any(*c1, *c2))); !some || c == nil || condKey(c) != want {
		t.Errorf("%v, want %s", c, want)
	}
}

// TestAnyCondEmpty: nothing added is no disjunction (some false), not the
// disjunction of none, which never holds.
func TestAnyCondEmpty(t *testing.T) {
	var a anyCond
	if c, some := a.cond(); c != nil || some {
		t.Errorf("%v %v", c, some)
	}
}
