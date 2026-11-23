package attacker

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// pathOf is the reference s.
func pathOf(t *testing.T, s string) []expr.PathElem {
	t.Helper()
	n, errs := expr.Parse(s)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	p, ok := expr.AccessPath(n)
	if !ok {
		t.Fatalf("%s is not a reference", s)
	}
	return p
}

func TestNarrows(t *testing.T) {
	comment := ev(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	body := pathOf(t, "github.event.comment.body")
	for _, c := range []struct {
		cond    string
		narrows bool
	}{
		{"github.event.comment.body == 'deploy'", true},
		{"github.event.comment.body == 'DEPLOY'", true},
		{"${{ '/deploy' == github.event.comment.body }}", true},
		{"github.event.comment.body == 'deploy' && github.event.issue.pull_request", true},
		{"always() && github.event.comment.body == 'deploy'", true},
		{"failure() || github.event.comment.body == 'deploy'", false},
		{"github.event.comment.body == 'a' || github.event.comment.body == 'b'", true},
		{"github.event.comment.body == 'a' || github.event.issue.title == 'b'", false},
		{"github.event_name == 'push' || github.event.comment.body == 'a'", true},
		{"github.event.comment.body != 'deploy'", false},
		{"${{ !(github.event.comment.body != 'deploy') }}", true},
		{`contains(fromJSON('["deploy","test"]'), github.event.comment.body)`, true},
		{`contains(fromJSON('["deploy",1]'), github.event.comment.body)`, false},
		{"contains(github.event.comment.body, 'deploy')", false},
		{"startsWith(github.event.comment.body, 'deploy')", false},
		{"github.event.comment.body == 1", false},
		{"github.event.comment.body == '$(id)'", false},
		{"github.event.comment.body == '-rf'", false},
		{"github.event.comment.body == 'a -rf'", false},
		{"github.event.comment.body == 'deploy prod/v1.2_x'", true},
		{"github.event.comment.body == ''", true},
		{"github.event.comment.body == 'deploy' || github.event.comment.body == '$(x)'", false},
		{"github.event.issue.title == 'deploy'", false},
		{"github.event['comment'].BODY == 'deploy'", true},
		{"${{ github.event.comment.body == 'deploy' }}", true},
		{"text ${{ github.event.comment.body == 'deploy' }}", false},
		{"github.actor == github.event.comment.body", false},
		{"format('{0}', github.event.comment.body == 'a')", false},
		{"github.event.comment.body == 'a' || github.event.comment.body == 1", false},
		{"github.event.comment.body == 'a' && startsWith(github.event.comment.body, 'b')", true},
		{"success() && github.event.comment.body == 'a'", true},
		{"cancelled() || github.event.comment.body == 'a'", false},
		{`contains(fromJSON('["a",null]'), github.event.comment.body)`, false},
	} {
		t.Run(c.cond, func(t *testing.T) {
			if got := Outsider.NarrowingOf(StepIf(nil, nil, ifOf(t, "issue_comment", c.cond))).Narrows(comment, body); got != c.narrows {
				t.Errorf("Narrows = %v, want %v", got, c.narrows)
			}
		})
	}
}

func TestNarrowsPaths(t *testing.T) {
	comment := ev(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	n := Outsider.NarrowingOf(StepIf(nil, nil, ifOf(t, "issue_comment", "github.event.comment.body == 'a'")))
	for _, c := range []struct {
		path    string
		narrows bool
	}{
		{"github.event.comment.body", true},
		{"github.event.comment.body.x", true}, // a property of a string
		{"github.event.comment", false},       // more than the value compared
		{"github.event.comment.user.login", false},
	} {
		if got := n.Narrows(comment, pathOf(t, c.path)); got != c.narrows {
			t.Errorf("%s: Narrows = %v, want %v", c.path, got, c.narrows)
		}
	}
	star := Outsider.NarrowingOf(StepIf(nil, nil, ifOf(t, "push", "github.event.commits.*.message == 'a'")))
	if star.Narrows(ev(workflow.EventNamePush, workflow.ActivityTypeUnset), pathOf(t, "github.event.commits.*.message")) {
		t.Error("a reference through a star is narrowed")
	}
	env := Outsider.NarrowingOf(StepIf(nil, nil, ifOf(t, "push", "env.X == 'a'")))
	if !env.NarrowsAnyEvent(pathOf(t, "env.X")) {
		t.Error("env.X is not narrowed")
	}
	if env.NarrowsAnyEvent(pathOf(t, "env.x")) {
		t.Error("env.x, another name, is narrowed")
	}
}

func TestNarrowsAnyEvent(t *testing.T) {
	x := pathOf(t, "inputs.x")
	for _, c := range []struct {
		cond    string
		narrows bool
	}{
		{"inputs.x == 'a'", true},
		{"github.event_name == 'push' || inputs.x == 'a'", false},
		{"github.event_name == 'workflow_dispatch' && inputs.x == 'a'", true},
		{"inputs.x != 'a'", false},
	} {
		if got := Outsider.NarrowingOf(StepIf(nil, nil, ifOf(t, "workflow_dispatch", c.cond))).NarrowsAnyEvent(x); got != c.narrows {
			t.Errorf("%s: NarrowsAnyEvent = %v, want %v", c.cond, got, c.narrows)
		}
	}
}

func TestKeptValue(t *testing.T) {
	comment := ev(workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	body := pathOf(t, "github.event.comment.body")
	c := ifOf(t, "issue_comment", "github.event.comment.body == 'deploy'")
	for _, v := range []struct {
		value string
		kept  bool
	}{
		{"deploy", true},
		{"Deploy", true},
		{`"; echo PWNED`, false},
	} {
		if got := Outsider.KeptValue(StepIf(nil, nil, c), comment, body, v.value); got != v.kept {
			t.Errorf("%q: KeptValue = %v, want %v", v.value, got, v.kept)
		}
	}
	owner := ifOf(t, "issue_comment", "github.event.comment.author_association == 'OWNER'")
	if got, want := Outsider.KeptValue(StepIf(nil, nil, owner), comment, body, `"; echo PWNED`), Outsider.Kept(StepIf(nil, nil, owner), comment); got != want {
		t.Errorf("KeptValue of another reference = %v, want Kept's %v", got, want)
	}
}
