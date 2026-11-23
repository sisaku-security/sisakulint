package ir

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

func TestIfSites(t *testing.T) {
	src := "on: pull_request_target\njobs:\n  a:\n    if: github.actor == 'dependabot[bot]'\n    runs-on: ubuntu-latest\n    steps:\n      - if: contains('alice bob', github.actor)\n        run: echo\n"
	x := newIR(t, src)
	sites := x.allIfSites()
	if len(sites) != 2 {
		t.Fatalf("%d sites", len(sites))
	}
	if b := sites[0].dependabotBypasses; len(b) != 1 || b[0].Path != "github.actor" || b[0].Replacement != "github.event.pull_request.user.login" {
		t.Errorf("job: %+v", b)
	}
	if len(sites[1].attackerOn) == 0 {
		t.Errorf("step: no events")
	}
}

// TestIfSiteFolded: an if of ${{ '…' }}, in an
// action.yml and in a job and a step of a workflow, is read from the
// string, whose spans are not in the value: the place of the reference is
// the whole value, and the fix is none.
func TestIfSiteFolded(t *testing.T) {
	const cond = "${{ 'github.actor == ''dependabot[bot]''' }}"
	action := "name: x\ndescription: x\nruns:\n  using: composite\n  steps:\n    - if: " + cond + "\n      run: echo\n      shell: bash\n"
	for _, c := range []struct {
		name, src string
		why       NoFixReason // manual where the condition has no author to compare also without the fold
		x         func(src string) *IR
	}{
		{"action.yml", action, NoFixReasonManual, func(src string) *IR {
			tree, a := parseAction(t, src)
			return New("action.yml", tree, nil, a)
		}},
		{"job", "on: pull_request_target\njobs:\n  a:\n    if: " + cond + "\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n", NoFixReasonForm, func(src string) *IR { return newIR(t, src) }},
		{"step", "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - if: " + cond + "\n        run: echo\n", NoFixReasonForm, func(src string) *IR { return newIR(t, src) }},
	} {
		x := c.x(c.src)
		sites := x.allIfSites()
		if len(sites) != 1 || len(sites[0].dependabotBypasses) != 1 {
			t.Errorf("%s: %+v", c.name, sites)
			continue
		}
		if !wholeValue(sites[0].dependabotBypasses[0].At, c.src, cond) {
			t.Errorf("%s: the reference is not at the whole value", c.name)
		}
		if p := sites[0].authorContext(x.RuleAccess(), 0); p.Fix != nil || p.NoFix.Reason != c.why {
			t.Errorf("%s: %+v", c.name, p.NoFix)
		}
	}
}

// wholeValue is whether h is at exactly the bytes value in src: the whole
// value of a folded if.
func wholeValue(h Handle, src, value string) bool {
	_, sp, exact, spanned := h.Locate()
	return spanned && exact && sp.Start >= 0 && sp.End <= len(src) && sp.Start <= sp.End && src[sp.Start:sp.End] == value
}

// TestIfSiteFoldedSubstring: the fixes of a call of contains in an if of
// ${{ '…' }} are none, and the call is at the whole if.
func TestIfSiteFoldedSubstring(t *testing.T) {
	for _, c := range []struct {
		cond string
		fix  func(*IfSite, *RuleAccess) FixPlan
	}{
		{"${{ 'contains(github.actor, ''alice'')' }}", func(s *IfSite, q *RuleAccess) FixPlan { return s.equality(q, 0) }},
		{"${{ 'contains(''alice bob'', github.actor)' }}", func(s *IfSite, q *RuleAccess) FixPlan { return s.containsArray(q, 0) }},
	} {
		src := "on: issue_comment\njobs:\n  a:\n    if: " + c.cond + "\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
		x := newIR(t, src)
		sites := x.allIfSites()
		if len(sites) != 1 || len(sites[0].substringBypasses) != 1 {
			t.Errorf("%s: %+v", c.cond, sites)
			continue
		}
		if !wholeValue(sites[0].substringBypasses[0].At, src, c.cond) {
			t.Errorf("%s: the call is not at the whole value", c.cond)
		}
		if p := c.fix(sites[0], x.RuleAccess()); p.Fix != nil || p.NoFix.Reason != NoFixReasonForm {
			t.Errorf("%s: %+v", c.cond, p)
		}
	}
}

// TestAuthorContext: an if that compares github.actor with Dependabot's
// login, on pull_request_target alone, is fixed to compare the author of
// the pull request; when the workflow runs on other events too, the if
// is not fixed.
func TestAuthorContext(t *testing.T) {
	for _, c := range []struct {
		on, cond, want string
		fix            bool
	}{
		{"pull_request_target", "github.actor == 'dependabot[bot]'", "github.event.pull_request.user.login == 'dependabot[bot]'", true},
		{"pull_request_target", "${{ github.actor_id == 49699333 && github.actor == 'dependabot[bot]' }}", "${{ github.event.pull_request.user.id == 49699333 && github.actor == 'dependabot[bot]' }}", true},
		{"[pull_request_target, issue_comment]", "github.actor == 'dependabot[bot]'", "", false},
	} {
		src := "on: " + c.on + "\njobs:\n  a:\n    if: " + c.cond + "\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
		x := newIR(t, src)
		s := x.allIfSites()[0]
		p := s.authorContext(x.RuleAccess(), 0)
		if (p.Fix != nil) != c.fix {
			t.Errorf("%s: %+v", c.cond, p)
			continue
		}
		if c.fix && applied(t, x, p) != "    if: "+c.want {
			t.Errorf("%s: %q", c.cond, applied(t, x, p))
		}
	}
}

// TestContainsArray: contains of a string of names and github.actor is
// fixed to contains of the array of the names.
func TestContainsArray(t *testing.T) {
	for _, c := range []struct{ cond, want string }{
		{"contains('alice bob', github.actor)", `contains(fromJSON('["alice","bob"]'), github.actor)`},
		{"contains('a,b', github.actor)", `contains(fromJSON('["a","b"]'), github.actor)`},
		{`contains('it''s "q" \x', github.actor)`, `contains(fromJSON('["it''s","\"q\"","\\x"]'), github.actor)`},
	} {
		src := "on: issue_comment\njobs:\n  a:\n    if: ${{ " + c.cond + " }}\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
		x := newIR(t, src)
		p := x.allIfSites()[0].containsArray(x.RuleAccess(), 0)
		if p.Fix == nil {
			t.Fatalf("%s: %+v", c.cond, p.NoFix)
		}
		if got := applied(t, x, p); got != "    if: ${{ "+c.want+" }}" {
			t.Errorf("%s: %q", c.cond, got)
		}
	}
}

// applied is the line of the if after the fix p (download_test.go applies
// fixes the same way).
func applied(t *testing.T, x *IR, p FixPlan) string {
	t.Helper()
	res, err := edit.Apply(x.tree, p.Fix.Edits)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(res.Tree.Bytes()), "\n") {
		if strings.HasPrefix(l, "    if: ") {
			return l
		}
	}
	return ""
}

// TestContainsArrayParts: a string that may part
// its values by | or ; gets no fix.
func TestContainsArrayParts(t *testing.T) {
	x := newIR(t, "on: issue_comment\njobs:\n  a:\n    if: ${{ contains('alice|bob', github.actor) }}\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
	if p := x.allIfSites()[0].containsArray(x.RuleAccess(), 0); p.Fix != nil || p.NoFix.Reason != NoFixReasonManual {
		t.Errorf("%+v", p)
	}
}

// TestEquality: == stands in place of contains only where nothing
// around the call binds more tightly than ==.
func TestEquality(t *testing.T) {
	for _, c := range []struct {
		cond, want string
		reason     NoFixReason
	}{
		{"contains(github.actor, 'alice')", "github.actor == 'alice'", 0},
		{"(contains(github.actor, 'alice'))", "(github.actor == 'alice')", 0},
		{"contains(github.actor, 'alice') && github.event_name == 'issue_comment'", "github.actor == 'alice' && github.event_name == 'issue_comment'", 0},
		{"true == contains(github.actor, 'alice')", "", NoFixReasonForm},
		{"contains(github.actor, 'alice') != false", "", NoFixReasonForm},
		{"startsWith(github.actor, 'alice')", "", NoFixReasonManual},
		{"contains(github.actor, 'a-')", "", NoFixReasonManual},
	} {
		src := "on: issue_comment\njobs:\n  a:\n    if: ${{ " + c.cond + " }}\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
		x := newIR(t, src)
		sites := x.allIfSites()
		if len(sites) != 1 || len(sites[0].substringBypasses) != 1 {
			t.Fatalf("%s: %+v", c.cond, sites)
		}
		p := sites[0].equality(x.RuleAccess(), 0)
		switch {
		case c.want != "" && p.Fix == nil:
			t.Errorf("%s: %+v", c.cond, p.NoFix)
		case c.want != "" && applied(t, x, p) != "    if: ${{ "+c.want+" }}":
			t.Errorf("%s: %q", c.cond, applied(t, x, p))
		case c.want == "" && (p.Fix != nil || p.NoFix.Reason != c.reason):
			t.Errorf("%s: %+v, want no fix for %v", c.cond, p, c.reason)
		}
	}
}

// TestFoldedIfNoFix: the fixes of an if of ${{ '…' }} say the same about
// the form, of a workflow as of an action.yml, and what to write by hand.
func TestFoldedIfNoFix(t *testing.T) {
	prefix := foldedIf(form, "").NoFix.Note
	for _, c := range []struct {
		on, cond, want string
		why            NoFixReason
		fix            func(*IfSite, *RuleAccess) FixPlan
	}{
		{"pull_request_target", "${{ 'github.actor == ''dependabot[bot]''' }}", "compare github.event.pull_request.user.login instead of github.actor", NoFixReasonForm, func(s *IfSite, q *RuleAccess) FixPlan { return s.authorContext(q, 0) }},
		{"[pull_request_target, issue_comment]", "${{ 'github.actor == ''dependabot[bot]''' }}", "compare the author of what the event is about (github.event.pull_request.user.login on pull_request_target) instead of github.actor, on each event the if runs on", NoFixReasonManual, func(s *IfSite, q *RuleAccess) FixPlan { return s.authorContext(q, 0) }},
		{"issue_comment", "${{ 'contains(''alice bob'', github.actor)' }}", "compare whole values: write contains(fromJSON('[...]'), github.actor) instead of the function call contains(...), with each word of 'alice bob' as one element of the JSON array", NoFixReasonForm, func(s *IfSite, q *RuleAccess) FixPlan { return s.containsArray(q, 0) }},
		{"issue_comment", "${{ 'contains(github.actor, ''alice'')' }}", "write github.actor == 'alice' instead of the function call contains(...)", NoFixReasonForm, func(s *IfSite, q *RuleAccess) FixPlan { return s.equality(q, 0) }},
	} {
		x := newIR(t, "on: "+c.on+"\njobs:\n  a:\n    if: "+c.cond+"\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
		p := c.fix(x.allIfSites()[0], x.RuleAccess())
		if p.NoFix == nil || p.NoFix.Reason != c.why || p.NoFix.Note != prefix+c.want {
			t.Errorf("%s: %+v, want the note %q", c.cond, p.NoFix, prefix+c.want)
			continue
		}
		if strings.Contains(p.NoFix.Note, "action.yml") || strings.Contains(p.NoFix.Note, "runner") {
			t.Errorf("%s: the note %q names one kind of file", c.cond, p.NoFix.Note)
		}
	}
}
