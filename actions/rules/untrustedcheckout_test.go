package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// checkoutFacts answers the facts of the rules of untrusted checkouts: the
// environment's protection, a pinned commit's guard, whether a checkout's
// tree runs. A field left nil is not known.
type checkoutFacts struct {
	protected *bool
	guarded   *bool
	executed  *bool
}

func (c checkoutFacts) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	var v *bool
	switch q.(type) {

	case facts.RepoEnvironmentProtected:
		v = c.protected
	case facts.GitCommitContains:
		v = c.guarded
	case facts.CheckoutExecuted:
		v = c.executed
	}
	if v == nil {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not in the table"}
	}
	b, _ := json.Marshal(*v)
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

func ptr(b bool) *bool { return &b }

func condJSON(t *testing.T, f lint.Finding) string {
	t.Helper()
	c := ruleCondition(f.Condition)
	if c == nil {
		return ""
	}
	b, err := c.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ruleCondition is c without the leaf repo.pull-request-target-allowed that
// the engine adds last to the condition of a finding on pull_request_target
// alone (TestPullRequestTargetCondition of package lint): the condition the
// rule gave.
func ruleCondition(c *lint.Condition) *lint.Condition {
	added := func(x lint.Condition) bool {
		qs := x.Queries()
		return x.Op() == lint.ConditionOpLeaf && len(qs) == 1 && qs[0].Kind() == facts.KindRepoPullRequestTargetAllowed
	}
	switch {
	case c == nil, added(*c):
		return nil
	case c.Op() == lint.ConditionOpAll:
		if ps := c.Parts(); len(ps) == 2 && added(ps[1]) {
			return &ps[0]
		}
	}
	return c
}

// checkoutJob is a job on on, with jobExtra, whose first step checks out
// with uses and with, and whose second step is after.
func checkoutJob(on, jobExtra, uses, with, after string) string {
	return "on: " + on + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + jobExtra + "    steps:\n      - uses: " + uses + "\n        with: " + with + "\n" + after
}

const (
	headSHAWith = "{ref: '${{ github.event.pull_request.head.sha }}', allow-unsafe-pr-checkout: true}"
	pinned      = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
	executedQ   = `{"query":{"kind":"checkout.executed","input_path":".github/workflows/w.yml","step":"jobs.a.steps[0]"},"eq":true}`
	unprotectQ  = `{"query":{"kind":"repo.environment-protected","environment":"prod"},"eq":false}`
)

func TestUntrustedCheckout(t *testing.T) {
	var guardConds []string
	for _, c := range []string{"9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "d23441a48e516b6c34aea4fa41551a30e30af803", "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", "11d5960a326750d5838078e36cf38b85af677262", "a37ce9120846195fa4ece8f58b268e6043cb2f26", "0717577d45739eb3c851188b29f50ed6c0b2194e"} {
		guardConds = append(guardConds, fmt.Sprintf(`{"query":{"kind":"git.commit-contains","repo":"actions/checkout","sha":"11bd71901bbe5b1630ceea73d27597364c9af683","commit":%q},"eq":false}`, c))
	}
	guardAll := `{"all":[` + join(guardConds) + `]}`
	for _, c := range []struct {
		name, on, jobExtra, uses, with, after string
		kind                                  string // "" for none
		events                                []string
		cond                                  string
	}{
		{"executed", "pull_request_target", "", "actions/checkout@v4", headSHAWith, "      - run: npm ci\n", "untrusted-checkout.executed", []string{"pull_request_target"}, ""},
		{"not seen to run", "pull_request_target", "", "actions/checkout@v4", headSHAWith, "      - run: echo done\n", "untrusted-checkout.checkout", []string{"pull_request_target"}, executedQ},
		{"pull_request", "pull_request", "", "actions/checkout@v4", headSHAWith, "      - run: npm ci\n", "", nil, ""},
		{"label", "{pull_request_target: {types: [labeled]}}", "", "actions/checkout@v4", headSHAWith, "      - run: npm ci\n", "", nil, ""},
		{"environment", "pull_request_target", "    environment: prod\n", "actions/checkout@v4", headSHAWith, "      - run: npm ci\n", "untrusted-checkout.executed", []string{"pull_request_target"}, unprotectQ},
		{"environment, not seen", "pull_request_target", "    environment: prod\n", "actions/checkout@v4", headSHAWith, "      - run: echo\n", "untrusted-checkout.checkout", []string{"pull_request_target"}, `{"all":[` + unprotectQ + "," + executedQ + `]}`},
		{"workflow_run", "{workflow_run: {workflows: [ci], types: [completed]}}", "", "actions/checkout@v4", "{ref: '${{ github.event.workflow_run.head_sha }}', allow-unsafe-pr-checkout: true}", "      - run: make\n", "untrusted-checkout.executed", []string{"workflow_run"}, ""},
		{"issue_comment", "{issue_comment: {types: [created]}}", "", "actions/checkout@v4", "{ref: 'refs/pull/${{ github.event.issue.number }}/head'}", "      - run: make\n", "untrusted-checkout.executed", []string{"issue_comment"}, ""},
		// the rule does not read permissions: code still runs in the job
		{"no permissions", "pull_request_target", "    permissions: {}\n", "actions/checkout@v4", headSHAWith, "      - run: ./run_tests.sh\n", "untrusted-checkout.executed", []string{"pull_request_target"}, ""},
		// the guard of actions/checkout
		{"guarded tag", "pull_request_target", "", "actions/checkout@v4", "{ref: '${{ github.event.pull_request.head.sha }}'}", "      - run: npm ci\n", "", nil, ""},
		{"old tag", "pull_request_target", "", "actions/checkout@v4.2.2", "{ref: '${{ github.event.pull_request.head.sha }}'}", "      - run: npm ci\n", "untrusted-checkout.executed", []string{"pull_request_target"}, ""},
		{"guarded tag on issue_comment too", "[pull_request_target, issue_comment]", "", "actions/checkout@v4", "{ref: 'refs/pull/${{ github.event.pull_request.number || github.event.issue.number }}/head'}", "      - run: npm ci\n", "untrusted-checkout.executed", []string{"issue_comment"}, ""},
		// the head's SHA has no value on issue_comment
		{"head sha on issue_comment", "[pull_request_target, issue_comment]", "", "actions/checkout@v4", "{ref: '${{ github.event.pull_request.head.sha }}'}", "      - run: npm ci\n", "", nil, ""},
		{"pinned", "pull_request_target", "", pinned, "{ref: '${{ github.event.pull_request.head.sha }}'}", "      - run: npm ci\n", "untrusted-checkout.executed", []string{"pull_request_target"}, guardAll},
		{"pinned on issue_comment too", "[pull_request_target, issue_comment]", "", pinned, "{ref: 'refs/pull/${{ github.event.pull_request.number || github.event.issue.number }}/head'}", "      - run: npm ci\n", "untrusted-checkout.executed", []string{"issue_comment"}, ""},
		// the guard's pattern does not match capitals
		{"capitals", "pull_request_target", "", "actions/checkout@v4", "{ref: 'Refs/Pull/${{ github.event.pull_request.number }}/head'}", "      - run: npm ci\n", "untrusted-checkout.executed", []string{"pull_request_target"}, ""},
		{"branch name alone", "pull_request_target", "", "actions/checkout@v4.2.2", "{ref: '${{ github.head_ref }}'}", "      - run: npm ci\n", "", nil, ""},
		{"fork and branch name", "pull_request_target", "", "actions/checkout@v4.2.2", "{repository: '${{ github.event.pull_request.head.repo.full_name }}', ref: '${{ github.head_ref }}'}", "      - run: npm ci\n", "untrusted-checkout.executed", []string{"pull_request_target"}, ""},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, wfFile(checkoutJob(c.on, c.jobExtra, c.uses, c.with, c.after)), checkoutFacts{})
		if c.kind == "" {
			if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
				t.Errorf("%s: %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			}
			continue
		}
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Errorf("%s: %d findings %+v", c.name, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			continue
		}
		f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
		var evs []string
		switch a := f.Args.(type) {
		case UntrustedCheckoutExecuted:
			evs = eventStrings(a.PRCodeOn)
		case UntrustedCheckoutCheckout:
			evs = eventStrings(a.PRCodeOn)
		}
		if f.Args.KindID().String() != c.kind || !slices.Equal(evs, c.events) || condJSON(t, f) != c.cond {
			t.Errorf("%s: %s %v %s; want %s %v %s", c.name, f.Args.KindID(), evs, condJSON(t, f), c.kind, c.events, c.cond)
		}
	}
}

// TestUntrustedCheckoutAssumed:
// by default the assumption makes the finding hold; with the fact false it
// is not there.
func TestUntrustedCheckoutAssumed(t *testing.T) {
	src := checkoutJob("pull_request_target", "", "actions/checkout@v4", headSHAWith, "      - run: echo done\n")
	rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, wfFile(src), facts.Assume(checkoutFacts{}))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Certainty != lint.CertaintyConfirmed {
		t.Errorf("assumed: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	rep, _, _ = checkRules(t, []lint.Rule{UntrustedCheckout}, wfFile(src), checkoutFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Certainty != lint.CertaintyConditional {
		t.Errorf("not known: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	rep, _, _ = checkRules(t, []lint.Rule{UntrustedCheckout}, wfFile(src), checkoutFacts{executed: ptr(false)})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("read as data: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

func eventStrings(evs []workflow.EventName) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.String())
	}
	return out
}

func join(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}

// A commit pinned by its SHA that is the commit of a release with the guard
// has the guard with no fact asked: commit-sha's fix pins a tag so
// (found in the corpus: pytorch's _binary-test-macos.yml).
func TestUntrustedCheckoutPinnedRelease(t *testing.T) {
	for _, c := range []struct {
		sha  string
		want int
	}{
		{"3d3c42e5aac5ba805825da76410c181273ba90b1", 0}, // v7, v7.0.1
		{"fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", 0}, // v5, v5.1.0
		{"11bd71901bbe5b1630ceea73d27597364c9af683", 1}, // v4.2.2: the fact is asked
	} {
		src := checkoutJob("pull_request_target", "", "actions/checkout@"+c.sha, "{ref: '${{ github.event.pull_request.head.sha }}'}", "      - run: npm ci\n")
		rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, wfFile(src), checkoutFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != c.want {
			t.Errorf("%s: %d findings, want %d", c.sha, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), c.want)
		}
	}
}
