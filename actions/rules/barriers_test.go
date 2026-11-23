package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/boundary"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestBarriersOfMatchesBoundary: the barriers of each added attacker are
// those its rows of boundary let past.
func TestBarriersOfMatchesBoundary(t *testing.T) {
	for _, v := range lint.AddedAttackers() {
		got := BarriersOf([]lint.AddedAttacker{v})
		for _, b := range analysis.Barriers() {
			want := false
			for _, r := range boundary.BarrierRows() {
				if r.AddedAttacker == v && r.Barrier == b {
					want = r.Passes
				}
			}
			if got.Passes(b) != want {
				t.Errorf("%s %s: %v, want %v", v, b, got.Passes(b), want)
			}
		}
	}
}

// TestOutsiderRules: the rules that read an attacker outside the
// repository alone, in an added run too, are
// rules of All.
func TestOutsiderRules(t *testing.T) {
	ids := map[lint.RuleID]bool{}
	for _, r := range All() {
		ids[r.Meta().ID] = true
	}
	for _, id := range OutsiderRules() {
		if !ids[id] {
			t.Errorf("%s is not a rule", id)
		}
	}
	if len(OutsiderRules()) != 4 {
		t.Errorf("%d outsider rules, want 4", len(OutsiderRules()))
	}
}

// runBarriers runs every rule on the workflow src at
// .github/workflows/w.yml, with the attacker past g, and gives the
// findings of the rule id.
func runBarriers(t *testing.T, id lint.RuleID, src string, g analysis.BarrierPasses) []lint.Finding {
	t.Helper()
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	reg = reg.WithBarriers(BarriersOf, OutsiderRules()...)
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	var out []lint.Finding
	for _, f := range lint.RunWithBarriers(context.Background(), in, reg, noFacts{}, g).Findings {
		if f.Rule == id {
			out = append(out, f)
		}
	}
	return out
}

const (
	labelApprovedCheckout = "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  test:\n    if: contains(github.event.pull_request.labels.*.name, 'safe to test')\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n      - run: make test\n"
	environmentCheckout   = "on: pull_request_target\njobs:\n  test:\n    environment: external\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n      - run: make test\n"
)

// TestLabelApprovalBarrier: an attacker who gets past the label approval
// gets the finding of the labeled job; the outsider does not.
func TestLabelApprovalBarrier(t *testing.T) {
	if fs := runBarriers(t, UntrustedCheckoutID, labelApprovedCheckout, analysis.BarrierPasses{}); len(fs) != 0 {
		t.Errorf("the outsider: %d findings", len(fs))
	}
	triage := BarriersOf([]lint.AddedAttacker{lint.AddedAttackerTriageAccount})
	if fs := runBarriers(t, UntrustedCheckoutID, labelApprovedCheckout, triage); len(fs) == 0 {
		t.Error("triage-account: no finding")
	}
}

// TestEnvironmentApprovalBarrier: a required reviewer gets the finding of
// the job of an environment without the condition that the environment is
// not protected; the outsider gets it on that condition.
func TestEnvironmentApprovalBarrier(t *testing.T) {
	reviewer := BarriersOf([]lint.AddedAttacker{lint.AddedAttackerRequiredReviewer})
	for _, id := range []lint.RuleID{UntrustedCheckoutID} {
		out := runBarriers(t, id, environmentCheckout, analysis.BarrierPasses{})
		if len(out) == 0 || !protectedCond(t, out[0]) {
			t.Errorf("%s, the outsider: %d findings, want one on the condition repo.environment-protected", id, len(out))
		}
		in := runBarriers(t, id, environmentCheckout, reviewer)
		if len(in) == 0 || protectedCond(t, in[0]) {
			t.Errorf("%s, required-reviewer: %d findings, want one without the condition repo.environment-protected", id, len(in))
		}
	}
}

// protectedCond is whether the condition of f asks repo.environment-protected.
func protectedCond(t *testing.T, f lint.Finding) bool {
	t.Helper()
	b, err := json.Marshal(f.Condition)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(b), "repo.environment-protected")
}

// noFacts answers no fact.
type noFacts struct{}

func (noFacts) Resolve(context.Context, facts.Query) facts.RawAnswer { return facts.RawAnswer{} }

// claudeComment is a job of claude-code-action on comments, its gate left
// as it is, that gives the agent the comment.
const claudeComment = "on:\n  issue_comment:\n    types: [created]\njobs:\n  agent:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: ${{ github.event.comment.body }}\n          claude_args: --allowedTools Bash\n"

// TestAgentGateBarrier: an attacker who gets past the gate of
// claude-code-action reaches the agent through the closed gate; the
// outsider and a triage account do not.
func TestAgentGateBarrier(t *testing.T) {
	issues := BarriersOf([]lint.AddedAttacker{lint.AddedAttackerWriterIssuesToken})
	triage := BarriersOf([]lint.AddedAttacker{lint.AddedAttackerTriageAccount})
	for _, id := range []lint.RuleID{AIActionPromptInjectionID} {
		if fs := runBarriers(t, id, claudeComment, analysis.BarrierPasses{}); len(fs) != 0 {
			t.Errorf("%s, the outsider: %d findings", id, len(fs))
		}
		if fs := runBarriers(t, id, claudeComment, triage); len(fs) != 0 {
			t.Errorf("%s, triage-account: %d findings", id, len(fs))
		}
		if fs := runBarriers(t, id, claudeComment, issues); len(fs) == 0 {
			t.Errorf("%s, writer-issues-token: no finding", id)
		}
	}
}

// commentOn is a job on issue_comment, run only on a comment on a pull
// request (pull) or only on a comment on an issue, that gives
// claude-code-action, its gate left as it is, the body of the comment.
func commentOn(pull bool) string {
	cond := "${{ !github.event.issue.pull_request }}"
	if pull {
		cond = "github.event.issue.pull_request"
	}
	return "on:\n  issue_comment:\n    types: [created]\njobs:\n  agent:\n    if: " + cond + "\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: ${{ github.event.comment.body }}\n"
}

// TestCommentTokens: a token whose only write access is the Issues
// permission comments on issues only, and one of the Pull requests
// permission on pull requests only (as observed on GitHub): a run that
// adds one reaches the agent only through a job on a comment of what the
// token comments on.
func TestCommentTokens(t *testing.T) {
	issues := BarriersOf([]lint.AddedAttacker{lint.AddedAttackerWriterIssuesToken})
	pulls := BarriersOf([]lint.AddedAttacker{lint.AddedAttackerWriterPullRequestsToken})
	for _, c := range []struct {
		name string
		pull bool
		g    analysis.BarrierPasses
		want bool
	}{
		{"writer-issues-token, a comment on an issue", false, issues, true},
		{"writer-issues-token, a comment on a pull request", true, issues, false},
		{"writer-pull-requests-token, a comment on a pull request", true, pulls, true},
		{"writer-pull-requests-token, a comment on an issue", false, pulls, false},
	} {
		if got := len(runBarriers(t, AIActionPromptInjectionID, commentOn(c.pull), c.g)) != 0; got != c.want {
			t.Errorf("%s: a finding %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAddedFixCheck: the check of a fix runs the rule again with the
// barriers of the run, so a fix of a finding that only an added attacker
// gives (a reference of secrets moved to env) is checked as the run reads it,
// and makes no error of the run.
func TestAddedFixCheck(t *testing.T) {
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	src := "on:\n  issues:\n    types: [opened]\n  workflow_dispatch:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          TITLE=\"${{ github.event.issue.title }}\"\n          curl -X POST \"${{ secrets.HOOK }}\" -d \"$TITLE\"\n"
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.RunAdded(context.Background(), in, reg, noFacts{}, []lint.AddedAttacker{lint.AddedAttackerSecretsWriter})
	if len(rep.Errors) != 0 {
		t.Errorf("errors %+v", rep.Errors)
	}
	marked := 0
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Rule == CodeInjectionID && f.AddedAttackers != nil {
			marked++
		}
	}
	if marked == 0 {
		t.Error("no marked finding of code-injection")
	}
}
