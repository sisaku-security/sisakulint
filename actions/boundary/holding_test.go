package boundary

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

func TestHoldingOf(t *testing.T) {
	for _, g := range ComparedGains() {
		if HoldingOf(g) == HoldingUnset {
			t.Errorf("%s needs no holding", g)
		}
	}
	if h := HoldingOf(lint.GainUseRegistryAccount); h != HoldingUnset {
		t.Errorf("use-registry-account is not compared, but needs %s", h)
	}
	if HoldingOf(lint.GainRunCode) != HoldingWriteTokenSecretsOrCache || HoldingOf(lint.GainSetOutputs) != HoldingWriteTokenSecretsOrCache {
		t.Error("run-code and set-outputs need a token that may write, the secrets or the cache")
	}
	if HoldingOf(lint.GainWriteCache) != HoldingWriteCache {
		t.Error("write-cache needs the cache")
	}
	if HoldingOf(lint.GainReachRunnerNetwork) != HoldingSelfHostedRunner {
		t.Error("reach-runner-network needs a self-hosted runner")
	}
}

func TestTexts(t *testing.T) {
	for _, h := range Holdings() {
		if h.Text() == "" {
			t.Errorf("%s has no text", h)
		}
	}
	for _, c := range Crossings() {
		if c.Text() == "" {
			t.Errorf("%s has no text", c)
		}
	}
	if len(holdingTexts) != len(holdingNames) || len(crossingTexts) != len(crossingNames) || len(Holdings()) != len(holdingNames)-1 || len(Crossings()) != len(crossingNames)-1 {
		t.Error("a holding or a crossing is missing from its names, texts or list")
	}
	for c, word := range map[Crossing]string{CrossingNone: "does not hold", CrossingByWorkflow: "takes it away", CrossingByBaseline: "does not take it away", CrossingUnknown: "not known"} {
		if !strings.Contains(c.Text(), word) {
			t.Errorf("the text of %s does not say %q: %s", c, word, c.Text())
		}
	}
	if HoldingUnset.Text() != "" || CrossingUnset.Text() != "" {
		t.Error("the zero values have a text")
	}
}

// TestHas: what a run and a role hold, by holding, for the cases the
// reader asked of: self-hosted-runner's run-code on a pull request from a
// fork of a public repository is none, and persist-on-runner by-baseline.
func TestHas(t *testing.T) {
	tb := testTables(t)
	public := answers(map[facts.Kind]bool{facts.KindRepoPublic: true})
	ran, has, _ := tb.runHas(RunRef{workflow.EventNamePullRequest, PRHeadFork}, public)
	want := map[Holding]expr.Truth{HoldingSecrets: expr.TruthFalse, HoldingWriteToken: expr.TruthFalse, HoldingWriteTokenOrSecrets: expr.TruthFalse, HoldingSelfHostedRunner: expr.TruthTrue,
		HoldingWriteCache: expr.TruthFalse, HoldingWriteTokenSecretsOrCache: expr.TruthFalse}
	if ran != expr.TruthTrue {
		t.Errorf("the run of pull_request from a fork: ran %v", ran)
	}
	for h, w := range want {
		if has[h] != w {
			t.Errorf("the run has %s: %v, want %v", h, has[h], w)
		}
	}
	held, _ := tb.roleHas(RoleNone, public)
	for h, w := range want {
		if held[h] != w {
			t.Errorf("one of none holds %s: %v, want %v", h, held[h], w)
		}
	}
	// the dimensions are the holdings by gain
	d, _ := tb.runDims(RunRef{workflow.EventNamePullRequest, PRHeadFork}, public)
	for _, g := range ComparedGains() {
		if d[g] != has[HoldingOf(g)] {
			t.Errorf("%s: dims %v, has %v", g, d[g], has[HoldingOf(g)])
		}
	}
	// the crossings the reader asked of
	rd, _ := tb.roleDims(RoleNone, public)
	if got := CrossingOf(d[lint.GainRunCode], rd[lint.GainRunCode]); got != CrossingNone {
		t.Errorf("run-code: %s, want none", got)
	}
	if got := CrossingOf(d[lint.GainPersistOnRunner], rd[lint.GainPersistOnRunner]); got != CrossingByBaseline {
		t.Errorf("persist-on-runner: %s, want by-baseline", got)
	}
	// no row: every holding unknown
	ran, has, b := tb.runHas(RunRef{workflow.EventNameIssues, PRHeadNone}, public)
	if ran != expr.TruthUnknown || b != BasisUnverified {
		t.Errorf("no row: ran %v, basis %s", ran, b)
	}
	for _, h := range Holdings() {
		if has[h] != expr.TruthUnknown {
			t.Errorf("no row: %s is %v", h, has[h])
		}
	}
}

func TestHoldsAndQueriesOf(t *testing.T) {
	c := lint.All(eq(t, facts.RepoPublic{}, false), eq(t, facts.RepoForkPRSecrets{}, true))
	qs := QueriesOf(c)
	if len(qs) != 2 || qs[0].Kind() == qs[1].Kind() {
		t.Fatalf("queries %v", qs)
	}
	got := ConditionTruth(c, answers(map[facts.Kind]bool{facts.KindRepoPublic: true}))
	if got != expr.TruthFalse {
		t.Errorf("public: %v, want false", got)
	}
	if QueriesOf(lint.Condition{}) != nil || ConditionTruth(lint.Condition{}, answers(nil)) != expr.TruthTrue {
		t.Error("the zero condition reads no fact and holds")
	}
}

// TestWriteCache: a run of pull_request_target may save to the cache of
// the default branch's scope when its workflow asks, and one
// of no role does in a pull_request run of their own, whose caches are of
// the merge ref: write-cache is by-workflow. It reads the rows of
// grants.go.
func TestWriteCache(t *testing.T) {
	tb := rows()
	public := answers(map[facts.Kind]bool{facts.KindRepoPublic: true})
	d, _ := tb.runDims(RunRef{workflow.EventNamePullRequestTarget, PRHeadFork}, public)
	rd, _ := tb.roleDims(RoleNone, public)
	if got := CrossingOf(d[lint.GainWriteCache], rd[lint.GainWriteCache]); got != CrossingByWorkflow {
		t.Errorf("write-cache on pull_request_target: %s, want by-workflow", got)
	}
	pr, _ := tb.runDims(RunRef{workflow.EventNamePullRequest, PRHeadFork}, public)
	if pr[lint.GainWriteCache] != expr.TruthFalse {
		t.Errorf("a pull_request run from a fork writes the cache: %v", pr[lint.GainWriteCache])
	}
}
