package facts

import (
	"context"
	"strings"
	"testing"
)

func TestAssumptions(t *testing.T) {
	ctx := context.Background()
	r := RepoWikiOpen{}.Ask(ctx, Assumptions())
	if r.State != StateFound || !r.Value {
		t.Errorf("repo.wiki-open = %+v, want the worst case: true", r)
	}
	raw := Checked(RepoWikiOpen{}, Assumptions().Resolve(ctx, RepoWikiOpen{}))
	if !raw.Assumed() {
		t.Errorf("not marked as assumed: %+v", raw)
	}
	if a := Assumptions().Resolve(ctx, TestFlag{Name: "a"}); a.State != StateUnknown || a.Reason == "" || a.Assumed() {
		t.Errorf("a kind without x-assume: %+v, want Unknown with a reason", a)
	}
	var info KindInfo
	for _, k := range Kinds() {
		if k.Kind == KindRepoWikiOpen {
			info = k
		}
	}
	if string(info.AssumedValue) != "true" || info.AssumedReason == "" || info.Provider != ProviderRepoSetting || !info.Permission.IsZero() {
		t.Errorf("KindInfo of repo.wiki-open = %+v", info)
	}
	if b, err := EncodeQuery(RepoWikiOpen{}); err != nil || string(b) != `{"kind":"repo.wiki-open"}` {
		t.Errorf("EncodeQuery = %s, %v", b, err)
	}
}

// Assume keeps the reason of what does not know when nothing is assumed:
// a report says why a fact is not known, not that nothing assumes it.
func TestAssume(t *testing.T) {
	ctx := context.Background()
	offline := resolverFunc(func(context.Context, Query) RawAnswer { return RawAnswer{State: StateUnknown, Reason: "offline"} })
	if r := Assume(offline).Resolve(ctx, TestFlag{Name: "a"}); r.State != StateUnknown || r.Reason != "offline" {
		t.Errorf("not assumed: %+v, want the reason of the resolver below", r)
	}
	if r := Assume(offline).Resolve(ctx, RepoWikiOpen{}); r.State != StateFound || !r.Assumed() {
		t.Errorf("assumed: %+v", r)
	}
	closed := resolverFunc(func(context.Context, Query) RawAnswer { return RawAnswer{State: StateFound, Value: []byte("false")} })
	if r := Assume(closed).Resolve(ctx, RepoWikiOpen{}); string(r.Value) != "false" || r.Assumed() {
		t.Errorf("what was found out wins: %+v", r)
	}
}

// The two kinds of untrusted-checkout are assumed their worst case: the
// checkout's tree runs (checkout.executed true), and the environment
// approves nothing (repo.environment-protected false). git.commit-contains
// comes from the API, so it is asked, not assumed.
func TestAssumptionsCheckout(t *testing.T) {
	ctx := context.Background()
	file, _ := ParseInputPath(".github/workflows/ci.yml")
	step, _ := WorkflowStep("build", 1)
	env, _ := ParseEnvironmentName("prod")
	if a := (CheckoutExecuted{InputPath: file, Step: step}).Ask(ctx, Assumptions()); a.State != StateFound || !a.Value {
		t.Errorf("checkout.executed = %+v, want the worst case: true", a)
	}
	if a := (RepoEnvironmentProtected{Environment: env}).Ask(ctx, Assumptions()); a.State != StateFound || a.Value {
		t.Errorf("repo.environment-protected = %+v, want the worst case: false", a)
	}
	sha, _ := ParseSHA(strings.Repeat("a", 40))
	if r := Assumptions().Resolve(ctx, GitCommitContains{Repo: mustRepo(t, "actions/checkout"), SHA: sha, Commit: sha}); r.State != StateUnknown {
		t.Errorf("git.commit-contains is assumed: %+v", r)
	}
	for _, k := range Kinds() {
		switch k.Kind {
		case KindCheckoutExecuted:
			if k.Provider != ProviderUserSupplied || !k.Permission.IsZero() {
				t.Errorf("KindInfo of checkout.executed = %+v", k)
			}
		case KindGitCommitContains:
			if k.Provider != ProviderGitHub || k.Permission.IsZero() {
				t.Errorf("KindInfo of git.commit-contains = %+v", k)
			}
		}
	}
	b, err := EncodeQuery(CheckoutExecuted{InputPath: file, Step: step})
	if err != nil || string(b) != `{"kind":"checkout.executed","input_path":".github/workflows/ci.yml","step":"jobs.build.steps[1]"}` {
		t.Errorf("EncodeQuery = %s, %v", b, err)
	}
	if q, err := DecodeQuery([]byte(`{"kind":"checkout.executed","input_path":"a.yml","step":"steps[0]"}`)); err == nil {
		t.Errorf("DecodeQuery of a step that is no StepPath = %#v", q)
	}
}

// repo.default-token-write is assumed true, the worst case: a job that
// writes no permissions gets a token that may write.
func TestAssumeDefaultTokenWrite(t *testing.T) {
	offline := resolverFunc(func(context.Context, Query) RawAnswer { return RawAnswer{State: StateUnknown, Reason: "offline"} })
	r := Assume(offline).Resolve(context.Background(), RepoDefaultTokenWrite{})
	if r.State != StateFound || string(r.Value) != "true" || !r.Assumed() {
		t.Errorf("%+v", r)
	}
}

// repo.public is assumed true, the worst case: a self-hosted runner of a
// repository whose visibility is not known is read as one anyone reaches.
func TestAssumePublic(t *testing.T) {
	offline := resolverFunc(func(context.Context, Query) RawAnswer { return RawAnswer{State: StateUnknown, Reason: "offline"} })
	r := Assume(offline).Resolve(context.Background(), RepoPublic{})
	if r.State != StateFound || string(r.Value) != "true" || !r.Assumed() {
		t.Errorf("%+v", r)
	}
}

// repo.pull-request-target-allowed is assumed true, the worst case: the
// Actions policies let a run of the workflow start on pull_request_target.
// The fact names the workflow file, and
// one without repo never matches one with repo.
func TestAssumePullRequestTargetAllowed(t *testing.T) {
	offline := resolverFunc(func(context.Context, Query) RawAnswer { return RawAnswer{State: StateUnknown, Reason: "offline"} })
	path, err := ParseInputPath(".github/workflows/a.yml")
	if err != nil {
		t.Fatal(err)
	}
	q := RepoPullRequestTargetAllowed{InputPath: path}
	r := Assume(offline).Resolve(context.Background(), q)
	if r.State != StateFound || string(r.Value) != "true" || !r.Assumed() {
		t.Errorf("%+v", r)
	}
	b, err := EncodeQuery(q)
	if err != nil || string(b) != `{"kind":"repo.pull-request-target-allowed","input_path":".github/workflows/a.yml"}` {
		t.Errorf("EncodeQuery = %s, %v", b, err)
	}
	if _, err := DecodeQuery([]byte(`{"kind":"repo.pull-request-target-allowed"}`)); err == nil {
		t.Error("a fact without input_path: no error")
	}
	repo, err := ParseRepo("o/r")
	if err != nil {
		t.Fatal(err)
	}
	named := RepoPullRequestTargetAllowed{Repo: repo, InputPath: path}
	if b, _ := EncodeQuery(named); string(b) == `{"kind":"repo.pull-request-target-allowed","input_path":".github/workflows/a.yml"}` {
		t.Error("a fact with repo is written as one without")
	}
}

// repo.fork-pr-app-checks and repo.merge-commit-app-checks are assumed
// true, the worst case: an app outside GitHub Actions makes a commit status
// or a check run for a commit of a pull request from a fork, and for a
// commit that the merge of a pull request puts in a branch, so that the
// runs of status, check_suite and check_run have that commit. The GitHub
// API source does not ask them.
func TestAssumeAppChecks(t *testing.T) {
	offline := resolverFunc(func(context.Context, Query) RawAnswer { return RawAnswer{State: StateUnknown, Reason: "offline"} })
	for _, c := range []struct {
		q    Query
		json string
	}{
		{RepoForkPRAppChecks{}, `{"kind":"repo.fork-pr-app-checks"}`},
		{RepoMergeCommitAppChecks{}, `{"kind":"repo.merge-commit-app-checks"}`},
	} {
		r := Assume(offline).Resolve(context.Background(), c.q)
		if r.State != StateFound || string(r.Value) != "true" || !r.Assumed() {
			t.Errorf("%s: %+v", c.json, r)
		}
		if b, err := EncodeQuery(c.q); err != nil || string(b) != c.json {
			t.Errorf("EncodeQuery = %s, %v; want %s", b, err, c.json)
		}
		if got := OnlineAnswerOf(c.q.Kind()); got != OnlineNone {
			t.Errorf("OnlineAnswerOf(%s) = %v, want OnlineNone", c.q.Kind(), got)
		}
	}
}
