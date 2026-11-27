package facts

import "testing"

// TestXAssumeValues: the kinds with an x-assume, each with its value and a
// text of when to write the other answer; a kind from the API has none.
func TestXAssumeValues(t *testing.T) {
	want := map[Kind]string{
		KindCheckoutExecuted:             "true",
		KindDownloadExecuted:             "true",
		KindRepoPublic:                   "true",
		KindRepoWikiOpen:                 "true",
		KindRepoDefaultTokenWrite:        "true",
		KindRepoForkPRSecrets:            "true",
		KindRepoEnvironmentProtected:     "false",
		KindRepoForkPRAppChecks:          "true",
		KindRepoMergeCommitAppChecks:     "true",
		KindRepoPullRequestTargetAllowed: "true",
		KindRequestDestinationTrusted:    "false",
		KindRepoRunnerLabelTrusted:       "false",
	}
	for _, k := range Kinds() {
		v, ok := want[k.Kind]
		if string(k.AssumedValue) != v || (ok && k.AssumedReason == "") || (!ok && k.AssumedReason != "") {
			t.Errorf("%s: x-assume %q (%q), want %q", k.Kind, k.AssumedValue, k.AssumedReason, v)
		}
	}
}

// TestKindInfoOfFactsWithoutAPI: the provider and the permission of kinds
// that a file of facts or --fact answers, against one from the API.
func TestKindInfoOfFactsWithoutAPI(t *testing.T) {
	for _, k := range Kinds() {
		switch k.Kind {
		case KindCheckoutExecuted:
			if k.Provider != ProviderUserSupplied || !k.Permission.IsZero() {
				t.Errorf("KindInfo of checkout.executed = %+v", k)
			}
		case KindRepoWikiOpen:
			if k.Provider != ProviderRepoSetting || !k.Permission.IsZero() {
				t.Errorf("KindInfo of repo.wiki-open = %+v", k)
			}
		case KindGitCommitContains:
			if k.Provider != ProviderGitHub || k.Permission.IsZero() {
				t.Errorf("KindInfo of git.commit-contains = %+v", k)
			}
		}
	}
	for _, k := range []Kind{KindRepoForkPRAppChecks, KindRepoMergeCommitAppChecks} {
		if got := OnlineAnswerOf(k); got != OnlineNone {
			t.Errorf("OnlineAnswerOf(%s) = %v, want OnlineNone", k, got)
		}
	}
}

// TestQueriesOfFactsWithoutAPI: how the queries of those kinds are written
// and read.
func TestQueriesOfFactsWithoutAPI(t *testing.T) {
	file, _ := ParseInputPath(".github/workflows/ci.yml")
	step, _ := WorkflowStep("build", 1)
	path, _ := ParseInputPath(".github/workflows/a.yml")
	repo, _ := ParseRepo("o/r")
	for _, c := range []struct {
		q    Query
		json string
	}{
		{RepoWikiOpen{}, `{"kind":"repo.wiki-open"}`},
		{CheckoutExecuted{InputPath: file, Step: step}, `{"kind":"checkout.executed","input_path":".github/workflows/ci.yml","step":"jobs.build.steps[1]"}`},
		{RepoPullRequestTargetAllowed{InputPath: path}, `{"kind":"repo.pull-request-target-allowed","input_path":".github/workflows/a.yml"}`},
		{RepoForkPRAppChecks{}, `{"kind":"repo.fork-pr-app-checks"}`},
		{RepoMergeCommitAppChecks{}, `{"kind":"repo.merge-commit-app-checks"}`},
	} {
		if b, err := EncodeQuery(c.q); err != nil || string(b) != c.json {
			t.Errorf("EncodeQuery = %s, %v; want %s", b, err, c.json)
		}
	}
	for _, bad := range []string{
		`{"kind":"checkout.executed","input_path":"a.yml","step":"steps[0]"}`, // a step that is no StepPath
		`{"kind":"repo.pull-request-target-allowed"}`,                         // no input_path
	} {
		if q, err := DecodeQuery([]byte(bad)); err == nil {
			t.Errorf("DecodeQuery(%s) = %#v", bad, q)
		}
	}
	named, _ := EncodeQuery(RepoPullRequestTargetAllowed{Repo: repo, InputPath: path})
	if string(named) == `{"kind":"repo.pull-request-target-allowed","input_path":".github/workflows/a.yml"}` {
		t.Error("a fact with repo is written as one without")
	}
}
