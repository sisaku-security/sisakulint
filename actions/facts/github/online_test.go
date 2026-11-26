package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// queriesOfEveryKind is a query of each kind but those of the tests, with
// the repository repo where the kind has one.
func queriesOfEveryKind(t *testing.T, repo facts.Repo) []facts.Query {
	t.Helper()
	var out []facts.Query
	for _, q := range []facts.Query{
		facts.ActionDefinition{}, facts.ActionRunsUsing{}, facts.CheckoutExecuted{}, facts.DependabotVersionUpdates{}, facts.DownloadExecuted{},
		facts.GitCommitContains{}, facts.GitCommitRef{}, facts.GitCommitTags{}, facts.GitRefCommit{}, facts.PackageAdvisories{},
		facts.RenovateManagerEnabled{}, facts.RepoAllowForking{}, facts.RepoArchived{}, facts.RepoDefaultTokenWrite{},
		facts.RepoEnvironmentProtected{}, facts.RepoForkPRRunWorkflows{}, facts.RepoForkPRSecrets{}, facts.RepoForkPRWriteTokens{},
		facts.RepoConfigurationVariables{}, facts.RepoEnvironmentConfigurationVariables{},
		facts.RepoActionList{}, facts.RepoAllowedActions{}, facts.RepoPublic{}, facts.RepoPullRequestTargetAllowed{}, facts.RepoRunnerLabelTrusted{}, facts.RepoForkPRAppChecks{}, facts.RepoMergeCommitAppChecks{}, facts.RepoWikiOpen{}, facts.RequestDestinationTrusted{}, facts.WorkflowDefinition{},
	} {
		v := reflect.New(reflect.TypeOf(q)).Elem()
		if f := v.FieldByName("Repo"); f.IsValid() {
			f.Set(reflect.ValueOf(repo))
		}
		out = append(out, v.Interface().(facts.Query))
	}
	return out
}

// TestOnlineAnswerOf: facts.OnlineAnswerOf says which kinds this package
// asks the API about, and no other: each kind but those of the tests has
// a query here. A kind it answers only of a named repository is not asked
// without one.
func TestOnlineAnswerOf(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{BaseURL: u, Client: srv.Client(), MaxRequests: 100})
	repo, err := facts.ParseRepo("o/r")
	if err != nil {
		t.Fatal(err)
	}
	asked := map[facts.Kind]bool{}
	named := map[facts.Kind]bool{}
	for _, q := range queriesOfEveryKind(t, repo) {
		asked[q.Kind()] = r.Resolve(context.Background(), q).Reason != otherKinds
	}
	for _, q := range queriesOfEveryKind(t, facts.Repo{}) {
		named[q.Kind()] = r.Resolve(context.Background(), q).Reason == noName
	}
	for _, k := range facts.Kinds() {
		if k.Provider == facts.ProviderTest {
			continue
		}
		if _, ok := asked[k.Kind]; !ok {
			t.Errorf("%s has no query in queriesOfEveryKind", k.Kind)
			continue
		}
		var want facts.OnlineAnswer
		switch {
		case !asked[k.Kind]:
			want = facts.OnlineNone
		case named[k.Kind] && k.Kind == facts.KindRepoWikiOpen:
			want = facts.OnlineNamedRepositoryFalse
		case named[k.Kind]:
			want = facts.OnlineNamedRepository
		default:
			want = facts.OnlineAll
		}
		if got := facts.OnlineAnswerOf(k.Kind); got != want {
			t.Errorf("%s: OnlineAnswerOf = %v, the source answers as %v", k.Kind, got, want)
		}
	}
}

// TestWikiOpenOnlyFalse: of a public repository with a wiki, the source
// does not answer repo.wiki-open (OnlineNamedRepositoryFalse).
func TestWikiOpenOnlyFalse(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){"/repos/o/r": body(200, `{"visibility": "public", "has_wiki": true, "archived": false}`)}}
	repo, err := facts.ParseRepo("o/r")
	if err != nil {
		t.Fatal(err)
	}
	got := start(t, f, "").Resolve(context.Background(), facts.RepoWikiOpen{Repo: repo})
	if got.State != facts.StateUnknown {
		t.Errorf("repo.wiki-open of a public repository with a wiki = %+v, want unknown", got)
	}
}
