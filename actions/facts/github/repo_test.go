package github

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// The answers of GitHub, as they were seen.
const (
	repoPublicBody  = `{"visibility":"public","private":false,"has_wiki":true,"allow_forking":true}`
	repoPrivateBody = `{"visibility":"private","private":true,"has_wiki":true,"allow_forking":false}`
	notFoundBody    = `{"message":"Not Found","documentation_url":"https://docs.github.com/rest/deployments/environments#get-an-environment","status":"404"}`
	forbiddenBody   = `{"message":"Resource not accessible by integration","documentation_url":"https://docs.github.com/rest/actions/permissions#get-default-workflow-permissions-for-a-repository","status":"403"}`
)

func mustRepo(t *testing.T, s string) facts.Repo {
	t.Helper()
	r, err := facts.ParseRepo(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRepoFacts(t *testing.T) {
	ctx := context.Background()
	env, _ := facts.ParseEnvironmentName("prod")
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/pub":    body(200, repoPublicBody),
		"/repos/o/priv":   body(200, repoPrivateBody),
		"/repos/o/int":    body(200, `{"visibility":"internal","private":true,"has_wiki":true}`),
		"/repos/o/nowiki": body(200, `{"visibility":"public","private":false,"has_wiki":false}`),
		"/repos/o/gone":   body(404, notFoundBody),

		"/repos/o/pub/actions/permissions/workflow":  body(200, `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":false}`),
		"/repos/o/priv/actions/permissions/workflow": body(200, `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`),
		"/repos/o/int/actions/permissions/workflow":  body(403, forbiddenBody),

		"/repos/o/pub/environments/prod":  body(200, `{"name":"prod","protection_rules":[{"id":1,"type":"wait_timer","wait_timer":5},{"id":2,"type":"required_reviewers","reviewers":[]}]}`),
		"/repos/o/priv/environments/prod": body(200, `{"name":"prod","protection_rules":[{"id":1,"type":"branch_policy"}]}`),
		"/repos/o/int/environments/prod":  body(404, notFoundBody),
		"/repos/o/gone/environments/prod": body(404, notFoundBody),

		"/repos/o/pub/actions/permissions/fork-pr-workflows-private-repos":  body(422, `{"message":"Fork PR workflow settings is not allowed for public repositories.","documentation_url":"https://docs.github.com/rest/actions/permissions#get-private-repo-fork-pr-workflow-settings-for-a-repository","status":"422"}`),
		"/repos/o/priv/actions/permissions/fork-pr-workflows-private-repos": body(200, `{"run_workflows_from_fork_pull_requests":true,"send_write_tokens_to_workflows":false,"send_secrets_and_variables":true,"require_approval_for_fork_pr_workflows":false}`),
		"/repos/o/int/actions/permissions/fork-pr-workflows-private-repos":  body(422, `{"message":"Validation Failed","status":"422"}`),
	}}
	r := start(t, f, "t")
	type want struct {
		state facts.State
		value bool
	}
	found := func(v bool) want { return want{facts.StateFound, v} }
	unknown := want{state: facts.StateUnknown}
	absentState := want{state: facts.StateAbsent}
	for _, c := range []struct {
		q    facts.Query
		want want
	}{
		{facts.RepoPublic{Repo: mustRepo(t, "o/pub")}, found(true)},
		{facts.RepoPublic{Repo: mustRepo(t, "o/priv")}, found(false)},
		{facts.RepoPublic{Repo: mustRepo(t, "o/int")}, found(false)},
		{facts.RepoPublic{Repo: mustRepo(t, "o/gone")}, unknown},
		{facts.RepoWikiOpen{Repo: mustRepo(t, "o/pub")}, unknown}, // the setting is in no API
		{facts.RepoWikiOpen{Repo: mustRepo(t, "o/priv")}, found(false)},
		{facts.RepoWikiOpen{Repo: mustRepo(t, "o/nowiki")}, found(false)},
		{facts.RepoDefaultTokenWrite{Repo: mustRepo(t, "o/pub")}, found(true)},
		{facts.RepoDefaultTokenWrite{Repo: mustRepo(t, "o/priv")}, found(false)},
		{facts.RepoDefaultTokenWrite{Repo: mustRepo(t, "o/int")}, unknown},
		{facts.RepoEnvironmentProtected{Repo: mustRepo(t, "o/pub"), Environment: env}, found(true)},
		{facts.RepoEnvironmentProtected{Repo: mustRepo(t, "o/priv"), Environment: env}, found(false)},
		{facts.RepoEnvironmentProtected{Repo: mustRepo(t, "o/int"), Environment: env}, found(false)}, // not there: made with no rules
		{facts.RepoEnvironmentProtected{Repo: mustRepo(t, "o/gone"), Environment: env}, unknown},     // the repository is not seen
		{facts.RepoAllowForking{Repo: mustRepo(t, "o/pub")}, found(true)},
		{facts.RepoAllowForking{Repo: mustRepo(t, "o/priv")}, found(false)},
		{facts.RepoAllowForking{Repo: mustRepo(t, "o/int")}, unknown}, // no allow_forking in the answer
		{facts.RepoForkPRRunWorkflows{Repo: mustRepo(t, "o/priv")}, found(true)},
		{facts.RepoForkPRWriteTokens{Repo: mustRepo(t, "o/priv")}, found(false)},
		{facts.RepoForkPRSecrets{Repo: mustRepo(t, "o/priv")}, found(true)},
		{facts.RepoForkPRSecrets{Repo: mustRepo(t, "o/int")}, unknown}, // another 422
		{facts.RepoForkPRSecrets{Repo: mustRepo(t, "o/gone")}, unknown},
		{facts.RepoForkPRRunWorkflows{Repo: mustRepo(t, "o/pub")}, absentState}, // a public repository has no such setting
		{facts.RepoForkPRSecrets{Repo: mustRepo(t, "o/pub")}, absentState},
	} {
		got := facts.Checked(c.q, r.Resolve(ctx, c.q))
		if got.State != c.want.state || got.State == facts.StateFound && string(got.Value) != strconv.FormatBool(c.want.value) {
			t.Errorf("%#v = %+v, want %+v", c.q, got, c.want)
		}
		if got.State == facts.StateUnknown && got.Reason == "" {
			t.Errorf("%#v: unknown without a reason", c.q)
		}
		if got.Source != facts.SourceGitHub {
			t.Errorf("%#v: source %v", c.q, got.Source)
		}
	}
	n := 0
	for _, p := range f.paths {
		if p == "/api/repos/o/pub" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("GET /repos/o/pub was sent %d times, want once: %v", n, f.paths)
	}
	n = 0
	for _, p := range f.paths {
		if strings.HasSuffix(p, "/repos/o/priv/actions/permissions/fork-pr-workflows-private-repos") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the fork pull request settings of o/priv were asked %d times, want once", n)
	}
}

// A fact of no name is not asked: the API needs the name.
func TestRepoFactsOfNoName(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){}}
	r := start(t, f, "t")
	env, _ := facts.ParseEnvironmentName("prod")
	for _, q := range []facts.Query{facts.RepoPublic{}, facts.RepoWikiOpen{}, facts.RepoDefaultTokenWrite{}, facts.RepoEnvironmentProtected{Environment: env}} {
		if got := r.Resolve(context.Background(), q); got.State != facts.StateUnknown || got.Reason == "" || got.Source != facts.SourceUnset {
			t.Errorf("%#v = %+v", q, got)
		}
	}
	if len(f.paths) != 0 {
		t.Errorf("asked %v", f.paths)
	}
}
