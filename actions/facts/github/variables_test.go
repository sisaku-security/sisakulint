package github

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// orgRepoBody is GET /repos/{owner}/{repo} of a repository of an
// organization; userRepoBody, of a user, whose organization-variables
// GitHub answered with userOrgVars on 2026-11-03.
const (
	orgRepoBody  = `{"visibility":"private","private":true,"has_wiki":true,"owner":{"login":"o","type":"Organization"}}`
	userRepoBody = `{"visibility":"private","private":true,"has_wiki":true,"owner":{"login":"u","type":"User"}}`
	userOrgVars  = `{"message":"Validation Failed","documentation_url":"https://docs.github.com/rest/actions/variables#list-repository-organization-variables","status":"422"}`
)

func variablesBody(total int, names ...string) string {
	var vs []string
	for _, n := range names {
		vs = append(vs, `{"name":"`+n+`","value":"v","created_at":"2026-11-03T00:00:00Z","updated_at":"2026-11-03T00:00:00Z"}`)
	}
	return `{"total_count":` + strconv.Itoa(total) + `,"variables":[` + strings.Join(vs, ",") + `]}`
}

func TestConfigurationVariables(t *testing.T) {
	ctx := context.Background()
	page1 := make([]string, 30)
	for i := range page1 {
		page1[i] = "V" + strconv.Itoa(i)
	}
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r": body(200, orgRepoBody),
		"/repos/o/r/actions/variables?per_page=30&page=1":              body(200, variablesBody(31, page1...)),
		"/repos/o/r/actions/variables?per_page=30&page=2":              body(200, variablesBody(31, "MASCOT")),
		"/repos/o/r/actions/organization-variables?per_page=30&page=1": body(200, variablesBody(2, "MASCOT", "ORG_ONLY")),
		"/repos/u/r": body(200, userRepoBody),
		"/repos/u/r/actions/variables?per_page=30&page=1":              body(200, variablesBody(1, "USER_VAR")),
		"/repos/u/r/actions/organization-variables?per_page=30&page=1": body(422, userOrgVars),
		"/repos/o/orgerr": body(200, orgRepoBody),
		"/repos/o/orgerr/actions/variables?per_page=30&page=1":              body(200, variablesBody(1, "A")),
		"/repos/o/orgerr/actions/organization-variables?per_page=30&page=1": body(422, userOrgVars),
		"/repos/o/moved": body(200, orgRepoBody),
		"/repos/o/moved/actions/variables?per_page=30&page=1": body(200, variablesBody(31, page1...)),
		"/repos/o/moved/actions/variables?per_page=30&page=2": body(200, variablesBody(30)),
		"/repos/o/denied": body(200, orgRepoBody),
		"/repos/o/denied/actions/variables?per_page=30&page=1": body(403, forbiddenBody),
	}}
	r := start(t, f, "t")
	a := facts.RepoConfigurationVariables{Repo: mustRepo(t, "o/r")}.Ask(ctx, r)
	if a.State != facts.StateFound || len(a.Value) != 32 {
		t.Fatalf("o/r = %+v; want the 31 names of the repository and ORG_ONLY, MASCOT once", a)
	}
	var got []string
	for _, n := range a.Value {
		got = append(got, n.String())
	}
	if !strings.Contains(strings.Join(got, " "), "MASCOT ORG_ONLY V0") {
		t.Errorf("o/r = %v; want the names in order", got)
	}
	if a := (facts.RepoConfigurationVariables{Repo: mustRepo(t, "u/r")}.Ask(ctx, r)); a.State != facts.StateFound || len(a.Value) != 1 || a.Value[0].String() != "USER_VAR" {
		t.Errorf("u/r = %+v; want USER_VAR, without asking organization-variables", a)
	}
	for _, p := range f.paths {
		if strings.HasPrefix(p, "/api/repos/u/r/actions/organization-variables") {
			t.Errorf("asked %s of a repository of a user", p)
		}
	}
	for _, repo := range []string{"o/orgerr", "o/moved"} {
		if a := (facts.RepoConfigurationVariables{Repo: mustRepo(t, repo)}.Ask(ctx, r)); a.State != facts.StateUnknown {
			t.Errorf("%s = %+v; want unknown", repo, a)
		}
	}
	if a := (facts.RepoConfigurationVariables{Repo: mustRepo(t, "o/denied")}.Ask(ctx, r)); a.State != facts.StateUnknown {
		t.Errorf("o/denied = %+v; want unknown", a)
	}
}

func TestEnvironmentConfigurationVariables(t *testing.T) {
	ctx := context.Background()
	prod, _ := facts.ParseEnvironmentName("prod")
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r": body(200, orgRepoBody),
		"/repos/o/r/environments/prod/variables?per_page=30&page=1":   body(200, variablesBody(1, "deploy_url")),
		"/repos/o/r/environments/none/variables?per_page=30&page=1":   body(404, notFoundBody),
		"/repos/o/r/environments/locked/variables?per_page=30&page=1": body(403, forbiddenBody),
		"/repos/o/gone": body(404, notFoundBody),
		"/repos/o/gone/environments/prod/variables?per_page=30&page=1": body(404, notFoundBody),
	}}
	r := start(t, f, "t")
	if a := (facts.RepoEnvironmentConfigurationVariables{Repo: mustRepo(t, "o/r"), Environment: prod}.Ask(ctx, r)); a.State != facts.StateFound || len(a.Value) != 1 || a.Value[0].String() != "DEPLOY_URL" {
		t.Errorf("prod = %+v; want DEPLOY_URL", a)
	}
	none, _ := facts.ParseEnvironmentName("none")
	if a := (facts.RepoEnvironmentConfigurationVariables{Repo: mustRepo(t, "o/r"), Environment: none}.Ask(ctx, r)); a.State != facts.StateFound || len(a.Value) != 0 {
		t.Errorf("an environment that is not there = %+v; want the empty list", a)
	}
	locked, _ := facts.ParseEnvironmentName("locked")
	if a := (facts.RepoEnvironmentConfigurationVariables{Repo: mustRepo(t, "o/r"), Environment: locked}.Ask(ctx, r)); a.State != facts.StateUnknown {
		t.Errorf("403 = %+v; want unknown", a)
	}
	if a := (facts.RepoEnvironmentConfigurationVariables{Repo: mustRepo(t, "o/gone"), Environment: prod}.Ask(ctx, r)); a.State != facts.StateUnknown {
		t.Errorf("a repository that is not seen = %+v; want unknown", a)
	}
}
