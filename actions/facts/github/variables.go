package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// variablePages is the most pages of 30 names a list of configuration
// variables is read in: 1,000 organization variables are 34 pages.
const variablePages = 40

// variableNames reads the names of a paged list of configuration variables
// at u (…/variables, …/organization-variables): the names, or why there
// are none, and whether GitHub answered 404. A name that is not one
// GitHub can define is not an answer.
func (r *resolver) variableNames(ctx context.Context, k facts.Kind, u string) ([]facts.ConfigurationVariableName, bool, string) {
	var out []facts.ConfigurationVariableName
	for page := 1; page <= variablePages; page++ {
		resp, why := r.get(ctx, k, u+"?per_page=30&page="+strconv.Itoa(page), "application/vnd.github+json", 1<<20)
		switch {
		case why != "":
			return nil, false, why
		case resp.status == http.StatusUnauthorized, resp.status == http.StatusForbidden, resp.status == http.StatusNotFound:
			return nil, resp.status == http.StatusNotFound, "github: the token cannot read the configuration variables (HTTP " + strconv.Itoa(resp.status) + ")"
		case resp.status != http.StatusOK:
			return nil, false, "github: HTTP " + strconv.Itoa(resp.status)
		}
		var v struct {
			TotalCount *int `json:"total_count"`
			Variables  []struct {
				Name string `json:"name"`
			} `json:"variables"`
		}
		if json.Unmarshal(resp.body, &v) != nil || v.TotalCount == nil {
			return nil, false, "github: the answer is not a list of configuration variables"
		}
		for _, x := range v.Variables {
			n, err := facts.ParseConfigurationVariableName(x.Name)
			if err != nil {
				return nil, false, "github: the answer has a name that is not one of a configuration variable"
			}
			out = append(out, n)
		}
		switch {
		case len(out) >= *v.TotalCount:
			return out, false, ""
		case len(v.Variables) == 0:
			// a page that ends the list before total_count: a variable was
			// deleted while the pages were read, and the pages moved
			return nil, false, "github: the list of configuration variables changed while it was read"
		}
	}
	return nil, false, "github: the list of configuration variables has more than " + strconv.Itoa(variablePages) + " pages"
}

// names is the answer of a list of names: in order, each once.
func names(ns []facts.ConfigurationVariableName) facts.RawAnswer {
	slices.SortFunc(ns, func(a, b facts.ConfigurationVariableName) int {
		switch {
		case a.String() < b.String():
			return -1
		case a.String() > b.String():
			return 1
		}
		return 0
	})
	ns = slices.Compact(ns)
	if ns == nil {
		ns = []facts.ConfigurationVariableName{}
	}
	b, err := json.Marshal(ns)
	if err != nil {
		return unknown("github: " + err.Error())
	}
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

// configurationVariables answers repo.configuration-variables: the names
// of the repository level and of the organization level shared with the
// repository. A repository of a user has no organization level, and GitHub
// answers its organization-variables with 422.
func (r *resolver) configurationVariables(ctx context.Context, q facts.RepoConfigurationVariables) facts.RawAnswer {
	path, why := r.repoPath(q.Repo)
	if why != "" {
		return unknown(why)
	}
	i, why := r.repo(ctx, q.Repo, facts.KindRepoConfigurationVariables)
	if why != "" {
		return unknown(why)
	}
	ns, _, why := r.variableNames(ctx, facts.KindRepoConfigurationVariables, path+"actions/variables")
	if why != "" {
		return unknown(why)
	}
	if !i.ownerUser {
		org, _, why := r.variableNames(ctx, facts.KindRepoConfigurationVariables, path+"actions/organization-variables")
		if why != "" {
			return unknown(why)
		}
		ns = append(ns, org...)
	}
	return names(ns)
}

// environmentConfigurationVariables answers
// repo.environment-configuration-variables: the names of the environment
// level. A job that names an environment that is not there makes it with
// no variables, so 404 is the empty list; but 404 is also what a
// repository that is not seen gives, so only of a repository that is seen.
func (r *resolver) environmentConfigurationVariables(ctx context.Context, q facts.RepoEnvironmentConfigurationVariables) facts.RawAnswer {
	path, why := r.repoPath(q.Repo)
	if why != "" {
		return unknown(why)
	}
	ns, notFound, why := r.variableNames(ctx, facts.KindRepoEnvironmentConfigurationVariables, path+"environments/"+url.PathEscape(q.Environment.String())+"/variables")
	switch {
	case notFound:
		if _, why := r.repo(ctx, q.Repo, facts.KindRepoEnvironmentConfigurationVariables); why != "" {
			return unknown(why)
		}
		return names(nil)
	case why != "":
		return unknown(why)
	}
	return names(ns)
}
