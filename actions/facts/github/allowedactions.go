package github

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// allowedActions answers repo.allowed-actions: the setting of allowed
// actions of the repository, from GET .../actions/permissions and, when
// allowed_actions is selected, GET .../actions/permissions/selected-actions.
// The answer of the repository is the setting that applies to its
// workflows: GitHub writes the setting of the organization into it, and a
// repository can only narrow the setting of the organization (tried on
// 2026-11-03). A repository where Actions is disabled has no setting.
func (r *resolver) allowedActions(ctx context.Context, q facts.RepoAllowedActions) facts.RawAnswer {
	path, why := r.repoPath(q.Repo)
	if why != "" {
		return unknown(why)
	}
	var p struct {
		Enabled    *bool                      `json:"enabled"`
		Policy     facts.AllowedActionsPolicy `json:"allowed_actions"`
		SHAPinning *bool                      `json:"sha_pinning_required"`
	}
	if why := r.actionsSettings(ctx, path+"actions/permissions", &p); why != "" {
		return unknown(why)
	}
	switch {
	case p.Enabled == nil:
		return unknown("github: the answer is not the Actions settings of a repository")
	case !*p.Enabled:
		return facts.RawAnswer{State: facts.StateAbsent}
	case p.SHAPinning == nil:
		return unknown("github: the answer of the Actions settings must have sha_pinning_required, and has none")
	}
	var s facts.AllowedActionsSetting
	var err error
	if p.Policy == facts.AllowedActionsPolicySelected {
		var sel struct {
			GitHubOwned *bool                          `json:"github_owned_allowed"`
			Verified    *bool                          `json:"verified_allowed"`
			Patterns    *[]facts.AllowedActionsPattern `json:"patterns_allowed"`
		}
		if why := r.actionsSettings(ctx, path+"actions/permissions/selected-actions", &sel); why != "" {
			return unknown(why)
		}
		if sel.GitHubOwned == nil || sel.Verified == nil || sel.Patterns == nil {
			return unknown("github: the answer of the selected actions must have github_owned_allowed, verified_allowed and patterns_allowed, and lacks at least one of the three")
		}
		patterns := *sel.Patterns
		if patterns == nil {
			patterns = []facts.AllowedActionsPattern{}
		}
		s, err = facts.NewAllowedActionsSetting(p.Policy, *sel.GitHubOwned, *sel.Verified, patterns, *p.SHAPinning)
	} else {
		s, err = facts.NewAllowedActionsSetting(p.Policy, false, false, nil, *p.SHAPinning)
	}
	if err != nil {
		return unknown("github: the answer is not a setting of allowed actions: " + err.Error())
	}
	b, err := json.Marshal(s)
	if err != nil {
		return unknown("github: " + err.Error())
	}
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

// actionsSettings reads an answer of the Actions settings of a repository
// at u into v, or says why there is none.
func (r *resolver) actionsSettings(ctx context.Context, u string, v any) string {
	resp, why := r.get(ctx, facts.KindRepoAllowedActions, u, "application/vnd.github+json", 1<<20)
	switch {
	case why != "":
		return why
	case resp.status == http.StatusUnauthorized, resp.status == http.StatusForbidden, resp.status == http.StatusNotFound:
		return "github: the token cannot read the repository's Actions settings (HTTP " + strconv.Itoa(resp.status) + ")"
	case resp.status != http.StatusOK:
		return "github: HTTP " + strconv.Itoa(resp.status)
	}
	if err := json.Unmarshal(resp.body, v); err != nil {
		return "github: the answer is not the Actions settings of a repository: " + err.Error()
	}
	return ""
}
