package github

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// The answers of GitHub to the two GETs, in the form that GitHub gave on
// 2026-11-01 and 2026-11-03, for a repository of a user and for a
// repository of an organization that set selected.
const (
	permissionsSelected = `{"enabled":true,"allowed_actions":"selected","selected_actions_url":"https://api.github.com/repositories/1/actions/permissions/selected-actions","sha_pinning_required":false}`
	selectedActions     = `{"github_owned_allowed":false,"patterns_allowed":["gradle/*","!gradle/actions/setup-gradle@*"],"verified_allowed":false}`
	permissionsAll      = `{"enabled":true,"allowed_actions":"all","sha_pinning_required":true}`
	permissionsDisabled = `{"enabled":false}`
)

func TestAllowedActionsOnline(t *testing.T) {
	ctx := context.Background()
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/sel/actions/permissions":                     body(200, permissionsSelected),
		"/repos/o/sel/actions/permissions/selected-actions":    body(200, selectedActions),
		"/repos/o/all/actions/permissions":                     body(200, permissionsAll),
		"/repos/o/off/actions/permissions":                     body(200, permissionsDisabled),
		"/repos/o/denied/actions/permissions":                  body(403, forbiddenBody),
		"/repos/o/gone/actions/permissions":                    body(404, `{"message":"Not Found"}`),
		"/repos/o/odd/actions/permissions":                     body(200, `{"enabled":true,"allowed_actions":"some"}`),
		"/repos/o/local/actions/permissions":                   body(200, `{"enabled":true,"allowed_actions":"local_only","sha_pinning_required":false}`),
		"/repos/o/nopin/actions/permissions":                   body(200, `{"enabled":true,"allowed_actions":"all"}`),
		"/repos/o/empty/actions/permissions":                   body(200, permissionsSelected),
		"/repos/o/empty/actions/permissions/selected-actions":  body(200, `{}`),
		"/repos/o/badpat/actions/permissions":                  body(200, permissionsSelected),
		"/repos/o/badpat/actions/permissions/selected-actions": body(200, `{"github_owned_allowed":false,"patterns_allowed":["a/*, b/*"],"verified_allowed":false}`),
		"/repos/o/selden/actions/permissions":                  body(200, permissionsSelected),
		"/repos/o/selden/actions/permissions/selected-actions": body(403, forbiddenBody),
	}}
	r := start(t, f, "t")
	want := map[string]struct {
		state facts.State
		value string
	}{
		"o/sel":    {facts.StateFound, `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["gradle/*","!gradle/actions/setup-gradle@*"],"sha_pinning_required":false}`},
		"o/all":    {facts.StateFound, `{"allowed_actions":"all","sha_pinning_required":true}`},
		"o/off":    {facts.StateAbsent, ""},
		"o/denied": {facts.StateUnknown, ""},
		"o/gone":   {facts.StateUnknown, ""},
		"o/odd":    {facts.StateUnknown, ""},
		"o/local":  {facts.StateFound, `{"allowed_actions":"local_only","sha_pinning_required":false}`},
		"o/nopin":  {facts.StateUnknown, ""},
		"o/empty":  {facts.StateUnknown, ""},
		"o/badpat": {facts.StateUnknown, ""},
		"o/selden": {facts.StateUnknown, ""},
	}
	for repo, w := range want {
		a := facts.RepoAllowedActions{Repo: mustRepo(t, repo)}.Ask(ctx, r)
		if a.State != w.state {
			t.Errorf("%s: state %v (%s), want %v", repo, a.State, a.Reason, w.state)
			continue
		}
		if w.state != facts.StateFound {
			continue
		}
		if b, err := json.Marshal(a.Value); err != nil || string(b) != w.value {
			t.Errorf("%s: value %s, %v; want %s", repo, b, err, w.value)
		}
	}
	for _, p := range f.paths {
		switch p {
		case "/api/repos/o/all/actions/permissions/selected-actions", "/api/repos/o/local/actions/permissions/selected-actions", "/api/repos/o/off/actions/permissions/selected-actions":
			t.Errorf("asked %s, of a repository whose policy is not selected", p)
		}
	}
	if a := (facts.RepoAllowedActions{}).Ask(ctx, r); a.State != facts.StateUnknown || a.Reason != noName {
		t.Errorf("no repo: %+v", a)
	}
}
