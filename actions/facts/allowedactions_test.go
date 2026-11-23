package facts

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
)

func TestParseAllowedActionsPattern(t *testing.T) {
	for _, ok := range []string{"actions/checkout@*", "!space-org/action@*", "*", "github/codeql-action/INIT@*", "docker://alpine:*"} {
		p, err := ParseAllowedActionsPattern(ok)
		if err != nil || p.String() != ok {
			t.Errorf("ParseAllowedActionsPattern(%q) = %v, %v", ok, p, err)
			continue
		}
		if b, err := json.Marshal(p); err != nil || string(b) != `"`+ok+`"` {
			t.Errorf("json of %q = %s, %v; want it as written", ok, b, err)
		}
	}
	for _, bad := range []string{"", "!", "!!a/b@*", "a/b@*, !c/d@*", " a/b@*", "a b"} {
		if _, err := ParseAllowedActionsPattern(bad); err == nil {
			t.Errorf("ParseAllowedActionsPattern(%q): no error", bad)
		}
	}
}

func selected(t *testing.T, githubOwned, verified bool, patterns ...string) AllowedActionsSetting {
	t.Helper()
	ps := []AllowedActionsPattern{}
	for _, p := range patterns {
		ps = append(ps, MustAllowedActionsPattern(p))
	}
	s, err := NewAllowedActionsSetting(AllowedActionsPolicySelected, githubOwned, verified, ps, false)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAllowedActionsAllows: the readings of the setting that the runs of
// GitHub showed (the forms of the comments).
func TestAllowedActionsAllows(t *testing.T) {
	all, err := NewAllowedActionsSetting(AllowedActionsPolicyAll, false, false, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewAllowedActionsSetting(AllowedActionsPolicyLocalOnly, false, false, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	const sha = "0057852bfaa89a56745cba8c7296529d2fc39830"
	o := mustRepo(t, "o/r")
	for _, c := range []struct {
		name    string
		setting AllowedActionsSetting
		repo    Repo
		uses    string
		want    AllowedActionsVerdict
	}{
		{"all", all, o, "x/y@v1", AllowedActionsAllowed},
		{"local_only, the same owner in another case", local, o, "O/other@v1", AllowedActionsAllowed},
		{"local_only, an action of GitHub", local, o, "actions/cache@" + sha, AllowedActionsNotAllowed},
		{"local_only, an image", local, o, "docker://alpine:3", AllowedActionsNotAllowed},
		{"local_only, no name of the repository", local, Repo{}, "x/y@v1", AllowedActionsNotAllowed},
		{"a ! pattern blocks what another pattern allows", selected(t, false, false, "gradle/*", "!gradle/actions/setup-gradle@*"), o, "gradle/actions/setup-gradle@" + sha, AllowedActionsNotAllowed},
		{"the pattern that the ! pattern does not name", selected(t, false, false, "gradle/*", "!gradle/actions/setup-gradle@*"), o, "gradle/actions/wrapper-validation@" + sha, AllowedActionsAllowed},
		{"a ! pattern in another case", selected(t, false, false, "docker/*", "!Docker/Setup-Buildx-Action@*"), o, "docker/setup-buildx-action@" + sha, AllowedActionsNotAllowed},
		{"a path in another case", selected(t, false, false, "github/codeql-action/INIT@*"), o, "github/codeql-action/init@" + sha, AllowedActionsAllowed},
		{"a ref in another case", selected(t, false, false, "actions/cache@V4"), o, "actions/cache@v4", AllowedActionsAllowed},
		{"a pattern with no * and no @", selected(t, false, false, "crazy-max/ghaction-dump-context"), o, "crazy-max/ghaction-dump-context@" + sha, AllowedActionsNotAllowed},
		{"owner/repo@* and a reusable workflow with a path", selected(t, false, false, "actions/reusable-workflows@*"), o, "actions/reusable-workflows/.github/workflows/basic-validation.yml@" + sha, AllowedActionsNotAllowed},
		{"owner/repo/* and a reusable workflow with a path", selected(t, false, false, "actions/reusable-workflows/*"), o, "actions/reusable-workflows/.github/workflows/basic-validation.yml@" + sha, AllowedActionsAllowed},
		{"an image by its registry", selected(t, false, false, "docker://alpine:*"), o, "docker://docker.io/library/alpine:3.20", AllowedActionsNotAllowed},
		{"an image by its digest", selected(t, false, false, "docker://alpine:*"), o, "docker://alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc", AllowedActionsNotAllowed},
		{"an image as the pattern writes it", selected(t, false, false, "docker://alpine:*"), o, "docker://alpine:3.20", AllowedActionsAllowed},
		{"GitHub-owned, actions in another case", selected(t, true, false), o, "Actions/Cache@" + sha, AllowedActionsAllowed},
		{"GitHub-owned, github", selected(t, true, false), o, "github/codeql-action/init@" + sha, AllowedActionsAllowed},
		{"GitHub-owned, an image", selected(t, true, false), o, "docker://alpine:3.20", AllowedActionsNotAllowed},
		{"GitHub-owned, another owner", selected(t, true, false), o, "docker/setup-buildx-action@" + sha, AllowedActionsNotAllowed},
		{"selected, the same owner", selected(t, false, false), o, "o/other/.github/workflows/r.yml@" + sha, AllowedActionsAllowed},
		{"selected, a ! pattern names the same owner", selected(t, false, false, "!o/bad@*"), o, "o/bad@v1", AllowedActionsNotAllowed},
		{"verified creators", selected(t, false, true), o, "x/y@v1", AllowedActionsUndecidedVerifiedCreator},
		{"verified creators, an image (not tried)", selected(t, false, true), o, "docker://alpine:3", AllowedActionsUndecidedVerifiedCreator},
		{"no name of the repository: no uses is of the owner", selected(t, false, false), Repo{}, "x/y@v1", AllowedActionsNotAllowed},
		{"no name of the repository, an action of GitHub", selected(t, true, false), Repo{}, "actions/cache@" + sha, AllowedActionsAllowed},
		{"no name of the repository, a pattern decides", selected(t, false, false, "x/*"), Repo{}, "x/y@v1", AllowedActionsAllowed},
		{"no name of the repository, a ! pattern decides", selected(t, false, false, "!x/*"), Repo{}, "x/y@v1", AllowedActionsNotAllowed},
		{"no name of the repository, an image", selected(t, false, false), Repo{}, "docker://alpine:3", AllowedActionsNotAllowed},
	} {
		if got := c.setting.Allows(c.repo, c.uses); got != c.want {
			t.Errorf("%s: Allows(%v, %q) = %v, want %v", c.name, c.repo, c.uses, got, c.want)
		}
	}
}

// TestAllowedActionsSettingJSON: the value is written back as read, and a
// value whose keys do not go with allowed_actions is not read.
func TestAllowedActionsSettingJSON(t *testing.T) {
	for _, ok := range []string{
		`{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["a/*","!A/B@V1"],"sha_pinning_required":false}`,
		`{"allowed_actions":"all","sha_pinning_required":true}`,
		`{"allowed_actions":"local_only","sha_pinning_required":false}`,
	} {
		var s AllowedActionsSetting
		if err := json.Unmarshal([]byte(ok), &s); err != nil {
			t.Errorf("Unmarshal(%s): %v", ok, err)
			continue
		}
		if b, err := json.Marshal(s); err != nil || string(b) != ok {
			t.Errorf("written back = %s, %v; want %s", b, err, ok)
		}
	}
	for _, bad := range []string{
		`{"allowed_actions":"all","patterns_allowed":[],"sha_pinning_required":false}`,
		`{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"sha_pinning_required":false}`,
		`{"allowed_actions":"all"}`,
		`{"allowed_actions":"some","sha_pinning_required":false}`,
		`{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["a b"],"sha_pinning_required":false}`,
		`{"allowed_actions":"all","github_owned_allowed":null,"sha_pinning_required":false}`,
		`{"allowed_actions":"all","patterns_allowed":null,"sha_pinning_required":false}`,
		`{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":null,"sha_pinning_required":false}`,
		`{"allowed_actions":"all","sha_pinning_required":null}`,
	} {
		var s AllowedActionsSetting
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Errorf("Unmarshal(%s): no error", bad)
		}
	}
	if _, err := NewAllowedActionsSetting(AllowedActionsPolicyAll, true, false, nil, false); err == nil {
		t.Error("NewAllowedActionsSetting: all with github_owned_allowed, no error")
	}
	if _, err := NewAllowedActionsSetting(AllowedActionsPolicyLocalOnly, false, false, []AllowedActionsPattern{MustAllowedActionsPattern("a/*")}, false); err == nil {
		t.Error("NewAllowedActionsSetting: local_only with patterns, no error")
	}
	if _, err := NewAllowedActionsSetting(AllowedActionsPolicySelected, false, false, []AllowedActionsPattern{{}}, false); err == nil {
		t.Error("NewAllowedActionsSetting: a zero pattern, no error")
	}
	// the setting keeps its own patterns
	ps := []AllowedActionsPattern{MustAllowedActionsPattern("a/*")}
	kept, err := NewAllowedActionsSetting(AllowedActionsPolicySelected, false, false, ps, false)
	if err != nil {
		t.Fatal(err)
	}
	ps[0] = MustAllowedActionsPattern("b/*")
	if kept.Allows(Repo{}, "a/x@v1") != AllowedActionsAllowed {
		t.Error("a change of the slice given changed the setting")
	}
}

// TestAllowedActionsPolicyValues: the values that the schema's setting
// takes are the values of the enumeration allowed-actions-policy.
func TestAllowedActionsPolicyValues(t *testing.T) {
	var vs []string
	for _, v := range allowedActionsPolicyValues() {
		vs = append(vs, v.String())
	}
	var schema struct {
		Defs map[string]struct {
			OneOf []struct {
				Properties map[string]struct {
					Enum  []string `json:"enum"`
					Const string   `json:"const"`
				} `json:"properties"`
			} `json:"oneOf"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		t.Fatal(err)
	}
	var taken []string
	for _, o := range schema.Defs["allowed-actions-setting"].OneOf {
		p := o.Properties["allowed_actions"]
		taken = append(taken, p.Enum...)
		if p.Const != "" {
			taken = append(taken, p.Const)
		}
	}
	slices.Sort(vs)
	slices.Sort(taken)
	if !slices.Equal(vs, taken) {
		t.Errorf("the enumeration has %v, the setting takes %v", vs, taken)
	}
}

// TestRepoAllowedActionsFile: a file of facts answers the fact with and
// without repo, and absent for a repository where Actions is disabled.
func TestRepoAllowedActionsFile(t *testing.T) {
	s, err := LoadStore([]byte(file(
		`{"query":{"kind":"repo.allowed-actions","repo":"o/r"},"state":"found","value":{"allowed_actions":"all","sha_pinning_required":true}}`,
		`{"query":{"kind":"repo.allowed-actions"},"state":"absent"}`,
	)))
	if err != nil {
		t.Fatal(err)
	}
	a := RepoAllowedActions{Repo: mustRepo(t, "o/r")}.Ask(context.Background(), s)
	if a.State != StateFound || !a.Value.PinningRequired() {
		t.Errorf("Ask(o/r) = %+v", a)
	}
	if a := (RepoAllowedActions{}).Ask(context.Background(), s); a.State != StateAbsent {
		t.Errorf("Ask() = %+v, want absent", a)
	}
}
