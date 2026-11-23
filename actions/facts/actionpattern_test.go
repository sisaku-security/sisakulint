package facts

import (
	"context"
	"encoding/json"
	"testing"
)

func TestParseActionPattern(t *testing.T) {
	for _, ok := range []string{"actions/checkout@*", "!space-org/action@*", "*", "Actions/Checkout@*", "docker://alpine:*", "o/r/.github/workflows/w.yml@v1"} {
		p, err := ParseActionPattern(ok)
		if err != nil || p.String() != ok {
			t.Errorf("ParseActionPattern(%q) = %v, %v", ok, p, err)
			continue
		}
		b, err := json.Marshal(p)
		if err != nil || string(b) != `"`+ok+`"` {
			t.Errorf("json of %q = %s, %v; want it as written", ok, b, err)
		}
	}
	for _, bad := range []string{"", "!", "!!a/b@*", "a/b@*, !c/d@*", " a/b@*", "a b", "a/b@*\n"} {
		if _, err := ParseActionPattern(bad); err == nil {
			t.Errorf("ParseActionPattern(%q): no error", bad)
		}
	}
}

func TestActionListAllows(t *testing.T) {
	for _, c := range []struct {
		list []string
		uses string
		want bool
	}{
		{[]string{"gradle/*"}, "gradle/actions/setup-gradle@v4", true},
		{[]string{"docker/setup-buildx-action@*"}, "Docker/Setup-Buildx-Action@v3", true},
		{[]string{"crazy-max/ghaction-dump-context"}, "crazy-max/ghaction-dump-context@v2", false},
		{[]string{"actions/reusable-workflows@*"}, "actions/reusable-workflows/.github/workflows/x.yml@v1", false},
		{[]string{"space-org/*", "!space-org/action@*"}, "space-org/action@v1", false},
		{[]string{"space-org/*", "!space-org/action@*"}, "space-org/other@v1", true},
		{[]string{"!space-org/action@*", "space-org/*"}, "space-org/action@v1", false},
		{[]string{"!space-org/action@*", "space-org/*"}, "space-org/other@v1", true},
		{[]string{"!a/b@*"}, "c/d@v1", false},
		{nil, "c/d@v1", false},
		{[]string{"docker://alpine:*"}, "docker://alpine:3.20", true},
		{[]string{"actions/checkout@*"}, "docker://alpine:3.20", false},
		{[]string{"a.b/c@*"}, "aXb/c@v1", false},
		{[]string{"actions/checkout@v4"}, "actions/checkout@v4.1", false},
		{[]string{"actions/checkout@v4"}, "actions/checkout@V4", false},
		{[]string{"Actions/Checkout@v4"}, "actions/checkout@v4", true},
		{[]string{"o/r/sub@*"}, "O/R/Sub@v1", false},
		{[]string{"o/r/sub@*"}, "O/R/sub@v1", true},
		{[]string{"*/octocat**@*"}, "Space/Octocat-x/path@v1", true},
		{[]string{"docker://alpine:*"}, "docker://Alpine:3", false},
		{[]string{"*", "!*/Internal@*"}, "o/r/Internal@v1", false},
		{[]string{"*", "!*/Evil@*"}, "x/Evil@v1", false},
		{[]string{"*", "!*/Evil@*"}, "x/evil@v1", false},
		{[]string{"*", "!Space-*/Action@*"}, "space-org/action@v1", false},
		{[]string{"*", "!actions/checkout@V4"}, "actions/checkout@v4", false},
		{[]string{"*/Octocat@*"}, "space/octocat@v1", false},
	} {
		var list []ActionPattern
		for _, s := range c.list {
			list = append(list, MustActionPattern(s))
		}
		if got := ActionListAllows(list, c.uses); got != c.want {
			t.Errorf("ActionListAllows(%q, %q) = %v, want %v", c.list, c.uses, got, c.want)
		}
	}
}

// TestRepoActionListFile: the fact has no argument but kind, and a file of
// facts gives the list back as written.
func TestRepoActionListFile(t *testing.T) {
	entry := `{"query":{"kind":"repo.action-list"},"state":"found","value":["Actions/Checkout@*","!evil/act@*"]}`
	s, err := LoadStore([]byte(file(entry)))
	if err != nil {
		t.Fatal(err)
	}
	a := RepoActionList{}.Ask(context.Background(), s)
	if a.State != StateFound || len(a.Value) != 2 || a.Value[0].String() != "Actions/Checkout@*" {
		t.Fatalf("Ask = %+v", a)
	}
	b, err := json.Marshal(a.Value)
	if err != nil || string(b) != `["Actions/Checkout@*","!evil/act@*"]` {
		t.Errorf("the list written back = %s, %v", b, err)
	}
	for _, bad := range []string{
		`{"query":{"kind":"repo.action-list","repo":"o/r"},"state":"found","value":[]}`,
		`{"query":{"kind":"repo.action-list"},"state":"found","value":["a/b@*, !c/d@*"]}`,
	} {
		if _, err := LoadStore([]byte(file(bad))); err == nil {
			t.Errorf("LoadStore(%s): no error", bad)
		}
	}
	if OnlineAnswerOf(KindRepoActionList) != OnlineNone {
		t.Error("--online asks repo.action-list")
	}
}
