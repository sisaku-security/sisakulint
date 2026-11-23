package github

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// TestCommitTags: the tags that point to a commit, from the pages of
// GET /repos/{owner}/{repo}/tags, read once a repository.
func TestCommitTags(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	page1 := `[{"name":"v4.1.2","commit":{"sha":"` + a + `"}},{"name":"v4","commit":{"sha":"` + a + `"}},{"name":"v3","commit":{"sha":"` + b + `"}}]`
	page2 := `[{"name":"v4.1.1","commit":{"sha":"` + strings.ToUpper(b) + `"}}]`
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/tags?per_page=100&page=1": func(w http.ResponseWriter) {
			w.Header().Set("Link", `<https://api.github.com/repos/o/r/tags?per_page=100&page=2>; rel="next"`)
			w.WriteHeader(200)
			w.Write([]byte(page1))
		},
		"/repos/o/r/tags?per_page=100&page=2":    body(200, page2),
		"/repos/o/gone/tags?per_page=100&page=1": body(404, notFoundBody),
		"/repos/o/many/tags?per_page=100&page=1": func(w http.ResponseWriter) {
			w.Header().Set("Link", `<x>; rel="next"`)
			w.WriteHeader(200)
			w.Write([]byte(`[]`))
		},
	}}
	for i := 2; i <= maxTagPages; i++ {
		f.answers["/repos/o/many/tags?per_page=100&page="+strconv.Itoa(i)] = f.answers["/repos/o/many/tags?per_page=100&page=1"]
	}
	r := start(t, f, "t")
	ctx := context.Background()
	ask := func(repo, sha string) facts.Answer[[]facts.RefName] {
		s, err := facts.ParseSHA(sha)
		if err != nil {
			t.Fatal(err)
		}
		return facts.GitCommitTags{Repo: mustRepo(t, repo), SHA: s}.Ask(ctx, r)
	}
	names := func(a facts.Answer[[]facts.RefName]) string {
		var out []string
		for _, n := range a.Value {
			out = append(out, n.String())
		}
		return strings.Join(out, " ")
	}
	if got := ask("o/r", a); got.State != facts.StateFound || names(got) != "refs/tags/v4 refs/tags/v4.1.2" {
		t.Errorf("a: %+v", got)
	}
	if got := ask("O/R", b); got.State != facts.StateFound || names(got) != "refs/tags/v3 refs/tags/v4.1.1" {
		t.Errorf("b, a SHA of upper case in the list: %+v", got)
	}
	n := len(f.paths)
	if got := ask("o/r", strings.Repeat("c", 40)); got.State != facts.StateFound || got.Value == nil || len(got.Value) != 0 || len(f.paths) != n {
		t.Errorf("no tag, from the list read before: %+v, %d requests after %d", got, len(f.paths), n)
	}
	if got := (facts.GitCommitTags{Repo: mustRepo(t, "o/r")}).Ask(ctx, r); got.State != facts.StateUnknown {
		t.Errorf("no commit: %+v", got)
	}
	if got := ask("o/gone", a); got.State != facts.StateUnknown {
		t.Errorf("gone: %+v", got)
	}
	if got := ask("o/many", a); got.State != facts.StateUnknown || !strings.Contains(got.Reason, "more than") {
		t.Errorf("many: %+v", got)
	}
}
