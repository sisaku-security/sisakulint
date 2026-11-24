package rules

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// The name of the repository given to lint is in every fact about the
// repository the rules ask; without one, none is (the facts of before).
func TestRepoNamedQueries(t *testing.T) {
	const wf = `on:
  gollum:
  pull_request_target:
jobs:
  wiki:
    runs-on: self-hosted
    steps:
      - run: echo "${{ github.event.pages[0].title }}"
  deploy:
    runs-on: ubuntu-latest
    environment: prod
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make
`
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(wf)}})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	kinds := func(rep lint.Report) map[string]string {
		got := map[string]string{} // kind -> the query
		for _, e := range rep.Facts {
			k := e.Query.Kind().String()
			if !strings.HasPrefix(k, "repo.") {
				continue
			}
			b, err := facts.EncodeQuery(e.Query)
			if err != nil {
				t.Fatal(err)
			}
			got[k] = string(b)
		}
		return got
	}
	unnamed := kinds(lint.Run(context.Background(), in, reg, noFacts{}))
	repo, _ := facts.ParseRepo("o/r")
	in.Repo = repo
	named := kinds(lint.Run(context.Background(), in, reg, noFacts{}))
	for _, k := range []string{"repo.public", "repo.wiki-open", "repo.default-token-write", "repo.environment-protected"} {
		if q, ok := unnamed[k]; !ok || strings.Contains(q, `"repo"`) {
			t.Errorf("no --repo: %s is %q", k, q)
		}
		if q, ok := named[k]; !ok || !strings.Contains(q, `"repo":"o/r"`) {
			t.Errorf("--repo o/r: %s is %q", k, q)
		}
	}
}
