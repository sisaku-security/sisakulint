package github

import (
	"context"
	"net/http"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
)

func askContains(t *testing.T, r facts.Resolver, sha, commit string) facts.Answer[bool] {
	t.Helper()
	rp, _ := facts.ParseRepo("o/r")
	s, err := facts.ParseSHA(sha)
	if err != nil {
		t.Fatal(err)
	}
	c, err := facts.ParseSHA(commit)
	if err != nil {
		t.Fatal(err)
	}
	return facts.GitCommitContains{Repo: rp, SHA: s, Commit: c}.Ask(context.Background(), r)
}

// TestCommitContains: compare/<commit>...<sha> is identical or ahead when
// sha has commit in its history.
func TestCommitContains(t *testing.T) {
	path := "/repos/o/r/compare/" + shaA + "..." + shaB
	for _, c := range []struct {
		name   string
		answer func(http.ResponseWriter)
		state  facts.State
		value  bool
		reason string
	}{
		{"identical", body(200, `{"status":"identical","ahead_by":0,"behind_by":0}`), facts.StateFound, true, ""},
		{"ahead", body(200, `{"status":"ahead","ahead_by":12,"behind_by":0}`), facts.StateFound, true, ""},
		{"behind", body(200, `{"status":"behind","ahead_by":0,"behind_by":11}`), facts.StateFound, false, ""},
		{"diverged", body(200, `{"status":"diverged","ahead_by":3,"behind_by":24}`), facts.StateFound, false, ""},
		// observed 2026-09-28: unrelated
		// histories are 404 with No common ancestor, which is false; a commit
		// that is not there, or a repository, is 404 Not Found
		{"no common ancestor", body(404, `{"message":"No common ancestor between dev and x.","status":"404"}`), facts.StateFound, false, ""},
		{"404", body(404, `{"message":"Not Found"}`), facts.StateUnknown, false, "github: the repository or a commit is not there, or the token cannot see it"},
		{"422", body(422, `{"message":"x"}`), facts.StateUnknown, false, "github: HTTP 422"},
		{"not a comparison", body(200, `[]`), facts.StateUnknown, false, "github: the answer is not a comparison"},
		{"another status", body(200, `{"status":"sideways"}`), facts.StateUnknown, false, "github: the comparison's status is sideways"},
		{"500", body(500, ""), facts.StateUnknown, false, "github: HTTP 500"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fake{answers: map[string]func(http.ResponseWriter){path: c.answer}}
			got := askContains(t, start(t, f, ""), shaB, shaA)
			if got.State != c.state || got.Value != c.value || got.Reason != c.reason {
				t.Errorf("= %+v, want %v %v %q", got, c.state, c.value, c.reason)
			}
			if len(f.paths) != 1 || f.paths[0] != "/api"+path {
				t.Errorf("asked %v, want %s", f.paths, "/api"+path)
			}
		})
	}
}

// The kinds that no API answers are not asked of GitHub.
func TestNotAskedKinds(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){}}
	r := start(t, f, "")
	path, _ := facts.ParseInputPath(".github/workflows/ci.yml")
	step, _ := facts.WorkflowStep("a", 0)
	env, _ := facts.ParseEnvironmentName("prod")
	for _, q := range []facts.Query{facts.CheckoutExecuted{InputPath: path, Step: step}, facts.RepoEnvironmentProtected{Environment: env}, facts.RepoWikiOpen{}} {
		if got := r.Resolve(context.Background(), q); got.State != facts.StateUnknown || got.Reason == "" {
			t.Errorf("%#v = %+v", q, got)
		}
	}
	if len(f.paths) != 0 {
		t.Errorf("asked %v", f.paths)
	}
}
