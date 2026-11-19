package github

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// TestLive asks the real API, only with ACTIONS_GITHUB_API=1. A token in
// GH_TOKEN or GITHUB_TOKEN is used when there is one; the package itself
// reads no environment.
func TestLive(t *testing.T) {
	if os.Getenv("ACTIONS_GITHUB_API") != "1" {
		t.Skip("ACTIONS_GITHUB_API=1 asks the real GitHub API")
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	r := New(Options{Token: token, ReadRunsUsing: liveRunsUsing})
	repo, _ := facts.ParseRepo("actions/checkout")
	// v4.2.2 is a tag that is not moved.
	got := facts.GitRefCommit{Repo: repo, Ref: "v4.2.2"}.Ask(context.Background(), r)
	if got.State != facts.StateFound || got.Value.SHA.String() != "11bd71901bbe5b1630ceea73d27597364c9af683" || got.Value.Ref.String() != "refs/tags/v4.2.2" {
		t.Errorf("v4.2.2 = %+v", got)
	}
	if got := (facts.GitRefCommit{Repo: repo, Ref: "no-such-ref-sisakulint"}).Ask(context.Background(), r); got.State != facts.StateAbsent {
		t.Errorf("a ref that is not there = %+v, want absent", got)
	}
	// the releases of actions/checkout that refuse a fork's code
	for _, c := range []struct {
		commit, sha string
		want        bool
	}{
		{"11d5960a326750d5838078e36cf38b85af677262", "11bd71901bbe5b1630ceea73d27597364c9af683", false}, // v4.4.0 ... v4.2.2: behind
		{"9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "3d3c42e5aac5ba805825da76410c181273ba90b1", true},  // v7.0.0 ... v7.0.1: ahead
		{"9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "11d5960a326750d5838078e36cf38b85af677262", false}, // v7.0.0 ... v4.4.0: diverged
		{"11d5960a326750d5838078e36cf38b85af677262", "11d5960a326750d5838078e36cf38b85af677262", true},  // identical
	} {
		commit, _ := facts.ParseSHA(c.commit)
		sha, _ := facts.ParseSHA(c.sha)
		if got := (facts.GitCommitContains{Repo: repo, SHA: sha, Commit: commit}).Ask(context.Background(), r); got.State != facts.StateFound || got.Value != c.want {
			t.Errorf("%s in the history of %s = %+v, want %v", c.commit, c.sha, got, c.want)
		}
	}
	if got := (facts.RepoPublic{Repo: repo}).Ask(context.Background(), r); got.State != facts.StateFound || !got.Value {
		t.Errorf("repo.public of actions/checkout = %+v", got)
	}
	// actions/create-release is archived, and its v1 declares node12; v5 of
	// actions/checkout declares node24
	release, _ := facts.ParseRepo("actions/create-release")
	if got := (facts.RepoArchived{Repo: release}).Ask(context.Background(), r); got.State != facts.StateFound || !got.Value {
		t.Errorf("repo.archived of %s = %+v", release, got)
	}
	if got := (facts.RepoArchived{Repo: repo}).Ask(context.Background(), r); got.State != facts.StateFound || got.Value {
		t.Errorf("repo.archived of %s = %+v", repo, got)
	}
	if got := (facts.ActionRunsUsing{Repo: release, Ref: "v1"}).Ask(context.Background(), r); got.State != facts.StateFound || got.Value != facts.RunsUsingNode12 {
		t.Errorf("action.runs-using of %s@v1 = %+v", release, got)
	}
	if got := (facts.ActionRunsUsing{Repo: repo, Ref: "v5"}).Ask(context.Background(), r); got.State != facts.StateFound || got.Value != facts.RunsUsingNode24 {
		t.Errorf("action.runs-using of %s@v5 = %+v", repo, got)
	}
	// an environment that is not there is 404, read as false of a repository
	// that is seen
	env, _ := facts.ParseEnvironmentName("no-such-environment-sisakulint")
	if got := (facts.RepoEnvironmentProtected{Repo: repo, Environment: env}).Ask(context.Background(), r); got.State != facts.StateFound || got.Value {
		t.Errorf("an environment that is not there = %+v, want false", got)
	}
	// the tags of v4.1.2 of actions/download-artifact, and the advisory of
	// its versions before 4.1.3
	download, _ := facts.ParseRepo("actions/download-artifact")
	v412, _ := facts.ParseSHA("eaceaf801fd36c7dee90939fad912460b18a1ffe")
	if got := (facts.GitCommitTags{Repo: download, SHA: v412}).Ask(context.Background(), r); got.State != facts.StateFound || !slices.ContainsFunc(got.Value, func(n facts.RefName) bool { return n.String() == "refs/tags/v4.1.2" }) {
		t.Errorf("the tags of v4.1.2 = %+v", got)
	}
	pkg, _ := facts.ParsePackageName("actions/download-artifact")
	for v, want := range map[string]bool{"v4.1.2": true, "v4.1.3": false} {
		ver, _ := facts.ParsePackageVersion(v)
		got := facts.PackageAdvisories{Package: pkg, Version: ver}.Ask(context.Background(), r)
		has := slices.ContainsFunc(got.Value, func(a facts.Advisory) bool { return a.GHSAID.String() == "GHSA-cxww-7g56-2vh6" })
		if got.State != facts.StateFound || has != want {
			t.Errorf("the advisories of %s@%s = %+v, want GHSA-cxww-7g56-2vh6 %v", pkg, v, got, want)
		}
	}
	if token == "" {
		t.Log("git.commit-ref past the tips needs a token")
		return
	}
	commitRef := func(sha string) facts.Answer[facts.RefName] {
		s, _ := facts.ParseSHA(sha)
		return facts.GitCommitRef{Repo: repo, SHA: s}.Ask(context.Background(), r)
	}
	if got := commitRef("11bd71901bbe5b1630ceea73d27597364c9af683"); got.State != facts.StateFound {
		t.Errorf("the commit of v4.2.2 = %+v", got)
	}
	// impostor commits:
	// the example of Chainguard, and the one of the Trivy incident
	for _, sha := range []string{"c7d749a2d57b4b375d1ebcd17cfbfb60c676f18e", "70379aad1a8b40919ce8b382d3cd7d0315cde1d0"} {
		if got := commitRef(sha); got.State != facts.StateAbsent {
			t.Errorf("the impostor %s = %+v, want absent", sha, got)
		}
	}
	// a public repository, which has no setting for the pull requests of
	// forks (seen on 2026-10-08), and a private one whose fork pull requests
	// run, which ACTIONS_GITHUB_API_PRIVATE_REPO names (the token must read
	// its settings)
	pub, _ := facts.ParseRepo("on-keyday/brgen")
	if got := (facts.RepoForkPRSecrets{Repo: pub}).Ask(context.Background(), r); got.State != facts.StateAbsent {
		t.Errorf("repo.fork-pr-secrets of %s = %+v, want absent", pub, got)
	}
	repos := []facts.Repo{pub}
	if name := os.Getenv("ACTIONS_GITHUB_API_PRIVATE_REPO"); name == "" {
		t.Log("ACTIONS_GITHUB_API_PRIVATE_REPO names no private repository: its settings are not asked")
	} else {
		priv, err := facts.ParseRepo(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := (facts.RepoForkPRRunWorkflows{Repo: priv}).Ask(context.Background(), r); got.State != facts.StateFound || !got.Value {
			t.Errorf("repo.fork-pr-run-workflows of %s = %+v", priv, got)
		}
		repos = append(repos, priv)
	}
	for _, repo := range repos {
		if got := (facts.RepoAllowForking{Repo: repo}).Ask(context.Background(), r); got.State != facts.StateFound {
			t.Errorf("repo.allow-forking of %s = %+v", repo, got)
		}
	}
}

// liveRunsUsing reads the first using: of a definition, the key of runs in
// the action.yml files TestLive reads; the CLI gives the reader of the
// model.
func liveRunsUsing(b []byte) (facts.RunsUsing, error) {
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "using:"); ok {
			return facts.ParseRunsUsing(strings.ToLower(strings.Trim(strings.TrimSpace(v), `'"`)))
		}
	}
	return facts.RunsUsingUnset, errors.New("no using")
}
