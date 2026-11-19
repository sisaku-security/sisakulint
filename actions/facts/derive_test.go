package facts

import (
	"context"
	"slices"
	"testing"
)

func TestParseRefName(t *testing.T) {
	for _, s := range []string{"refs/heads/main", "refs/heads/releases/v4", "refs/tags/v4"} {
		if r, err := ParseRefName(s); err != nil || r.String() != s {
			t.Errorf("ParseRefName(%q) = %v, %v", s, r, err)
		}
	}
	for _, s := range []string{"", "main", "v4", "refs/pull/1/head", "refs/tags/", "refs/heads/", "heads/main",
		// git check-ref-format: revisions and what no ref name has
		"refs/heads/main~1", "refs/heads/main^", "refs/tags/v1@{1}", "refs/heads/a..b", "refs/heads/a:b", "refs/heads/a b",
		"refs/heads/a?", "refs/heads/a*", "refs/heads/a[", `refs/heads/a\b`, "refs/heads/a.lock", "refs/heads/a.", "refs/heads/a//b",
		"refs/heads/.a", "refs/heads/a/", "refs/heads/@", "refs/heads/a\x01"} {
		if _, err := ParseRefName(s); err == nil {
			t.Errorf("ParseRefName(%q): no error", s)
		}
	}
}

// TestStoreDerivesCommitRef: a file of facts that says which ref the
// runner runs for repo@ref, and that it is at sha, says that ref has sha.
func TestStoreDerivesCommitRef(t *testing.T) {
	const (
		shaA = "11bd71901bbe5b1630ceea73d27597364c9af683"
		shaB = "ee770a9615648ecfcf3ca4bf8b549375d3be713e"
	)
	st, err := LoadStore([]byte(`{"schema": "sisakulint/facts/v0", "facts": [
		{"query": {"kind": "git.ref-commit", "repo": "actions/checkout", "ref": "v4"}, "state": "found", "value": {"sha": "` + shaA + `", "ref": "refs/tags/v4"}},
		{"query": {"kind": "git.ref-commit", "repo": "actions/checkout", "ref": "main"}, "state": "found", "value": {"sha": "` + shaA + `", "ref": "refs/heads/main"}},
		{"query": {"kind": "git.ref-commit", "repo": "actions/checkout", "ref": "` + shaB + `"}, "state": "found", "value": {"sha": "` + shaB + `"}},
		{"query": {"kind": "git.ref-commit", "repo": "actions/checkout", "ref": "v5"}, "state": "found", "value": {"sha": "` + shaB + `", "ref": "refs/tags/v5"}},
		{"query": {"kind": "git.ref-commit", "repo": "a/commit", "ref": "` + shaA + `"}, "state": "found", "value": {"sha": "` + shaA + `"}},
		{"query": {"kind": "git.ref-commit", "repo": "other/repo", "ref": "v1"}, "state": "found", "value": {"sha": "` + shaB + `", "ref": "refs/tags/v1"}},
		{"query": {"kind": "git.commit-ref", "repo": "other/repo", "sha": "` + shaB + `"}, "state": "absent"},
		{"query": {"kind": "git.commit-ref", "repo": "actions/checkout", "sha": "` + shaB + `"}, "state": "unknown", "reason": "rate limited"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	ask := func(repo, sha string) Answer[RefName] {
		s, _ := ParseSHA(sha)
		return GitCommitRef{Repo: mustRepo(t, repo), SHA: s}.Ask(context.Background(), st)
	}
	if got := ask("Actions/Checkout", shaA); got.State != StateFound || got.Value.String() != "refs/heads/main" {
		t.Errorf("two refs at sha = %+v, want the first by name", got)
	}
	if got := ask("actions/checkout", shaB); got.State != StateUnknown || got.Reason != "rate limited" {
		t.Errorf("unknown in the file = %+v: a replay answers as the run it records", got)
	}
	if got := ask("a/commit", shaA); got.State != StateUnknown {
		t.Errorf("a full SHA found as a commit = %+v: a commit is no ref's", got)
	}
	if got := ask("another/repo", shaA); got.State != StateUnknown {
		t.Errorf("another repository = %+v", got)
	}
	if got := ask("other/repo", shaB); got.State != StateAbsent {
		t.Errorf("what the file says = %+v, want it over what is derived", got)
	}
}

// TestStoreAnsweredKinds: the kinds a file answers, with git.commit-ref
// when a found git.ref-commit has a ref to derive it from.
func TestStoreAnsweredKinds(t *testing.T) {
	const sha = "11bd71901bbe5b1630ceea73d27597364c9af683"
	load := func(entries string) []Kind {
		st, err := LoadStore([]byte(`{"schema": "sisakulint/facts/v0", "facts": [` + entries + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		return st.AnsweredKinds()
	}
	tag := `{"query": {"kind": "git.ref-commit", "repo": "actions/checkout", "ref": "v4"}, "state": "found", "value": {"sha": "` + sha + `", "ref": "refs/tags/v4"}}`
	commit := `{"query": {"kind": "git.ref-commit", "repo": "a/commit", "ref": "` + sha + `"}, "state": "found", "value": {"sha": "` + sha + `"}}`
	public := `{"query": {"kind": "repo.public", "repo": "o/r"}, "state": "absent"}`
	unknown := `{"query": {"kind": "package.advisories", "package": "actions/checkout"}, "state": "unknown", "reason": "offline"}`
	commitRef := `{"query": {"kind": "git.commit-ref", "repo": "o/r", "sha": "` + sha + `"}, "state": "absent"}`
	for _, c := range []struct {
		name, entries string
		want          []Kind
	}{
		{"none", ``, nil},
		{"found and absent, not unknown", public + "," + unknown, []Kind{KindRepoPublic}},
		{"a ref to derive from", tag, []Kind{KindGitRefCommit, KindGitCommitRef}},
		{"a commit only: nothing to derive", commit, []Kind{KindGitRefCommit}},
		{"git.commit-ref once", tag + "," + commitRef, []Kind{KindGitCommitRef, KindGitRefCommit}},
	} {
		if got := load(c.entries); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
