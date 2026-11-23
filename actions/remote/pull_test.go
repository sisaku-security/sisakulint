package remote

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/githubtest"
	"github.com/gh-intel/sisakulint/actions/lint"
)

func paths(ps ...string) []facts.InputPath {
	var out []facts.InputPath
	for _, p := range ps {
		out = append(out, facts.MustCleanInputPath(p))
	}
	return out
}

func TestReadPullRequest(t *testing.T) {
	g := githubtest.NewGit(t)
	root := g.Commit("o/r", "", map[string]githubtest.File{"a.txt": githubtest.Blob("a")})
	head := g.Commit("o/r", "feature", map[string]githubtest.File{"a.txt": githubtest.Blob("b")}, root)
	base := g.Commit("o/r", "main", map[string]githubtest.File{"a.txt": githubtest.Blob("c")}, root)
	g.Pull("o/r", 7, githubtest.PullRequest{Head: head, BaseRef: "main"})
	pr, err := ReadPullRequest(context.Background(), client(g), repo, 7, facts.SHA{})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Number != 7 || pr.Head.String() != head || pr.BaseRef != "main" || pr.Base.String() != base || pr.MergeBase.String() != root || pr.BehindBy != 1 {
		t.Errorf("ReadPullRequest = %+v", pr)
	}
	if _, err := ReadPullRequest(context.Background(), client(g), repo, 7, mustSHA(base)); !errors.Is(err, ErrHeadMoved) {
		t.Errorf("another head: %v, want ErrHeadMoved", err)
	}
	if _, err := ReadPullRequest(context.Background(), client(g), repo, 7, mustSHA(head)); err != nil {
		t.Errorf("the head: %v", err)
	}
	var nf *NotFoundError
	if _, err := ReadPullRequest(context.Background(), client(g), repo, 8, facts.SHA{}); !errors.As(err, &nf) {
		t.Errorf("no pull request: %v", err)
	}
}

func TestChangedPaths(t *testing.T) {
	e := func(mode, sha string) Entry { return Entry{Mode: mode, SHA: mustSHA(strings.Repeat(sha, 40))} }
	from := map[facts.InputPath]Entry{
		facts.MustCleanInputPath("same"):    e("100644", "a"),
		facts.MustCleanInputPath("content"): e("100644", "a"),
		facts.MustCleanInputPath("mode"):    e("100644", "a"),
		facts.MustCleanInputPath("gone"):    e("100644", "a"),
	}
	to := map[facts.InputPath]Entry{
		facts.MustCleanInputPath("same"):    e("100644", "a"),
		facts.MustCleanInputPath("content"): e("100644", "b"),
		facts.MustCleanInputPath("mode"):    e("100755", "a"),
		facts.MustCleanInputPath("new"):     e("100644", "a"),
	}
	if got := ChangedPaths(from, to); !slices.Equal(got, paths("content", "gone", "mode", "new")) {
		t.Errorf("ChangedPaths = %v", got)
	}
}

func TestChangedInputs(t *testing.T) {
	g := githubtest.NewGit(t)
	sub := strings.Repeat("b", 40)
	c := g.Commit("o/r", "main", map[string]githubtest.File{
		".github/workflows/ci.yml":      githubtest.Blob(okWorkflow),
		".github/workflows/sub.yml":     githubtest.Blob("on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./vendor/sub/act\n"),
		"act/action.yml":                githubtest.Symlink("../shared/real.yml"),
		"shared/real.yml":               githubtest.Blob(okAction),
		"vendored/x/action.yml":         githubtest.Blob(okAction),
		"vendor/sub":                    githubtest.Submodule(sub),
		".github/dependabot.yml":        githubtest.Blob("version: 2\nupdates: []\n"),
		".github/workflows/renamed.yml": githubtest.Blob(okWorkflow),
	})
	tree := open(t, g, c, Limits{})
	ex, _ := lint.ParseExclude("vendored")
	in, err := lint.EnumerateExcept(tree, []lint.Exclude{ex})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.Open(".github/dependabot.yml"); err != nil { // as repofile reads it
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		changed []string
		want    ChangedSet
	}{
		{"a workflow", []string{".github/workflows/ci.yml"}, ChangedSet{Inputs: paths(".github/workflows/ci.yml")}},
		{"a renamed one, by its new path; the old path is not an input", []string{".github/workflows/old.yml", ".github/workflows/renamed.yml"}, ChangedSet{Inputs: paths(".github/workflows/renamed.yml")}},
		{"the target of a symlink action", []string{"shared/real.yml"}, ChangedSet{Inputs: paths("act/action.yml")}},
		{"a submodule's commit", []string{"vendor/sub"}, ChangedSet{Inputs: paths(".github/workflows/sub.yml")}},
		{"an input under --exclude", []string{"vendored/x/action.yml"}, ChangedSet{Excluded: paths("vendored/x/action.yml")}},
		{"a file read that is not an input", []string{".github/dependabot.yml"}, ChangedSet{ReadNonInput: true}},
		{"a file not read", []string{"README.md"}, ChangedSet{}},
	} {
		got := ChangedInputs(in, tree, paths(c.changed...))
		if !slices.Equal(got.Inputs, c.want.Inputs) || !slices.Equal(got.Excluded, c.want.Excluded) || got.ReadNonInput != c.want.ReadNonInput {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestBaseChanges(t *testing.T) {
	e := func(sha string) Entry { return Entry{Mode: "100644", SHA: mustSHA(strings.Repeat(sha, 40))} }
	mb := map[facts.InputPath]Entry{facts.MustCleanInputPath("README.md"): e("a"), facts.MustCleanInputPath(".github/labeler.yml"): e("a")}
	base := map[facts.InputPath]Entry{
		facts.MustCleanInputPath("README.md"):                      e("b"),
		facts.MustCleanInputPath(".github/labeler.yml"):            e("b"),
		facts.MustCleanInputPath(".github/workflows/target.yml"):   e("a"),
		facts.MustCleanInputPath(".github/workflows/sub/deep.yml"): e("a"),
		facts.MustCleanInputPath("x/action.yaml"):                  e("a"),
	}
	if got := BaseChanges(mb, base, paths(".github/labeler.yml")); got != 3 {
		t.Errorf("BaseChanges = %d, want 3: the new workflow, the new action, the labeler's file read", got)
	}
}
