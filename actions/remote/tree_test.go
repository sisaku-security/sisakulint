package remote

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/internal/githubapi"
	"github.com/sisaku-security/sisakulint/actions/internal/githubtest"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

const okWorkflow = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
const okAction = "runs:\n  using: composite\n  steps:\n    - run: echo\n      shell: bash\n"

func client(g *githubtest.Git) *githubapi.Client {
	return githubapi.New(githubapi.Options{Token: "t", BaseURL: g.URL(), HTTP: g.Client()})
}

func mustRepo(s string) facts.Repo {
	r, err := facts.ParseRepo(s)
	if err != nil {
		panic(err)
	}
	return r
}

func mustSHA(s string) facts.SHA {
	sha, err := facts.ParseSHA(s)
	if err != nil {
		panic(err)
	}
	return sha
}

var repo = mustRepo("o/r")

func open(t *testing.T, g *githubtest.Git, commit string, l Limits) *Tree {
	t.Helper()
	tree, err := OpenTree(context.Background(), client(g), repo, mustSHA(commit), l)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func names(in lint.Inputs) string {
	var out []string
	for _, i := range in.List {
		out = append(out, i.Name.String()+"="+i.InputKind.String()+"/"+i.State.String())
	}
	return strings.Join(out, " ")
}

// TestTreeEnumeratesAsAMapFS: lint reads the tree as it reads the same
// files on disk.
func TestTreeEnumeratesAsAMapFS(t *testing.T) {
	g := githubtest.NewGit(t)
	c := g.Commit("o/r", "main", map[string]githubtest.File{
		".github/workflows/ci.yml":   githubtest.Blob(okWorkflow),
		".github/workflows/link.yml": githubtest.Symlink("ci.yml"),
		"act/real/action.yml":        githubtest.Blob(okAction),
		"act/action.yml":             githubtest.Symlink("real/action.yml"),
		"sub":                        githubtest.Submodule(strings.Repeat("a", 40)),
		".github/labeler.yml":        githubtest.Blob("x: y\n"),
	})
	tree := open(t, g, c, Limits{})
	got, err := lint.Enumerate(tree)
	if err != nil {
		t.Fatal(err)
	}
	want, err := lint.Enumerate(fstest.MapFS{
		".github/workflows/ci.yml":   {Data: []byte(okWorkflow)},
		".github/workflows/link.yml": {Data: []byte("ci.yml"), Mode: fs.ModeSymlink},
		"act/real/action.yml":        {Data: []byte(okAction)},
		"act/action.yml":             {Data: []byte("real/action.yml"), Mode: fs.ModeSymlink},
		"sub":                        {Mode: fs.ModeDir},
		".github/labeler.yml":        {Data: []byte("x: y\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if names(got) != names(want) {
		t.Errorf("Enumerate(tree) =\n%s\nwant\n%s", names(got), names(want))
	}
	if subs := tree.Submodules(); len(subs) != 1 || subs[0].String() != "sub" {
		t.Errorf("Submodules = %v", subs)
	}
	if hops := tree.Hops(facts.MustCleanInputPath("act/action.yml")); len(hops) != 2 || hops[1].String() != "act/real/action.yml" {
		t.Errorf("Hops(act/action.yml) = %v, want the link and act/real/action.yml", hops)
	}
	if tree.SHA() == (facts.SHA{}) || tree.Commit().String() != c {
		t.Errorf("SHA %v, Commit %v", tree.SHA(), tree.Commit())
	}
	var paths []string
	for _, f := range tree.ReadFiles() {
		paths = append(paths, f.Path.String()+":"+f.Mode)
	}
	if want := ".github/workflows/ci.yml:100644 act/action.yml:120000 act/real/action.yml:100644"; strings.Join(paths, " ") != want {
		t.Errorf("ReadFiles = %v, want %s", paths, want)
	}
}

func TestOpenTreeErrors(t *testing.T) {
	g := githubtest.NewGit(t)
	c := g.Commit("o/r", "main", map[string]githubtest.File{"a.txt": githubtest.Blob("a")})
	g.Truncate(c)
	if _, err := OpenTree(context.Background(), client(g), repo, mustSHA(c), Limits{}); !errors.Is(err, ErrTruncated) {
		t.Errorf("truncated: %v", err)
	}
	var nf *NotFoundError
	if _, err := OpenTree(context.Background(), client(g), mustRepo("o/none"), mustSHA(c), Limits{}); !errors.As(err, &nf) {
		t.Errorf("no repository: %v", err)
	}
	if _, err := ResolveCommit(context.Background(), client(g), repo, "nope"); !errors.As(err, &nf) {
		t.Errorf("no ref: %v", err)
	}
	if sha, err := ResolveCommit(context.Background(), client(g), repo, ""); err != nil || sha.String() != c {
		t.Errorf("the default branch: %v %v", sha, err)
	}
}

func TestTreeLimits(t *testing.T) {
	g := githubtest.NewGit(t)
	big := strings.Repeat("#", 2<<20)
	files := map[string]githubtest.File{".github/workflows/big.yml": githubtest.Blob(big)}
	for _, n := range []string{"a", "b", "c", "d"} {
		files[".github/actions/"+n+"/action.yml"] = githubtest.Blob(okAction + "# " + n + "\n")
	}
	files[".github/workflows/w.yml"] = githubtest.Blob(okWorkflow)
	c := g.Commit("o/r", "main", files)
	g.FailBlob(okAction+"# b\n", http.StatusInternalServerError)
	// the tree is one request; 3 blobs are left
	tree := open(t, g, c, Limits{MaxRequests: 4, MaxBlobBytes: 1 << 20})
	tree.Prefetch([]facts.InputPath{facts.MustCleanInputPath(".github/workflows/w.yml")})
	in, err := lint.Enumerate(tree)
	if err != nil {
		t.Fatal(err)
	}
	want := ".github/actions/a/action.yml=action-metadata/read .github/actions/b/action.yml=action-metadata/unreadable .github/actions/c/action.yml=action-metadata/unreadable .github/actions/d/action.yml=action-metadata/unreadable .github/workflows/big.yml=workflow/unreadable .github/workflows/w.yml=workflow/read"
	if got := names(in); got != want {
		t.Errorf("Enumerate =\n%s\nwant\n%s", got, want)
	}
	for _, i := range in.List {
		if i.State == lint.InputStateUnreadable && i.Reason == "" {
			t.Errorf("%s: no reason", i.Name)
		}
	}
	if u := tree.Unread(); len(u) != 4 {
		t.Errorf("Unread = %v, want the 4 not read", u)
	}
}

func TestTreeEntries(t *testing.T) {
	g := githubtest.NewGit(t)
	c := g.Commit("o/r", "main", map[string]githubtest.File{"a.txt": githubtest.Blob("a"), "../x": githubtest.Blob("x")})
	tree := open(t, g, c, Limits{})
	e := tree.Entries()
	if _, ok := e[facts.MustCleanInputPath("a.txt")]; !ok || len(e) != 1 {
		t.Errorf("Entries = %v, want a.txt only (a path with .. is no path of the tree)", e)
	}
	listed, err := ListTree(context.Background(), client(g), repo, mustSHA(c))
	if err != nil || len(listed) != 1 {
		t.Errorf("ListTree = %v %v", listed, err)
	}
}
