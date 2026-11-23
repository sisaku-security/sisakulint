package cli

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/internal/githubtest"
)

// filesOf are the files under dir, as a commit of githubtest.Git has
// them: a symlink by its target.
func filesOf(t *testing.T, dir string) map[string]githubtest.File {
	t.Helper()
	files := map[string]githubtest.File{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			files[rel] = githubtest.Symlink(filepath.ToSlash(target))
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[rel] = githubtest.Blob(string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// withoutRevision is the JSON report without remote_revision.
func withoutRevision(t *testing.T, s string) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("%v:\n%s", err, s)
	}
	delete(v, "remote_revision")
	return v
}

func revisionOf(t *testing.T, s string) map[string]any {
	t.Helper()
	var v struct {
		Remote map[string]any `json:"remote_revision"`
	}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v.Remote
}

func remoteRepo(t *testing.T) (*githubtest.Git, string, string) {
	t.Helper()
	dir := repo(t)
	g := githubtest.NewGit(t)
	c := g.Commit("o/r", "main", filesOf(t, dir))
	return g, c, dir
}

func TestRemoteSameAsRoot(t *testing.T) {
	g, _, dir := remoteRepo(t)
	api := g.URL().String()
	for _, extra := range [][]string{nil, {"--exclude", ".github/actions"}} {
		local := run(t, args(append([]string{"--root", dir, "--repo", "o/r"}, extra...)...))
		remote := run(t, args(append([]string{"--remote", "o/r", "--github-api", api}, extra...)...))
		if local.code != remote.code {
			t.Errorf("%v: exit %d with --root, %d with --remote (%s)", extra, local.code, remote.code, remote.stderr)
		}
		l, r := withoutRevision(t, local.stdout), withoutRevision(t, remote.stdout)
		lb, _ := json.Marshal(l)
		rb, _ := json.Marshal(r)
		if string(lb) != string(rb) {
			t.Errorf("%v: the reports differ:\n--root   %s\n--remote %s", extra, lb, rb)
		}
	}
	pathLocal := run(t, args("--root", dir, "--repo", "o/r", "--read-all", ".github/workflows/ci.yml"))
	pathRemote := run(t, args("--remote", "o/r", "--github-api", api, "--read-all", ".github/workflows/ci.yml"))
	lb, _ := json.Marshal(withoutRevision(t, pathLocal.stdout))
	rb, _ := json.Marshal(withoutRevision(t, pathRemote.stdout))
	if string(lb) != string(rb) || pathLocal.code != pathRemote.code {
		t.Errorf("--read-all: the reports differ:\n--root   %s\n--remote %s", lb, rb)
	}
}

func TestRemoteRevision(t *testing.T) {
	g, c, _ := remoteRepo(t)
	got := run(t, args("--remote", "o/r@main", "--github-api", g.URL().String()))
	rev := revisionOf(t, got.stdout)
	if rev["repository"] != "o/r" || rev["ref"] != "main" || rev["commit"] != c || rev["tree"] == nil || rev["pull_request"] != nil {
		t.Errorf("remote_revision = %v", rev)
	}
	files, _ := rev["read_files"].([]any)
	if len(files) == 0 {
		t.Fatalf("no read_files in %v", rev)
	}
	first := files[0].(map[string]any)
	if first["path"] == nil || first["blob"] == nil || first["mode"] == nil {
		t.Errorf("read_files[0] = %v", first)
	}
	local := run(t, args("--root", repo(t)))
	if rev := revisionOf(t, local.stdout); rev != nil {
		t.Errorf("a local run has remote_revision %v, want null", rev)
	}
	text := run(t, raw("--remote", "o/r", "--github-api", g.URL().String()))
	if !strings.HasPrefix(text.stdout, "remote  o/r at "+c+"\n") {
		t.Errorf("the text does not start with the repository and the commit:\n%s", text.stdout)
	}
}

func TestRemoteUsage(t *testing.T) {
	g, _, _ := remoteRepo(t)
	api := g.URL().String()
	for _, a := range [][]string{
		{"--remote", "o/r", "--github-api", api, "--root", "."},
		{"--remote", "o/r", "--github-api", api, "--stdin-name", "x.yml"},
		{"--remote", "o/r", "--github-api", api, "--repo", "o/r"},
		{"--remote", "o/r", "--github-api", api, "--fix"},
		{"--remote", "o", "--github-api", api},
		{"--remote", "o/r@", "--github-api", api},
		{"--remote", "https://github.com/o/r", "--github-api", api},
		{"--remote", "https://example.com/o/r"},
		{"--remote", "https://github.com/o/r/blob/main/x"},
		{"--remote", "https://github.com/o/r/pull/x"},
		{"--github-api", api},
	} {
		got := run(t, raw(a...))
		if got.code != ExitUsage || got.stdout != "" {
			t.Errorf("%v: exit %d, stdout %q; want %d and nothing", a, got.code, got.stdout, ExitUsage)
		}
	}
}

func TestRemoteNoInput(t *testing.T) {
	g, c, dir := remoteRepo(t)
	api := g.URL().String()
	trunc := g.Commit("o/r", "big", map[string]githubtest.File{"a.txt": githubtest.Blob("a")})
	g.Truncate(trunc)
	files := filesOf(t, dir)
	files[".github/dependabot.yml"] = githubtest.Blob("version: 2\nupdates: []\n")
	g.Commit("o/r", "labels", files, c)
	g.FailBlob("version: 2\nupdates: []\n", http.StatusInternalServerError)
	for _, a := range [][]string{
		{"--remote", "o/none"},
		{"--remote", "o/r@nope"},
		{"--remote", "o/r@big"},
		{"--remote", "o/r@labels"},
	} {
		got := run(t, args(append(a, "--github-api", api)...))
		if got.code != ExitNoInput || got.stdout != "" {
			t.Errorf("%v: exit %d, %d bytes on stdout, stderr %q; want %d and nothing", a, got.code, len(got.stdout), got.stderr, ExitNoInput)
		}
	}
}

func TestRemoteURLForms(t *testing.T) {
	g, c, _ := remoteRepo(t)
	api := g.URL()
	web := "http://" + api.Host
	for _, v := range []string{web + "/o/r", web + "/o/r/", web + "/o/r.git", web + "/o/r/tree/main", strings.ToUpper("http://"+api.Host) + "/o/r?x=1#y", "https://" + api.Host + "/o/r"} {
		got := run(t, args("--remote", v, "--github-api", api.String()))
		if got.code == ExitUsage || got.code == ExitNoInput || revisionOf(t, got.stdout)["commit"] != c {
			t.Errorf("%s: exit %d, %s", v, got.code, got.stderr)
		}
	}
	if got := run(t, args("--remote", web+"/o/r/tree/main/dir", "--github-api", api.String())); got.code != ExitNoInput {
		t.Errorf("/tree/main/dir: exit %d, want %d (the ref main/dir is not there)", got.code, ExitNoInput)
	}
	ghes := run(t, args("--remote", web+"/o/r", "--github-api", api.String()+"/api/v3"))
	if ghes.code == ExitUsage || ghes.code == ExitNoInput {
		t.Errorf("GHES: exit %d, %s", ghes.code, ghes.stderr)
	}
}

func TestRemoteToken(t *testing.T) {
	g, _, _ := remoteRepo(t)
	e := args("--remote", "o/r", "--github-api", g.URL().String())
	got := run(t, e)
	if !strings.Contains(got.stderr, "GITHUB_TOKEN is empty") {
		t.Errorf("no note of the empty token: %q", got.stderr)
	}
	e.Getenv = func(k string) string {
		if k == "GITHUB_TOKEN" {
			return "secret"
		}
		return ""
	}
	before := len(g.Authorizations())
	run(t, e)
	for _, a := range g.Authorizations()[before:] {
		if a != "Bearer secret" {
			t.Errorf("a request without the token: %q", a)
		}
	}
}

// TestRemoteDryRun: --remote --fix --dry-run writes the diff --root --fix
// --dry-run writes of the same files.
func TestRemoteDryRun(t *testing.T) {
	files := prFiles(t)
	g := githubtest.NewGit(t)
	g.Commit("o/r", "main", files)
	local := repoOfFiles(t, files)
	l := run(t, raw("--root", local, "--rule", "code-injection", "--fix=review", "--dry-run"))
	r := run(t, raw("--remote", "o/r", "--github-api", g.URL().String(), "--rule", "code-injection", "--fix=review", "--dry-run"))
	if l.stdout == "" || l.stdout != r.stdout || l.code != r.code {
		t.Errorf("the diffs differ (exit %d, %d):\n--root\n%s\n--remote\n%s\n%s", l.code, r.code, l.stdout, r.stdout, r.stderr)
	}
}
