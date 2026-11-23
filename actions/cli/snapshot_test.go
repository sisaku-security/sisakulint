package cli

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/internal/githubtest"
)

func gitHash(b []byte) string {
	h := sha1.Sum([]byte("blob " + strconv.Itoa(len(b)) + "\x00" + string(b)))
	return hex.EncodeToString(h[:])
}

func TestWriteSnapshot(t *testing.T) {
	files := prFiles(t)
	files["act/real/action.yml"] = githubtest.Blob(injectAction)
	files["act/link/action.yml"] = githubtest.Symlink("../real/action.yml")
	files["outside"] = githubtest.Blob("never read\n")
	g := githubtest.NewGit(t)
	g.Commit("o/r", "main", files)
	dir := filepath.Join(t.TempDir(), "snap")
	remote := run(t, args("--remote", "o/r", "--github-api", g.URL().String(), "--write-snapshot", dir))
	if remote.code >= ExitUsage {
		t.Fatalf("exit %d: %s", remote.code, remote.stderr)
	}
	var written []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			written = append(written, filepath.ToSlash(rel))
			if d.Type()&fs.ModeSymlink != 0 {
				t.Errorf("%s is a symlink", rel)
			}
		}
		return nil
	})
	if strings.Contains(strings.Join(written, " "), "outside") || !strings.Contains(strings.Join(written, " "), "act/link/action.yml") {
		t.Errorf("written %v: want the files read, the symlink's as a file, and not outside", written)
	}
	again := run(t, args("--root", dir, "--repo", "o/r"))
	l, r := withoutRevision(t, again.stdout), withoutRevision(t, remote.stdout)
	lb, _ := json.Marshal(l)
	rb, _ := json.Marshal(r)
	if string(lb) != string(rb) {
		t.Errorf("--root DIR differs from --remote:\n%s\n%s", lb, rb)
	}
	for _, f := range revisionOf(t, remote.stdout)["read_files"].([]any) {
		m := f.(map[string]any)
		if m["mode"] == "120000" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, m["path"].(string)))
		if err != nil || gitHash(b) != m["blob"] {
			t.Errorf("%s: %v, hash %s, want %s", m["path"], err, gitHash(b), m["blob"])
		}
	}
	before := len(g.Requests())
	if got := run(t, args("--remote", "o/r", "--github-api", g.URL().String(), "--write-snapshot", dir)); got.code != ExitUsage || len(g.Requests()) != before {
		t.Errorf("DIR there already: exit %d, %d requests; want %d and none", got.code, len(g.Requests())-before, ExitUsage)
	}
	if got := run(t, args("--root", ".", "--write-snapshot", filepath.Join(t.TempDir(), "x"))); got.code != ExitUsage {
		t.Errorf("--write-snapshot without --remote: exit %d", got.code)
	}
}

func TestWriteSnapshotFix(t *testing.T) {
	files := prFiles(t)
	g := githubtest.NewGit(t)
	g.Commit("o/r", "main", files)
	dir := filepath.Join(t.TempDir(), "snap")
	got := run(t, args("--remote", "o/r", "--github-api", g.URL().String(), "--write-snapshot", dir, "--fix=review", "--rule", "code-injection"))
	if got.code >= ExitUsage {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	local := repoOfFiles(t, files)
	if l := run(t, args("--root", local, "--fix=review", "--rule", "code-injection")); l.code >= ExitUsage {
		t.Fatalf("--root --fix: exit %d", l.code)
	}
	for _, p := range []string{".github/workflows/other.yml", ".github/workflows/called.yml"} {
		a, _ := os.ReadFile(filepath.Join(dir, p))
		b, _ := os.ReadFile(filepath.Join(local, p))
		if string(a) != string(b) || string(a) == files[p].Data {
			t.Errorf("%s: DIR has\n%s\n--root has\n%s", p, a, b)
		}
	}
	var rep struct {
		Fix struct{ Written []string } `json:"fix"`
	}
	json.Unmarshal([]byte(got.stdout), &rep)
	if len(rep.Fix.Written) == 0 {
		t.Errorf("fix.written is empty: %s", got.stdout)
	}
}

func TestWriteSnapshotFixSymlink(t *testing.T) {
	files := maps.Clone(prFiles(t))
	files["act/real/action.yml"] = githubtest.Blob(injectAction)
	files["act/link/action.yml"] = githubtest.Symlink("../real/action.yml")
	delete(files, "act/real/action.yml")
	files["shared/real.yml"] = githubtest.Blob(injectAction)
	files["act/link/action.yml"] = githubtest.Symlink("../../shared/real.yml")
	g := githubtest.NewGit(t)
	g.Commit("o/r", "main", files)
	dir := filepath.Join(t.TempDir(), "snap")
	got := run(t, args("--remote", "o/r", "--github-api", g.URL().String(), "--write-snapshot", dir, "--fix=review", "--rule", "code-injection"))
	if got.code != ExitFix {
		t.Errorf("a fix of a symlink of the tree: exit %d, want %d (%s)", got.code, ExitFix, got.stderr)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "act/link/action.yml"))
	if string(b) != injectAction {
		t.Errorf("the file of the symlink changed:\n%s", b)
	}
}

// repoOfFiles writes files (blobs only) to a new directory.
func repoOfFiles(t *testing.T, files map[string]githubtest.File) string {
	t.Helper()
	dir := t.TempDir()
	for p, f := range files {
		full := filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(f.Data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestWriteSnapshotNotLeftAfterAFailure: a run that stops before writing
// leaves no DIR.
func TestWriteSnapshotNotLeftAfterAFailure(t *testing.T) {
	g := githubtest.NewGit(t)
	dir := filepath.Join(t.TempDir(), "snap")
	if got := run(t, args("--remote", "o/none", "--github-api", g.URL().String(), "--write-snapshot", dir)); got.code != ExitNoInput {
		t.Fatalf("exit %d", got.code)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("%s is left: %v", dir, err)
	}
}
