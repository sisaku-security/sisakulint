package cli

import (
	"encoding/json"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

const (
	ciPath     = ".github/workflows/ci.yml"
	actionPath = ".github/actions/build/action.yml"
)

type fixJSON struct {
	Fix *struct {
		Safety  string
		Written []string
		Error   *string
	}
	Findings []struct {
		Fix json.RawMessage
	}
}

func parse(t *testing.T, stdout string) fixJSON {
	t.Helper()
	var r fixJSON
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("not a report: %v\n%s", err, stdout)
	}
	return r
}

func read(t *testing.T, dir, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, p))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// withoutFix is a report as it would be without --fix: what came of the
// fixes is its last member, after errors (a finding's fix is before it).
func withoutFix(stdout string) string {
	e := strings.LastIndex(stdout, `,"errors":`)
	if i := strings.LastIndex(stdout, `,"fix":`); e >= 0 && i > e {
		return stdout[:i] + "}\n"
	}
	return stdout
}

func TestFix(t *testing.T) {
	dir, gh := repo(t), fakeGitHub(t)
	file := filepath.Join(t.TempDir(), "facts.json")
	before := run(t, args("--root", dir, "--online", "--github-api", gh.URL))
	got := run(t, args("--root", dir, "--online", "--github-api", gh.URL, "--write-facts", file, "--fix"))
	r := parse(t, got.stdout)
	if r.Fix == nil || r.Fix.Safety != "safe" || strings.Join(r.Fix.Written, " ") != actionPath+" "+ciPath || r.Fix.Error != nil {
		t.Fatalf("fix = %+v; stderr %s", r.Fix, got.stderr)
	}
	if withoutFix(got.stdout) != before.stdout || got.code != before.code || got.code&int(lint.ConfirmedBit) == 0 {
		t.Errorf("the report is not the one before the fixes: exit %d, not %d\n%s\n%s", got.code, before.code, got.stdout, before.stdout)
	}
	if !strings.Contains(read(t, dir, ciPath), "actions/checkout@"+shaCheckout) || !strings.Contains(read(t, dir, actionPath), "inner/action@"+shaInner) {
		t.Errorf("not fixed:\n%s\n%s", read(t, dir, ciPath), read(t, dir, actionPath))
	}
	after := parse(t, run(t, args("--root", dir, "--facts", file)).stdout)
	for _, f := range after.Findings {
		if f.Fix != nil {
			t.Errorf("after the fixes, a finding with a fix is still there: %s", f.Fix)
		}
	}
}

func TestFixReview(t *testing.T) {
	dir, gh := repo(t), fakeGitHub(t)
	r := parse(t, run(t, args("--root", dir, "--online", "--github-api", gh.URL, "--fix=review")).stdout)
	if r.Fix == nil || r.Fix.Safety != "review" || len(r.Fix.Written) != 2 {
		t.Errorf("fix = %+v", r.Fix)
	}
}

func TestFixKeepsPermissions(t *testing.T) {
	dir, gh := repo(t), fakeGitHub(t)
	for p, m := range map[string]os.FileMode{ciPath: 0o755, actionPath: 0o444} {
		if err := os.Chmod(filepath.Join(dir, p), m); err != nil {
			t.Fatal(err)
		}
	}
	got := run(t, args("--root", dir, "--online", "--github-api", gh.URL, "--fix"))
	if r := parse(t, got.stdout); r.Fix == nil || len(r.Fix.Written) != 2 {
		t.Fatalf("fix = %+v; stderr %s", r.Fix, got.stderr)
	}
	for p, m := range map[string]os.FileMode{ciPath: 0o755, actionPath: 0o444} {
		if st, _ := os.Stat(filepath.Join(dir, p)); st.Mode().Perm() != m {
			t.Errorf("%s: %v, want %v", p, st.Mode().Perm(), m)
		}
	}
}

func TestFixNothing(t *testing.T) {
	clean := t.TempDir()
	if err := os.MkdirAll(filepath.Join(clean, ".github/workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clean, ciPath), []byte("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{"no finding": clean, "no fix known (offline)": repo(t)} {
		old := time.Now().Add(-time.Hour)
		for _, p := range []string{ciPath, actionPath} {
			os.Chtimes(filepath.Join(dir, p), old, old)
		}
		got := run(t, args("--root", dir, "--fix"))
		r := parse(t, got.stdout)
		if r.Fix == nil || len(r.Fix.Written) != 0 || r.Fix.Error != nil || got.code > 7 {
			t.Errorf("%s: exit %d, fix %+v", name, got.code, r.Fix)
		}
		if !strings.Contains(got.stdout, `"fix":{"safety":"safe","written":[],"unchecked_rules":[]}`) {
			t.Errorf("%s: %s", name, got.stdout)
		}
		for _, p := range []string{ciPath, actionPath} {
			if st, err := os.Stat(filepath.Join(dir, p)); err == nil && !st.ModTime().Equal(old) {
				t.Errorf("%s: %s was touched", name, p)
			}
		}
	}
}

// symlinked makes action.yml a symlink to a file beside it.
func symlinked(t *testing.T, dir string) {
	t.Helper()
	a := filepath.Join(dir, actionPath)
	if err := os.Rename(a, filepath.Join(filepath.Dir(a), "real.yml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.yml", a); err != nil {
		t.Fatal(err)
	}
}

func TestFixRefusesSymlink(t *testing.T) {
	dir, gh := repo(t), fakeGitHub(t)
	symlinked(t, dir)
	ci := read(t, dir, ciPath)
	got := run(t, args("--root", dir, "--online", "--github-api", gh.URL, "--fix"))
	r := parse(t, got.stdout)
	if got.code != ExitFix || r.Fix == nil || r.Fix.Error == nil || len(r.Fix.Written) != 0 {
		t.Errorf("exit %d, fix %+v; want %d, an error, nothing written", got.code, r.Fix, ExitFix)
	}
	if read(t, dir, ciPath) != ci {
		t.Error("ci.yml was written, though action.yml was refused")
	}
}

func TestPrecheckChanged(t *testing.T) {
	dir := repo(t)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	in, err := lint.Enumerate(root.FS())
	if err != nil {
		t.Fatal(err)
	}
	out := map[facts.InputPath][]byte{facts.MustCleanInputPath(ciPath): []byte("fixed")}
	if _, err := precheck(root, in, out, nil); err != nil {
		t.Fatalf("precheck of files as they were read: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ciPath), []byte("changed by an editor"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := precheck(root, in, out, nil); err == nil {
		t.Error("precheck takes a file changed since it was read")
	}
}

// TestFixWritesNothingOnAFailure: every file is written to a temporary
// file first, so a directory that cannot be written stops the fixes before
// any file changes.
func TestFixWritesNothingOnAFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a directory without the permission to")
	}
	dir, gh := repo(t), fakeGitHub(t)
	workflows := filepath.Join(dir, ".github/workflows")
	if err := os.Chmod(workflows, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(workflows, 0o755) })
	action := read(t, dir, actionPath)
	got := run(t, args("--root", dir, "--online", "--github-api", gh.URL, "--fix"))
	r := parse(t, got.stdout)
	if got.code != ExitFix || r.Fix == nil || r.Fix.Error == nil || len(r.Fix.Written) != 0 {
		t.Errorf("exit %d, fix %+v; want %d, an error, nothing written", got.code, r.Fix, ExitFix)
	}
	if read(t, dir, actionPath) != action {
		t.Error("action.yml was written")
	}
	noTemporary(t, dir)
}

// TestFixLongName: the temporary file does not take the name of the file
// it replaces, so the longest name a file system takes (255 bytes) is fixed.
func TestFixLongName(t *testing.T) {
	dir, gh := repo(t), fakeGitHub(t)
	long := ".github/workflows/" + strings.Repeat("a", 251) + ".yml"
	if err := os.Rename(filepath.Join(dir, ciPath), filepath.Join(dir, long)); err != nil {
		t.Fatal(err)
	}
	got := run(t, args("--root", dir, "--online", "--github-api", gh.URL, "--fix"))
	if r := parse(t, got.stdout); r.Fix == nil || r.Fix.Error != nil || strings.Join(r.Fix.Written, " ") != actionPath+" "+long {
		t.Errorf("exit %d, fix %+v", got.code, r.Fix)
	}
}

func noTemporary(t *testing.T, dir string) {
	t.Helper()
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && strings.Contains(d.Name(), "sisakulint-tmp") {
			t.Errorf("a temporary file is left: %s", p)
		}
		return nil
	})
}

func TestFixAndWriteFail(t *testing.T) {
	dir, gh := repo(t), fakeGitHub(t)
	symlinked(t, dir)
	base := []string{"--root", dir, "--online", "--github-api", gh.URL, "--fix"}
	if got := run(t, args(append(base, "--write-facts", filepath.Join(t.TempDir(), "no/dir/f.json"))...)); got.code != ExitFix {
		t.Errorf("the fixes and the facts fail: exit %d, want %d", got.code, ExitFix)
	}
	if got := run(t, Env{Args: base, Stdout: failingWriter{}}); got.code != ExitIO {
		t.Errorf("the fixes and stdout fail: exit %d, want %d", got.code, ExitIO)
	}
}

func TestFixUsage(t *testing.T) {
	dir := repo(t)
	ci := read(t, dir, ciPath)
	for _, c := range []struct {
		name string
		env  Env
		says string
	}{
		{"--fix=all", args("--root", dir, "--fix=all"), ""},
		{"--fix=false", args("--root", dir, "--fix=false"), ""},
		{"--fix with stdin", Env{Args: []string{"--fix", "--stdin-name", ciPath}, Stdin: strings.NewReader(ci)}, ""},
		{"--fix after a PATH", args("--root", dir, ciPath, "--fix"), ""},
		{"--fix review", args("--root", dir, "--fix", "review"), "--fix=review"},
	} {
		got := run(t, c.env)
		if got.code != ExitUsage || got.stdout != "" || !strings.Contains(got.stderr, c.says) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d", c.name, got.code, got.stdout, got.stderr, ExitUsage)
		}
	}
	if read(t, dir, ciPath) != ci {
		t.Error("a file was written")
	}
}

func TestStdinOpensNoRoot(t *testing.T) {
	got := run(t, Env{Args: []string{"--root", filepath.Join(t.TempDir(), "nope"), "--stdin-name", ciPath}, Stdin: strings.NewReader("on: push\njobs: {}\n")})
	if got.code > 7 {
		t.Errorf("stdin with a root that is not there: exit %d, stderr %s", got.code, got.stderr)
	}
}
