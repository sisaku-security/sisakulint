package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// example is a copy of the example of every rule (actions/rules/testdata/all-rules).
func example(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "rules", "testdata", "all-rules"))); err != nil {
		t.Fatal(err)
	}
	return dir
}

// --dry-run writes nothing and gives, on stdout, the diff of what --fix
// would write; git apply of it writes what --fix writes.
func TestDryRun(t *testing.T) {
	dir := example(t)
	wf := ".github/workflows/all-rules.yml"
	before := read(t, dir, wf)
	facts := filepath.Join(dir, "facts.json")
	got := run(t, raw("--root", dir, "--facts", facts, "--fix=review", "--dry-run"))
	plain := run(t, raw("--root", dir, "--facts", facts))
	if got.code != plain.code || got.stderr != "" {
		t.Errorf("exit %d (without --fix %d), stderr %q", got.code, plain.code, got.stderr)
	}
	if read(t, dir, wf) != before {
		t.Fatal("--dry-run wrote the file")
	}
	golden(t, "dryrun.golden.diff", got.stdout)

	fixed := example(t)
	if r := run(t, raw("--root", fixed, "--facts", filepath.Join(fixed, "facts.json"), "--fix=review")); r.code == ExitFix {
		t.Fatalf("--fix: %s", r.stderr)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	cmd := exec.Command(git, "apply", "-")
	cmd.Dir, cmd.Stdin = dir, strings.NewReader(got.stdout)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git apply: %v %s", err, out)
	}
	if read(t, dir, wf) != read(t, fixed, wf) {
		t.Errorf("git apply of the diff wrote\n%s\n--fix wrote\n%s", read(t, dir, wf), read(t, fixed, wf))
	}
}

func TestDryRunUsage(t *testing.T) {
	dir := example(t)
	for _, a := range [][]string{
		{"--root", dir, "--dry-run"},
		{"--root", dir, "--fix", "--dry-run", "--format", "json"},
		{"--stdin-name", "w.yml", "--dry-run"},
	} {
		if r := run(t, raw(a...)); r.code != ExitUsage {
			t.Errorf("%v: exit %d", a, r.code)
		}
	}
}

// The report of --report says no fix, as nothing is written.
func TestDryRunReport(t *testing.T) {
	dir := example(t)
	file := filepath.Join(t.TempDir(), "r.json")
	run(t, raw("--root", dir, "--facts", filepath.Join(dir, "facts.json"), "--fix", "--dry-run", "--report", file))
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Fix json.RawMessage `json:"fix"`
	}
	if err := json.Unmarshal(b, &rep); err != nil || rep.Fix != nil {
		t.Errorf("the report has what came of the fixes (%v):\n%s", err, b)
	}
}

// The text says what fact a finding holds by, and where its answer comes
// from.
func TestTextFacts(t *testing.T) {
	dir := example(t)
	got := run(t, raw("--root", dir, "--facts", filepath.Join(dir, "facts.json"), "--color=never"))
	const want = "  fact: git.commit-ref repo=actions/checkout sha=70379aad1a8b40919ce8b382d3cd7d0315cde1d0 = absent (the file of facts)\n"
	if !strings.Contains(got.stdout, want) {
		t.Errorf("no %q in\n%s", want, got.stdout)
	}
}

// --dry-run fails where --fix fails: a symlink is not written.
func TestDryRunSymlink(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	if err := os.MkdirAll(a, 0o755); err != nil {
		t.Fatal(err)
	}
	const action = "name: a\ndescription: d\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n"
	if err := os.WriteFile(filepath.Join(a, "real.yml"), []byte(action), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.yml", filepath.Join(a, "action.yml")); err != nil {
		t.Fatal(err)
	}
	facts := filepath.Join("..", "rules", "testdata", "all-rules", "facts.json")
	if r := run(t, raw("--root", dir, "--facts", facts, "--fix=review")); r.code != ExitFix {
		t.Fatalf("--fix: exit %d, %s", r.code, r.stderr)
	}
	r := run(t, raw("--root", dir, "--facts", facts, "--fix=review", "--dry-run"))
	if r.code != ExitFix || r.stdout != "" {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
}
