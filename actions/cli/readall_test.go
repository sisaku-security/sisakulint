package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readAllRepo is a repository where caller.yml gives the title of an
// issue to called.yml, which writes it into a run script, and other.yml
// writes the title of an issue into a run script by itself: the finding of
// called.yml is where the value is used, its evidence where caller.yml
// gives it.
func readAllRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		".github/workflows/caller.yml": "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n",
		".github/workflows/called.yml": "on:\n  workflow_call:\n    inputs:\n      t:\n        type: string\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n",
		".github/workflows/other.yml":  "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n",
		"x/action.yml":                 "runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n",
		"README.md":                    "hi\n",
	}
	for n, s := range files {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type readAllReport struct {
	Inputs   []struct{ Name string } `json:"inputs"`
	Reported []string                `json:"reported_inputs"`
	Findings []struct {
		Rule     string `json:"rule"`
		Location struct {
			File struct{ Input string } `json:"file"`
		} `json:"location"`
	} `json:"findings"`
}

func readAllRun(t *testing.T, a ...string) (readAllReport, result) {
	t.Helper()
	got := run(t, args(a...))
	var rep readAllReport
	if got.code < ExitUsage {
		if err := json.Unmarshal([]byte(got.stdout), &rep); err != nil {
			t.Fatalf("%v: %v\n%s", a, err, got.stdout)
		}
	}
	return rep, got
}

func TestReadAll(t *testing.T) {
	dir := readAllRepo(t)
	for _, path := range []string{".github/workflows/caller.yml", ".github/workflows/called.yml"} {
		rep, got := readAllRun(t, "--root", dir, "--rule", "code-injection", "--read-all", path)
		if got.code != 1 {
			t.Errorf("%s: exit %d, want 1; stderr %s", path, got.code, got.stderr)
		}
		if len(rep.Reported) != 1 || rep.Reported[0] != path {
			t.Errorf("%s: reported_inputs %v", path, rep.Reported)
		}
		if len(rep.Inputs) != 4 {
			t.Errorf("%s: %d inputs, want the 4 read", path, len(rep.Inputs))
		}
		if len(rep.Findings) != 1 || rep.Findings[0].Location.File.Input != ".github/workflows/called.yml" {
			t.Errorf("%s: findings %+v, want the one of called.yml (other.yml's is not reported)", path, rep.Findings)
		}
	}
	// text and line write the places of the PATHs only: other.yml's finding is
	// not reported.
	for _, format := range []string{"text", "line"} {
		got := run(t, raw("--root", dir, "--rule", "code-injection", "--format", format, "--read-all", ".github/workflows/caller.yml"))
		if !strings.Contains(got.stdout, "called.yml") || strings.Contains(got.stdout, "other.yml") {
			t.Errorf("--format %s: want called.yml and not other.yml in\n%s", format, got.stdout)
		}
	}
	// Without --read-all, the PATH caller.yml alone gives nothing.
	if rep, got := readAllRun(t, "--root", dir, "--rule", "code-injection", ".github/workflows/caller.yml"); len(rep.Findings) != 0 || got.code != 0 {
		t.Errorf("caller.yml alone: %d findings, exit %d; want none and 0", len(rep.Findings), got.code)
	}
}

func TestReadAllCountsOnlyThePaths(t *testing.T) {
	dir := readAllRepo(t)
	if err := os.WriteFile(filepath.Join(dir, ".github/workflows/other.yml"), []byte("on: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, got := readAllRun(t, "--root", dir, "--rule", "code-injection", "--read-all", ".github/workflows/caller.yml"); got.code != 1 {
		t.Errorf("an invalid input not reported: exit %d, want 1 (bit 16 not set)", got.code)
	}
	if _, got := readAllRun(t, "--root", dir, "--rule", "code-injection"); got.code&16 == 0 {
		t.Errorf("the whole repository: exit %d, want bit 16 for the invalid input", got.code)
	}
	text := run(t, raw("--root", dir, "--rule", "code-injection", "--read-all", ".github/workflows/caller.yml"))
	if !strings.Contains(text.stdout, "the PATHs of --read-all; 3 more inputs under --root, not reported") {
		t.Errorf("the text does not say what else was read:\n%s", text.stdout)
	}
	line := run(t, raw("--root", dir, "--rule", "code-injection", "--format", "line", "--read-all", ".github/workflows/caller.yml"))
	for _, out := range []string{text.stdout, line.stdout} {
		if strings.Contains(out, "not valid") || strings.Contains(out, "invalid") || strings.Contains(out, "other.yml") {
			t.Errorf("the output names an input not reported:\n%s", out)
		}
	}
}

func TestReadAllExclude(t *testing.T) {
	dir := readAllRepo(t)
	rep, got := readAllRun(t, "--root", dir, "--rule", "code-injection", "--exclude", "x", "--read-all", ".github/workflows/caller.yml")
	if got.code != 1 || len(rep.Findings) != 1 {
		t.Errorf("--exclude with --read-all: exit %d, %d findings; stderr %s", got.code, len(rep.Findings), got.stderr)
	}
}

func TestReadAllUsage(t *testing.T) {
	dir := readAllRepo(t)
	caller := ".github/workflows/caller.yml"
	for _, c := range []struct {
		name string
		a    []string
		code int
	}{
		{"no PATH", []string{"--root", dir, "--read-all"}, ExitUsage},
		{"stdin", []string{"--read-all", "--stdin-name", caller, caller}, ExitUsage},
		{"not an input", []string{"--root", dir, "--read-all", "README.md"}, ExitUsage},
		{"excluded", []string{"--root", dir, "--exclude", "x", "--read-all", "x/action.yml"}, ExitUsage},
		{"given twice", []string{"--root", dir, "--read-all", caller, caller}, ExitUsage},
		{"missing", []string{"--root", dir, "--read-all", ".github/workflows/none.yml"}, ExitNoInput},
		{"a directory", []string{"--root", dir, "--read-all", ".github"}, ExitNoInput},
	} {
		got := run(t, raw(c.a...))
		if got.code != c.code || got.stdout != "" {
			t.Errorf("%s: exit %d, stdout %q; want %d and nothing (stderr %s)", c.name, got.code, got.stdout, c.code, got.stderr)
		}
	}
}

// TestReadAllFix: --read-all applies the fixes of the findings it reports,
// which may write a file that is not a PATH.
func TestReadAllFix(t *testing.T) {
	dir := readAllRepo(t)
	before, _ := os.ReadFile(filepath.Join(dir, ".github/workflows/other.yml"))
	if got := run(t, raw("--root", dir, "--rule", "code-injection", "--fix=review", "--read-all", ".github/workflows/caller.yml")); got.code >= ExitUsage {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	called, _ := os.ReadFile(filepath.Join(dir, ".github/workflows/called.yml"))
	other, _ := os.ReadFile(filepath.Join(dir, ".github/workflows/other.yml"))
	if !strings.Contains(string(called), "env:") || string(other) != string(before) {
		t.Errorf("--read-all caller.yml: called.yml\n%s\nother.yml\n%s\nwant called.yml fixed and other.yml as it was", called, other)
	}
}
