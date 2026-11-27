package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSkippedCallerOnly: a local reusable workflow whose only caller job
// never runs (pull_request opened, if merged) gives no Finding; one whose
// other caller can run still does.
func TestSkippedCallerOnly(t *testing.T) {
	const callee = "on: workflow_call\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	const skipped = "on:\n  pull_request:\n    types: [opened]\njobs:\n  c:\n    if: github.event.pull_request.merged == true\n    uses: ./.github/workflows/callee.yml\n"
	for _, c := range []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"only caller skipped", map[string]string{"caller.yml": skipped}, false},
		{"another caller runs", map[string]string{"caller.yml": skipped, "other.yml": "on: push\njobs:\n  c:\n    uses: ./.github/workflows/callee.yml\n"}, true},
	} {
		dir := t.TempDir()
		wd := filepath.Join(dir, ".github", "workflows")
		if err := os.MkdirAll(wd, 0o755); err != nil {
			t.Fatal(err)
		}
		c.files["callee.yml"] = callee
		for n, s := range c.files {
			if err := os.WriteFile(filepath.Join(wd, n), []byte(s), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		rep, _ := runText(t, dir)
		got := false
		for _, f := range rep.Findings {
			if f.Location.File.Input.String() == ".github/workflows/callee.yml" {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("%s: a Finding at callee.yml = %v, want %v: %+v", c.name, got, c.want, rep.Findings)
		}
	}
}
