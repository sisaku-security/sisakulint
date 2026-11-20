package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

func linesOf(t *testing.T, rep lint.Report, in lint.Inputs, color bool) string {
	t.Helper()
	var b bytes.Buffer
	if err := writeLines(&b, rep, in, registry(t), color); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestLineGolden(t *testing.T) {
	rep, in := runText(t, textRepo)
	golden(t, "line.golden", linesOf(t, rep, in, false))
	golden(t, "line-color.golden", linesOf(t, rep, in, true))
}

// lineCount is how many lines --format line writes for rep.
func lineCount(rep lint.Report) int {
	n := len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) + len(rep.QualityFindings) + len(rep.FindingsWith(lint.CertaintyInconclusive)) + len(rep.Errors)
	for _, i := range rep.Inputs {
		switch {
		case i.State == lint.InputStateRead:
		case i.State == lint.InputStateInvalid && len(i.Diagnostics) > 0:
			n += len(i.Diagnostics)
		default:
			n++
		}
	}
	if rep.Fix != nil && rep.Fix.Error != "" {
		n++
	}
	return n
}

// Each finding, of every certainty, is a line that starts where it is, in
// the order of the report; then the quality findings, the inputs, the
// errors, and why the fixes failed.
func TestLineCount(t *testing.T) {
	rep, in := runText(t, textRepo)
	rep.Errors = []lint.RunError{{Message: "broke\x1b[2J"}, {Rule: lint.MustRuleID("commit-sha"), Input: facts.MustCleanInputPath("a.yml"), Message: "again"}}
	rep.Fix = &lint.FixResult{Safety: lint.SafetySafe, Error: "b.yml: permission denied"}
	got := linesOf(t, rep, in, false)
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != lineCount(rep) {
		t.Fatalf("%d lines, want %d:\n%s", len(lines), lineCount(rep), got)
	}
	for i, r := range rep.Findings {
		x, _ := in.Lookup(r.Location.File.Input)
		pos := x.Tree.Position(r.Location.Span.Start)
		if want := fmt.Sprintf("%s:%d:%d: %s %s: ", r.Location.File.Input, pos.Line, pos.Column, r.Severity, r.KindText()); !strings.HasPrefix(lines[i], want) {
			t.Errorf("line %d = %q, want it to start with %q", i, lines[i], want)
		}
	}
	for _, want := range []string{
		".github/workflows/bad.yml:",
		`sisakulint: error: broke\x1b[2J`,
		"sisakulint: error: commit-sha a.yml: again",
		"sisakulint: fix: b.yml: permission denied",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
}

func TestLineTags(t *testing.T) {
	rep, in := runText(t, textRepo)
	got := linesOf(t, rep, in, false)
	for _, want := range []string{
		"and an attacker controls it on issues [--fix=review]\n",
		"controls it on gollum [assumed repo.wiki-open = true, --fix=review]\n",
		"is not pinned to a full commit SHA [via alias at 10:15]\n",
		" [conditional]\n",
		".github/workflows/pins.yml:7:32: high commit-sha.unpinned: actions/setup-go@v5 is not pinned to a full commit SHA\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	for i := range rep.Findings {
		if rep.Findings[i].Certainty != lint.CertaintyInconclusive {
			rep.Findings[i].Location.Exact = false
			break
		}
	}
	if got := linesOf(t, rep, in, false); !strings.Contains(strings.SplitN(got, "\n", 2)[0], "not exact]") {
		t.Errorf("a place not exact is not tagged:\n%s", got)
	}
}

// TestLineColonInPath: a path with a colon in it, in --format line.
func TestLineColonInPath(t *testing.T) {
	src := []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/setup-go@v5\npermissions: {}\n")
	in, err := lint.Single(lint.InputBytes{Name: facts.MustCleanInputPath(".github/workflows/a: b.yml"), Bytes: src})
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(t.Context(), in, registry(t), facts.Assume(offline{}))
	got := linesOf(t, rep, in, false)
	if strings.Count(got, "\n") != lineCount(rep) || !strings.HasPrefix(got, ".github/workflows/a: b.yml:6:") {
		t.Errorf("not a line a finding starting with its place:\n%s", got)
	}
}

// TestLineUnknownPosition: a place with no line and column, in --format
// line.
func TestLineUnknownPosition(t *testing.T) {
	rep, _ := runText(t, textRepo)
	got := linesOf(t, rep, lint.Inputs{}, false) // the inputs are not there: no line and column
	if !strings.Contains(got, ":@") || strings.Count(got, "\n") != lineCount(rep) {
		t.Errorf("a place with no position:\n%s", got)
	}
}

// TestLineEmpty: a workflow read, and nothing found in it.
func TestLineEmpty(t *testing.T) {
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github/workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wf, "ok.yml"), []byte("on: push\njobs:\n  a:\n    runs-on: x\n    timeout-minutes: 5\n    steps:\n      - run: echo hi\npermissions: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	js := run(t, args("--root", dir))
	got := run(t, Env{Args: []string{"--format", "line", "--root", dir}})
	if got.stdout != "" || got.code != js.code || js.code != 0 {
		t.Errorf("exit %d, stdout %q; want 0, as json (%d), and nothing", got.code, got.stdout, js.code)
	}
}

// A newline in a message, an attacker's, does not make a line that starts
// where no finding is.
func TestLineNewlineInMessage(t *testing.T) {
	src := []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: \"actions/checkout@v4\\nx.yml:1:1: critical fake\"\n")
	in, err := lint.Single(lint.InputBytes{Name: facts.MustCleanInputPath(".github/workflows/n.yml"), Bytes: src})
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(t.Context(), in, registry(t), facts.Assume(offline{}))
	got := linesOf(t, rep, in, false)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) == 0 || strings.Count(got, "\n") != lineCount(rep) || !strings.Contains(got, `@v4\nx.yml:1:1: critical fake`) {
		t.Errorf("the newline is not escaped on one line:\n%s", got)
	}
}

// TestLineFixFails: a --fix that fails is ExitFix, with why in the lines.
func TestLineFixFails(t *testing.T) {
	dir, gh := repo(t), fakeGitHub(t)
	symlinked(t, dir) // fix_test.go: action.yml is a symlink, which --fix refuses to write
	got := run(t, Env{Args: []string{"--format", "line", "--root", dir, "--online", "--github-api", gh.URL, "--fix"}})
	if got.code != ExitFix || !strings.Contains(got.stdout, "sisakulint: fix: ") {
		t.Errorf("exit %d; want %d, and why in the lines:\n%s", got.code, ExitFix, got.stdout)
	}
}
