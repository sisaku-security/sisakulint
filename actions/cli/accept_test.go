package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// twoPlaces is a repository whose one workflow has two inconclusive places
// (self-hosted-runner input-dispatch), in the jobs a and b, and nothing else.
func twoPlaces(t *testing.T, runsOnB string) string {
	t.Helper()
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "on:\n  workflow_dispatch:\n    inputs:\n      runner:\n        type: string\npermissions: {}\njobs:\n" +
		"  a:\n    runs-on: ${{ inputs.runner }}\n    timeout-minutes: 5\n    steps:\n      - run: echo hi\n" +
		"  b:\n    runs-on: " + runsOnB + "\n    timeout-minutes: 5\n    steps:\n      - run: echo hi\n"
	if err := os.WriteFile(filepath.Join(wf, "w.yml"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// acceptFile writes a file of acceptances of the inconclusive places of the
// report of dir whose key path is one of keyPaths, made from the report as
// a person makes one, and gives its path.
func acceptFile(t *testing.T, dir string, keyPaths ...string) string {
	t.Helper()
	got := run(t, raw("--root", dir, "--format", "json"))
	var rep struct {
		Findings []struct {
			Rule      string `json:"rule"`
			Certainty string `json:"certainty"`
			Args      struct {
				KindID string `json:"kind_id"`
			} `json:"args"`
			Location struct {
				File struct {
					Input string `json:"input"`
				} `json:"file"`
			} `json:"location"`
			KeyPath   string `json:"key_path"`
			SpanText  string `json:"span_text"`
			SpanLines string `json:"span_lines"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &rep); err != nil {
		t.Fatalf("%v: %s", err, got.stdout)
	}
	var entries []map[string]string
	for _, g := range rep.Findings {
		if g.Certainty != "inconclusive" {
			continue
		}
		for _, k := range keyPaths {
			if g.KeyPath == k {
				entries = append(entries, map[string]string{"rule": g.Rule, "kind_id": g.Args.KindID, "input": g.Location.File.Input,
					"key_path": g.KeyPath, "span_text": g.SpanText, "span_lines": g.SpanLines, "reason": "the runner is chosen from our own list"})
			}
		}
	}
	if len(entries) != len(keyPaths) {
		t.Fatalf("the places of %v: %+v", keyPaths, rep.Findings)
	}
	b, err := json.Marshal(map[string]any{"schema": "sisakulint/acceptances/v0", "inconclusive": entries})
	if err != nil {
		t.Fatal(err)
	}
	return writeAccept(t, string(b))
}

func writeAccept(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "accept.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAccept(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	both, one := acceptFile(t, dir, "jobs.a.runs-on", "jobs.b.runs-on"), acceptFile(t, dir, "jobs.a.runs-on")
	for _, format := range []string{"text", "line", "json"} {
		if got := run(t, raw("--root", dir, "--accept", both, "--format", format)); got.code != 0 {
			t.Errorf("--format %s, both accepted: exit %d, want 0\n%s%s", format, got.code, got.stdout, got.stderr)
		}
		if got := run(t, raw("--root", dir, "--accept", one, "--format", format)); got.code != 8 {
			t.Errorf("--format %s, one accepted: exit %d, want 8\n%s%s", format, got.code, got.stdout, got.stderr)
		}
	}
	got := run(t, raw("--root", dir, "--accept", one, "--format", "json"))
	if strings.Count(got.stdout, `"acceptance":{"reason":"the runner is chosen from our own list"}`) != 1 || got.stderr != "" {
		t.Errorf("the report of one accepted place:\n%s\nstderr %q", got.stdout, got.stderr)
	}
}

// TestAcceptLineChanged: an accepted place whose line changes sets bit 8
// again, and the entry that matches no place is on stderr.
func TestAcceptLineChanged(t *testing.T) {
	both := acceptFile(t, twoPlaces(t, "${{ inputs.runner }}"), "jobs.a.runs-on", "jobs.b.runs-on")
	got := run(t, raw("--root", twoPlaces(t, "${{ inputs.runner || 'ubuntu-latest' }}"), "--accept", both))
	if got.code != 8 || !strings.Contains(got.stderr, "jobs.b.runs-on") || strings.Contains(got.stderr, "jobs.a.runs-on") {
		t.Errorf("exit %d, stderr %q; want 8 and the entry of jobs.b alone", got.code, got.stderr)
	}
}

func TestAcceptErrors(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	for name, p := range map[string]string{
		"no file":         filepath.Join(t.TempDir(), "none.json"),
		"not JSON":        writeAccept(t, "{"),
		"an unknown rule": writeAccept(t, `{"schema": "sisakulint/acceptances/v0", "inconclusive": [{"rule": "nope", "kind_id": "nope.k", "input": "a.yml", "key_path": "", "span_text": "", "span_lines": "", "reason": "r"}]}`),
	} {
		got := run(t, raw("--root", dir, "--accept", p))
		if got.code != ExitNoInput || got.stdout != "" || !strings.Contains(got.stderr, "--accept") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d, nothing on stdout, and the flag named", name, got.code, got.stdout, got.stderr, ExitNoInput)
		}
	}
}

// TestAcceptUnmatchedStderr: the entry that matches
// no place is on stderr, so the report on stdout stays JSON; an entry of a
// rule the run leaves out is not.
func TestAcceptUnmatchedStderr(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	stale := writeAccept(t, `{"schema": "sisakulint/acceptances/v0", "inconclusive": [{"rule": "self-hosted-runner", "kind_id": "self-hosted-runner.runs-on-expr", "input": ".github/workflows/w.yml", "key_path": "jobs.c.runs-on", "span_text": "x", "span_lines": "runs-on: x", "reason": "r"}]}`)
	got := run(t, raw("--root", dir, "--accept", stale, "--format", "json"))
	var v any
	if err := json.Unmarshal([]byte(got.stdout), &v); err != nil || got.code != 8 || !strings.Contains(got.stderr, "jobs.c.runs-on") {
		t.Errorf("exit %d, JSON %v, stderr %q", got.code, err, got.stderr)
	}
	if got := run(t, raw("--root", dir, "--accept", stale, "--rule", "permissions")); got.stderr != "" {
		t.Errorf("--rule permissions: stderr %q, want nothing of the entry of self-hosted-runner", got.stderr)
	}
}

// TestAcceptWithFix: with --fix --dry-run, the acceptance
// still takes the place out of bit 8.
func TestAcceptWithFix(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	both := acceptFile(t, dir, "jobs.a.runs-on", "jobs.b.runs-on")
	if got := run(t, raw("--root", dir, "--accept", both, "--fix", "--dry-run")); got.code != 0 {
		t.Errorf("exit %d, want 0\n%s%s", got.code, got.stdout, got.stderr)
	}
}

func TestAcceptFlag(t *testing.T) {
	for _, args := range [][]string{{"--accept="}, {"--explain", "terms", "--accept", "a.json"}, {"--registry", "--accept", "a.json"}, {"--examples", "--html", "x.html", "--accept", "a.json"}} {
		if got := run(t, raw(args...)); got.code != ExitUsage {
			t.Errorf("%q: exit %d, want %d", args, got.code, ExitUsage)
		}
	}
}

// TestAcceptText: the text counts the inconclusive findings not accepted
// where it counted every inconclusive finding, and the accepted ones on a
// line of their own; full lists them with the reason.
func TestAcceptText(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	one := acceptFile(t, dir, "jobs.a.runs-on")
	for _, c := range []struct {
		detail string
		want   []string
		not    []string
	}{
		{"summary", []string{"inconclusive  1 finding (self-hosted-runner)\n", "accepted      1 inconclusive finding that an entry of --accept matches; the finding does not set bit 8\n"}, []string{"2 findings"}},
		{"normal", []string{"inconclusive  1 finding: the rules could not decide whether the place of each finding has the problem that the rule of the finding looks for; a person decides\n  self-hosted-runner  input-dispatch 1\n",
			"self-hosted-runner.input-dispatch  .github/workflows/w.yml:", "accepted  1 inconclusive finding that an entry of --accept matches; the finding does not set bit 8 (-v)\n"}, []string{"the runner is chosen"}},
		{"full", []string{"inconclusive  1 finding: the rules could not decide whether the place of each finding has the problem that the rule of the finding looks for; a person decides\n", "accepted  1 inconclusive finding that an entry of --accept matches; the finding does not set bit 8\n",
			"self-hosted-runner input-dispatch: accepted: the runner is chosen from our own list\n"}, nil},
	} {
		got := run(t, raw("--root", dir, "--accept", one, "--detail", c.detail, "--color", "never"))
		for _, w := range c.want {
			if !strings.Contains(got.stdout, w) {
				t.Errorf("--detail %s: no %q in\n%s", c.detail, w, got.stdout)
			}
		}
		for _, n := range c.not {
			if strings.Contains(got.stdout, n) {
				t.Errorf("--detail %s: %q in\n%s", c.detail, n, got.stdout)
			}
		}
	}
}

func TestAcceptLine(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	got := run(t, raw("--root", dir, "--accept", acceptFile(t, dir, "jobs.a.runs-on"), "--format", "line", "--color", "never"))
	want := ".github/workflows/w.yml:9:14: high self-hosted-runner.input-dispatch: "
	if !strings.Contains(got.stdout, want) || !strings.Contains(got.stdout, "[inconclusive, accepted by --accept: the runner is chosen from our own list]\n") ||
		strings.Count(got.stdout, " self-hosted-runner.input-dispatch: ") != 2 || strings.Count(got.stdout, "accepted by --accept") != 1 {
		t.Errorf("no %q, or not one line of the other place, in\n%s", want, got.stdout)
	}
}

// TestAcceptBelowThreshold: the line of the inconclusive findings below
// --fail-on counts no accepted one.
func TestAcceptBelowThreshold(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	got := run(t, raw("--root", dir, "--accept", acceptFile(t, dir, "jobs.a.runs-on"), "--fail-on", "critical", "--color", "never"))
	if !strings.Contains(got.stdout, "1 inconclusive finding is of a rule whose severity is below --fail-on critical") {
		t.Errorf("not one place below --fail-on in\n%s", got.stdout)
	}
}
