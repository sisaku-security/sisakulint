package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const notRunKVA = "not run  known-vulnerable-actions: the rule runs, with all its kinds of findings (also those that need no fact), when --rule names the rule; in a run without --rule, the rule runs when --online is given, or when --facts or --fact gives a found or absent answer to any fact of package.advisories\n"

// factsWithout writes the file of facts of dir with no answer of
// package.advisories: with none of its entries, or, when unknown, with
// each of them unknown, as an offline --write-facts writes them.
func factsWithout(t *testing.T, dir string, unknown bool) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "facts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Schema string                       `json:"schema"`
		Facts  []map[string]json.RawMessage `json:"facts"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	var kept []map[string]json.RawMessage
	for _, e := range file.Facts {
		var q struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(e["query"], &q); err != nil {
			t.Fatal(err)
		}
		switch {
		case q.Kind != "package.advisories":
			kept = append(kept, e)
		case unknown:
			kept = append(kept, map[string]json.RawMessage{"query": e["query"], "state": json.RawMessage(`"unknown"`), "reason": json.RawMessage(`"offline: pass --facts or --online"`)})
		}
	}
	file.Facts = kept
	out, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "facts.json")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ranRules are the IDs of the rules that ran, of the report stdout.
func ranRules(t *testing.T, stdout string) []string {
	t.Helper()
	var rep struct {
		Rules []struct {
			ID string `json:"id"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	var ids []string
	for _, r := range rep.Rules {
		ids = append(ids, r.ID)
	}
	return ids
}

// TestDefaultRunFacts: known-vulnerable-actions runs by default only with
// an answer of package.advisories, and the text says so when the rule does
// not run by default.
func TestDefaultRunFacts(t *testing.T) {
	dir := example(t)
	with := filepath.Join(dir, "facts.json")
	for _, c := range []struct {
		name   string
		args   []string
		runs   bool
		notRun bool
	}{
		{"offline", []string{"--root", dir}, false, true},
		{"--facts answering", []string{"--root", dir, "--facts", with}, true, false},
		{"--facts without the kind", []string{"--root", dir, "--facts", factsWithout(t, dir, false)}, false, true},
		{"--facts of unknown answers", []string{"--root", dir, "--facts", factsWithout(t, dir, true)}, false, true},
		{"--fact answering", []string{"--root", dir, "--fact", "package.advisories[package=actions/download-artifact]=[]"}, true, false},
		{"--rule names the rule", []string{"--root", dir, "--rule", "known-vulnerable-actions"}, true, false},
		{"--skip-rule names the rule", []string{"--root", dir, "--skip-rule", "known-vulnerable-actions"}, false, false},
		{"--rule names another rule", []string{"--root", dir, "--rule", "commit-sha"}, false, false},
	} {
		text := run(t, raw(append(slices.Clone(c.args), "--color", "never", "--detail", "summary")...))
		js := run(t, raw(append(slices.Clone(c.args), "--format", "json")...))
		if got := slices.Contains(ranRules(t, js.stdout), "known-vulnerable-actions"); got != c.runs {
			t.Errorf("%s: runs %v, want %v (%s)", c.name, got, c.runs, js.stderr)
		}
		if got := strings.Contains(text.stdout, notRunKVA); got != c.notRun {
			t.Errorf("%s: the not run line %v, want %v:\n%s", c.name, got, c.notRun, text.stdout)
		}
		if text.code != js.code {
			t.Errorf("%s: exit code %d in text, %d in json", c.name, text.code, js.code)
		}
	}
	skip := run(t, raw("--root", dir, "--color", "never", "--skip-rule", "known-vulnerable-actions"))
	if !strings.Contains(skip.stdout, "skipped: known-vulnerable-actions\n") {
		t.Errorf("--skip-rule: no rules line:\n%s", skip.stdout)
	}
}

// TestDefaultRunOnlineFailure: with --online, known-vulnerable-actions runs
// though the API fails, and its inconclusive places set bit 8.
func TestDefaultRunOnlineFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	got := run(t, raw("--root", example(t), "--online", "--github-api", srv.URL, "--rule", "known-vulnerable-actions,commit-sha", "--format", "json"))
	if !strings.Contains(got.stdout, `"kind_id":"known-vulnerable-actions.advisories-unknown"`) {
		t.Fatalf("no advisories-unknown (%d):\n%s\n%s", got.code, got.stdout, got.stderr)
	}
	if got.code&8 == 0 {
		t.Errorf("exit code %d: bit 8 is not set", got.code)
	}
}

// TestDefaultRunBadFactsAndRule: an unreadable --facts is read before the
// rules are selected, so that it is the error of a run whose --rule is not
// known either.
func TestDefaultRunBadFactsAndRule(t *testing.T) {
	got := run(t, raw("--root", example(t), "--facts", filepath.Join(t.TempDir(), "none.json"), "--rule", "nope"))
	if got.code != ExitNoInput {
		t.Errorf("an unreadable --facts and an unknown --rule: %d, want %d (%s)", got.code, ExitNoInput, got.stderr)
	}
}

// inconclusiveOnly is a repository whose one workflow gives an inconclusive
// place of self-hosted-runner (high) and nothing else: runs-on is an input.
func inconclusiveOnly(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "on:\n  workflow_dispatch:\n    inputs:\n      runner:\n        type: string\npermissions: {}\njobs:\n  a:\n    runs-on: ${{ inputs.runner }}\n    timeout-minutes: 5\n    steps:\n      - run: echo hi\n"
	if err := os.WriteFile(filepath.Join(wf, "w.yml"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestInconclusiveBitAlone: an inconclusive place alone exits 8 whatever
// the format, and 0 when its rule is below --fail-on; the text says why.
func TestInconclusiveBitAlone(t *testing.T) {
	dir := inconclusiveOnly(t)
	for _, c := range []struct {
		failOn string
		want   int
		line   string
	}{
		{"info", 8, "bits 8 = 8 (inconclusive findings)\n"},
		{"critical", 0, "1 inconclusive finding is of a rule whose severity is below --fail-on critical, and does not count toward bit 8\n"},
	} {
		for _, format := range []string{"text", "line", "json"} {
			got := run(t, raw("--root", dir, "--fail-on", c.failOn, "--format", format, "--color", "never"))
			if got.code != c.want {
				t.Errorf("--fail-on %s --format %s: exit %d, want %d", c.failOn, format, got.code, c.want)
			}
			if format == "text" && !strings.Contains(got.stdout, c.line) {
				t.Errorf("--fail-on %s: no %q in\n%s", c.failOn, c.line, got.stdout)
			}
		}
	}
}

// TestInconclusiveLines: --format line gives a
// line for each inconclusive finding, so that bit 8 has its reason there.
func TestInconclusiveLines(t *testing.T) {
	got := run(t, raw("--root", inconclusiveOnly(t), "--format", "line"))
	if got.code != 8 || !strings.Contains(got.stdout, ".github/workflows/w.yml:9:14: high self-hosted-runner.input-dispatch: ") || !strings.Contains(got.stdout, " [inconclusive]\n") {
		t.Errorf("exit %d:\n%s", got.code, got.stdout)
	}
}

// TestOnlineWarningAfterSelect: an unknown --rule
// is the one error of the run; the warning of the empty GITHUB_TOKEN is
// not written before it.
func TestOnlineWarningAfterSelect(t *testing.T) {
	got := run(t, raw("--root", inconclusiveOnly(t), "--online", "--rule", "nope"))
	if got.code != ExitUsage || strings.Contains(got.stderr, "GITHUB_TOKEN") {
		t.Errorf("exit %d, stderr %q; want %d and no warning", got.code, got.stderr, ExitUsage)
	}
}

// TestDefaultRunFactsQuality: archived-uses and deprecated-node-runtime run
// by default only with an answer of their kind of fact, and when --rule
// names them.
func TestDefaultRunFactsQuality(t *testing.T) {
	dir := example(t)
	for _, c := range []struct {
		rule, fact string
	}{
		{"archived-uses", "repo.archived[repo=actions/checkout]=false"},
		{"deprecated-node-runtime", `action.runs-using[repo=actions/checkout,ref=v4]="node24"`},
	} {
		ran := func(args ...string) bool {
			var rep struct {
				QualityRules []string `json:"quality_rules"`
			}
			got := run(t, raw(append([]string{"--root", dir, "--format", "json"}, args...)...))
			if err := json.Unmarshal([]byte(got.stdout), &rep); err != nil {
				t.Fatalf("%v: %s", err, got.stdout)
			}
			return slices.Contains(rep.QualityRules, c.rule)
		}
		if ran() {
			t.Errorf("%s ran offline", c.rule)
		}
		if !ran("--fact", c.fact) {
			t.Errorf("%s did not run with --fact %s", c.rule, c.fact)
		}
		if !ran("--rule", c.rule) {
			t.Errorf("%s did not run when --rule names it", c.rule)
		}
	}
}

// TestDefaultRunFactsImpostorCommit: impostor-commit runs by default only
// with an answer of git.commit-ref, of the file of facts or derived by it
// from a git.ref-commit found as a tag, and when --rule names it.
func TestDefaultRunFactsImpostorCommit(t *testing.T) {
	const (
		sha    = "70379aad1a8b40919ce8b382d3cd7d0315cde1d0"
		notRun = "not run  impostor-commit: "
	)
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + sha + "\n"
	if err := os.WriteFile(filepath.Join(wf, "w.yml"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	file := func(entry string) string {
		p := filepath.Join(t.TempDir(), "facts.json")
		if err := os.WriteFile(p, []byte(`{"schema": "sisakulint/facts/v0", "facts": [`+entry+`]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	absent := file(`{"query": {"kind": "git.commit-ref", "repo": "actions/checkout", "sha": "` + sha + `"}, "state": "absent"}`)
	tag := file(`{"query": {"kind": "git.ref-commit", "repo": "actions/checkout", "ref": "v4"}, "state": "found", "value": {"sha": "11bd71901bbe5b1630ceea73d27597364c9af683", "ref": "refs/tags/v4"}}`)
	// as an --online run whose questions all failed writes the file
	unknown := file(`{"query": {"kind": "git.commit-ref", "repo": "actions/checkout", "sha": "` + sha + `"}, "state": "unknown", "reason": "rate limited"}`)
	for _, c := range []struct {
		name      string
		args      []string
		runs      bool
		certainty string // of the finding of impostor-commit; empty for none
	}{
		{"offline", nil, false, ""},
		{"--facts answering absent", []string{"--facts", absent}, true, "confirmed"},
		{"--facts deriving git.commit-ref", []string{"--facts", tag}, true, "conditional"},
		{"--facts of unknown answers", []string{"--facts", unknown}, false, ""},
		{"--fact answering", []string{"--fact", `git.commit-ref[repo=actions/checkout,sha=` + sha + `]="refs/tags/v4"`}, true, ""},
		{"--rule names the rule", []string{"--rule", "impostor-commit"}, true, "conditional"},
	} {
		base := append([]string{"--root", dir}, c.args...)
		js := run(t, raw(append(slices.Clone(base), "--format", "json")...))
		text := run(t, raw(append(slices.Clone(base), "--color", "never", "--detail", "summary")...))
		if got := slices.Contains(ranRules(t, js.stdout), "impostor-commit"); got != c.runs {
			t.Errorf("%s: runs %v, want %v (%s)", c.name, got, c.runs, js.stderr)
		}
		if got := strings.Contains(text.stdout, notRun); got == c.runs {
			t.Errorf("%s: the not run line %v, want %v:\n%s", c.name, got, !c.runs, text.stdout)
		}
		var certainty string
		for _, f := range selection(t, js.stdout).Findings {
			if f.Rule == "impostor-commit" {
				certainty = f.Certainty
			}
		}
		if certainty != c.certainty {
			t.Errorf("%s: the finding of impostor-commit is %q, want %q", c.name, certainty, c.certainty)
		}
	}
}

// TestImpostorCommitNotCheckedByFix: --fact derives no git.commit-ref, so
// the SHA a fix of commit-sha writes is not checked by impostor-commit,
// and the report says so; the same answer in a file of facts derives
// git.commit-ref, and impostor-commit checks the fix.
func TestImpostorCommitNotCheckedByFix(t *testing.T) {
	const answer = `{"sha": "11bd71901bbe5b1630ceea73d27597364c9af683", "ref": "refs/tags/v4"}`
	repo := func() string {
		dir := t.TempDir()
		wf := filepath.Join(dir, ".github", "workflows")
		if err := os.MkdirAll(wf, 0o755); err != nil {
			t.Fatal(err)
		}
		src := "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
		if err := os.WriteFile(filepath.Join(wf, "w.yml"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	unchecked := func(a ...string) []string {
		s := selection(t, run(t, args(append([]string{"--root", repo(), "--fix"}, a...)...)).stdout)
		if s.Fix == nil {
			t.Fatalf("%v: no fix", a)
		}
		return s.Fix.Unchecked
	}
	if got := unchecked("--fact", "git.ref-commit[repo=actions/checkout,ref=v4]="+strings.ReplaceAll(answer, " ", "")); !slices.Contains(got, "impostor-commit") {
		t.Errorf("--fact: unchecked_rules %v, want impostor-commit in them", got)
	}
	file := filepath.Join(t.TempDir(), "facts.json")
	if err := os.WriteFile(file, []byte(`{"schema": "sisakulint/facts/v0", "facts": [{"query": {"kind": "git.ref-commit", "repo": "actions/checkout", "ref": "v4"}, "state": "found", "value": `+answer+`}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := unchecked("--facts", file); slices.Contains(got, "impostor-commit") {
		t.Errorf("--facts: unchecked_rules %v, want no impostor-commit", got)
	}
}
