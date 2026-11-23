package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/repofile"
	"github.com/sisaku-security/sisakulint/actions/rules"
)

// repo is a copy of testdata/repo that a test may change.
func repo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("testdata/repo")); err != nil {
		t.Fatal(err)
	}
	return dir
}

type result struct {
	stdout, stderr string
	code           int
}

func run(t *testing.T, e Env) result {
	t.Helper()
	var out, errOut bytes.Buffer
	if e.Getenv == nil {
		e.Getenv = func(string) string { return "" }
	}
	if e.Stdin == nil {
		e.Stdin = strings.NewReader("")
	}
	if e.Stdout == nil {
		e.Stdout = &out
	}
	e.Stderr = &errOut
	ctx := context.Background()
	code := Main(ctx, e)
	return result{out.String(), errOut.String(), code}
}

// args are the arguments a with --format=json first: the tests read the
// report.
func args(a ...string) Env { return Env{Args: append([]string{"--format=json"}, a...)} }

// raw are the arguments a as they are.
func raw(a ...string) Env { return Env{Args: a} }

func registry(t *testing.T) *lint.Registry {
	t.Helper()
	reg, err := lint.NewRegistry(rules.All(), rules.Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// want is what lint writes for in, offline, and its exit code: of the
// rules the zero Selection runs, as the command selects by default. root
// is the --root whose files that are not inputs answer first, as the
// command reads them; empty for stdin, which reads none.
func want(t *testing.T, in lint.Inputs, threshold lint.Severity, root string) (string, int) {
	t.Helper()
	reg, err := registry(t).Select(lint.Selection{}, lint.FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	var r facts.Resolver = offline{}
	if root != "" {
		r = facts.First(repofile.New(os.DirFS(root)), offline{})
	}
	rep := lint.Run(context.Background(), in, reg, facts.Assume(r)) // as the command answers by default
	b, err := rep.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n", int(lint.Classify(rep, threshold))
}

func TestSameAsLint(t *testing.T) {
	dir := repo(t)
	whole, err := lint.Enumerate(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	one, err := lint.Files(os.DirFS(dir), []string{".github/workflows/ci.yml"})
	if err != nil {
		t.Fatal(err)
	}
	ci, _ := os.ReadFile(filepath.Join(dir, ".github/workflows/ci.yml"))
	stdin, err := lint.Single(lint.InputBytes{Name: facts.MustCleanInputPath(".github/workflows/ci.yml"), Bytes: ci})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		env  Env
		in   lint.Inputs
		root string
	}{
		{"the repository", args("--root", dir), whole, dir},
		{"a PATH", args("--root", dir, ".github/workflows/ci.yml"), one, dir},
		{"stdin", Env{Args: []string{"--format=json", "--stdin-name", ".github/workflows/ci.yml"}, Stdin: bytes.NewReader(ci)}, stdin, ""},
	} {
		got := run(t, c.env)
		out, code := want(t, c.in, lint.SeverityInfo, c.root)
		if got.stdout != out || got.code != code {
			t.Errorf("%s: exit %d, stdout\n%s\nwant exit %d, stdout\n%s\nstderr: %s", c.name, got.code, got.stdout, code, out, got.stderr)
		}
	}
	if got := run(t, args("--root", dir)); !strings.Contains(got.stdout, "gone/repo@v1&2 is not pinned") {
		t.Errorf("the report escapes & (json.Marshal is not MarshalJSON):\n%s", got.stdout)
	}
	if got := run(t, args("--root", dir)); !strings.Contains(got.stdout, `"reason":"offline: pass --facts or --online"`) {
		t.Errorf("the facts are not unknown for being offline:\n%s", got.stdout)
	}
}

func TestUsage(t *testing.T) {
	dir := repo(t)
	for _, c := range []struct {
		name string
		env  Env
	}{
		{"an unknown flag", args("--root", dir, "--nope")},
		{"a severity in capitals", args("--root", dir, "--fail-on", "HIGH")},
		{"an empty severity", args("--root", dir, "--fail-on", "")},
		{"the name of no severity", args("--root", dir, "--fail-on", "SeverityUnset")},
		{"a number for a severity", args("--root", dir, "--fail-on", "0")},
		{"stdin and a PATH", args("--root", dir, "--stdin-name", "a.yml", "a.yml")},
		{"an empty stdin name", args("--root", dir, "--stdin-name", "")},
		{"an absolute PATH", args("--root", dir, "/etc/passwd")},
		{"a PATH out with ..", args("--root", dir, "../x.yml")},
		{"a PATH twice", args("--root", dir, ".github/workflows/ci.yml", "./.github/workflows/ci.yml")},
		{"a flag after a PATH", args("--root", dir, ".github/workflows/ci.yml", "--fail-on", "high")},
		{"help", raw("-h")},
		{"an empty root", args("--root", "")},
		{"the registry and a PATH", raw("--registry", "a.yml")},
		{"the registry and a flag", raw("--root", dir, "--registry")},
		{"explain and a PATH", raw("--explain=commit-sha", "a.yml")},
		{"explain and a flag", raw("--color=never", "--explain=commit-sha")},
		{"explain and the registry", raw("--explain=commit-sha", "--registry")},
		{"explain of no rule", raw("--explain=nope")},
		{"explain of no ID", raw("--explain=Nope")},
		{"an empty explain", raw("--explain=")},
		{"terms and a rule", raw("--explain=terms", "--explain=commit-sha")},
		{"terms and all", raw("--explain=all", "--explain=terms")},
		{"exclude and a PATH", args("--root", dir, "--exclude", "x", ".github/workflows/ci.yml")},
		{"exclude and stdin", args("--root", dir, "--exclude", "x", "--stdin-name", "a.yml")},
		{"exclude .github", args("--root", dir, "--exclude", ".github")},
		{"exclude the workflows", args("--root", dir, "--exclude", ".github/workflows")},
		{"exclude a workflow", args("--root", dir, "--exclude", ".github/workflows/ci.yml")},
		{"exclude out with ..", args("--root", dir, "--exclude", "../x")},
		{"exclude an absolute path", args("--root", dir, "--exclude", "/x")},
		{"an empty exclude", args("--root", dir, "--exclude", "")},
	} {
		got := run(t, c.env)
		if got.code != ExitUsage || got.stdout != "" || got.stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d, nothing on stdout, why on stderr", c.name, got.code, got.stdout, got.stderr, ExitUsage)
		}
	}
	if got := run(t, args("--root", dir, "--nope")); strings.Count(got.stderr, "-nope") != 1 {
		t.Errorf("the error of a flag is written %d times:\n%s", strings.Count(got.stderr, "-nope"), got.stderr)
	}
	if got := run(t, args("--root", dir, "--fail-on", "0")); !strings.Contains(got.stderr, "info, low, medium, high, critical") {
		t.Errorf("--fail-on 0 does not say what the severities are:\n%s", got.stderr)
	}
	if got := run(t, args("--root", dir, "--", "-x.yml")); got.code != ExitNoInput {
		t.Errorf("-x.yml after --: exit %d, want %d (read as a PATH, which is not there)", got.code, ExitNoInput)
	}
}

// TestRegistry: --registry writes the registry as lint does, and nothing
// else, from a directory with no workflow.
func TestRegistry(t *testing.T) {
	b, err := registry(t).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	got := run(t, raw("--registry"))
	if got.code != 0 || got.stdout != string(b)+"\n" || got.stderr != "" {
		t.Errorf("exit %d, stdout\n%s\nstderr %q; want 0 and\n%s", got.code, got.stdout, got.stderr, b)
	}
}

// TestExplain: --explain writes what lint's Explain writes, for the rules
// asked, in the order of the registry, each once; all is every rule.
func TestExplain(t *testing.T) {
	reg := registry(t)
	want := func(ids ...lint.RuleID) string {
		b, err := reg.Explain(ids, commit(debug.ReadBuildInfo()))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	t.Chdir(t.TempDir())
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--explain=commit-sha", "--explain=code-injection", "--explain=commit-sha"}, want(rules.CodeInjectionID, rules.CommitSHAID)},
		{[]string{"--explain", "impostor-commit"}, want(rules.ImpostorCommitID)},
		{[]string{"--explain=all"}, want()},
		{[]string{"--explain=commit-sha", "--explain=all"}, want()},
	} {
		got := run(t, raw(c.args...))
		if got.code != 0 || got.stdout != c.want || got.stderr != "" {
			t.Errorf("%v: exit %d, stderr %q, stdout\n%s", c.args, got.code, got.stderr, got.stdout)
		}
	}
	terms := string(lint.Terms(commit(debug.ReadBuildInfo())))
	for _, args := range [][]string{{"--explain=terms"}, {"--explain=terms", "--explain=terms"}} {
		got := run(t, raw(args...))
		if got.code != 0 || got.stdout != terms || got.stderr != "" {
			t.Errorf("%v: exit %d, stderr %q, stdout\n%s", args, got.code, got.stderr, got.stdout)
		}
	}
	var ids []string
	for _, r := range rules.All() {
		ids = append(ids, r.Meta().ID.String())
	}
	for _, q := range rules.Quality() {
		ids = append(ids, q.QualityMeta().ID.String())
	}
	slices.Sort(ids)
	for _, id := range []string{"nope", "Nope"} {
		got := run(t, raw("--explain="+id))
		if got.code != ExitUsage || !strings.Contains(got.stderr, strings.Join(ids, ", ")) {
			t.Errorf("--explain=%s: exit %d; it does not say which rules there are:\n%s", id, got.code, got.stderr)
		}
	}
	for _, r := range rules.All() {
		if id := r.Meta().ID.String(); id == "all" || id == "terms" {
			t.Errorf("a rule is named %s, which --explain reads otherwise", id)
		}
	}
}

func TestCommit(t *testing.T) {
	bi := func(kv ...string) *debug.BuildInfo {
		b := &debug.BuildInfo{}
		for i := 0; i < len(kv); i += 2 {
			b.Settings = append(b.Settings, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
		}
		return b
	}
	for _, c := range []struct {
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		{nil, false, "unknown"},
		{bi(), true, "unknown"},
		{bi("vcs.modified", "true"), true, "unknown"},
		{bi("vcs.revision", "abc"), true, "abc"},
		{bi("vcs.revision", "abc", "vcs.modified", "false"), true, "abc"},
		{bi("vcs.modified", "true", "vcs.revision", "abc"), true, "abc (modified)"},
	} {
		if got := commit(c.bi, c.ok); got != c.want {
			t.Errorf("commit(%+v) = %q, want %q", c.bi, got, c.want)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("the pipe broke") }

func TestNoInput(t *testing.T) {
	dir := repo(t)
	outside := t.TempDir()
	secret := "name: SECRET-OUTSIDE-THE-ROOT\n"
	if err := os.WriteFile(filepath.Join(outside, "action.yml"), []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "ext")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, ".github/workflows/ci.yml")
	for _, c := range []struct {
		name string
		env  Env
	}{
		{"no root", args("--root", filepath.Join(dir, "nope"))},
		{"a root that is a file", args("--root", file)},
		{"no such PATH", args("--root", dir, ".github/workflows/nope.yml")},
		{"a PATH that is a directory", args("--root", dir, ".github/workflows")},
		{"a PATH out of the root through a symlink", args("--root", dir, "ext/action.yml")},
		{"stdin that fails", Env{Args: []string{"--stdin-name", "a.yml"}, Stdin: failingReader{}}},
	} {
		got := run(t, c.env)
		if got.code != ExitNoInput || got.stdout != "" || got.stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d, nothing on stdout, why on stderr", c.name, got.code, got.stdout, got.stderr, ExitNoInput)
		}
		if strings.Contains(got.stderr, "SECRET") {
			t.Errorf("%s: stderr shows what is outside the root: %s", c.name, got.stderr)
		}
	}
	if got := run(t, args("--root", dir, ".github/workflows")); !strings.Contains(got.stderr, "is a directory") {
		t.Errorf("a directory: stderr %q does not say so", got.stderr)
	}
}

func TestSymlinkOutOfTheRoot(t *testing.T) {
	dir := repo(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "action.yml"), []byte("name: SECRET-OUTSIDE-THE-ROOT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "action.yml"), filepath.Join(dir, "sub/action.yml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "ext")); err != nil {
		t.Fatal(err)
	}
	got := run(t, args("--root", dir))
	if got.code&int(lint.UnreadBit) == 0 || strings.Contains(got.stdout, "SECRET") {
		t.Errorf("exit %d; want bit 16, and nothing of the file outside:\n%s", got.code, got.stdout)
	}
	var rep struct {
		Inputs   []struct{ Name, State string }
		Complete bool
	}
	if err := json.Unmarshal([]byte(got.stdout), &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, i := range rep.Inputs {
		if i.Name == "sub/action.yml" {
			found = i.State == "unreadable"
		}
	}
	if !found {
		t.Errorf("sub/action.yml is not an unreadable input: %+v", rep.Inputs)
	}
	if rep.Complete {
		t.Error("a symlink to a directory out of the root, and the inputs are complete")
	}
}

func TestFailOn(t *testing.T) {
	dir := repo(t)
	if all, info := run(t, args("--root", dir)), run(t, args("--root", dir, "--fail-on", "info")); all.code != info.code || all.code == 0 {
		t.Errorf("exit %d without --fail-on, %d with --fail-on info; want the same, not 0", all.code, info.code)
	}
	m, _ := registry(t).Meta(rules.CommitSHAID)
	sev := m.Severity()
	if got := run(t, args("--root", dir, "--fail-on", sev.String())); got.code&int(lint.ConfirmedBit) == 0 {
		t.Errorf("--fail-on %s: exit %d, want bit 1", sev, got.code)
	}
	if sev == lint.SeverityCritical {
		t.Skip("no severity above the rule's")
	}
	above := lint.Severity(sev + 1)
	if got := run(t, args("--root", dir, "--fail-on", above.String())); got.code&int(lint.ConfirmedBit) != 0 {
		t.Errorf("--fail-on %s: exit %d, want no bit 1", above, got.code)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("the disk is full") }

func TestStdoutFails(t *testing.T) {
	got := run(t, Env{Args: []string{"--root", repo(t)}, Stdout: failingWriter{}})
	if got.code != ExitIO || got.stderr == "" {
		t.Errorf("exit %d, stderr %q; want %d and why", got.code, got.stderr, ExitIO)
	}
}

func TestCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut bytes.Buffer
	code := Main(ctx, Env{Args: []string{"--format=json", "--root", repo(t)}, Getenv: func(string) string { return "" },
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut})
	if code&int(lint.ErrorBit) == 0 || code > 7 || !json.Valid(out.Bytes()) {
		t.Errorf("exit %d, stdout %q; want a report and bit 4", code, out.String())
	}
}

// TestExclude: --exclude is lint.EnumerateExcept, byte for byte.
func TestExclude(t *testing.T) {
	dir := repo(t)
	ex, err := lint.ParseExclude(".github/actions")
	if err != nil {
		t.Fatal(err)
	}
	in, err := lint.EnumerateExcept(os.DirFS(dir), []lint.Exclude{ex})
	if err != nil {
		t.Fatal(err)
	}
	wantOut, wantCode := want(t, in, lint.SeverityInfo, dir)
	got := run(t, args("--root", dir, "--exclude", ".github/actions/"))
	if got.stdout != wantOut || got.code != wantCode {
		t.Errorf("exit %d, want %d; stdout\n%s\nwant\n%s", got.code, wantCode, got.stdout, wantOut)
	}
	if !strings.Contains(got.stdout, `"excluded":[".github/actions"]`) || !strings.Contains(got.stdout, `"state":"excluded"`) {
		t.Errorf("no excluded in\n%s", got.stdout)
	}
}

func TestRegistryFull(t *testing.T) {
	plain := run(t, raw("--registry"))
	full := run(t, raw("--registry=full"))
	if plain.code != 0 || full.code != 0 {
		t.Fatalf("codes %d %d: %s %s", plain.code, full.code, plain.stderr, full.stderr)
	}
	if strings.Contains(plain.stdout, `"facts":`) || !strings.Contains(full.stdout, `"facts":`) {
		t.Error("the default has facts, or full has none")
	}
	if got := run(t, raw("--registry=brief")); got.code != ExitUsage {
		t.Errorf("--registry=brief: %d", got.code)
	}
}
