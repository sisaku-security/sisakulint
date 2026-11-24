package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestConfigurationKeysOrder: the keys, in the order they are read (repo
// before fact, whose repo.* facts are of the repository of repo).
func TestConfigurationKeysOrder(t *testing.T) {
	var names []string
	for _, k := range configurationKeys {
		names = append(names, k.name)
	}
	want := []string{"exclude", "fail-on", "rule", "skip-rule", "accept", "facts", "repo", "fact", "add-attacker"}
	if !slices.Equal(names, want) {
		t.Errorf("the keys are %v, want %v", names, want)
	}
}

// TestKeyUsage: the usage of a key of a list says that its flag may be
// given again; that of the other keys does not.
func TestKeyUsage(t *testing.T) {
	for _, k := range configurationKeys {
		again := strings.HasSuffix(keyUsage(k), "; --"+k.name+" may be given again on the command line")
		if again != (k.form == formList) {
			t.Errorf("%s: the usage %q; may be given again: %v, want %v", k.name, keyUsage(k), again, k.form == formList)
		}
	}
}

// TestKeyFlags: the flags of the keys behave as they did before the table.
func TestKeyFlags(t *testing.T) {
	dir := repo(t)
	two := run(t, args("--root", dir, "--rule", "commit-sha,impostor-commit"))
	again := run(t, args("--root", dir, "--rule", "commit-sha", "--rule", "impostor-commit"))
	if two.code != again.code || two.stdout != again.stdout {
		t.Errorf("--rule a,b and --rule a --rule b differ:\n%s\n%s", two.stdout, again.stdout)
	}
	before := run(t, args("--root", dir, "--fact", "repo.public=false", "--repo", "o/r"))
	after := run(t, args("--root", dir, "--repo", "o/r", "--fact", "repo.public=false"))
	if before.code != after.code || before.stdout != after.stdout || before.stderr != "" {
		t.Errorf("--fact before --repo differs from --fact after --repo (stderr %q)", before.stderr)
	}
	for _, flag := range []string{"--accept", "--facts"} {
		if got := run(t, args("--root", dir, flag, "")); got.code != ExitUsage || !strings.Contains(got.stderr, flag) {
			t.Errorf("%s empty: exit %d, stderr %q", flag, got.code, got.stderr)
		}
	}
}

// configurationFile writes src as a configuration file in dir.
func configurationFile(t *testing.T, dir, src string) string {
	t.Helper()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// keySource is the values as a key of a configuration file.
func keySource(k configurationKey, values []string) string {
	switch k.form {
	case formList:
		var quoted []string
		for _, v := range values {
			quoted = append(quoted, strconv.Quote(v))
		}
		return k.name + ": [" + strings.Join(quoted, ", ") + "]\n"
	}
	return k.name + ": " + strconv.Quote(values[0]) + "\n"
}

// keyArgs are the values as flags.
func keyArgs(k configurationKey, values []string) []string {
	var a []string
	for _, v := range values {
		a = append(a, "--"+k.name, v)
	}
	return a
}

// TestConfigurationFileAsFlags: every key of the configuration file does
// what the flag of the same name does.
func TestConfigurationFileAsFlags(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	cfg := t.TempDir()
	accept := acceptFile(t, dir, "jobs.a.runs-on")
	if err := os.Rename(accept, filepath.Join(cfg, "accept.json")); err != nil {
		t.Fatal(err)
	}
	if got := run(t, raw("--root", dir, "--write-facts", filepath.Join(cfg, "facts.json"))); got.code == ExitUsage || got.code == ExitNoInput {
		t.Fatalf("--write-facts: exit %d, %s", got.code, got.stderr)
	}
	// Each case is run with flags and with a file; the values of the paths
	// are relative to the directory of the file.
	cases := []map[string][]string{
		{"exclude": {".github/actions"}},
		{"fail-on": {"high"}},
		{"rule": {"self-hosted-runner,permissions"}},
		{"skip-rule": {"self-hosted-runner"}},
		{"accept": {"accept.json"}},
		{"facts": {"facts.json"}},
		{"repo": {"o/r"}, "fact": {"repo.public=false", "repo.fork-pr-secrets=false"}},
		{"add-attacker": {"read-member,triage-account"}},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		var src string
		flags := []string{"--root", dir}
		for _, k := range configurationKeys {
			v, ok := c[k.name]
			if !ok {
				continue
			}
			seen[k.name] = true
			src += keySource(k, v)
			if k.path {
				v = []string{filepath.Join(cfg, v[0])}
			}
			flags = append(flags, keyArgs(k, v)...)
		}
		byFlags := run(t, args(flags...))
		byFile := run(t, args("--root", dir, "--config", configurationFile(t, cfg, src)))
		if byFlags.code != byFile.code || byFlags.stdout != byFile.stdout || byFlags.stderr != byFile.stderr || byFlags.code >= ExitUsage {
			t.Errorf("%v: by flags exit %d, stderr %q; by the file exit %d, stderr %q\n%s\n%s", c, byFlags.code, byFlags.stderr, byFile.code, byFile.stderr, byFlags.stdout, byFile.stdout)
		}
	}
	for _, k := range configurationKeys {
		if !seen[k.name] {
			t.Errorf("no case of the key %s", k.name)
		}
	}
}

// TestConfigurationMerge: a flag replaces the key of the same name, but
// exclude and fact add to it, and --rule or --skip-rule replaces both rule
// and skip-rule.
func TestConfigurationMerge(t *testing.T) {
	dir := repo(t)
	cfg := t.TempDir()
	same := func(name string, a, b result) {
		t.Helper()
		if a.code != b.code || a.stdout != b.stdout || a.code >= ExitUsage {
			t.Errorf("%s: exit %d and %d (stderr %q, %q)\n%s\n%s", name, a.code, b.code, a.stderr, b.stderr, a.stdout, b.stdout)
		}
	}
	c := configurationFile(t, cfg, "fail-on: \"high\"\n")
	same("fail-on", run(t, args("--root", dir, "--config", c, "--fail-on", "low")), run(t, args("--root", dir, "--fail-on", "low")))
	c = configurationFile(t, cfg, "skip-rule: [\"commit-sha\"]\n")
	same("rule", run(t, args("--root", dir, "--config", c, "--rule", "commit-sha")), run(t, args("--root", dir, "--rule", "commit-sha")))
	c = configurationFile(t, cfg, "exclude: [\".github/actions/build\"]\n")
	same("exclude", run(t, args("--root", dir, "--config", c, "--exclude", "docs")), run(t, args("--root", dir, "--exclude", ".github/actions/build", "--exclude", "docs")))
	c = configurationFile(t, cfg, "repo: \"o/r\"\nfact: [\"repo.public=true\", \"repo.fork-pr-secrets=true\"]\n")
	same("fact", run(t, args("--root", dir, "--config", c, "--fact", "repo.public=false")), run(t, args("--root", dir, "--repo", "o/r", "--fact", "repo.public=false", "--fact", "repo.fork-pr-secrets=true")))
}

// TestConfigurationExcludeWithPaths: exclude of the file is left out of a
// run of PATHs or of stdin, but not of --read-all.
func TestConfigurationExcludeWithPaths(t *testing.T) {
	dir := repo(t)
	c := configurationFile(t, t.TempDir(), "exclude: [\".github/actions/build\"]\n")
	wf := ".github/workflows/ci.yml"
	same := func(name string, a, b result) {
		t.Helper()
		if a.code != b.code || a.stdout != b.stdout || a.code >= ExitUsage {
			t.Errorf("%s: exit %d and %d (stderr %q, %q)", name, a.code, b.code, a.stderr, b.stderr)
		}
	}
	same("PATH", run(t, args("--root", dir, "--config", c, wf)), run(t, args("--root", dir, wf)))
	src, err := os.ReadFile(filepath.Join(dir, wf))
	if err != nil {
		t.Fatal(err)
	}
	stdin := func(a ...string) Env { e := args(a...); e.Stdin = bytes.NewReader(src); return e }
	same("stdin", run(t, stdin("--root", dir, "--config", c, "--stdin-name", wf)), run(t, stdin("--root", dir, "--stdin-name", wf)))
	same("--read-all", run(t, args("--root", dir, "--config", c, "--read-all", wf)), run(t, args("--root", dir, "--read-all", "--exclude", ".github/actions/build", wf)))
}

// TestConfigurationErrors: an error of the file is exit 66, with nothing
// on stdout, and stderr names the file.
func TestConfigurationErrors(t *testing.T) {
	dir := repo(t)
	cfg := t.TempDir()
	for _, c := range []struct{ name, src string }{
		{"not YAML", "exclude: [\n"},
		{"a sequence", "- exclude\n"},
		{"an unknown key", "exclud: [\"x\"]\n"},
		{"a key twice", "fail-on: \"high\"\nfail-on: \"low\"\n"},
		{"two documents", "fail-on: \"high\"\n---\nrepo: \"o/r\"\n"},
		{"a number", "fail-on: 1\n"},
		{"a number in a list", "exclude: [2024]\n"},
		{"a string for a list", "exclude: \"x\"\n"},
		{"an alias", "exclude: &x [\"a\"]\nrule: *x\n"},
		{"the workflows", "exclude: [\".github/workflows\"]\n"},
		{"no severity", "fail-on: \"bogus\"\n"},
		{"rule and skip-rule", "rule: [\"commit-sha\"]\nskip-rule: [\"permissions\"]\n"},
		{"no rule", "rule: [\"comit-sha\"]\n"},
		{"an empty path", "accept: \"\"\n"},
	} {
		p := configurationFile(t, cfg, c.src)
		got := run(t, args("--root", dir, "--config", p))
		if got.code != ExitNoInput || got.stdout != "" || !strings.Contains(got.stderr, "--config "+p) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d", c.name, got.code, got.stdout, got.stderr, ExitNoInput)
		}
	}
	if got := run(t, args("--root", dir, "--config", filepath.Join(cfg, "none.yaml"))); got.code != ExitNoInput || got.stdout != "" {
		t.Errorf("no file: exit %d, stdout %q", got.code, got.stdout)
	}
}

// TestConfigurationEmpty: a file with no key, and a key with no value, are
// a run without the file.
func TestConfigurationEmpty(t *testing.T) {
	dir := repo(t)
	want := run(t, args("--root", dir))
	for _, src := range []string{"", "# nothing\n", "{}\n", "---\n# nothing\n", "exclude:\n", "exclude: []\n"} {
		got := run(t, args("--root", dir, "--config", configurationFile(t, t.TempDir(), src)))
		if got.code != want.code || got.stdout != want.stdout || got.stderr != want.stderr {
			t.Errorf("%q: exit %d, stderr %q; want %d", src, got.code, got.stderr, want.code)
		}
	}
}

// TestConfigurationRelativePath: a path of the file is read from the
// directory of the file, whatever --root and the working directory are.
func TestConfigurationRelativePath(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	sub := filepath.Join(t.TempDir(), "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(acceptFile(t, dir, "jobs.a.runs-on", "jobs.b.runs-on"), filepath.Join(sub, "a.json")); err != nil {
		t.Fatal(err)
	}
	c := configurationFile(t, sub, "accept: \"a.json\"\n")
	t.Chdir(t.TempDir())
	if got := run(t, args("--root", dir, "--config", c)); got.code != 0 {
		t.Errorf("exit %d, want 0 (both places accepted); stderr %q", got.code, got.stderr)
	}
}

// TestConfigurationUsage: --config does not go with what reads nothing,
// and may not be empty.
func TestConfigurationUsage(t *testing.T) {
	c := configurationFile(t, t.TempDir(), "")
	for _, a := range [][]string{
		{"--config", c, "--version"},
		{"--config", c, "--registry"},
		{"--config", c, "--explain=commit-sha"},
		{"--config", c, "--examples", "--html", filepath.Join(t.TempDir(), "x.html")},
		{"--config", ""},
	} {
		if got := run(t, raw(a...)); got.code != ExitUsage || got.stdout != "" {
			t.Errorf("%v: exit %d, want %d", a, got.code, ExitUsage)
		}
	}
}

// TestNoAssumptionsRefused: --no-assumptions and its key, which a run of
// an earlier version took, are refused as any unknown flag and any unknown
// key are: a run answers no fact by an assumed value.
func TestNoAssumptionsRefused(t *testing.T) {
	dir := repo(t)
	if got := run(t, args("--root", dir, "--no-assumptions")); got.code != ExitUsage || !strings.Contains(got.stderr, "flag provided but not defined: -no-assumptions") {
		t.Errorf("--no-assumptions: exit %d, stderr %q; want %d", got.code, got.stderr, ExitUsage)
	}
	cfg := configurationFile(t, t.TempDir(), "no-assumptions: true\n")
	if got := run(t, args("--root", dir, "--config", cfg)); got.code != ExitNoInput || !strings.Contains(got.stderr, "no-assumptions: not a key") {
		t.Errorf("the key no-assumptions: exit %d, stderr %q; want %d", got.code, got.stderr, ExitNoInput)
	}
}

// TestConfigurationRefusals: an alias in the configuration file and a
// fact given twice are refused, each with what it is.
func TestConfigurationRefusals(t *testing.T) {
	dir := repo(t)
	cfg := t.TempDir()
	for _, c := range []struct{ name, src, says string }{
		{"an alias", "exclude: [&a \"sub\", *a]\n", "alias"},
	} {
		got := run(t, args("--root", dir, "--config", configurationFile(t, cfg, c.src)))
		if got.code != ExitNoInput || !strings.Contains(got.stderr, c.says) {
			t.Errorf("%s: exit %d, stderr %q; want %d and %q", c.name, got.code, got.stderr, ExitNoInput, c.says)
		}
	}
	if got := run(t, args("--root", dir, "--repo", "o/r", "--fact", "repo.public=false", "--fact", "repo.public=true")); got.code != ExitUsage || !strings.Contains(got.stderr, "repo.public") {
		t.Errorf("a fact twice: exit %d, stderr %q; want the fact named", got.code, got.stderr)
	}
}

// TestOwnerFixes: forms that the owner asked on 2026-10-30 to fix, each as
// the input that showed it.
func TestOwnerFixes(t *testing.T) {
	dir := repo(t)
	cfg := t.TempDir()
	for _, name := range []string{"accept", "facts"} {
		p := configurationFile(t, cfg, name+": \"nope.json\"\n")
		got := run(t, args("--root", dir, "--config", p))
		if want := "--config " + p + ": " + name; got.code != ExitNoInput || !strings.Contains(got.stderr, want) {
			t.Errorf("%s of the file not there: exit %d, stderr %q; want %d and %q", name, got.code, got.stderr, ExitNoInput, want)
		}
	}
	if got := run(t, raw("--init", "--rule", "nosuch")); got.code != ExitUsage || got.stdout != "" {
		t.Errorf("--init --rule nosuch: exit %d, stdout %q; want %d and nothing", got.code, got.stdout, ExitUsage)
	}
	b, err := os.ReadFile(initFile(t))
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); strings.Contains(s, "in a workflow, --repo") || !strings.Contains(s, "not expanded") {
		t.Errorf("the comment of repo in the template:\n%s", s)
	}
	help := run(t, raw("-h")).stderr
	if !strings.Contains(help, `(in a workflow, --repo "$GITHUB_REPOSITORY")`) {
		t.Errorf("the usage of --repo lost its phrase:\n%s", help)
	}
	if u := configurationUsage(); !strings.Contains(u, "--stdin-name") || !strings.Contains(u, "the key exclude") {
		t.Errorf("the usage of --config does not say when exclude of the file is not used: %q", u)
	}
}

// TestFileOfKeyError: the error of a file named by accept or facts of the
// configuration file has one form: the key, a colon, then the error, which
// names the path once.
func TestFileOfKeyError(t *testing.T) {
	dir := repo(t)
	cfg := t.TempDir()
	for _, name := range []string{"accept", "facts"} {
		p := configurationFile(t, cfg, name+": \"nope.json\"\n")
		got := run(t, args("--root", dir, "--config", p))
		if want := "--config " + p + ": " + name + ": open "; !strings.Contains(got.stderr, want) || strings.Count(got.stderr, "nope.json") != 1 {
			t.Errorf("%s: stderr %q; want %q and the path once", name, got.stderr, want)
		}
	}
}

// TestActionListFromConfiguration: a configuration file that answers
// repo.action-list with fact runs action-list, offline and with --repo, and
// a finding of the rule sets bit 1; without the answer, the rule does not
// run, and the text says when the rule runs (DefaultRunGivenFacts).
func TestActionListFromConfiguration(t *testing.T) {
	dir := t.TempDir()
	wf := "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - uses: untrusted/action@11bd71901bbe5b1630ceea73d27597364c9af683\n"
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github", "workflows", "w.yml"), []byte(wf), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(conf, []byte("repo: o/r\nfact:\n  - 'repo.action-list=[\"actions/checkout@*\"]'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := run(t, args("--root", dir, "--config", conf))
	if !strings.Contains(got.stdout, `"kind_id":"action-list.unlisted"`) || got.code&1 == 0 {
		t.Errorf("with the list: exit %d, stderr %q, no finding of action-list.unlisted or no bit 1:\n%s", got.code, got.stderr, got.stdout)
	}
	if strings.Count(got.stdout, `"kind_id":"action-list.unlisted"`) != 1 {
		t.Errorf("findings of action-list.unlisted: %d, want 1 (untrusted/action)", strings.Count(got.stdout, `"kind_id":"action-list.unlisted"`))
	}
	text := run(t, raw("--root", dir))
	if strings.Contains(text.stdout, "action-list.unlisted") || !strings.Contains(text.stdout, "not run  action-list: ") {
		t.Errorf("without the list:\n%s", text.stdout)
	}
}
