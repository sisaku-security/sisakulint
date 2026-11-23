package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// TestResolverRepoFileOrder: --fact answers before the files of the
// repository under --root, and those before the file of facts; a fact the
// files leave unknown is answered by the file of facts.
func TestResolverRepoFileOrder(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".github/dependabot.yml", "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n")
	write("renovate.json", `{"extends": ["github>org/renovate-config"]}`)
	factsFile := filepath.Join(t.TempDir(), "facts.json")
	if err := os.WriteFile(factsFile, []byte(`{"schema":"sisakulint/facts/v0","facts":[
{"query":{"kind":"dependabot.version-updates","package_ecosystem":"github-actions","input_path":".github/workflows/ci.yml"},"state":"found","value":false},
{"query":{"kind":"renovate.manager-enabled","manager":"github-actions","input_path":".github/workflows/ci.yml"},"state":"found","value":true}
]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ci, _ := facts.ParseInputPath(".github/workflows/ci.yml")
	dependabot := facts.DependabotVersionUpdates{PackageEcosystem: facts.PackageEcosystemGitHubActions, InputPath: ci}
	renovate := facts.RenovateManagerEnabled{Manager: facts.RenovateManagerGitHubActions, InputPath: ci}
	ask := func(t *testing.T, q facts.Query, a ...string) facts.RawAnswer {
		t.Helper()
		o, err := parseArgs(append([]string{"--root", dir}, a...), io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		r, _, err := resolver(o, func(string) string { return "" }, root.FS())
		if err != nil {
			t.Fatal(err)
		}
		return r.Resolve(context.Background(), q)
	}
	if a := ask(t, dependabot); a.State != facts.StateFound || string(a.Value) != "true" || a.Source != facts.SourceRepoFile {
		t.Errorf("from the files: %+v", a)
	}
	if a := ask(t, dependabot, "--fact", "dependabot.version-updates[package_ecosystem=github-actions,input_path=.github/workflows/ci.yml]=false"); a.State != facts.StateFound || string(a.Value) != "false" || a.Source != facts.SourceArgument {
		t.Errorf("--fact first: %+v", a)
	}
	if a := ask(t, dependabot, "--facts", factsFile); string(a.Value) != "true" || a.Source != facts.SourceRepoFile {
		t.Errorf("the files before the file of facts: %+v", a)
	}
	if a := ask(t, renovate); a.State != facts.StateUnknown || !strings.Contains(a.Reason, "github>org/renovate-config") || a.Source != facts.SourceRepoFile {
		t.Errorf("a preset of an organization: %+v, want the reason of the files", a)
	}
	empty := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(empty, []byte(`{"schema":"sisakulint/facts/v0","facts":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if a := ask(t, renovate, "--facts", empty); a.State != facts.StateUnknown || !strings.Contains(a.Reason, "github>org/renovate-config") {
		t.Errorf("a file of facts without the answer: %+v, want the reason of the files", a)
	}
	if a := ask(t, renovate, "--facts", factsFile); a.State != facts.StateFound || string(a.Value) != "true" || a.Source != facts.SourceFile {
		t.Errorf("the file of facts answers what the files leave unknown: %+v", a)
	}
}

// TestResolverWithoutRoot: with no root (--stdin-name), the files of the
// repository answer nothing.
func TestResolverWithoutRoot(t *testing.T) {
	o, err := parseArgs([]string{"--stdin-name", ".github/workflows/ci.yml"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := resolver(o, func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ci, _ := facts.ParseInputPath(".github/workflows/ci.yml")
	if a := r.Resolve(context.Background(), facts.DependabotVersionUpdates{PackageEcosystem: facts.PackageEcosystemGitHubActions, InputPath: ci}); a.State != facts.StateUnknown || a.Source == facts.SourceRepoFile {
		t.Errorf("%+v", a)
	}
}
