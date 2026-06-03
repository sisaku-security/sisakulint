package core

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDependabotConfiguredEcosystems(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "dependabot.yaml")
	content := `version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	got, err := dependabotConfiguredEcosystems(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got["npm"] || !got["gomod"] {
		t.Errorf("expected npm and gomod, got %v", got)
	}
	if got["pip"] {
		t.Errorf("pip should not be present, got %v", got)
	}
}

func TestRenovateManagedEcosystems_BroadPreset(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	githubDir := filepath.Join(tmp, ".github")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	renovate := `{ "extends": ["config:recommended"] }`
	if err := os.WriteFile(filepath.Join(githubDir, "renovate.json"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	_, all := renovateManagedEcosystems(tmp)
	if !all {
		t.Errorf("expected config:recommended to enable all managers (all=true)")
	}
}

func TestRenovateManagedEcosystems_JSON5BroadPreset(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	githubDir := filepath.Join(tmp, ".github")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// renovate.json5 with // line comments, a /* */ block comment, and a trailing
	// comma. yaml.Unmarshal alone rejects all three; the JSON5 strip path must
	// recover so the broad preset is detected and "all" is reported as true.
	renovate := `{
  // Inherit the broad preset that enables every manager.
  "extends": [
    "config:recommended", /* trailing comma below is JSON5-only */
  ],
}
`
	if err := os.WriteFile(filepath.Join(githubDir, "renovate.json5"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	_, all := renovateManagedEcosystems(tmp)
	if !all {
		t.Errorf("expected JSON5 renovate config with config:recommended to enable all managers (all=true)")
	}
}

func TestRenovateManagedEcosystems_JSON5SpecificManagers(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	githubDir := filepath.Join(tmp, ".github")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// String literals containing "//" must not be treated as comments.
	renovate := `{
  // scoped to cargo only
  "packageRules": [
    {
      "description": "see https://example.com//docs",
      "matchManagers": ["cargo",],
    },
  ],
}
`
	if err := os.WriteFile(filepath.Join(githubDir, "renovate.json5"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	managed, all := renovateManagedEcosystems(tmp)
	if all {
		t.Errorf("expected all=false when only specific matchManagers are set")
	}
	if !managed["cargo"] {
		t.Errorf("expected cargo to be managed from JSON5 renovate config, got %v", managed)
	}
}

func TestRenovateManagedEcosystems_EnabledManagersOverridesBroadPreset(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	githubDir := filepath.Join(tmp, ".github")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// extends a broad preset but limits Renovate to github-actions only. Per Renovate
	// docs, enabledManagers disables every manager not in the list, so npm/cargo/...
	// must NOT be treated as managed. The "all" return value must be false.
	renovate := `{
  "extends": ["config:recommended"],
  "enabledManagers": ["github-actions"]
}`
	if err := os.WriteFile(filepath.Join(githubDir, "renovate.json"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	managed, all := renovateManagedEcosystems(tmp)
	if all {
		t.Errorf("expected all=false when enabledManagers narrows the broad preset")
	}
	// github-actions is intentionally outside renovateManagerToEcosystem (it's handled
	// by DependabotGitHubActionsRule), so the managed set stays empty for npm/cargo/etc.
	if managed["npm"] || managed["cargo"] {
		t.Errorf("expected npm/cargo to remain unmanaged under enabledManagers=[github-actions], got %v", managed)
	}
}

func TestRenovateManagedEcosystems_EnabledManagersListsEcosystem(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	githubDir := filepath.Join(tmp, ".github")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// extends + enabledManagers:["npm"] limits Renovate to npm only. The broad preset
	// no longer implies all=true, but npm itself must be reported as managed.
	renovate := `{
  "extends": ["config:recommended"],
  "enabledManagers": ["npm"]
}`
	if err := os.WriteFile(filepath.Join(githubDir, "renovate.json"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	managed, all := renovateManagedEcosystems(tmp)
	if all {
		t.Errorf("expected all=false when enabledManagers is set, got all=true")
	}
	if !managed["npm"] {
		t.Errorf("expected npm to be managed via enabledManagers, got %v", managed)
	}
	if managed["cargo"] {
		t.Errorf("cargo should NOT be managed when enabledManagers=[npm], got %v", managed)
	}
}

func TestRenovateManagedEcosystems_PackageRulesIgnoredForDisabledManagers(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	githubDir := filepath.Join(tmp, ".github")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// enabledManagers globally disables every manager except github-actions, so the
	// packageRules entry targeting "npm" must be ignored — Renovate would not run it.
	renovate := `{
  "enabledManagers": ["github-actions"],
  "packageRules": [{ "matchManagers": ["npm"] }]
}`
	if err := os.WriteFile(filepath.Join(githubDir, "renovate.json"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	managed, all := renovateManagedEcosystems(tmp)
	if all {
		t.Errorf("expected all=false when enabledManagers is set, got all=true")
	}
	if managed["npm"] {
		t.Errorf("expected npm to be ignored — its packageRule manager is globally disabled, got managed=%v", managed)
	}
}

func TestStripJSON5Sugar_PreservesStrings(t *testing.T) {
	t.Parallel()

	in := []byte(`{"k": "a // not a comment, still a string", "x": [1, 2,],}`)
	out := string(stripJSON5Sugar(in))
	// Trailing commas before ] and } must be removed; string content must be intact.
	want := `{"k": "a // not a comment, still a string", "x": [1, 2]}`
	if out != want {
		t.Errorf("stripJSON5Sugar mismatch:\n  got:  %q\n  want: %q", out, want)
	}
}

// TestStripJSON5Sugar_TrailingCommaWithCommentsRemoved exercises the comma+comment
// interleaving the original lookahead missed: trailing commas followed by a line or
// block comment before the closing bracket. The trailing comma must be dropped (not
// just have its neighbouring comment stripped) so the output is valid strict JSON.
func TestStripJSON5Sugar_TrailingCommaWithCommentsRemoved(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
	}{
		{
			name: "block comment between trailing comma and bracket",
			in:   `{"x": ["cargo", /* trailing */ ]}`,
		},
		{
			name: "line comment between trailing comma and bracket",
			in:   "{\"x\": [\"cargo\", // trailing\n]}",
		},
		{
			name: "block comment between trailing comma and brace",
			in:   `{"x": "y", /* trailing */ }`,
		},
		{
			name: "consecutive block comments after trailing comma",
			in:   `{"x": ["cargo", /* a */ /* b */ ]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := string(stripJSON5Sugar([]byte(tc.in)))
			// After stripping, no "," may immediately precede a closing bracket
			// (allowing whitespace in between, but not non-stripped content).
			for i := 0; i < len(out)-1; i++ {
				if out[i] != ',' {
					continue
				}
				j := i + 1
				for j < len(out) && (out[j] == ' ' || out[j] == '\t' || out[j] == '\r' || out[j] == '\n') {
					j++
				}
				if j < len(out) && (out[j] == ']' || out[j] == '}') {
					t.Fatalf("trailing comma still present after strip:\n  input:  %q\n  output: %q", tc.in, out)
				}
			}
			// And the result must parse as strict JSON.
			var got any
			if err := yaml.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("stripped output failed to parse: %v\n  input:  %q\n  output: %q", err, tc.in, out)
			}
		})
	}
}

func TestRenovateManagedEcosystems_SpecificManagers(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	githubDir := filepath.Join(tmp, ".github")
	if err := os.MkdirAll(githubDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Renovate scoped to npm only; gomod manager maps to the gomod ecosystem.
	renovate := `{ "packageRules": [{ "matchManagers": ["npm", "gomod"] }] }`
	if err := os.WriteFile(filepath.Join(githubDir, "renovate.json"), []byte(renovate), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	managed, all := renovateManagedEcosystems(tmp)
	if all {
		t.Errorf("expected all=false when only specific matchManagers are set")
	}
	if !managed["npm"] || !managed["gomod"] {
		t.Errorf("expected npm and gomod managed, got %v", managed)
	}
	if managed["cargo"] {
		t.Errorf("cargo should not be managed, got %v", managed)
	}
}
