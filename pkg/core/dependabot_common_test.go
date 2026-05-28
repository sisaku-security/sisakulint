package core

import (
	"os"
	"path/filepath"
	"testing"
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
