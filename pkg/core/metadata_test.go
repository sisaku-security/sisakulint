package core

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestActionMetadataParsesCompositeRunsSteps(t *testing.T) {
	t.Parallel()

	content := []byte(`
name: setup
runs:
  using: composite
  steps:
    - uses: actions/cache@v5
      if: always()
      with:
        path: ~/.pnpm-store
        key: Linux-pnpm-store-${{ hashFiles('**/pnpm-lock.yaml') }}
`)

	var meta ActionMetadata
	if err := yaml.Unmarshal(content, &meta); err != nil {
		t.Fatalf("yaml.Unmarshal returned error: %v", err)
	}

	if meta.Runs == nil {
		t.Fatal("Runs metadata is nil")
	}
	if meta.Runs.Using != "composite" {
		t.Fatalf("Runs.Using = %q, want %q", meta.Runs.Using, "composite")
	}
	if len(meta.Runs.Steps) != 1 {
		t.Fatalf("len(Runs.Steps) = %d, want 1", len(meta.Runs.Steps))
	}

	step := meta.Runs.Steps[0]
	if step.Uses != "actions/cache@v5" {
		t.Fatalf("step.Uses = %q, want actions/cache@v5", step.Uses)
	}
	if step.If != "always()" {
		t.Fatalf("step.If = %q, want always()", step.If)
	}
	if got := step.With["key"]; got != "Linux-pnpm-store-${{ hashFiles('**/pnpm-lock.yaml') }}" {
		t.Fatalf("step.With[key] = %q", got)
	}
}
