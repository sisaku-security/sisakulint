package core

import (
	"strings"
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
        fail-on-cache-miss: true
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
	if got := step.With["fail-on-cache-miss"]; got != "true" {
		t.Fatalf("step.With[fail-on-cache-miss] = %q, want true", got)
	}
}

func TestParseRemoteActionSpecSupportsRootAndSubpathActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec string
		dir  string
	}{
		{
			name: "root action",
			spec: "owner/repo@main",
			dir:  ".",
		},
		{
			name: "subpath action",
			spec: "TanStack/config/.github/setup@main",
			dir:  ".github/setup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRemoteActionSpec(tt.spec)
			if !ok {
				t.Fatalf("parseRemoteActionSpec(%q) returned !ok", tt.spec)
			}
			if got.owner != strings.Split(tt.spec, "/")[0] {
				t.Fatalf("owner = %q", got.owner)
			}
			if got.dir != tt.dir {
				t.Fatalf("dir = %q, want %q", got.dir, tt.dir)
			}
			if got.ref != "main" {
				t.Fatalf("ref = %q, want main", got.ref)
			}
		})
	}
}

func TestRemoteActionMetadataPathsSupportsRootAction(t *testing.T) {
	t.Parallel()

	got := remoteActionMetadataPaths(".")
	want := []string{"action.yml", "action.yaml"}
	if len(got) != len(want) {
		t.Fatalf("len(remoteActionMetadataPaths(.)) = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("remoteActionMetadataPaths(.)[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseRemoteActionSpecRejectsAbsoluteActionPath(t *testing.T) {
	t.Parallel()

	if got, ok := parseRemoteActionSpec("owner/repo//absolute/path@main"); ok {
		t.Fatalf("parseRemoteActionSpec returned ok with absolute path: %#v", got)
	}
}
