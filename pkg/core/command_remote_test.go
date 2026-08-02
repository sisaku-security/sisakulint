package core

import (
	"slices"
	"testing"
)

func TestRemoteTargetFlagsString(t *testing.T) {
	var targets remoteTargetFlags
	if got := targets.String(); got != "" {
		t.Fatalf("zero-value String() = %q, want empty string", got)
	}
	if err := targets.Set(".github/workflows/ci.yml"); err != nil {
		t.Fatal(err)
	}
	if err := targets.Set(".github/workflows/release.yml"); err != nil {
		t.Fatal(err)
	}
	if got := targets.String(); got != ".github/workflows/ci.yml,.github/workflows/release.yml" {
		t.Fatalf("String() = %q", got)
	}
	var nilTargets *remoteTargetFlags
	if got := nilTargets.String(); got != "" {
		t.Fatalf("nil String() = %q, want empty string", got)
	}
}

func TestSelectRemoteTargetsDefaultsToChangedWorkflows(t *testing.T) {
	changed := []string{
		".github/workflows/z.yml",
		".github/workflows/a.yaml",
	}
	targets, err := selectRemoteTargets(nil, changed)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		".github/workflows/a.yaml",
		".github/workflows/z.yml",
	}
	if !slices.Equal(targets, want) {
		t.Fatalf("targets = %#v, want %#v", targets, want)
	}
}

func TestSelectRemoteTargetsRestrictsExplicitScope(t *testing.T) {
	changed := []string{
		".github/workflows/a.yml",
		".github/workflows/b.yml",
	}
	targets, err := selectRemoteTargets([]string{
		".github/workflows/b.yml",
		".github/workflows/b.yml",
	}, changed)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(targets, []string{".github/workflows/b.yml"}) {
		t.Fatalf("targets = %#v", targets)
	}

	for _, requested := range []string{
		".github/workflows/not-changed.yml",
		"../outside.yml",
		"/etc/passwd",
	} {
		if _, err := selectRemoteTargets([]string{requested}, changed); err == nil {
			t.Fatalf("unsafe or unchanged target %q was accepted", requested)
		}
	}
}
