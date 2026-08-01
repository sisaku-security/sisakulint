package core

import (
	"slices"
	"testing"
)

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
	} {
		if _, err := selectRemoteTargets([]string{requested}, changed); err == nil {
			t.Fatalf("unsafe or unchanged target %q was accepted", requested)
		}
	}
}
