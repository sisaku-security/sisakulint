package repofile

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// want is an expected answer: found with the value, or unknown.
type want int

const (
	wantFalse want = iota
	wantTrue
	wantUnknown
)

func (w want) String() string { return [...]string{"false", "true", "unknown"}[w] }

func check(t *testing.T, fsys fstest.MapFS, q facts.Query, w want) {
	t.Helper()
	a := New(fsys).Resolve(context.Background(), q)
	switch w {
	case wantUnknown:
		if a.State != facts.StateUnknown || a.Reason == "" {
			t.Errorf("%v: %+v, want unknown with a reason", q, a)
		}
	default:
		if a.State != facts.StateFound || string(a.Value) != w.String() {
			t.Errorf("%v: %+v (%s), want %v", q, a, a.Value, w)
		}
	}
	if a.Source != facts.SourceRepoFile {
		t.Errorf("%v: source %v, want repo-file", q, a.Source)
	}
}

func inputPath(t *testing.T, s string) facts.InputPath {
	t.Helper()
	p, err := facts.ParseInputPath(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func dependabotQuery(t *testing.T, path string) facts.Query {
	return facts.DependabotVersionUpdates{PackageEcosystem: facts.PackageEcosystemGitHubActions, InputPath: inputPath(t, path)}
}

func renovateQuery(t *testing.T, path string) facts.Query {
	return facts.RenovateManagerEnabled{Manager: facts.RenovateManagerGitHubActions, InputPath: inputPath(t, path)}
}

func TestResolverOtherKinds(t *testing.T) {
	a := New(fstest.MapFS{}).Resolve(context.Background(), facts.RepoPublic{})
	if a.State != facts.StateUnknown || a.Reason == "" {
		t.Errorf("%+v, want unknown", a)
	}
}
