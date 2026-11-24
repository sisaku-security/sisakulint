package taint

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/attacker"
)

// TestCallerNarrowing: a called workflow runs only past the ifs of the
// jobs that call it, so an if of every caller narrows a reference in it
// as the if of its own job does (Callers.callerNarrowings); a caller whose
// if does not narrow it, or a workflow that runs on its own events too,
// keeps the reference the attacker's.
func TestCallerNarrowing(t *testing.T) {
	const called = "on: workflow_call\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.head_ref }}\"\n"
	caller := func(name, cond string) [2]string {
		return [2]string{".github/workflows/" + name + ".yml", "on: pull_request_target\njobs:\n  call:\n    if: " + cond + "\n    uses: ./.github/workflows/called.yml\n"}
	}
	for _, c := range []struct {
		what    string
		called  string
		callers [][2]string
		want    []string
	}{
		{"one caller narrows", called, [][2]string{caller("a", "github.head_ref == 'release'")}, nil},
		{"every caller narrows", called, [][2]string{caller("a", "github.head_ref == 'release'"), caller("b", "github.head_ref == 'main'")}, nil},
		{"a caller does not narrow", called, [][2]string{caller("a", "github.head_ref == 'release'"), caller("b", "always()")}, []string{"pull_request_target"}},
		{"own events too", "on:\n  workflow_call:\n  pull_request_target:\n" + called[len("on: workflow_call\n"):], [][2]string{caller("a", "github.head_ref == 'release'")}, []string{"pull_request_target"}},
	} {
		files := append([][2]string{{".github/workflows/called.yml", c.called}}, c.callers...)
		got := refsIn(t, attacker.Outsider, files...)
		if r, ok := got["github.head_ref"]; !ok || !slices.Equal(r, c.want) {
			t.Errorf("%s: got %v, want %v", c.what, got, c.want)
		}
	}
}
