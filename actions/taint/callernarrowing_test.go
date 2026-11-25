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

// TestCallerNarrowingGithubOnly: a caller's if narrows in the called
// workflow only github, which is the same in both; its inputs and needs
// are values of the caller's own, not those of the called workflow.
func TestCallerNarrowingGithubOnly(t *testing.T) {
	const top = "on: pull_request_target\njobs:\n  call:\n    uses: ./.github/workflows/mid.yml\n    with:\n      x: safe\n"
	const mid = "on:\n  workflow_call:\n    inputs:\n      x:\n        type: string\njobs:\n  call:\n    if: inputs.x == 'safe'\n    uses: ./.github/workflows/leaf.yml\n    with:\n      x: ${{ github.event.pull_request.title }}\n"
	const leaf = "on:\n  workflow_call:\n    inputs:\n      x:\n        type: string\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.x }}\"\n"
	got := refsIn(t, attacker.Outsider, [2]string{".github/workflows/leaf.yml", leaf}, [2]string{".github/workflows/mid.yml", mid}, [2]string{".github/workflows/top.yml", top})
	if r, ok := got["inputs.x"]; !ok || !slices.Equal(r, []string{"pull_request_target"}) {
		t.Errorf("inputs: got %v", got)
	}
	const caller = "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n      o: ok\n    steps:\n      - run: echo\n  call:\n    needs: a\n    if: needs.a.outputs.o == 'ok'\n    uses: ./.github/workflows/called.yml\n"
	const called = "on: workflow_call\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n      o: ${{ github.event.pull_request.title }}\n    steps:\n      - run: echo\n  b:\n    needs: a\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ needs.a.outputs.o }}\"\n"
	withCaller := refsIn(t, attacker.Outsider, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", caller})
	alone := refsIn(t, attacker.Outsider, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", "on: pull_request_target\njobs:\n  call:\n    uses: ./.github/workflows/called.yml\n"})
	if !slices.Equal(withCaller["needs.a.outputs.o"], alone["needs.a.outputs.o"]) {
		t.Errorf("needs: got %v, want as without the if %v", withCaller, alone)
	}
}

// TestCallerNarrowingMiddleOwnEvents: a workflow in the middle of the
// chain that runs on an event of its own calls the leaf past none of the
// ifs of its callers in those runs.
func TestCallerNarrowingMiddleOwnEvents(t *testing.T) {
	const top = "on: pull_request_target\njobs:\n  call:\n    if: github.head_ref == 'release'\n    uses: ./.github/workflows/mid.yml\n"
	const mid = "on: [workflow_call, pull_request_target]\njobs:\n  call:\n    uses: ./.github/workflows/leaf.yml\n"
	const leaf = "on: workflow_call\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.head_ref }}\"\n"
	got := refsIn(t, attacker.Outsider, [2]string{".github/workflows/leaf.yml", leaf}, [2]string{".github/workflows/mid.yml", mid}, [2]string{".github/workflows/top.yml", top})
	if r, ok := got["github.head_ref"]; !ok || !slices.Equal(r, []string{"pull_request_target"}) {
		t.Errorf("got %v", got)
	}
}
