package rules

import (
	"slices"
	"testing"
)

// TestBackslashInputName: a workflow whose file name holds a backslash,
// which no fact can name, is read by every rule without an error, and the
// findings that would ask a fact of its name hold as if the fact were true
// (two rules once panicked on it; see
// https://github.com/gh-intel/sisakulint/issues/738).
func TestBackslashInputName(t *testing.T) {
	rep := runEveryRule(t, map[string]string{
		`.github/workflows/a\b.yml`: `on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
  fetch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo done
`,
		`.github/workflows/c\d.yml`: `on:
  workflow_run:
    workflows: [ci]
    types: [completed]
jobs:
  apply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: out
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
`,
	}, nil)
	got := reportedKinds(rep)
	for _, k := range []string{"dangerous-triggers.token-write", "untrusted-checkout.executed", "untrusted-checkout.checkout", "artifact-poisoning.download", "dependabot-github-actions.no-update-tool"} {
		if !slices.Contains(got, k) {
			t.Errorf("no %s in %v", k, got)
		}
	}
}
