package taint

import "testing"

// The outputs of a step that runs alongside are not there yet: a step of
// the same parallel group, or one before the wait of a background step,
// does not see them; the steps after the group or the wait do.
func TestParallelStepOutputs(t *testing.T) {
	check(t, `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - parallel:
          - id: g
            run: echo "o=x" >> "$GITHUB_OUTPUT"
          - run: echo "${{ steps.g.outputs.o }}"
      - run: echo "${{ steps.g.outputs.o }}"
      - id: b
        run: echo "o=x" >> "$GITHUB_OUTPUT"
        background: true
      - run: echo "${{ steps.b.outputs.o }}"
      - wait: b
      - run: echo "${{ steps.b.outputs.o }}"
`, false,
		"run steps.g.outputs.o NotControlled",
		"run steps.g.outputs.o Inconclusive step-output-run",
		"run steps.b.outputs.o NotControlled",
		"run steps.b.outputs.o Inconclusive step-output-run")
}
