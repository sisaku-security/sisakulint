package taint

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// The ifs of a job and of a step that runs a script narrow a reference they
// compare with plain literals (attacker.Narrowing).
func TestAnalyzeNarrowing(t *testing.T) {
	const comment = "on:\n  issue_comment:\n    types: [created]\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
	check(t, comment+`    if: github.event.comment.body == 'deploy'
    steps:
      - run: echo "${{ github.event.comment.body }}" "${{ github.event.issue.title }}"
      - if: always()
        run: echo "${{ github.event.comment.body }}"
`, false,
		"run github.event.comment.body NotControlled",
		"run github.event.issue.title Controlled issue_comment",
		"run github.event.comment.body NotControlled")
	// the if of a step: the attacker's event that the other operand leaves
	check(t, `on: [issues, issue_comment]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - if: github.event_name == 'issues' || github.event.issue.title == 'x'
        run: echo "${{ github.event.issue.title }}"
`, false, "run github.event.issue.title Controlled issues")
	// the pre step of an action runs whatever the if of its step: the if of
	// a step that uses an action does not narrow its with, the if of the job
	// does
	check(t, comment+`    steps:
      - if: github.event.comment.body == 'deploy'
        uses: actions/github-script@v7
        with:
          script: console.log("${{ github.event.comment.body }}")
`, false, "github-script github.event.comment.body Controlled issue_comment")
	check(t, comment+`    if: github.event.comment.body == 'deploy'
    steps:
      - uses: actions/github-script@v7
        with:
          script: console.log("${{ github.event.comment.body }}")
`, false, "github-script github.event.comment.body NotControlled")
	// through env, set at the job and at the step
	check(t, comment+`    if: github.event.comment.body == 'deploy'
    env:
      B: ${{ github.event.comment.body }}
    steps:
      - run: echo "${{ env.B }}"
`, false, "run env.B NotControlled")
	check(t, comment+`    steps:
      - if: env.B == 'deploy'
        env:
          B: ${{ github.event.comment.body }}
        run: echo "${{ env.B }}"
      - if: env.b == 'deploy'
        env:
          B: ${{ github.event.comment.body }}
        run: echo "${{ env.B }}"
`, false,
		"run env.B NotControlled",
		"run env.B Controlled issue_comment via env")
	// the outputs of a step, the inputs of a dispatch, a matrix not written out
	check(t, comment+`    steps:
      - id: s
        run: echo
      - if: steps.s.outputs.x == 'a'
        run: echo "${{ steps.s.outputs.x }}"
`, false, "run steps.s.outputs.x NotControlled")
	check(t, `on: workflow_dispatch
jobs:
  j:
    if: inputs.x == 'a'
    runs-on: ubuntu-latest
    strategy:
      matrix: ${{ fromJSON(vars.M) }}
    steps:
      - if: matrix.v == 'a'
        run: echo "${{ inputs.x }}" "${{ matrix.v }}"
`, false, "run inputs.x NotControlled", "run matrix.v NotControlled")
	// not narrowed: the whole object, !=, another reference, a string of code
	check(t, comment+`    if: github.event.comment.body == 'deploy'
    steps:
      - run: echo '${{ toJSON(github.event.comment) }}'
`, false, "run github.event.comment Controlled issue_comment")
	check(t, comment+`    steps:
      - if: github.event.comment.body != 'deploy'
        run: echo "${{ github.event.comment.body }}"
      - if: github.event.issue.title == 'deploy'
        run: echo "${{ github.event.comment.body }}"
      - if: github.event.comment.body == '$(id)'
        run: echo "${{ github.event.comment.body }}"
`, false,
		"run github.event.comment.body Controlled issue_comment",
		"run github.event.comment.body Controlled issue_comment",
		"run github.event.comment.body Controlled issue_comment")
}

// A variable of the script is narrowed as env.<name> is, but not one the
// runner writes over env.
func TestAnalyzeNarrowingVariables(t *testing.T) {
	// writes and args are the writes to an environment file and the words
	// of commands with a value an attacker may control
	writes := func(src string) (writes, args int) {
		t.Helper()
		w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
		for _, s := range Analyze(w, nil).Sinks {
			writes += len(s.EnvironmentFileWrites)
			args += len(s.Arguments)
		}
		return writes, args
	}
	if n, _ := writes(`on: issue_comment
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - if: env.B == 'deploy'
        env:
          B: ${{ github.event.comment.body }}
        run: echo "B=$B" >> "$GITHUB_ENV"
`); n != 0 {
		t.Errorf("a variable the if compares: %d writes, want 0", n)
	}
	if _, n := writes(`on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - if: env.GITHUB_HEAD_REF == 'main'
        env:
          GITHUB_HEAD_REF: main
        run: git checkout $GITHUB_HEAD_REF
`); n == 0 {
		t.Error("a variable the runner writes over env is narrowed by env")
	}
}

// The if of the job that calls a reusable workflow narrows the value it
// gives the input.
func TestCallersInputNarrowed(t *testing.T) {
	caller := "on: issues\njobs:\n  c:\n    if: github.event.issue.title == 'deploy'\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n"
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", calledEcho}, [2]string{".github/workflows/ci.yml", caller})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.NotControlled {
		t.Fatalf("ref = %+v", r)
	}
}

// An env read from the level after the step's (C reads env.B of the job) is
// not what the step's if compares.
func TestAnalyzeNarrowingEnvLevel(t *testing.T) {
	check(t, `on: issue_comment
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      B: ${{ github.event.comment.body }}
    steps:
      - if: env.B == 'safe'
        env:
          B: safe
          C: ${{ env.B }}
        run: echo "${{ env.C }}"
`, false, "run env.C Controlled issue_comment via env")
}

// The if of a step that uses an action does not narrow its with; the if of
// a step of a composite action that runs a script narrows the inputs.
func TestCallersInputNarrowedSteps(t *testing.T) {
	caller := "on: issue_comment\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.event.comment.body == 'deploy'\n        uses: ./.github/actions/a\n        with:\n          x: ${{ github.event.comment.body }}\n"
	action := "inputs:\n  x:\n    description: x\nruns:\n  using: composite\n  steps:\n    - run: echo \"${{ inputs.x }}\"\n      shell: bash\n"
	c := callersOf(t, true, [2]string{".github/actions/a/action.yml", action}, [2]string{".github/workflows/ci.yml", caller})
	if r := sinkRef(t, c, ".github/actions/a/action.yml"); r.Verdict != analysis.Controlled {
		t.Errorf("the with of a step whose if compares: ref = %+v", r)
	}
	check(t, `inputs:
  x:
    description: x
runs:
  using: composite
  steps:
    - if: inputs.x == 'a'
      run: echo "${{ inputs.x }}"
      shell: bash
    - if: inputs.x == 'a'
      uses: actions/github-script@v7
      with:
        script: console.log("${{ inputs.x }}")
`, true, "run inputs.x NotControlled", "github-script inputs.x Inconclusive input-call")
}

// The if of the calling job compares the caller's inputs, not the inputs
// that a called workflow's default reads.
func TestCallersDefaultNotNarrowedByCallerInputs(t *testing.T) {
	caller := "on: issue_comment\njobs:\n  c:\n    if: inputs.x == ''\n    uses: ./.github/workflows/called.yml\n    with:\n      x: ${{ github.event.comment.body }}\n"
	called := "on:\n  workflow_call:\n    inputs:\n      x:\n        type: string\n      y:\n        type: string\n        default: ${{ inputs.x }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.y }}\"\n"
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", caller})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.Controlled {
		t.Errorf("ref = %+v", r)
	}
}
