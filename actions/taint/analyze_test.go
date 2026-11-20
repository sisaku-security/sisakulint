package taint

import (
	"fmt"
	"github.com/sisaku-security/sisakulint/actions/analysis"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// analyze reads src as a workflow (or an action.yml) and gives its
// references as lines: the sink, the reference, and what it is.
func analyze(t *testing.T, src string, action bool) []string {
	t.Helper()
	tr := cst.ParseMode([]byte(src), cst.ModeGitHub)
	var a Analysis
	if action {
		act, _ := workflow.ParseActionMetadata(tr)
		a = Analyze(nil, act)
	} else {
		w, _ := workflow.Parse(tr)
		a = Analyze(w, nil)
	}
	var out []string
	for _, s := range a.Sinks {
		text := s.Value.Text()
		for _, r := range s.Refs {
			line := s.Kind.String() + " " + text[r.Span.Start:r.Span.End] + " " + r.Verdict.String()
			switch r.Verdict {
			case analysis.Controlled:
				var names []string
				for _, e := range r.ControlledOn {
					if !slices.Contains(names, e.Name().String()) {
						names = append(names, e.Name().String())
					}
				}
				line += " " + strings.Join(names, ",")
				if len(r.Env) > 0 {
					line += " via env"
				}
			case analysis.Inconclusive:
				line += " " + r.InconclusiveKind.String()
			}
			out = append(out, line)
		}
	}
	return out
}

func check(t *testing.T, src string, action bool, want ...string) {
	t.Helper()
	got := analyze(t, src, action)
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestAnalyzeEvents(t *testing.T) {
	check(t, `on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }} ${{ github.event.issue.number }} ${{ github.run_id }} ${{ github.head_ref }}"
`, false,
		"run github.event.issue.title Controlled issues",
		"run github.event.issue.number NotControlled",
		"run github.run_id NotControlled",
		"run github.head_ref NotControlled")
	// push has no issue; pull_request is not an attacker's event
	check(t, `on: [push, pull_request]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }} ${{ github.event.head_commit.message }}"
`, false,
		"run github.event.pull_request.title NotControlled",
		"run github.event.head_commit.message Controlled push")
	check(t, `on:
  pull_request:
  workflow_dispatch:
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
`, false, "run github.event.pull_request.title NotControlled")
}

func TestAnalyzeIf(t *testing.T) {
	// the job's if leaves push, whose payload has no issue
	check(t, `on: [issues, push]
jobs:
  j:
    if: github.event_name == 'PUSH'
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`, false, "run github.event.issue.title NotControlled")
	check(t, `on: [issues, issue_comment]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - if: ${{ github.event_name != 'issues' }}
        run: echo "${{ github.event.issue.title }}"
`, false, "run github.event.issue.title Controlled issue_comment")
	// what is not known before the run leaves every event
	check(t, `on: [issues, issue_comment]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - if: github.actor == 'me' || success()
        run: echo "${{ github.event.issue.title }}"
      - if: text ${{ github.event_name == 'push' }}
        run: echo "${{ github.event.issue.title }}"
`, false,
		"run github.event.issue.title Controlled issue_comment,issues",
		"run github.event.issue.title Controlled issue_comment,issues")
}

func TestAnalyzeTypes(t *testing.T) {
	src := `on:
  issues:
    types: [%s]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.changes.title.from }}"
`
	check(t, strings.Replace(src, "%s", "labeled", 1), false, "run github.event.changes.title.from NotControlled")
	check(t, strings.Replace(src, "%s", "edited", 1), false, "run github.event.changes.title.from Controlled issues")
	// by default pull_request_target runs on opened, synchronize and reopened
	// (GitHub's documentation of the events), none of which is edited
	check(t, `on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.changes.title.from }} ${{ github.event.pull_request.title }}"
`, false,
		"run github.event.changes.title.from NotControlled",
		"run github.event.pull_request.title Controlled pull_request_target")
	// issue_comment runs on pinned and unpinned; case counts (as observed
	// on 2026-10-03 and 2026-10-14)
	pinned := `on:
  issue_comment:
    types: [%s]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.comment.body }}"
`
	check(t, strings.Replace(pinned, "%s", "pinned, unpinned", 1), false, "run github.event.comment.body Controlled issue_comment")
	check(t, strings.Replace(pinned, "%s", "Pinned", 1), false, "run github.event.comment.body NotControlled")
}

func TestAnalyzeEnv(t *testing.T) {
	check(t, `on: issues
env:
  TITLE: ${{ github.event.issue.title }}
  FIXED: x
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      OTHER: ${{ env.TITLE }}
    steps:
      - run: echo "${{ env.title }} ${{ env.FIXED }} ${{ env.OTHER }} ${{ env.NOWHERE }}"
      - env:
          TITLE: fixed here
        run: echo "${{ env.TITLE }}"
`, false,
		"run env.title Controlled issues via env",
		"run env.FIXED NotControlled",
		"run env.OTHER Controlled issues via env",
		"run env.NOWHERE Inconclusive env-unset",
		"run env.TITLE NotControlled")
	// env that refers to itself ends. An env value sees
	// only the env of the levels around it: B's env.B and A's env.A are
	// set nowhere the workflow says, but may be at run time ($GITHUB_ENV)
	check(t, `on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      A: ${{ env.A }}
    steps:
      - env:
          B: ${{ env.B }}${{ env.A }}
        run: echo "${{ env.B }}"
`, false, "run env.B Inconclusive env-unset")
	check(t, `on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    env: ${{ fromJSON(github.event.issue.body) }}
    steps:
      - run: echo "${{ env.X }}"
`, false, "run env.X Inconclusive env-dynamic")
}

func TestAnalyzeFunctions(t *testing.T) {
	check(t, `on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ format('{0}', github.event.issue.title) }}"
          echo "${{ contains(github.event.issue.title, 'x') }} ${{ github.event.issue.title == 'x' }} ${{ !github.event.issue.body }}"
          echo "${{ toJSON(github.event) }} ${{ github.event.issue.title || 'none' }}"
          echo "${{ hashFiles(github.event.issue.title) }}"
`, false,
		"run github.event.issue.title Controlled issues",
		"run github.event Controlled issues",
		"run github.event.issue.title Controlled issues")
}

func TestAnalyzeUnexamined(t *testing.T) {
	check(t, `on:
  workflow_dispatch:
    inputs:
      x: {}
jobs:
  a:
    runs-on: ubuntu-latest
    outputs:
      o: ${{ steps.s.outputs.o }}
    steps:
      - id: s
        run: echo
  j:
    needs: a
    runs-on: ubuntu-latest
    strategy:
      matrix: ${{ fromJSON(needs.a.outputs.o) }}
    steps:
      - id: s
        run: echo
      - run: echo "${{ steps.s.outputs.o }} ${{ steps.s.outcome }} ${{ needs.a.outputs.o }} ${{ needs.a.result }} ${{ inputs.x }} ${{ github.event.inputs.x }} ${{ matrix.v }} ${{ secrets.T }} ${{ vars.V }}"
  static:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        v: [a, b]
    steps:
      - run: echo "${{ matrix.v }}"
  tainted:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - v: ${{ github.event.issue.title }}
    steps:
      - run: echo "${{ matrix.v }}"
`, false,
		"run steps.s.outputs.o Inconclusive step-output-run",
		"run steps.s.outcome NotControlled",
		"run needs.a.outputs.o Inconclusive job-output",
		"run needs.a.result NotControlled",
		"run inputs.x Inconclusive input-dispatch",
		"run github.event.inputs.x Inconclusive input-dispatch",
		"run matrix.v Inconclusive matrix",
		"run secrets.T NotControlled",
		"run vars.V NotControlled",
		"run matrix.v NotControlled",
		"run matrix.v Inconclusive matrix")
}

// The kind of steps.<id>.outputs is the form of the step before that has
// the id; a step that has not run yet gives nothing, and so
// does no step.
func TestAnalyzeStepOutputs(t *testing.T) {
	check(t, `on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: r
        run: echo
      - id: l
        uses: ./.github/actions/a
      - id: self
        uses: $/.github/actions/a
      - id: rem
        uses: some/action@v1
      - id: folded
        uses: ${{ 'some/action@v1' }}
      - id: d
        uses: docker://alpine:3
      - id: me
        run: echo "${{ steps.R.outputs.o }} ${{ steps.l.outputs.o }} ${{ steps.self.outputs.o }} ${{ steps.rem.outputs.o }} ${{ steps.folded.outputs.o }} ${{ steps.d.outputs.o }} ${{ steps.me.outputs.o }} ${{ steps.later.outputs.o }} ${{ steps.nowhere.outputs.o }} ${{ steps.*.outputs.o }}"
      - id: later
        run: echo
  first:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ steps.*.outputs.o }}"
`, false,
		"run steps.R.outputs.o Inconclusive step-output-run",
		"run steps.l.outputs.o Inconclusive step-output-local-action",
		"run steps.self.outputs.o Inconclusive step-output-local-action",
		"run steps.rem.outputs.o Inconclusive step-output-remote-action",
		"run steps.folded.outputs.o Inconclusive step-output-remote-action",
		"run steps.d.outputs.o Inconclusive step-output-docker",
		"run steps.me.outputs.o NotControlled",
		"run steps.later.outputs.o NotControlled",
		"run steps.nowhere.outputs.o NotControlled",
		"run steps.*.outputs.o NotControlled", // an array: Array
		"run steps.*.outputs.o NotControlled")
	// a composite action's steps are its own
	check(t, `runs:
  using: composite
  steps:
    - id: s
      uses: some/action@v1
    - run: echo "${{ steps.s.outputs.o }} ${{ steps.outer.outputs.o }}"
      shell: bash
`, true,
		"run steps.s.outputs.o Inconclusive step-output-remote-action",
		"run steps.outer.outputs.o NotControlled")
}

// The kind of needs.<id>.outputs is the form of the job needed; a job not
// in needs gives nothing, and a composite action has no
// needs.
func TestAnalyzeJobOutputs(t *testing.T) {
	check(t, `on: issues
jobs:
  steps:
    runs-on: ubuntu-latest
    steps:
      - run: echo
  local:
    uses: ./.github/workflows/w.yml
  remote:
    uses: some/repo/.github/workflows/w.yml@v1
  other:
    runs-on: ubuntu-latest
    steps:
      - run: echo
  j:
    needs: [steps, Local, remote]
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ needs.steps.outputs.o }} ${{ needs.local.outputs.o }} ${{ needs.remote.outputs.o }} ${{ needs.other.outputs.o }} ${{ needs.nowhere.outputs.o }} ${{ needs.*.outputs.o }}"
`, false,
		"run needs.steps.outputs.o Inconclusive job-output",
		"run needs.local.outputs.o Inconclusive job-output-local-call",
		"run needs.remote.outputs.o Inconclusive job-output-remote-call",
		"run needs.other.outputs.o NotControlled",
		"run needs.nowhere.outputs.o NotControlled",
		"run needs.*.outputs.o NotControlled") // an array: Array
	check(t, `runs:
  using: composite
  steps:
    - run: echo "${{ needs.a.outputs.o }}"
      shell: bash
`, true, "run needs.a.outputs.o NotControlled")
}

// inputs are the dispatcher's when there is a workflow_dispatch, even
// with a workflow_call; the caller's otherwise.
func TestAnalyzeInputs(t *testing.T) {
	for _, c := range []struct{ on, want string }{
		{"workflow_dispatch", "input-dispatch"},
		{"workflow_call", "input-call"},
		{"[workflow_call, workflow_dispatch]", "input-dispatch"},
	} {
		check(t, "on: "+c.on+`
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.x }}"
`, false, "run inputs.x Inconclusive "+c.want)
	}
}

func TestAnalyzeEnvWhole(t *testing.T) {
	check(t, `on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(env) }} ${{ env[matrix.k] }}'
`, false,
		"run env Inconclusive env-whole",
		"run env[matrix.k] Inconclusive env-whole")
}

func TestAnalyzeScript(t *testing.T) {
	check(t, `on: issue_comment
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          github-token: ${{ github.event.comment.body }}
          script: console.log('${{ github.event.comment.body }}')
      - uses: Actions/GitHub-Script@main
        with:
          script: ${{ github.event.comment.body }}
      - uses: other/script@v1
        with:
          script: ${{ github.event.comment.body }}
`, false,
		"github-script github.event.comment.body Controlled issue_comment",
		"github-script github.event.comment.body Controlled issue_comment")
}

// A reusable workflow and a composite action run on the events of their
// callers: any of an attacker's.
func TestAnalyzeCalled(t *testing.T) {
	check(t, `on: workflow_call
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }} ${{ github.event.pull_request.head.ref }}"
`, false,
		"run github.event.issue.title Controlled issue_comment,issues",
		"run github.event.pull_request.head.ref Controlled pull_request_target")
	check(t, `runs:
  using: composite
  steps:
    - run: echo "${{ github.head_ref }} ${{ inputs.x }}"
      shell: bash
`, true,
		"run github.head_ref Controlled pull_request_target",
		"run inputs.x Inconclusive input-call")
}

// TestAnalyzeEnvFanOut: env that refers to env, many times at each level,
// is resolved once for each level and name, not once for each reference.
// The time is compared with ACTIONS_SCALE=1 only, as it depends on the
// machine.
func TestAnalyzeEnvFanOut(t *testing.T) {
	refs := func(name string, n int) string { return strings.Repeat("${{ env."+name+" }}", n) }
	const n = 30
	src := "on: workflow_call\nenv:\n  W: " + strings.Repeat("${{ github.event.issue.title }}", n) +
		"\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      K: " + refs("W", n) +
		"\n    steps:\n      - env:\n          S: " + refs("K", n) + "\n        run: echo \"" + refs("S", n) + "\"\n"
	start := time.Now()
	got := analyze(t, src, false)
	if d := time.Since(start); os.Getenv("ACTIONS_SCALE") == "1" && d > 2*time.Second {
		t.Errorf("Analyze took %v", d)
	}
	if len(got) != n || !strings.Contains(got[0], "Controlled") {
		t.Errorf("got %d refs: %v", len(got), got[:1])
	}
}

// Steps and needs written out whole, or a step
// or a job of them whole, have their outputs in them.
func TestAnalyzeWholeOutputs(t *testing.T) {
	check(t, `on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo
  j:
    needs: a
    runs-on: ubuntu-latest
    steps:
      - id: s
        uses: some/action@v1
      - run: echo '${{ toJSON(steps) }} ${{ toJSON(steps.s) }} ${{ toJSON(needs) }} ${{ toJSON(needs.a) }} ${{ steps.s.outcome }} ${{ needs.a.result }}'
`, false,
		"run steps Inconclusive step-output-remote-action",
		"run steps.s Inconclusive step-output-remote-action",
		"run needs Inconclusive job-output",
		"run needs.a Inconclusive job-output",
		"run steps.s.outcome NotControlled",
		"run needs.a.result NotControlled")
}

// What of a step or a job is picked by a star or an
// index not known may be its outputs.
func TestAnalyzeStarOutputs(t *testing.T) {
	check(t, `on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo
  j:
    needs: a
    runs-on: ubuntu-latest
    steps:
      - id: r
        run: echo
      - run: echo "${{ steps.r.*.o }} ${{ toJSON(steps.r.*) }} ${{ steps.r[matrix.k] }} ${{ needs.a.*.o }}"
`, false,
		"run steps.r.*.o NotControlled", // an array: Array
		"run steps.r.* Inconclusive step-output-run",
		"run steps.r[matrix.k] Inconclusive step-output-run",
		"run needs.a.*.o NotControlled") // an array: Array
}

// TestRefDashRepoName: a reference carries the events of LeadingDash on
// which every value that may begin with - is the name of a repository,
// through env as well. Each reference of an expression is its own (the ||
// of a branch's name and a repository's name gives two), so that the
// branch's name keeps every spelling.
func TestRefDashRepoName(t *testing.T) {
	src := `on: pull_request_target
env:
  N: ${{ github.event.pull_request.head.repo.name }}
  M: ${{ github.event.pull_request.head.repo.name }}${{ github.head_ref }}
  K: ${{ github.event.pull_request.head.repo.name }}=${{ github.event.pull_request.head.label }}
  R: ${{ github.event.pull_request.head.repo.name }}-${{ github.event.pull_request.head.repo.name }}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ env.N }}" "${{ env.M }}" "${{ env.K }}" "${{ env.R }}" "${{ github.head_ref }}" "${{ github.head_ref || github.event.pull_request.head.repo.name }}" "${{ github.event.pull_request.head.repo.name }}"
`
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	a := Analyze(w, nil)
	var got []bool
	for _, r := range a.Sinks[0].Refs {
		got = append(got, len(r.DashRepoName) > 0 && slices.Equal(r.DashRepoName, r.LeadingDash))
	}
	if !slices.Equal(got, []bool{true, false, false, true, false, false, true, true}) {
		t.Errorf("events of a repository's name: %v", got)
	}
}

// TestRefLoginPrefixed: the label of a pull request's head and the full
// name of its repository, through env, are known not to begin with -; of
// ||, the label is a reference of its own, and the branch's name still may.
func TestRefLoginPrefixed(t *testing.T) {
	src := `on: pull_request_target
env:
  L: ${{ github.event.pull_request.head.label }}
  F: ${{ github.event.pull_request.head.repo.full_name }}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ env.L }}" "${{ env.F }}" "${{ github.event.pull_request.head.label || github.head_ref }}"
`
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	a := Analyze(w, nil)
	var got []string
	for _, r := range a.Sinks[0].Refs {
		got = append(got, fmt.Sprintf("%v/%v", len(r.LeadingDash) > 0, len(r.DashUndecided) > 0))
	}
	if !slices.Equal(got, []string{"false/false", "false/false", "false/false", "true/false"}) {
		t.Errorf("leading dash/undecided: %v", got)
	}
}

// TestRefLeadingDash: a reference carries the events on which an attacker
// can make it begin with -, through env as well.
func TestRefLeadingDash(t *testing.T) {
	src := `on: pull_request_target
env:
  H: ${{ github.head_ref }}
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      L: ${{ github.event.pull_request.head.label }}
    steps:
      - run: echo "${{ env.H }}" "${{ env.L }}" "${{ github.event.pull_request.title }}"
`
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	a := Analyze(w, nil)
	var got []bool
	for _, r := range a.Sinks[0].Refs {
		got = append(got, len(r.LeadingDash) > 0)
	}
	if !slices.Equal(got, []bool{true, false, true}) {
		t.Errorf("events with a leading dash: %v", got)
	}
}
