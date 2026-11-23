package ir

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// remoteComposite is a reader that answers o/a@v1 with the composite action
// whose steps are steps.
func remoteComposite(t *testing.T, steps string) *composite.Reader {
	t.Helper()
	repo, _ := facts.ParseRepo("o/a")
	sha, _ := facts.ParseSHA(strings.Repeat("1", 40))
	v, err := json.Marshal(facts.ActionFile{Commit: sha, File: facts.ActionFileYML, Content: "runs:\n  using: composite\n  steps:\n" + steps})
	if err != nil {
		t.Fatal(err)
	}
	d := definitions{facts.ActionDefinition{Repo: repo, Ref: "v1"}: {State: facts.StateFound, Value: v, Source: facts.SourceGitHub}}
	return composite.NewReader(func(string) (facts.InputPath, *cst.Tree, *workflow.ActionMetadata, bool) {
		return facts.InputPath{}, nil, nil, false
	}, d)
}

// TestCompositeStepIfNeeds: the if of a step of a composite action does
// not read the needs context of the job of the step that runs the action
// (in a composite action, needs is not the job's), while the if of a step
// of the job does: GitHub runs the job test only after build succeeded.
func TestCompositeStepIfNeeds(t *testing.T) {
	const wf = `on: push
jobs:
  build:
    runs-on: x
    steps:
      - run: echo
  test:
    needs: build
    runs-on: x
    steps:
      - uses: o/a@v1
`
	inner := "    - if: needs.build.result != 'success'\n      uses: actions/cache@v4\n      with: {path: p, key: \"k-${{ github.sha }}\", restore-keys: k-}\n"
	x := newIR(t, wf).WithComposite(context.Background(), remoteComposite(t, inner))
	saves := x.allCacheRestoreSaves()
	if len(saves) != 1 || len(saves[0].savesOn) == 0 {
		t.Errorf("the step of the composite action: %d saves, want 1 on push", len(saves))
	}
	// the same if on a step of the job
	own := strings.Replace(wf, "      - uses: o/a@v1\n", "      - if: needs.build.result != 'success'\n        uses: actions/cache@v4\n        with: {path: p, key: \"k-${{ github.sha }}\", restore-keys: k-}\n", 1)
	for _, s := range newIR(t, own).allCacheRestoreSaves() {
		if len(s.savesOn) != 0 {
			t.Errorf("the step of the job: saves on %v, want none", s.savesOn)
		}
	}
}

// TestCompositeLaterStepIfNeeds: a later step of a composite action that
// runs an agent does not read the needs context of the job of the step
// that runs the action, while a later step of the job does
// (agent.LaterSteps).
func TestCompositeLaterStepIfNeeds(t *testing.T) {
	const wf = `on:
  issues: {types: [opened]}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo
  a:
    needs: build
    runs-on: ubuntu-latest
    steps:
`
	const inner = `    - uses: openai/codex-action@v1
      with: {sandbox: danger-full-access}
    - if: needs.build.result != 'success'
      run: npm test
      shell: bash
      env: {NPM: "${{ secrets.NPM }}"}
`
	x := newIR(t, wf+"      - uses: o/a@v1\n").WithComposite(context.Background(), remoteComposite(t, inner))
	got := x.allAgentSteps()
	if len(got) != 1 || len(got[0].laterSteps) != 1 || len(got[0].laterSteps[0].On) == 0 {
		t.Errorf("the later step of the composite action: %+v, want one on issues.opened", got)
	}
	const own = `      - uses: openai/codex-action@v1
        with: {sandbox: danger-full-access}
      - if: needs.build.result != 'success'
        run: npm test
        env: {NPM: "${{ secrets.NPM }}"}
`
	for _, s := range newIR(t, wf+own).allAgentSteps() {
		for _, l := range s.laterSteps {
			if len(l.On) != 0 {
				t.Errorf("the later step of the job: on %v, want none", l.On)
			}
		}
	}
}

// TestStepIfSiteNeeds: the if of a step, as an IfSite, reads the results of
// the jobs its job needs: a step that runs only when github.actor is
// dependabot[bot] lets a run of Dependabot through (attacker.StepIf).
func TestStepIfSiteNeeds(t *testing.T) {
	src := func(jobIf string) string {
		return `on: pull_request_target
jobs:
  build:
    runs-on: x
    steps:
      - run: echo
  test:
    needs: build
` + jobIf + `    runs-on: x
    steps:
      - if: needs.build.result == 'failure' || github.actor == 'dependabot[bot]'
        uses: actions/checkout@v4
`
	}
	for _, c := range []struct {
		jobIf string
		want  int
	}{{"", 1}, {"    if: always()\n", 0}} {
		n := 0
		for _, s := range newIR(t, src(c.jobIf)).allIfSites() {
			n += len(s.dependabotBypasses)
		}
		if n != c.want {
			t.Errorf("%q: %d bypasses, want %d", c.jobIf, n, c.want)
		}
	}
}

// TestCompositeAgentStepIfNeeds: the if of an agent's step of a composite
// action does not read the needs context of the job of the step that runs
// the action.
func TestCompositeAgentStepIfNeeds(t *testing.T) {
	const wf = `on:
  issues: {types: [opened]}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo
  a:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: o/a@v1
`
	const inner = `    - if: needs.build.result != 'success'
      uses: openai/codex-action@v1
      with: {sandbox: danger-full-access}
`
	got := newIR(t, wf).WithComposite(context.Background(), remoteComposite(t, inner)).allAgentSteps()
	if len(got) != 1 || len(got[0].attackerOn) == 0 {
		t.Errorf("the agent's step of the composite action: %+v, want one on issues.opened", got)
	}
}

// TestCompositeCacheSaveStepIfNeeds: a cache save of a composite action that
// a step of the job runs after a checkout does not read the needs context
// of the job, while the step of the job that runs the action does.
func TestCompositeCacheSaveStepIfNeeds(t *testing.T) {
	wf := func(outer string) string {
		return `on: pull_request_target
cache-mode: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo
  a:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
` + outer
	}
	const inner = `    - if: needs.build.result != 'success'
      uses: actions/cache@v4
      with: {path: ., key: k}
`
	for _, c := range []struct {
		outer string // the step of the job that runs the action
		saves bool
	}{
		{"      - uses: o/a@v1\n", true},
		{"      - if: needs.build.result != 'success'\n        uses: o/a@v1\n", false},
	} {
		x := newIR(t, wf(c.outer)).WithComposite(context.Background(), remoteComposite(t, inner))
		var on int
		n := 0
		for _, s := range x.allCheckoutSites() {
			for _, v := range s.cacheSaves {
				n++
				on += len(v.SaveOn)
			}
		}
		if n == 0 {
			t.Fatalf("%q: no cache save of the composite action", c.outer)
		}
		if (on > 0) != c.saves {
			t.Errorf("%q: saves on %d events, want saves %v", c.outer, on, c.saves)
		}
	}
}
