package ir

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
)

// TestJobTimeoutProjection: each job on a runner, and whether it writes
// timeout-minutes; not a job that calls a reusable workflow.
func TestJobTimeoutProjection(t *testing.T) {
	x := newIR(t, `on: push
jobs:
  a:
    runs-on: x
    steps: [{run: a}]
  b:
    runs-on: x
    timeout-minutes: 10
    steps: [{run: a}]
  c:
    uses: ./.github/workflows/c.yml
`)
	got := x.allJobTimeouts()
	if len(got) != 2 || got[0].job != "a" || got[0].written || got[1].job != "b" || !got[1].written {
		t.Errorf("%+v", got)
	}
}

func TestCacheRestoreSaveProjection(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string // the events of each summary, joined by commas
	}{
		{"unified with restore-keys", `on: [push, issue_comment]
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache@v4
        with: {path: p, key: "k-${{ github.run_id }}", restore-keys: k-}
`, []string{"push"}},
		{"unified, exact only", `on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache@v4
        with: {path: p, key: k}
`, nil},
		{"lookup-only", `on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache@v4
        with: {path: p, key: k, restore-keys: k-, lookup-only: true}
`, nil},
		{"split", `on: [push, pull_request]
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache/restore@v4
        with: {path: p, key: "k-${{ github.sha }}", restore-keys: k-}
      - run: make
      - uses: actions/cache/save@v4
        with: {path: p, key: "k-${{ github.sha }}"}
`, []string{"push,pull_request"}},
		{"split by event", `on: [push, pull_request]
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache/restore@v4
        if: github.event_name != 'push'
        with: {path: p, key: "k-${{ github.sha }}", restore-keys: k-}
      - uses: actions/cache/save@v4
        if: github.event_name == 'push'
        with: {path: p, key: "k-${{ github.sha }}"}
`, nil},
		{"read only", `on: push
cache-mode: read
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache@v4
        with: {path: p, key: "k-${{ github.sha }}", restore-keys: k-}
`, nil},
		{"save before restore", `on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache/save@v4
        with: {path: p, key: k}
      - uses: actions/cache/restore@v4
        with: {path: p, key: k, restore-keys: k-}
`, nil},
		{"job if", `on: [push, pull_request]
jobs:
  a:
    if: github.event_name == 'pull_request'
    runs-on: x
    steps:
      - uses: actions/cache@v4
        with: {path: p, key: "k-${{ github.sha }}", restore-keys: k-}
`, []string{"pull_request"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, s := range newIR(t, c.src).allCacheRestoreSaves() {
				var evs []string
				for _, e := range s.savesOn {
					evs = append(evs, e.String())
				}
				if len(evs) > 0 {
					got = append(got, strings.Join(evs, ","))
				}
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("%v, want %v", got, c.want)
			}
		})
	}
}

func TestDependencyReviewStepProjection(t *testing.T) {
	x := newIR(t, `on: pull_request
permissions: {contents: read}
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          warn-only: true
          vulnerability-check: "FALSE"
          license-check: yes
          deny-licenses: GPL-3.0
          comment-summary-in-pr: on-failure
      - uses: Actions/Dependency-Review-Action@v4
        with:
          warn-only: ${{ inputs.w }}
      - uses: actions/checkout@v4
`)
	got := x.allDependencyReviewSteps()
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	a, b := got[0], got[1]
	if a.warnOnly != analysis.ActionBooleanTrue || a.vulnerabilityCheck != analysis.ActionBooleanFalse || a.licenseCheck != analysis.ActionBooleanOther ||
		!a.licensePolicy || !a.commentRequested || a.pullRequestsWrite != analysis.PullRequestsWriteNo {
		t.Errorf("%+v", a)
	}
	if b.warnOnly != analysis.ActionBooleanExpression || b.commentRequested || b.vulnerabilityCheck != analysis.ActionBooleanUnwritten {
		t.Errorf("%+v", b)
	}
}

// TestRunsUsingSiteProjection: the runs.using of an action.yml, as
// written; none of a workflow.
func TestRunsUsingSiteProjection(t *testing.T) {
	tree, a := parseAction(t, "name: x\ndescription: y\nruns:\n  using: Node20\n  main: index.js\n")
	got := New("a/action.yml", tree, nil, a).allRunsUsingSites()
	if len(got) != 1 || got[0].using != "Node20" {
		t.Fatalf("%+v", got)
	}
	if b, _, _, _ := got[0].at.Locate(); string(b.Node.Bytes()) != "Node20" {
		t.Errorf("at %q", b.Node.Bytes())
	}
	if got := newIR(t, "on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: a}]\n").allRunsUsingSites(); len(got) != 0 {
		t.Errorf("of a workflow: %+v", got)
	}
}

// TestNodeRuntimeSettingProjection: the keys of env, of the workflow, a
// job, a step and a step of a composite action, that name a setting of
// the Node.js runtime, compared without case.
func TestNodeRuntimeSettingProjection(t *testing.T) {
	x := newIR(t, `on: push
env:
  ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION: true
  OTHER: x
jobs:
  a:
    runs-on: x
    env:
      force_javascript_actions_to_node20: 'true'
    steps:
      - run: a
        env:
          actions_allow_use_unsecure_node_version: 'false'
  b:
    runs-on: x
    env: ${{ fromJSON(vars.E) }}
    steps: [{run: a}]
`)
	var names []string
	for _, s := range x.allNodeRuntimeSettings() {
		names = append(names, s.name)
	}
	if strings.Join(names, ",") != "ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION,force_javascript_actions_to_node20,actions_allow_use_unsecure_node_version" {
		t.Errorf("%v", names)
	}
	tree, a := parseAction(t, "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: a\n      shell: bash\n      env: {FORCE_JAVASCRIPT_ACTIONS_TO_NODE20: 'true'}\n")
	if got := New("a/action.yml", tree, nil, a).allNodeRuntimeSettings(); len(got) != 1 || got[0].name != "FORCE_JAVASCRIPT_ACTIONS_TO_NODE20" {
		t.Errorf("composite: %+v", got)
	}
}

// TestSetupNodeVersionProjection: node-version of actions/setup-node, as
// written, when it has no ${{ }}.
func TestSetupNodeVersionProjection(t *testing.T) {
	x := newIR(t, `on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/setup-node@v4
        with: {node-version: 20}
      - uses: Actions/Setup-Node@v4
        with: {node-version: '20.x'}
      - uses: actions/setup-node@v4
        with: {node-version: lts/*}
      - uses: actions/setup-node@v4
        with: {node-version: '${{ matrix.node }}'}
      - uses: actions/setup-node@v4
      - uses: actions/setup-node/sub@v4
        with: {node-version: 18}
      - uses: other/setup-node@v4
        with: {node-version: 18}
`)
	var got []string
	for _, s := range x.allSetupNodeVersions() {
		got = append(got, s.nodeVersion)
	}
	if !slices.Equal(got, []string{"20", "20.x", "lts/*"}) {
		t.Errorf("%q", got)
	}
}
