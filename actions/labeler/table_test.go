package labeler

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// filesOf are the workflows of root as the inputs of a run.
func filesOf(t *testing.T, root fstest.MapFS, names ...string) []calls.File {
	t.Helper()
	var out []calls.File
	for _, n := range names {
		tree := cst.ParseMode(root[n].Data, cst.ModeGitHub)
		f := calls.File{Name: facts.MustCleanInputPath(n), Tree: tree}
		if strings.HasPrefix(n, ".github/workflows/") {
			f.Workflow, _ = workflow.Parse(tree)
		} else {
			f.Action, _ = workflow.ParseActionMetadata(tree)
		}
		out = append(out, f)
	}
	return out
}

// zellij are the three files of
// https://github.com/fooagen/zellij/tree/039c8d5962dd341bb58dd7dcd09eb2cf7389ac7a
// that a pull request of 2026-04-25 from a fork went through: the labeler
// added documentation with a personal access token, which started the
// labeled run.
var zellij = fstest.MapFS{
	".github/workflows/labeler.yaml": {Data: []byte(`name: "Auto Labeler"
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: read
  pull-requests: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Apply Documentation Label
        uses: actions/labeler@v5
        with:
          configuration-path: .github/labeler.yaml
          sync-labels: true
          repo-token: ${{ secrets.PAT }}
`)},
	".github/labeler.yaml": {Data: []byte(`documentation:
  - changed-files:
      - any-glob-to-any-file:
          - 'pages/**/*.md'
          - 'pages/**/*.mdx'
      - all-globs-to-all-files:
          - 'pages/**/*.md'
          - 'pages/**/*.mdx'
`)},
	".github/workflows/build-artefacts.yaml": {Data: []byte(`name: Build Docs Artefacts
on:
  pull_request_target:
    types: [labeled]
jobs:
  build-and-greet:
    if: github.event.label.name == 'documentation'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.number }}/merge
      - run: npm ci
        working-directory: pages
`)},
}

func TestTable(t *testing.T) {
	tab := Read(filesOf(t, zellij, ".github/workflows/build-artefacts.yaml", ".github/workflows/labeler.yaml"), zellij, func(facts.InputPath) bool { return false })
	steps := tab.Steps()
	if len(steps) != 1 {
		t.Fatalf("got %d steps, want 1", len(steps))
	}
	s := steps[0]
	if s.Input.String() != ".github/workflows/labeler.yaml" || s.Token != TokenSourceAccount || s.Unknown || s.AnyLabel || s.Labels["documentation"] != freeReach {
		t.Errorf("got %+v", s)
	}
	if got := Read(nil, nil, nil).Steps(); len(got) != 0 {
		t.Errorf("no files: got %v", got)
	}
}

func TestTableSameFile(t *testing.T) {
	root := fstest.MapFS{
		".github/labeler.yml": {Data: []byte(freeConfig)},
		".github/workflows/ci.yml": {Data: []byte(`on:
  pull_request_target:
    types: [opened, labeled]
jobs:
  label:
    if: github.event.action == 'opened'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5
        with:
          repo-token: ${{ secrets.PAT }}
  build:
    if: github.event.action == 'labeled' && github.event.label.name == 'safe-to-test'
    runs-on: ubuntu-latest
    steps:
      - run: echo build
`)},
	}
	if got := Read(filesOf(t, root, ".github/workflows/ci.yml"), root, func(facts.InputPath) bool { return false }).Steps(); len(got) != 1 {
		t.Errorf("got %v, want the labeler of the file", got)
	}
}

func TestTableTwoLabelers(t *testing.T) {
	root := fstest.MapFS{
		".github/labeler.yml":     {Data: []byte(freeConfig)},
		".github/workflows/a.yml": {Data: []byte(labelerWorkflow("v5", "", "          repo-token: ${{ secrets.GITHUB_TOKEN }}\n"))},
		".github/workflows/b.yml": {Data: []byte(labelerWorkflow("v5", "", "          repo-token: ${{ secrets.PAT }}\n"))},
	}
	got := Read(filesOf(t, root, ".github/workflows/a.yml", ".github/workflows/b.yml"), root, func(facts.InputPath) bool { return false }).Steps()
	if len(got) != 1 || got[0].Input.String() != ".github/workflows/b.yml" {
		t.Errorf("got %v, want the labeler of b.yml", got)
	}
}

// TestTableCalled: actions/labeler in a reusable workflow or a composite
// action that a workflow on pull_request_target calls is read on the
// events of the caller, as in the job of the caller; one that nothing of
// the repository calls is not.
func TestTableCalled(t *testing.T) {
	labelerStep := `      - uses: actions/labeler@v5
        with:
          repo-token: ${{ secrets.PAT }}
`
	for _, c := range []struct {
		name, callee, calleeSrc, caller string
		want                            int
	}{
		{"reusable", ".github/workflows/label.yml",
			"on: workflow_call\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n" + labelerStep,
			"on: pull_request_target\njobs:\n  label:\n    uses: ./.github/workflows/label.yml\n    secrets: inherit\n", 1},
		{"composite", ".github/actions/label/action.yml",
			"runs:\n  using: composite\n  steps:\n" + labelerStep,
			"on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/label\n", 1},
		{"reusable called on push", ".github/workflows/label.yml",
			"on: workflow_call\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n" + labelerStep,
			"on: push\njobs:\n  label:\n    uses: ./.github/workflows/label.yml\n", 0},
		{"composite behind a false if", ".github/actions/label/action.yml",
			"runs:\n  using: composite\n  steps:\n" + labelerStep,
			"on: pull_request_target\njobs:\n  label:\n    if: github.event_name == 'push'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/label\n", 0},
		{"reusable not called", ".github/workflows/label.yml",
			"on: workflow_call\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n" + labelerStep,
			"on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n", 0},
		{"composite given the PAT", ".github/actions/label/action.yml", "runs:\n  using: composite\n  steps:\n    - uses: actions/labeler@v5\n      with:\n        repo-token: ${{ inputs.token }}\n", "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/label\n        with:\n          token: ${{ secrets.PAT }}\n", 1},
		{"composite given the GITHUB_TOKEN", ".github/actions/label/action.yml", "runs:\n  using: composite\n  steps:\n    - uses: actions/labeler@v5\n      with:\n        repo-token: ${{ inputs.token }}\n", "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/label\n        with:\n          token: ${{ github.token }}\n", 0},
		{"composite with the default GITHUB_TOKEN", ".github/actions/label/action.yml", "inputs:\n  token:\n    default: ${{ github.token }}\nruns:\n  using: composite\n  steps:\n    - uses: actions/labeler@v5\n      with:\n        repo-token: ${{ inputs.token }}\n", "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/label\n", 0},
		{"composite in a job for the same repository", ".github/actions/label/action.yml", "runs:\n  using: composite\n  steps:\n    - uses: actions/labeler@v5\n      with:\n        repo-token: ${{ inputs.token }}\n", "on: pull_request_target\njobs:\n  label:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/label\n        with:\n          token: ${{ secrets.PAT }}\n", 0},
		{"composite in a step for the same repository", ".github/actions/label/action.yml", "runs:\n  using: composite\n  steps:\n    - uses: actions/labeler@v5\n      with:\n        repo-token: ${{ inputs.token }}\n", "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - if: github.event.pull_request.head.repo.full_name == github.repository\n        uses: ./.github/actions/label\n        with:\n          token: ${{ secrets.PAT }}\n", 0},
		{"reusable given the GITHUB_TOKEN", ".github/workflows/label.yml", "on:\n  workflow_call:\n    inputs:\n      token:\n        type: string\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v5\n        with:\n          repo-token: ${{ inputs.token }}\n", "on: pull_request_target\njobs:\n  label:\n    uses: ./.github/workflows/label.yml\n    with:\n      token: ${{ github.token }}\n", 0},
		{"reusable given the PAT", ".github/workflows/label.yml", "on:\n  workflow_call:\n    inputs:\n      token:\n        type: string\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v5\n        with:\n          repo-token: ${{ inputs.token }}\n", "on: pull_request_target\njobs:\n  label:\n    uses: ./.github/workflows/label.yml\n    with:\n      token: ${{ secrets.PAT }}\n", 1},
		{"reusable given the GITHUB_TOKEN as a secret", ".github/workflows/label.yml", "on: workflow_call\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v5\n        with:\n          repo-token: ${{ secrets.LABELER_PAT }}\n", "on: pull_request_target\njobs:\n  label:\n    uses: ./.github/workflows/label.yml\n    secrets:\n      LABELER_PAT: ${{ secrets.GITHUB_TOKEN }}\n", 0},
		{"reusable in a job for the same repository", ".github/workflows/label.yml", "on: workflow_call\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v5\n        with:\n          repo-token: ${{ secrets.LABELER_PAT }}\n", "on: pull_request_target\njobs:\n  label:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    uses: ./.github/workflows/label.yml\n    secrets: inherit\n", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := fstest.MapFS{
				".github/labeler.yml":      {Data: []byte(freeConfig)},
				c.callee:                   {Data: []byte(c.calleeSrc)},
				".github/workflows/ci.yml": {Data: []byte(c.caller)},
			}
			got := Read(filesOf(t, root, ".github/workflows/ci.yml", c.callee), root, func(facts.InputPath) bool { return false }).Steps()
			if len(got) != c.want {
				t.Fatalf("got %v, want %d steps", got, c.want)
			}
			if c.want == 1 && (got[0].Input.String() != c.callee || got[0].Token != TokenSourceAccount || got[0].Unknown || got[0].Labels["safe-to-test"] != freeReach) {
				t.Errorf("got %+v", got[0])
			}
		})
	}
}

// TestTableCalledToken: the token that a calling job makes with
// actions/create-github-app-token is the app's, read among the steps of
// that job; an environment of a calling job may hold the run, so the step
// is Unknown.
func TestTableCalledToken(t *testing.T) {
	action := "runs:\n  using: composite\n  steps:\n    - uses: actions/labeler@v5\n      with:\n        repo-token: ${{ inputs.token }}\n"
	for _, c := range []struct {
		name, caller string
		token        TokenSource
		unknown      bool
	}{
		{"app token", "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - id: app\n        uses: actions/create-github-app-token@v2\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/label\n        with:\n          token: ${{ steps.app.outputs.token }}\n", TokenSourceApp, false},
		{"environment", "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    environment: approval\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/label\n        with:\n          token: ${{ secrets.PAT }}\n", TokenSourceAccount, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := fstest.MapFS{
				".github/labeler.yml":              {Data: []byte(freeConfig)},
				".github/actions/label/action.yml": {Data: []byte(action)},
				".github/workflows/ci.yml":         {Data: []byte(c.caller)},
			}
			got := Read(filesOf(t, root, ".github/workflows/ci.yml", ".github/actions/label/action.yml"), root, func(facts.InputPath) bool { return false }).Steps()
			if len(got) != 1 || got[0].Token != c.token || got[0].Unknown != c.unknown {
				t.Errorf("got %+v", got)
			}
		})
	}
}

// TestTableOtherRepo: a job that calls a workflow of another repository at
// the path of an input runs that repository's workflow, when the
// repository of the inputs is known.
func TestTableOtherRepo(t *testing.T) {
	root := fstest.MapFS{
		".github/labeler.yml":                  {Data: []byte(freeConfig)},
		".github/workflows/label-reusable.yml": {Data: []byte("on: workflow_call\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v5\n        with:\n          repo-token: ${{ secrets.PAT }}\n")},
		".github/workflows/ci.yml":             {Data: []byte("on: pull_request_target\njobs:\n  label:\n    uses: other-org/lib/.github/workflows/label-reusable.yml@v1\n    secrets: inherit\n")},
	}
	files := filesOf(t, root, ".github/workflows/ci.yml", ".github/workflows/label-reusable.yml")
	repo, err := facts.ParseRepo("example-org/app")
	if err != nil {
		t.Fatal(err)
	}
	if got := ReadIn(attacker.Outsider, repo, files, root, func(facts.InputPath) bool { return false }).Steps(); len(got) != 0 {
		t.Errorf("another repository's workflow: got %v", got)
	}
	repo, _ = facts.ParseRepo("other-org/lib")
	if got := ReadIn(attacker.Outsider, repo, files, root, func(facts.InputPath) bool { return false }).Steps(); len(got) != 1 {
		t.Errorf("the repository's own workflow: got %v", got)
	}
}
