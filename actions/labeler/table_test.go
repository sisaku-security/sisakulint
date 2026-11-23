package labeler

import (
	"testing"
	"testing/fstest"

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
		w, _ := workflow.Parse(tree)
		out = append(out, calls.File{Name: facts.MustCleanInputPath(n), Tree: tree, Workflow: w})
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
