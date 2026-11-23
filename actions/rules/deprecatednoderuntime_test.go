package rules

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// nodeFindings are the quality findings of deprecated-node-runtime on fsys,
// as "<input>: <kind> <detected>", sorted, with r answering the facts.
func nodeFindings(t *testing.T, fsys fstest.MapFS, r facts.Resolver) []string {
	t.Helper()
	var out []string
	for _, f := range qualityReportFS(t, DeprecatedNodeRuntimeID, fsys, r).QualityFindings {
		out = append(out, f.Location.File.Input.String()+": "+f.Args.KindID().String()+" "+f.Detected())
	}
	slices.Sort(out)
	return out
}

func action(using string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("name: x\ndescription: y\nruns:\n  using: " + using + "\n  main: index.js\n")}
}

func TestDeprecatedNodeRuntimeDeclared(t *testing.T) {
	fsys := fstest.MapFS{
		"n12/action.yml":          action("node12"),
		"n16/action.yml":          action("node16"),
		"n20/action.yml":          action("Node20"),
		"n24/action.yml":          action("node24"),
		"c/action.yml":            {Data: []byte("name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - run: a\n      shell: bash\n")},
		"d/action.yml":            {Data: []byte("name: x\ndescription: y\nruns:\n  using: docker\n  image: Dockerfile\n")},
		".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: ./n20\n")},
	}
	got := nodeFindings(t, fsys, storeOf(t))
	want := []string{
		"n12/action.yml: deprecated-node-runtime.declared-runtime the action declares runs.using: node12, an older Node.js version than node24",
		"n16/action.yml: deprecated-node-runtime.declared-runtime the action declares runs.using: node16, an older Node.js version than node24",
		"n20/action.yml: deprecated-node-runtime.declared-runtime the action declares runs.using: Node20, an older Node.js version than node24",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestDeprecatedNodeRuntimeUsedAction(t *testing.T) {
	fsys := fstest.MapFS{".github/workflows/w.yml": {Data: []byte(`on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/create-release@v1
      - uses: actions/checkout@v5
      - uses: actions/cache/restore@v4
      - uses: o/gone@v1
      - uses: ./local
      - uses: docker://alpine:3
  b:
    uses: o/w/.github/workflows/w.yml@v1
`)}}
	answers := storeOf(t,
		`{"query":{"kind":"action.runs-using","repo":"actions/create-release","ref":"v1"},"state":"found","value":"node12"}`,
		`{"query":{"kind":"action.runs-using","repo":"actions/checkout","ref":"v5"},"state":"found","value":"node24"}`,
		`{"query":{"kind":"action.runs-using","repo":"actions/cache","path":"restore","ref":"v4"},"state":"found","value":"node20"}`,
		`{"query":{"kind":"action.runs-using","repo":"o/gone","ref":"v1"},"state":"absent"}`)
	got := nodeFindings(t, fsys, answers)
	want := []string{
		".github/workflows/w.yml: deprecated-node-runtime.used-action the action actions/cache/restore@v4 declares runs.using: node20, an older Node.js version than node24",
		".github/workflows/w.yml: deprecated-node-runtime.used-action the action actions/create-release@v1 declares runs.using: node12, an older Node.js version than node24",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// with no answer, each step's uses of another repository is
	// conditional, and asks only action.runs-using of its repo, path and ref
	rep := qualityReportFS(t, DeprecatedNodeRuntimeID, fsys, storeOf(t))
	if len(rep.QualityFindings) != 4 {
		t.Fatalf("%d findings, want 4", len(rep.QualityFindings))
	}
	for _, f := range rep.QualityFindings {
		if f.Certainty != lint.CertaintyConditional {
			t.Errorf("%s: %v", f.Detected(), f.Certainty)
		}
		qs := f.Condition.Queries()
		if len(qs) != 1 {
			t.Errorf("%s asks %v", f.Detected(), qs)
			continue
		}
		q, ok := qs[0].(facts.ActionRunsUsing)
		if !ok {
			t.Errorf("asks %#v", qs[0])
			continue
		}
		if q.Repo.String() == "actions/cache" && (q.Path.String() != "restore" || q.Ref != "v4") {
			t.Errorf("asks %#v", q)
		}
	}
}

func TestDeprecatedNodeRuntimeSettings(t *testing.T) {
	fsys := fstest.MapFS{".github/workflows/w.yml": {Data: []byte(`on: push
env:
  ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION: 'false'
  OTHER: x
jobs:
  a:
    runs-on: x
    env:
      FORCE_JAVASCRIPT_ACTIONS_TO_NODE20: true
    steps:
      - run: a
`)}}
	got := nodeFindings(t, fsys, storeOf(t))
	want := []string{
		".github/workflows/w.yml: deprecated-node-runtime.runtime-setting the env sets ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION, a setting of the Node.js version that runs actions; the setting is reported whatever its value",
		".github/workflows/w.yml: deprecated-node-runtime.runtime-setting the env sets FORCE_JAVASCRIPT_ACTIONS_TO_NODE20, a setting of the Node.js version that runs actions; the setting is reported whatever its value",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestDeprecatedNodeRuntimeEOLNodeVersion(t *testing.T) {
	var steps []string
	for _, v := range []string{"20", "'20.x'", "v18.2.0", "21", "25", "8", "'0.12'", "0.10.48", "22", "24", "lts/*", "'>=18'", "node", "'18 || 20'", "16-nightly", "'0'", "'0.11'"} {
		steps = append(steps, "      - uses: actions/setup-node@v4\n        with: {node-version: "+v+"}")
	}
	fsys := fstest.MapFS{".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n" + strings.Join(steps, "\n") + "\n")}}
	answers := storeOf(t, `{"query":{"kind":"action.runs-using","repo":"actions/setup-node","ref":"v4"},"state":"found","value":"node24"}`)
	got := nodeFindings(t, fsys, answers)
	want := []string{
		".github/workflows/w.yml: deprecated-node-runtime.eol-node-version node-version 0.10.48 names Node.js 0.10, whose support ended on 2016-10-31",
		".github/workflows/w.yml: deprecated-node-runtime.eol-node-version node-version 0.12 names Node.js 0.12, whose support ended on 2016-12-31",
		".github/workflows/w.yml: deprecated-node-runtime.eol-node-version node-version 20 names Node.js 20, whose support ended on 2026-04-30",
		".github/workflows/w.yml: deprecated-node-runtime.eol-node-version node-version 20.x names Node.js 20, whose support ended on 2026-04-30",
		".github/workflows/w.yml: deprecated-node-runtime.eol-node-version node-version 21 names Node.js 21, whose support ended on 2024-06-01",
		".github/workflows/w.yml: deprecated-node-runtime.eol-node-version node-version 25 names Node.js 25, whose support ended on 2026-06-01",
		".github/workflows/w.yml: deprecated-node-runtime.eol-node-version node-version 8 names Node.js 8, whose support ended on 2019-12-31",
		".github/workflows/w.yml: deprecated-node-runtime.eol-node-version node-version v18.2.0 names Node.js 18, whose support ended on 2025-04-30",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestDeprecatedNodeRuntimeRemoteComposite: a uses inside a composite
// action of another repository, which action.definition answers, is a
// finding at the uses of the workflow that runs the composite action, with
// the evidence in the file of the fact; a step of a composite action of the
// inputs is the finding of that input, not again of its caller.
func TestDeprecatedNodeRuntimeRemoteComposite(t *testing.T) {
	fsys := fstest.MapFS{
		".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: example-org/node-composite@v1\n      - uses: ./local\n")},
		"local/action.yml":        {Data: []byte("runs:\n  using: composite\n  steps:\n    - uses: actions/create-release@v1\n")},
	}
	rep := qualityReportFS(t, DeprecatedNodeRuntimeID, fsys, limitFacts{})
	var got []string
	for _, f := range rep.QualityFindings {
		g := f.Location.File.Input.String() + ": " + f.Detected()
		for _, e := range f.Evidence {
			if e.Location.File.Query != nil {
				g += " (in " + e.Location.File.Query.Kind().String() + ")"
			}
		}
		got = append(got, g)
	}
	slices.Sort(got)
	want := []string{
		".github/workflows/w.yml: the action actions/create-release@v1 declares runs.using: node12, an older Node.js version than node24 (in action.definition)",
		"local/action.yml: the action actions/create-release@v1 declares runs.using: node12, an older Node.js version than node24",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
