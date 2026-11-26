package ir

import (
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// jobNamed is the job id of w.
func jobNamed(t *testing.T, w *workflow.Workflow, id string) *workflow.Job {
	t.Helper()
	e, ok := w.Jobs.Value.Lookup(id)
	if !ok || e.Value.Status != workflow.Present {
		t.Fatalf("no job %s", id)
	}
	return &e.Value.Value
}

// firstStepEnv is the env of the first step of the job id of w.
func firstStepEnv(t *testing.T, w *workflow.Workflow, id string) workflow.Base {
	t.Helper()
	s := jobNamed(t, w, id).Steps.Value.Items[0]
	if s.Env.Status != workflow.Present {
		t.Fatalf("no env in the first step of %s", id)
	}
	return s.Env.Value.Base
}

// TestAlwaysSkipped: the element is in a job GitHub skips in every run
// (alwaysSkipped), read by github.event_name and github.event.action on
// every event and activity type of on.
func TestAlwaysSkipped(t *testing.T) {
	const steps = "    runs-on: ubuntu-latest\n    steps:\n      - env:\n          K: v\n        run: echo\n"
	job := func(w *workflow.Workflow) workflow.Base { return firstStepEnv(t, w, "x") }
	env := func(w *workflow.Workflow) workflow.Base { return w.Env.Value.Base }
	for _, c := range []struct {
		name string
		src  string
		at   func(*workflow.Workflow) workflow.Base
		want bool
	}{
		{"if false", "on: push\njobs:\n  x:\n    if: false\n" + steps, job, true},
		{"needs result", "on: push\njobs:\n  b:\n" + steps + "  x:\n    needs: b\n    if: needs.b.result == 'failure'\n" + steps, job, true},
		{"needed job skipped", "on: push\njobs:\n  b:\n    if: false\n" + steps + "  x:\n    needs: b\n" + steps, job, true},
		{"other event", "on: push\njobs:\n  x:\n    if: github.event_name == 'pull_request'\n" + steps, job, true},
		{"empty on", "on: {}\njobs:\n  x:\n" + steps, job, true},
		{"no on", "jobs:\n  x:\n" + steps, job, true},
		{"every job skipped", "on: push\nenv:\n  K: v\njobs:\n  x:\n    if: false\n" + steps, env, true},
		{"failure after a skipped chain", "on: push\njobs:\n  a:\n    if: false\n" + steps + "  b:\n    needs: a\n" + steps + "  x:\n    needs: b\n    if: failure()\n" + steps, job, true},
		{"failure with no needs", "on: push\njobs:\n  x:\n    if: failure()\n" + steps, job, true},
		{"always after skipped", "on: push\njobs:\n  b:\n    if: false\n" + steps + "  x:\n    needs: b\n    if: always()\n" + steps, job, false},
		{"step if false", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - if: false\n        env:\n          K: v\n        run: echo\n", job, true},
		{"step if of other event", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.event_name == 'issues'\n        env:\n          K: v\n        run: echo\n", job, true},
		{"uses step if false", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - if: false\n        env:\n          K: v\n        uses: o/a@v1\n", job, false},
		{"merged on opened", "on:\n  pull_request:\n    types: [opened]\njobs:\n  x:\n    if: github.event.pull_request.merged == true\n" + steps, job, true},
		{"merged on closed", "on:\n  pull_request:\n    types: [opened, closed]\njobs:\n  x:\n    if: github.event.pull_request.merged == true\n" + steps, job, false},
		{"merged on push", "on: push\njobs:\n  x:\n    if: github.event.pull_request.merged == true\n" + steps, job, true},
		{"pull_request on push", "on: push\njobs:\n  x:\n    if: github.event.pull_request\n" + steps, job, true},
		{"merged on review", "on: pull_request_review\njobs:\n  x:\n    if: github.event.pull_request.merged == true\n" + steps, job, false},
		{"merged on synchronize", "on:\n  pull_request:\n    types: [synchronize]\njobs:\n  x:\n    if: github.event.pull_request.merged == true\n" + steps, job, true},
		{"merged on labeled", "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  x:\n    if: github.event.pull_request.merged == true\n" + steps, job, false},
		{"step matrix of no value", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        os: [ubuntu]\n    steps:\n      - if: matrix.os == 'windows'\n        env:\n          K: v\n        run: echo\n", job, true},
		{"step matrix of a value", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        os: [ubuntu, windows]\n    steps:\n      - if: matrix.os == 'windows'\n        env:\n          K: v\n        run: echo\n", job, false},
		{"step matrix include", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        os: [ubuntu]\n        include:\n          - os: windows\n    steps:\n      - if: matrix.os == 'windows'\n        env:\n          K: v\n        run: echo\n", job, false},
		{"step matrix exclude", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        os: [ubuntu]\n        v: [1, 2]\n        exclude:\n          - v: 2\n    steps:\n      - if: matrix.os == 'windows' || matrix.v == 3\n        env:\n          K: v\n        run: echo\n", job, true},
		{"step matrix number", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        v: [18, 20]\n    steps:\n      - if: matrix.v == 20\n        env:\n          K: v\n        run: echo\n", job, false},
		{"step matrix expression", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix: ${{ fromJSON('{}') }}\n    steps:\n      - if: matrix.os == 'windows'\n        env:\n          K: v\n        run: echo\n", job, false},
		{"own event", "on: push\njobs:\n  x:\n    if: github.event_name == 'push'\n" + steps, job, false},
		{"stacked", "on:\n  pull_request:\n    types: [opened, stacked]\njobs:\n  x:\n    if: github.event.action == 'stacked'\n" + steps, job, false},
		{"unknown event", "on: [push, no_such_event]\njobs:\n  x:\n    if: github.event_name == 'no_such_event'\n" + steps, job, false},
		{"one job of two skipped", "on: push\nenv:\n  K: v\njobs:\n  a:\n    if: false\n" + steps + "  x:\n" + steps, env, false},
		{"workflow_call", "on: workflow_call\njobs:\n  x:\n    if: github.event_name == 'issues'\n" + steps, job, false},
		{"alias used in a job that runs", "on: push\njobs:\n  a:\n    if: false\n    runs-on: ubuntu-latest\n    steps: &s\n      - env:\n          K: v\n        run: echo\n  x:\n    runs-on: ubuntu-latest\n    steps: *s\n", job, false},
		{"alias defined in the job that is skipped", "on: push\njobs:\n  x:\n    if: false\n    runs-on: ubuntu-latest\n    steps: &s\n      - env:\n          K: v\n        run: echo\n  b:\n    runs-on: ubuntu-latest\n    steps: *s\n", job, true},
	} {
		x := newIR(t, c.src)
		if got := x.alwaysSkipped(c.at(x.workflow)); got != c.want {
			t.Errorf("%s: alwaysSkipped = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAlwaysSkippedCalled: a called workflow whose callers among the
// inputs are all skipped is not skipped (a caller in another repository
// is not seen); a remote called workflow is skipped when the job of the
// input that calls it is.
func TestAlwaysSkippedCalled(t *testing.T) {
	const called = "on: workflow_call\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          K: v\n        run: echo\n"
	x := calledIR(t, [2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", "on: push\njobs:\n  c:\n    if: false\n    uses: ./.github/workflows/called.yml\n"})
	if x.alwaysSkipped(firstStepEnv(t, x.workflow, "x")) {
		t.Errorf("a called workflow whose callers among the inputs are skipped is skipped")
	}
	for _, c := range []struct {
		cond string
		want bool
	}{{"false", true}, {"true", false}} {
		g := callerstest.Graph(t, true, false, [2]string{".github/workflows/ci.yml",
			"on: issues\njobs:\n  c:\n    if: " + c.cond + "\n    uses: o/wf/.github/workflows/w.yml@v1\n"})
		ci, _ := g.File(calls.InputNode(facts.MustCleanInputPath(".github/workflows/ci.yml")))
		job := &ci.Workflow.Jobs.Value.Entries[0].Value.Value
		w := callerstest.File(t, ".github/workflows/w.yml", called)
		repo, err := facts.ParseRepo("o/wf")
		if err != nil {
			t.Fatal(err)
		}
		path, err := facts.ParseUsesPath(".github/workflows/w.yml")
		if err != nil {
			t.Fatal(err)
		}
		q := facts.WorkflowDefinition{Repo: repo, Path: path, Ref: "v1"}
		r := &calls.RemoteCalled{Called: composite.Called{Workflow: w.Workflow, Origin: composite.Origin{Query: q, Tree: w.Tree}, By: job, Parent: -1}, Top: ci.Name, TopJob: job}
		g.AddRemote(r, calls.Call{Caller: ci.Node(), Job: job, StepIndex: -1, With: job.With, Resolved: true})
		cl := taint.NewCallers(g)
		rx := NewRemote(r).WithCallers(func() *taint.Callers { return cl })
		if got := rx.alwaysSkipped(firstStepEnv(t, rx.workflow, "x")); got != c.want {
			t.Errorf("remote called by a job whose if is %s: alwaysSkipped = %v, want %v", c.cond, got, c.want)
		}
	}
}

// TestSummariesAlwaysSkipped: each summary of a job whose if is false is
// always skipped, and each of the same job without the if is not.
func TestSummariesAlwaysSkipped(t *testing.T) {
	body := `    runs-on: ubuntu-latest
    container: node:20
    env:
      ALL: ${{ toJSON(secrets) }}
      PART: ${{ fromJSON(secrets.DB).pass }}
    steps:
      - uses: actions/checkout@v4
      - uses: docker://alpine:3
      - id: w
        env:
          KEY: ${{ secrets.KEY }}
        run: |
          echo "${KEY:1}"
          echo "o=${KEY:1}" >> "$GITHUB_OUTPUT"
      - env:
          V: ${{ steps.w.outputs.o }}
        run: echo
      - uses: actions/upload-artifact@v4
        with:
          path: .
          include-hidden-files: true
`
	call := "    uses: o/r/.github/workflows/w.yml@v1\n    secrets: inherit\n"
	src := "on: push\njobs:\n  a:\n    if: false\n" + body + "  b:\n" + body + "  ca:\n    if: false\n" + call + "  cb:\n" + call
	x := newIR(t, src)
	type summary struct {
		key     Key
		skipped bool
	}
	var all = map[string][]summary{}
	add := func(name string, k Key, s bool) { all[name] = append(all[name], summary{k, s}) }
	for _, s := range x.allUses() {
		add("Uses", s.key, s.alwaysSkipped)
	}
	for _, s := range x.allImageSites() {
		add("ImageSite", s.key, s.alwaysSkipped)
	}
	for _, s := range x.allLeftCredentials() {
		add("LeftCredential", s.key, s.alwaysSkipped)
	}
	for _, s := range x.allUploads() {
		add("Upload", s.key, s.alwaysSkipped)
	}
	for _, s := range x.allJobs() {
		add("Job", s.key, s.alwaysSkipped)
	}
	for _, s := range x.allSinks() {
		add("Sink", s.key, s.alwaysSkipped)
	}
	for _, s := range x.allPrintedOutputs() {
		add("PrintedOutput", s.key, s.alwaysSkipped)
	}
	for _, s := range x.allSecretsContextReads() {
		add("SecretsContextRead", s.key, s.alwaysSkipped)
	}
	for _, s := range x.allSecretParts() {
		add("SecretPart", s.key, s.alwaysSkipped)
	}
	for _, name := range []string{"Uses", "ImageSite", "LeftCredential", "Upload", "Job", "Sink", "PrintedOutput", "SecretsContextRead", "SecretPart"} {
		var skipped, runs int
		for _, s := range all[name] {
			switch p := s.key.Path(); {
			case strings.HasPrefix(p, "jobs.a.") || p == "jobs.a" || strings.HasPrefix(p, "jobs.ca"):
				skipped++
				if !s.skipped {
					t.Errorf("%s at %s: not always skipped", name, p)
				}
			default:
				runs++
				if s.skipped {
					t.Errorf("%s at %s: always skipped", name, p)
				}
			}
		}
		if skipped == 0 || runs == 0 {
			t.Errorf("%s: %d in the skipped jobs, %d in the others", name, skipped, runs)
		}
	}
}

// TestInheritCallersSkipped: a job that calls with secrets: inherit and that
// GitHub skips in every run is still an InheritCaller: a caller in
// another repository, which the inputs do not have, may call the workflow
// in a run, as when the callers of the inputs are all skipped.
func TestInheritCallersSkipped(t *testing.T) {
	const called = "on: workflow_call\njobs:\n  x:\n    runs-on: ubuntu-latest\n    env:\n      ALL: ${{ toJSON(secrets) }}\n    steps:\n      - run: echo\n"
	x := calledIR(t, [2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", "on: push\njobs:\n  c:\n    if: false\n    uses: ./.github/workflows/called.yml\n    secrets: inherit\n"})
	_, callers := x.inheritCallers()
	if len(callers) != 1 || callers[0].Job != "c" {
		t.Errorf("inherit callers %+v, want the job c", callers)
	}
}

// TestCalledContextReadsSkipped: a read of the secrets without a name in a
// job of the called workflow that GitHub skips in every run is not one of
// the reads of the calling job.
func TestCalledContextReadsSkipped(t *testing.T) {
	const called = "on: workflow_call\njobs:\n  s:\n    if: false\n    runs-on: ubuntu-latest\n    env:\n      ALL: ${{ toJSON(secrets) }}\n    steps:\n      - run: echo\n  r:\n    runs-on: ubuntu-latest\n    env:\n      ALL: ${{ toJSON(secrets) }}\n    steps:\n      - run: echo\n"
	c := taint.NewCallers(callerstest.Graph(t, true, false, [2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    secrets: inherit\n"}))
	f, ok := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(".github/workflows/ci.yml")))
	if !ok {
		t.Fatal("no ci.yml")
	}
	x := New(f.Name.String(), f.Tree, f.Workflow, f.Action).WithCallers(func() *taint.Callers { return c })
	jobs := x.allJobs()
	if len(jobs) != 1 || len(jobs[0].calledContextReads) != 1 {
		t.Fatalf("jobs %d, reads %+v, want one read", len(jobs), jobs[0].calledContextReads)
	}
}
