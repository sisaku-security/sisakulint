package ir

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
	"github.com/gh-intel/sisakulint/actions/taint"
)

const jobWF = "on: issues\njobs:\n  deploy:\n    runs-on: [self-hosted, linux]\n    environment: production\n    steps:\n      - run: ./deploy\n        env: {K: '${{ secrets.DEPLOY_KEY }}'}\n  other:\n    runs-on: ${{ inputs.r }}\n    permissions: {}\n    steps:\n      - run: echo\n"

func TestJobProjection(t *testing.T) {
	x := newIR(t, jobWF)
	js := x.allJobs()
	if len(js) != 2 {
		t.Fatalf("%d jobs", len(js))
	}
	d, o := js[0], js[1]
	if d.key.Path() != "jobs.deploy" || len(d.privilegedOn) == 0 || d.approval != analysis.ApprovalEnvironment || d.environment.String() != "production" ||
		d.tokenWrite != analysis.TokenWriteUnwritten || d.secrets.All || len(d.secrets.Names) != 1 || d.secrets.Names[0] != "DEPLOY_KEY" ||
		len(d.runnerLabels) != 2 || !d.runnerLabels[0].HasSelfHostedLabel || len(d.inconclusiveLabels) != 0 {
		t.Errorf("deploy: %+v", d)
	}
	if o.tokenWrite != analysis.TokenWriteNo || len(o.runnerLabels) != 0 || len(o.inconclusiveLabels) != 1 {
		t.Errorf("other: %+v", o)
	}
}

// TestJobAction: an action.yml has no jobs.
func TestJobAction(t *testing.T) {
	x := New("action.yml", nil, nil, nil)
	if js := x.allJobs(); len(js) != 0 {
		t.Errorf("%+v", js)
	}
}

// TestJobLeastPrivilege: the fields permissions and secrets-inherit read.
func TestJobLeastPrivilege(t *testing.T) {
	src := "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n" +
		"  b:\n    uses: Octo/Shared/.github/workflows/b.yml@v1\n    permissions: {}\n    secrets: inherit\n"
	js := newIR(t, src).allJobs()
	if len(js) != 2 {
		t.Fatalf("%d jobs", len(js))
	}
	a, b := js[0], js[1]
	if a.writeAll != analysis.WriteAllWorkflow || a.calledOnly || a.inheritSecrets || a.calledKind != analysis.CalledWorkflowKindNone {
		t.Errorf("a: %+v", a)
	}
	if b.writeAll != analysis.WriteAllNo || !b.inheritSecrets || b.calledKind != analysis.CalledWorkflowKindRemote ||
		b.calledRepo.String() != "octo/shared" || b.usesText != "Octo/Shared/.github/workflows/b.yml@v1" {
		t.Errorf("b: %+v", b)
	}
}

// TestJobCalledContextReads: a job that calls a reusable workflow of the
// inputs with secrets: inherit reads what the called workflow reads, and the
// reads of the secrets context without a name are where they are written
// (a run showed that GitHub passes the runner of a called job only the
// secrets that the job reads by name, unless the job reads them without a
// name).
func TestJobCalledContextReads(t *testing.T) {
	ciOf := func(t *testing.T, files ...[2]string) *IR {
		t.Helper()
		c := taint.NewCallers(callerstest.Graph(t, true, false, files...))
		f, ok := c.Graph().File(calls.InputNode(facts.MustCleanInputPath(".github/workflows/ci.yml")))
		if !ok {
			t.Fatal("no ci.yml")
		}
		return New(f.Name.String(), f.Tree, f.Workflow, f.Action).WithCallers(func() *taint.Callers { return c })
	}
	ci := [2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n    secrets: inherit\n"}
	called := func(v string) [2]string {
		return [2]string{".github/workflows/c.yml", "on:\n  workflow_call:\njobs:\n  c:\n    runs-on: x\n    steps:\n      - run: x\n        env: {X: '${{ " + v + " }}'}\n"}
	}
	j := ciOf(t, ci, called("toJSON(secrets)")).allJobs()[0]
	if !j.secrets.All || len(j.calledContextReads) != 1 || j.calledContextReads[0].InputName() != ".github/workflows/c.yml" {
		t.Errorf("nameless: %+v %+v", j.secrets, j.calledContextReads)
	}
	j = ciOf(t, ci, called("secrets.A")).allJobs()[0]
	if j.secrets.All || len(j.secrets.Names) != 1 || j.secrets.Names[0] != "A" || len(j.calledContextReads) != 0 {
		t.Errorf("named: %+v %+v", j.secrets, j.calledContextReads)
	}
	j = newIR(t, ci[1]).allJobs()[0]
	if !j.secrets.All || len(j.calledContextReads) != 0 {
		t.Errorf("no callers: %+v", j.secrets)
	}
}
