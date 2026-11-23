package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// remoteDefs answers workflow.definition from the contents by repository,
// and the other facts as limitFacts.
type remoteDefs map[string]string

func (d remoteDefs) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	if w, ok := q.(facts.WorkflowDefinition); ok {
		content, ok := d[w.Repo.String()]
		if !ok {
			return facts.RawAnswer{}
		}
		sha, _ := facts.ParseSHA(strings.Repeat("e", 40))
		b, err := json.Marshal(facts.WorkflowFile{Commit: sha, Content: content})
		if err != nil {
			panic(err)
		}
		return facts.RawAnswer{State: facts.StateFound, Value: b, Source: facts.SourceFile}
	}
	return limitFacts{}.Resolve(ctx, q)
}

const remoteTitleEcho = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n"

// TestRemoteFindingRelocated: a finding in a reusable workflow of another
// repository is at the uses of the job that calls it, with where it was
// first in its Evidence, and no fix.
func TestRemoteFindingRelocated(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\npermissions: {}\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
	}, remoteDefs{"o/wf": remoteTitleEcho})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings, want 1: %+v", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	if f.Location.File.Input.String() != ".github/workflows/ci.yml" || f.Location.LineText() != "    uses: o/wf/.github/workflows/w.yml@v1" {
		t.Errorf("at %v %q, want the uses of the job c", f.Location.File, f.Location.LineText())
	}
	if len(f.Evidence) == 0 || f.Evidence[0].Location.File.Query == nil || !strings.Contains(f.Evidence[0].Note, "o/wf/.github/workflows/w.yml") {
		t.Errorf("evidence %+v, want first the place in the reusable workflow", f.Evidence)
	}
	if f.Fix != nil {
		t.Errorf("a fix %+v of a file of another repository", f.Fix)
	}
}

// TestRemoteTwoCallers: one file called by two jobs gets a finding at the
// uses of each.
func TestRemoteTwoCallers(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    uses: o/wf/.github/workflows/w.yml@v1\n  b:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
	}, remoteDefs{"o/wf": remoteTitleEcho})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Location.Span == rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].Location.Span {
		t.Fatalf("findings %+v, want one at each uses", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestRemoteNested: a finding at depth 2 is at the uses of the job of the
// input, with the uses of the job of the workflow at depth 1 in Related.
func TestRemoteNested(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\npermissions: {}\njobs:\n  c:\n    uses: o/mid/.github/workflows/m.yml@v1\n",
	}, remoteDefs{"o/mid": "on: workflow_call\njobs:\n  m:\n    uses: o/wf/.github/workflows/w.yml@v1\n", "o/wf": remoteTitleEcho})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings, want 1", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	if f.Location.File.Input.String() != ".github/workflows/ci.yml" {
		t.Errorf("at %v", f.Location.File)
	}
	found := false
	for _, r := range f.Related {
		if r.Location.File.Query != nil && strings.Contains(r.Note, "o/mid/.github/workflows/m.yml") {
			found = true
		}
	}
	if !found {
		t.Errorf("related %+v, want the uses of the job m of m.yml", f.Related)
	}
}

// TestRemoteInconclusiveRelocated: an inconclusive place in a reusable
// workflow of another repository is at the uses of the job that calls it,
// with where it was, in w.yml, first in Related.
func TestRemoteInconclusiveRelocated(t *testing.T) {
	called := "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - id: s\n        uses: some/action@v1\n      - run: echo \"${{ steps.s.outputs.x }}\"\n"
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\npermissions: {}\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
	}, remoteDefs{"o/wf": called})
	if len(rep.FindingsWith(lint.CertaintyInconclusive)) == 0 {
		t.Fatal("no inconclusive place")
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		if g.Location.File.Input.String() != ".github/workflows/ci.yml" || len(g.Related) == 0 || g.Related[0].Location.File.Query == nil || !strings.Contains(g.Related[0].Note, "o/wf/.github/workflows/w.yml") {
			t.Errorf("inconclusive %+v, want at the uses with the place in w.yml in Related", g)
		}
	}
}

// TestRemoteQualityFinding: a quality rule reads a reusable workflow of
// another repository too.
func TestRemoteQualityFinding(t *testing.T) {
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/ci.yml": {Data: []byte("on: push\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n")}})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(nil, MissingTimeoutMinutes)
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(context.Background(), in, reg, remoteDefs{"o/wf": remoteTitleEcho})
	if len(rep.QualityFindings) != 1 || rep.QualityFindings[0].Location.File.Input.String() != ".github/workflows/ci.yml" {
		t.Fatalf("quality findings %+v, want one at the uses", rep.QualityFindings)
	}
}

// TestRemoteInvalidWorkflow: a reusable workflow the model rejects gets no
// place.
func TestRemoteInvalidWorkflow(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\npermissions: {}\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
	}, remoteDefs{"o/wf": "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: 3\n"})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))+len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
		t.Fatalf("findings %+v, inconclusive %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// TestRemoteOwnOnLeftOut: the on of a reusable workflow of another
// repository starts runs in that repository; called from a job on push, it
// runs on push alone (GHSL-2024-275: build-images-base.yaml of
// cilium/cilium 475310f713fb25897b1b939668c73db7da359d08 has
// pull_request_target and workflow_call, and its caller runs on push).
func TestRemoteOwnOnLeftOut(t *testing.T) {
	called := "on:\n  pull_request_target:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          T: ${{ secrets.TOKEN }}\n        run: echo \"${{ github.event.pull_request.head.ref }}\"\n"
	rep, _, _ := checkRules(t, []lint.Rule{DangerousTriggers, CodeInjection}, map[string]string{
		".github/workflows/ci.yml": "on: push\npermissions: {}\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n    secrets: inherit\n",
	}, remoteDefs{"o/wf": called})
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		t.Errorf("finding %s at %v: want none, the call runs on push", f.Args.KindID(), f.Location.File)
	}
}

// TestRemoteOwnDispatchLeftOut: the workflow_dispatch of a reusable
// workflow of another repository starts runs in that repository; its
// inputs come from the caller.
func TestRemoteOwnDispatchLeftOut(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs:\n      ref: {type: string}\n  workflow_dispatch:\n    inputs:\n      ref: {type: string}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ inputs.ref }}\n      - run: echo \"${{ inputs.ref }}\"\n"
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection, UntrustedCheckout}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request\npermissions: {}\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n    with:\n      ref: main\n",
	}, remoteDefs{"o/wf": called})
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		if strings.Contains(g.InconclusiveKind.String(), "dispatch") {
			t.Errorf("inconclusive %s %s: the call gives the input", g.Rule, g.InconclusiveKind)
		}
	}
}

// TestRemoteNoRepositoryName: without --repo, a job that calls a reusable
// workflow of another repository whose path is also an input still reads
// the answer of workflow.definition.
func TestRemoteNoRepositoryName(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\npermissions: {}\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
		".github/workflows/w.yml":  "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
	}, remoteDefs{"o/wf": remoteTitleEcho})
	found := false
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Location.File.Input.String() == ".github/workflows/ci.yml" && len(f.Evidence) > 0 && f.Evidence[0].Location.File.Query != nil {
			found = true
		}
	}
	if !found {
		t.Errorf("findings %+v, want one moved from the reusable workflow of o/wf", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestRemoteEvidenceNotes: the with of the caller is a caller's, not the
// default of an input.
func TestRemoteEvidenceNotes(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\npermissions: {}\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n    with:\n      t: ${{ github.event.pull_request.title }}\n",
	}, remoteDefs{"o/wf": called})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings, want 1", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	for _, e := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Evidence {
		if strings.Contains(e.Note, "default") {
			t.Errorf("evidence %q at %v: the with of the caller is not a default", e.Note, e.Location.File)
		}
	}
}

// TestRemoteNoInputStepFact: a checkout of a reusable workflow of another
// repository asks no fact of a step of the input.
func TestRemoteNoInputStepFact(t *testing.T) {
	called := "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n"
	rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
	}, remoteDefs{"o/wf": called})
	for _, x := range rep.Facts {
		if x.Query.Kind() == facts.KindCheckoutExecuted {
			t.Errorf("asked %+v: a step of the input", x.Query)
		}
	}
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) == 0 {
		t.Error("no finding of the checkout")
	}
}

// TestRemoteFingerprints: two findings moved to one uses have two
// fingerprints (checkRules fails on a finding reported twice).
func TestRemoteFingerprints(t *testing.T) {
	called := "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n      - run: echo \"${{ github.event.pull_request.body }}\"\n"
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, map[string]string{
		".github/workflows/ci.yml": "on: pull_request_target\npermissions: {}\njobs:\n  c:\n    uses: o/wf/.github/workflows/w.yml@v1\n",
	}, remoteDefs{"o/wf": called})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fingerprint == rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].Fingerprint {
		t.Fatalf("findings %+v, want two with two fingerprints", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}
