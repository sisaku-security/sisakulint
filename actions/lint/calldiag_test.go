package lint

import (
	"context"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/workflow"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

const calledRequired = "on:\n  workflow_call:\n    inputs:\n      t: {type: string, required: true}\njobs:\n  j:\n    runs-on: x\n    steps: [{run: y}]\n"

// The diagnostics of a call of a workflow among the inputs are the
// caller's, which is then invalid; the called is not.
func TestCallDiagnostics(t *testing.T) {
	rep := run(t, map[string]string{
		".github/workflows/called.yml": calledRequired,
		".github/workflows/ci.yml":     "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n",
	}, nil)
	if got := names(Inputs{List: rep.Inputs}); got != ".github/workflows/called.yml=workflow/read .github/workflows/ci.yml=workflow/invalid" {
		t.Fatalf("inputs = %s", got)
	}
	ds := rep.Inputs[1].Diagnostics
	if len(ds) != 1 || ds[0].Code != workflow.MissingKey {
		t.Errorf("diagnostics %+v", ds)
	}
}

// Without the called workflow among the inputs, nothing is known.
func TestCallDiagnosticsCalledNotRead(t *testing.T) {
	rep := run(t, map[string]string{
		".github/workflows/ci.yml": "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n",
	}, nil)
	if got := names(Inputs{List: rep.Inputs}); got != ".github/workflows/ci.yml=workflow/read" {
		t.Fatalf("inputs = %s", got)
	}
}

// A fix is checked against the diagnostics of its input's own reading: one
// that makes a new UnknownKey in a caller that already has an UnknownKey
// of its call (which the reading again does not give) is dropped for its
// new diagnostic.
func TestFixDiagnosticBesideCallDiagnostic(t *testing.T) {
	fixer := fixing(meta("fixer"), FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	rule := testRule{meta: fixer, check: func(_ context.Context, c *RuleContext) error {
		if c.input.Name.String() != ".github/workflows/ci.yml" {
			return nil
		}
		for _, s := range steps(c) {
			if s.Run.Status != workflow.Present {
				continue
			}
			end := s.Run.Value.Base.Node.ContentSpan().End
			bogus := edit.Edit{Span: cstSpan(end, end), New: []byte("\n        bogus: 1")}
			c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{bogus}}})
		}
		return nil
	}}
	rep := run(t, map[string]string{
		".github/workflows/called.yml": "on: workflow_call\njobs:\n  j:\n    runs-on: x\n    steps: [{run: y}]\n",
		".github/workflows/ci.yml":     "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      zz: x\n  b:\n    runs-on: x\n    steps:\n      - run: echo a\n",
	}, nil, rule)
	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Message, "makes a new diagnostic") {
		t.Errorf("errors %+v", rep.Errors)
	}
}
