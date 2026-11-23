package lint

import (
	"context"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// ifFlipRule reports a job's if that keeps the push alone, with the fix
// that drops it (if: true), and each reference an attacker controls, with
// no fix: dropping the caller's if lets issues reach its called workflow.
type ifFlipRule struct{ refs bool }

func (r ifFlipRule) Meta() Meta {
	return fixing(meta("test"), FixKind{ID: fixF, Title: "if true", Safety: SafetySafe})
}

func (r ifFlipRule) Check(_ context.Context, c *RuleContext, v ir.CodeInjectionReader) error {
	if w := c.workflow; w != nil {
		for _, je := range w.Jobs.Value.Entries {
			f := je.Value.Value.If
			if f.Status != workflow.Present || !strings.Contains(f.Value.Text(), "'push'") {
				continue
			}
			e, err := edit.Replace(f.Value.Value, 0, len(f.Value.Text()), "github.event_name != 'none'")
			if err != nil {
				return err
			}
			c.Report(FindingDraft{Args: said("if"), Location: At(c.input, f.Value.Base), Fix: &Fix{KindID: fixF, Title: "if true", Edits: []edit.Edit{e}}})
		}
	}
	if !r.refs {
		return nil
	}
	for _, s := range v.Sinks() {
		for _, x := range s.Refs() {
			if x.Verdict == analysis.Controlled {
				c.Report(FindingDraft{Args: said("ref"), Location: c.At(x.At), NoFix: &NoFix{Reason: ir.NoFixReasonManual}})
			}
		}
	}
	return nil
}

const calledSrc = "on:\n  workflow_call:\n    inputs: {t: {type: string}}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"

func callerRepo(t *testing.T, ci string) Inputs {
	t.Helper()
	in, err := Enumerate(fstest.MapFS{
		".github/workflows/called.yml": {Data: []byte(calledSrc)},
		".github/workflows/ci.yml":     {Data: []byte(ci)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

const ifPushCaller = "on: [push, issues]\njobs:\n  c:\n    if: github.event_name == 'push'\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n"

// TestApplyFixSeesDependents: the check of a fix of a caller runs the
// rule on the workflows it calls too, and a finding the fix makes there
// drops the fix.
func TestApplyFixSeesDependents(t *testing.T) {
	reg, err := NewRegistry([]Rule{WithView[ir.CodeInjectionReader](ifFlipRule{refs: true}, ir.CodeInjectionView)})
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), callerRepo(t, ifPushCaller), reg, nil)
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 || rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Fix != nil {
		t.Fatalf("findings %+v, errors %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
	}
	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Message, "makes a new finding") {
		t.Fatalf("errors %+v", rep.Errors)
	}
}

// TestUncheckedSeesDependents: a fix of a caller that changes what a rule
// skipped reads of the workflow it calls is said, with the called
// workflow's summary and no fix by it (no edit of the fixes is there).
func TestUncheckedSeesDependents(t *testing.T) {
	a, err := uncheckedAfter(t, map[string]string{".github/workflows/called.yml": calledSrc, ".github/workflows/ci.yml": ifPushCaller},
		[]Rule{WithView[ir.CodeInjectionReader](ifFlipRule{}, ir.CodeInjectionView), reader("sink-reader", workflowOnly, ir.FieldSinkRefs)}, "sink-reader")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Unchecked) != 1 || len(a.Unchecked[0].Changed) != 1 || a.Unchecked[0].Changed[0].Input.String() != ".github/workflows/called.yml" || len(a.Unchecked[0].Changed[0].By) != 0 {
		t.Fatalf("unchecked %+v", a.Unchecked)
	}
}

// TestCallersUnreadable: an input that cannot be read may be a caller, so
// an action's callers are not all among the inputs.
func TestCallersUnreadable(t *testing.T) {
	in, err := Enumerate(fstest.MapFS{
		"x/action.yml":             {Data: []byte("runs:\n  using: composite\n  steps:\n    - run: echo \"${{ inputs.t }}\"\n      shell: bash\n")},
		".github/workflows/ci.yml": {Data: []byte("on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./x\n")},
		"y/action.yml":             {Data: []byte("\xff\xfe")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c := callersOf(context.Background(), in, nil).Coverage(calls.InputNode(facts.MustCleanInputPath("x/action.yml"))); c != analysis.CallerCoveragePartial {
		t.Fatalf("coverage %v", c)
	}
}

// countingRule is ifFlipRule that counts its checks of each input.
type countingRule struct {
	ifFlipRule
	mu sync.Mutex
	n  map[string]int
}

func (r *countingRule) Check(ctx context.Context, c *RuleContext, v ir.CodeInjectionReader) error {
	r.mu.Lock()
	r.n[c.input.Name.String()]++
	r.mu.Unlock()
	return r.ifFlipRule.Check(ctx, c, v)
}

// TestFixCheckRunsDependentOnce: the check of the fixes of a caller runs the
// rule on each workflow the caller calls once before the fixes, for all of
// them, and once after each fix (not the rule before the fix again for each
// fix).
func TestFixCheckRunsDependentOnce(t *testing.T) {
	const ci = "on: [push, issues]\njobs:\n" +
		"  a:\n    if: github.event_name == 'push'\n    uses: ./.github/workflows/c1.yml\n" +
		"  b:\n    if: github.event_name == 'push'\n    uses: ./.github/workflows/c2.yml\n" +
		"  c:\n    if: github.event_name == 'push'\n    uses: ./.github/workflows/c1.yml\n"
	in, err := Enumerate(fstest.MapFS{
		".github/workflows/c1.yml": {Data: []byte(calledSrc)},
		".github/workflows/c2.yml": {Data: []byte(calledSrc)},
		".github/workflows/ci.yml": {Data: []byte(ci)},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &countingRule{n: map[string]int{}}
	reg, err := NewRegistry([]Rule{WithView[ir.CodeInjectionReader](r, ir.CodeInjectionView)})
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), in, reg, nil)
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 3 || len(rep.Errors) != 0 {
		t.Fatalf("findings %+v, errors %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
	}
	for _, called := range []string{".github/workflows/c1.yml", ".github/workflows/c2.yml"} {
		// the run of the rule on it, the run before the fixes, and a run
		// after each of the 3 fixes
		if got := r.n[called]; got != 5 {
			t.Errorf("%s: %d checks, want 5", called, got)
		}
	}
}
