package lint

import (
	"context"
	"slices"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// usesRule reports each uses whose ref is v1, with the fix that writes v2.
type usesRule struct{ id string }

func (r usesRule) Meta() Meta {
	return fixing(meta(r.id), FixKind{ID: fixF, Title: "write v2", Safety: SafetySafe})
}

func (r usesRule) Check(_ context.Context, c *RuleContext, v ir.CommitSHAReader) error {
	for _, u := range v.Uses() {
		if u.Ref() != "v1" {
			continue
		}
		f := FindingDraft{Args: said("x"), Location: c.At(u.RefAt())}
		if e, err := u.RefAt().Replace("v2"); err == nil {
			f.Fix = &Fix{KindID: fixF, Title: "v2", Edits: []edit.Edit{e}}
		}
		c.Report(f)
	}
	return nil
}

const usesInput = "on: push\njobs:\n  b:\n    steps:\n      - uses: o/r@v1\n"

// captureIRs records the IRs the runs of the test make. The checks of
// the fixes make theirs at once (checkApplied), so it takes a lock.
func captureIRs(t *testing.T) *[]*ir.IR {
	var made []*ir.IR
	var mu sync.Mutex
	old := newIR
	newIR = func(input string, tr *cst.Tree, w *workflow.Workflow, a *workflow.ActionMetadata) *ir.IR {
		x := old(input, tr, w, a)
		mu.Lock()
		made = append(made, x)
		mu.Unlock()
		return x
	}
	t.Cleanup(func() { newIR = old })
	return &made
}

// TestWithViewDeclaresTheReads: the Meta of a rule of WithView reads what
// its view declares.
func TestWithViewDeclaresTheReads(t *testing.T) {
	m := WithView[ir.CommitSHAReader](usesRule{"uses"}, ir.CommitSHAView).Meta()
	if !slices.Equal(m.ViewFields, ir.CommitSHAView.Fields()) || len(m.ViewFields) == 0 {
		t.Errorf("reads %v", m.ViewFields)
	}
}

// TestOneIRForTheRulesOfAnInput: the rules of one input read one IR, and
// its summaries of a type are made once.
func TestOneIRForTheRulesOfAnInput(t *testing.T) {
	made := captureIRs(t)
	rep := run(t, wf(usesInput), nil,
		WithView[ir.CommitSHAReader](usesRule{"uses-a"}, ir.CommitSHAView),
		WithView[ir.CommitSHAReader](usesRule{"uses-b"}, ir.CommitSHAView))
	if len(rep.Errors) != 0 {
		t.Fatalf("errors %v", rep.Errors)
	}
	// the run, and the check of the fix of each rule
	if len(*made) != 3 || (*made)[0].Made(ir.SummaryUses) != 1 {
		t.Errorf("IRs %d", len(*made))
	}
}

// TestFixCheckReadsTheFixedIR: the check of a fix runs the rule on the IR
// of the fixed tree, where the ref is v2 and the finding is gone.
func TestFixCheckReadsTheFixedIR(t *testing.T) {
	rep := run(t, wf(usesInput), nil, WithView[ir.CommitSHAReader](usesRule{"uses"}, ir.CommitSHAView))
	if len(rep.Errors) != 0 || len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 || rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Fix == nil {
		t.Fatalf("errors %v, findings %v", rep.Errors, rep.FindingsWith(CertaintyConfirmed, CertaintyConditional))
	}
}

// sinksRule reads the sinks of the input and reports nothing.
type sinksRule struct{}

func (sinksRule) Meta() Meta { return meta("sinks") }

func (sinksRule) Check(_ context.Context, _ *RuleContext, v ir.CodeInjectionReader) error {
	for _, s := range v.Sinks() {
		_ = s.Refs()
	}
	return nil
}

// TestNarrowedRunMakesOnlyWhatItReads: a rule skipped by the selection
// makes none of the summaries only it reads, in the run and in the check
// of the fixes; ApplyFixes makes them once before the fixes and once
// after, to compare them for it.
func TestNarrowedRunMakesOnlyWhatItReads(t *testing.T) {
	src := "on: issues\njobs:\n  b:\n    steps:\n      - uses: o/r@v1\n      - run: echo \"${{ github.event.issue.title }}\"\n"
	for _, skip := range []bool{false, true} {
		made := captureIRs(t)
		rules := []Rule{WithView[ir.CommitSHAReader](usesRule{"uses"}, ir.CommitSHAView), WithView[ir.CodeInjectionReader](sinksRule{}, ir.CodeInjectionView)}
		fsys := map[string]string{".github/workflows/w.yml": src}
		in := inputsOf(t, fsys)
		reg, err := newRegistry(rules, true)
		if err != nil {
			t.Fatal(err)
		}
		if skip {
			sel, err := ParseSelector("sinks")
			if err != nil {
				t.Fatal(err)
			}
			if reg, err = reg.Select(Skip(sel), FactSources{}); err != nil {
				t.Fatal(err)
			}
		}
		rep := Run(context.Background(), in, reg, mapResolver{})
		if _, err := ApplyFixes(context.Background(), in, reg, mapResolver{}, rep, SafetyReview); err != nil {
			t.Fatal(err)
		}
		if len(*made) < 3 { // the run, the check of the fix, the run of ApplyFixes
			t.Fatalf("skip %t: IRs %d", skip, len(*made))
		}
		sinks := 0
		for _, x := range *made {
			sinks += x.Made(ir.SummarySink) + x.Made(ir.SummaryStepFix) + x.Made(ir.SummaryCheckoutSite)
		}
		if skip && sinks != 2 || !skip && sinks == 0 {
			t.Errorf("skip %t: the summaries of taint and prcode were made %d times", skip, sinks)
		}
	}
}

// inputsOf are the inputs of the files.
func inputsOf(t *testing.T, files map[string]string) Inputs {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// withRule reports each controlled reference of code-injection's view,
// with the with of its callers as the evidence.
type withRule struct{}

func (withRule) Meta() Meta { return meta("test") }

func (withRule) Check(_ context.Context, c *RuleContext, v ir.CodeInjectionReader) error {
	for _, s := range v.Sinks() {
		for _, r := range s.Refs() {
			if r.Verdict != analysis.Controlled {
				continue
			}
			f := FindingDraft{Args: said("x"), Location: c.At(r.At)}
			for _, w := range r.With {
				f.Evidence = append(f.Evidence, Related{Location: c.At(w), Note: "the caller gives it here"})
			}
			c.Report(f)
		}
	}
	return nil
}

// TestAtOtherInput: a handle on another input locates in it, and the
// callers among the inputs of the whole repository decide inputs.
func TestAtOtherInput(t *testing.T) {
	fsys := fstest.MapFS{
		".github/workflows/called.yml": {Data: []byte("on:\n  workflow_call:\n    inputs: {t: {type: string}}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n")},
		".github/workflows/ci.yml":     {Data: []byte("on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n")},
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry([]Rule{WithView[ir.CodeInjectionReader](withRule{}, ir.CodeInjectionView)})
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), in, reg, nil)
	if len(rep.Errors) != 0 || len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 1 {
		t.Fatalf("findings %+v, errors %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
	}
	f := rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0]
	if f.Location.File.Input.String() != ".github/workflows/called.yml" || len(f.Evidence) != 1 || f.Evidence[0].Location.File.Input.String() != ".github/workflows/ci.yml" {
		t.Fatalf("finding %+v", f)
	}
}
