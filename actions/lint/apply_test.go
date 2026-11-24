package lint

import (
	"context"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// marker is a rule that reports every step not marked and fixes it by
// writing the comment text, with the given safety.
func marker(id, text string, safety Safety) Rule {
	m := meta(id)
	var es []ir.SideEffect
	if safety == SafetyReview {
		es = []ir.SideEffect{ir.SideEffectUnquotedOneWord}
	}
	m = fixing(m, FixKind{ID: fixF, Title: "mark", Safety: safety, PossibleSideEffects: es})
	return unmarkedStep(m, func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "mark", Edits: []edit.Edit{markEdit(c, s, text)}, SideEffects: es}}
	})
}

// applied runs rules on files, applies the fixes of the report, and gives
// what ApplyFixes gives.
func applied(t *testing.T, files map[string]string, safety Safety, rules ...Rule) (Report, map[facts.InputPath][]byte, error) {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := newRegistry(rules, true)
	if err != nil {
		t.Fatal(err)
	}
	var r facts.Resolver = mapResolver{}
	rep := Run(context.Background(), in, reg, r)
	if len(rep.Errors) != 0 {
		t.Fatalf("errors %+v", rep.Errors)
	}
	a, err := ApplyFixes(context.Background(), in, reg, r, rep, safety)
	return rep, a.Files, err
}

const wfPath = ".github/workflows/w.yml"

func TestApplyFixes(t *testing.T) {
	_, out, err := applied(t, map[string]string{wfPath: twoSteps, ".github/workflows/clean.yml": "on: push\njobs: {}\n"}, SafetySafe, marker("mark", "m", SafetySafe))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("changed %d inputs, want only w.yml: an input that does not change is not given", len(out))
	}
	got := string(out[facts.MustCleanInputPath(wfPath)])
	if strings.Count(got, " # m") != 2 {
		t.Errorf("w.yml =\n%s", got)
	}
}

func TestApplyFixesMergesTheSameEdit(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - &s\n        run: echo\n  b:\n    runs-on: x\n    steps:\n      - *s\n"
	rep, out, err := applied(t, map[string]string{wfPath: src}, SafetySafe, marker("mark", "m", SafetySafe))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 2 {
		t.Fatalf("findings %d, want the anchor's step and its alias", len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)))
	}
	if got := string(out[facts.MustCleanInputPath(wfPath)]); strings.Count(got, " # m") != 1 {
		t.Errorf("the edit of the anchor, in both findings, is applied once:\n%s", got)
	}
}

func TestApplyFixesRefusesOverlaps(t *testing.T) {
	_, out, err := applied(t, map[string]string{wfPath: twoSteps}, SafetySafe, marker("mark-a", "a", SafetySafe), marker("mark-b", "b", SafetySafe))
	if err == nil || out != nil {
		t.Errorf("two rules write at one place: out %v, err %v", out, err)
	}
}

func TestApplyFixesBySafety(t *testing.T) {
	_, out, err := applied(t, map[string]string{wfPath: twoSteps}, SafetySafe, marker("mark", "m", SafetyReview))
	if err != nil || len(out) != 0 {
		t.Errorf("SafetySafe applies a fix to review: out %v, err %v", out, err)
	}
	_, out, err = applied(t, map[string]string{wfPath: twoSteps}, SafetyReview, marker("mark", "m", SafetyReview))
	if err != nil || len(out) != 1 {
		t.Errorf("SafetyReview does not apply a fix to review: out %v, err %v", out, err)
	}
}

// TestApplyFixesChecksTheWhole: each fix closes its finding alone, but
// the fixes together make a finding of another rule; nothing is given.
func TestApplyFixesChecksTheWhole(t *testing.T) {
	watcher := testRule{meta: meta("watcher"), check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			if marked(c, s) {
				c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base)})
			}
		}
		return nil
	}}
	_, out, err := applied(t, map[string]string{wfPath: twoSteps}, SafetySafe, marker("mark", "m", SafetySafe), watcher)
	if err == nil || out != nil || !strings.Contains(err.Error(), "new finding") {
		t.Errorf("out %v, err %v", out, err)
	}
}

func TestApplyFixesNeedsTheInputs(t *testing.T) {
	fsys := fstest.MapFS{wfPath: {Data: []byte(twoSteps)}}
	in, _ := Enumerate(fsys)
	reg, _ := newRegistry([]Rule{marker("mark", "m", SafetySafe)}, true)
	rep := Run(context.Background(), in, reg, mapResolver{})
	other, _ := Enumerate(fsys) // the same files, read again: other trees
	if _, err := ApplyFixes(context.Background(), other, reg, mapResolver{}, rep, SafetySafe); err == nil {
		t.Error("the fixes of a report applied to inputs it was not made from")
	}
}

// counting counts what it is asked, and answers every flag true.
type counting struct {
	mu sync.Mutex
	n  int
}

func (c *counting) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
}

// TestApplyFixesReplaysTheFacts: the run after
// the fixes answers from the facts of the report, and does not ask again.
func TestApplyFixesReplaysTheFacts(t *testing.T) {
	m := meta("asker")
	m = asking(m, facts.KindTestFlag)
	m = fixing(m, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	mark := unmarkedStep(m, func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}}}
	})
	rule := testRule{meta: m, check: func(ctx context.Context, c *RuleContext) error {
		facts.TestFlag{Name: "asked"}.Ask(ctx, c.Resolver) // on every input, fixed or not
		return mark.Check(ctx, c)
	}}
	in, _ := Enumerate(fstest.MapFS{wfPath: {Data: []byte(twoSteps)}})
	reg, _ := newRegistry([]Rule{rule}, true)
	r := &counting{}
	rep := Run(context.Background(), in, reg, r)
	before := r.n
	if _, err := ApplyFixes(context.Background(), in, reg, r, rep, SafetySafe); err != nil {
		t.Fatal(err)
	}
	if r.n != before {
		t.Errorf("asked %d times, then %d more after the fixes", before, r.n-before)
	}
}

// TestApplyFixesKeepsAnswers: an answer of the report is the answer in the
// run after the fixes too, as the report has it: given the resolver the
// report came from, or one that does not know the fact, a finding the
// answer dropped stays dropped.
func TestApplyFixesKeepsAnswers(t *testing.T) {
	closed, _ := FactEq(facts.RepoWikiOpen{}, false)
	m := meta("closed-wiki")
	m = asking(m, facts.KindRepoWikiOpen)
	wiki := testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Condition: &closed})
		}
		return nil
	}}
	fm := meta("mark")
	fm = fixing(fm, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	mark := unmarkedStep(fm, func(c *RuleContext, s workflow.Step) FindingDraft {
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}}}
	})
	in, _ := Enumerate(fstest.MapFS{wfPath: {Data: []byte(twoSteps)}})
	reg, _ := newRegistry([]Rule{wiki, mark}, true)
	r := mapResolver{facts.RepoWikiOpen{}: foundJSON("true")}
	rep := Run(context.Background(), in, reg, r)
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		if f.Rule == m.ID {
			t.Fatalf("the answer (open) drops the finding on a closed wiki: %+v", f)
		}
	}
	if len(rep.Facts) != 1 || rep.Facts[0].RawAnswer.State != facts.StateFound {
		t.Fatalf("facts %+v, want repo.wiki-open found", rep.Facts)
	}
	if _, err := ApplyFixes(context.Background(), in, reg, r, rep, SafetySafe); err != nil {
		t.Errorf("with the resolver of the report: %v", err)
	}
	if _, err := ApplyFixes(context.Background(), in, reg, mapResolver{}, rep, SafetySafe); err != nil {
		t.Errorf("with a resolver that does not know the fact: %v", err)
	}
}

// TestApplyFixesChecksOnlyWhatRuns: the run again after the fixes is of
// the rules that run.
func TestApplyFixesChecksOnlyWhatRuns(t *testing.T) {
	watcher := testRule{meta: ruleOf("watcher"), check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			if marked(c, s) {
				c.Report(FindingDraft{Args: said("y"), Location: At(c.input, s.Base)})
			}
		}
		return nil
	}}
	in, _ := Enumerate(fstest.MapFS{wfPath: {Data: []byte(twoSteps)}})
	for _, c := range []struct {
		skip    bool
		wantErr bool
	}{{false, true}, {true, false}} {
		reg, _ := newRegistry([]Rule{marker("mark", "m", SafetySafe), watcher}, true)
		if c.skip {
			reg, _ = reg.Select(Skip(sel(t, "watcher")...), FactSources{})
		}
		rep := Run(context.Background(), in, reg, mapResolver{})
		a, err := ApplyFixes(context.Background(), in, reg, mapResolver{}, rep, SafetySafe)
		if (err != nil) != c.wantErr || !c.wantErr && len(a.Files) != 1 {
			t.Errorf("skip %v: %d written, %v", c.skip, len(a.Files), err)
		}
	}
}

// weakening reports every step: with no condition until the step is
// marked, and then on the flag of when (which mapResolver does not answer,
// so the finding is conditional). The fix of marker makes it weaker.
func weakening(when string, before string) Rule {
	m := asking(meta("weak"), facts.KindTestFlag)
	return testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			f := FindingDraft{Args: said("x"), Location: At(c.input, s.Base)}
			name := before
			if marked(c, s) {
				name = when
			}
			if name != "" {
				cond, _ := FactEq(facts.TestFlag{Name: name}, true)
				f.Condition = &cond
			}
			c.Report(f)
		}
		return nil
	}}
}

// TestApplyFixesRefusesAWeakerFinding: a finding of another rule there
// before and after, of the same fingerprint, made conditional by the fixes
// is an error, as a new one is.
func TestApplyFixesRefusesAWeakerFinding(t *testing.T) {
	_, out, err := applied(t, map[string]string{wfPath: twoSteps}, SafetySafe, marker("mark", "m", SafetySafe), weakening("x", ""))
	if err == nil || out != nil || !strings.Contains(err.Error(), "from confirmed to conditional") {
		t.Errorf("out %v, err %v", out, err)
	}
}

// TestApplyFixesRefusesAnotherCondition: the same certainty on another
// condition is an error too.
func TestApplyFixesRefusesAnotherCondition(t *testing.T) {
	_, out, err := applied(t, map[string]string{wfPath: twoSteps}, SafetySafe, marker("mark", "m", SafetySafe), weakening("y", "x"))
	if err == nil || out != nil || !strings.Contains(err.Error(), "the condition of") {
		t.Errorf("out %v, err %v", out, err)
	}
}

// TestApplyFixesKeepsTheSameFinding: a finding the fixes do not change is
// no error.
func TestApplyFixesKeepsTheSameFinding(t *testing.T) {
	if _, out, err := applied(t, map[string]string{wfPath: twoSteps}, SafetySafe, marker("mark", "m", SafetySafe), weakening("x", "x")); err != nil || len(out) != 1 {
		t.Errorf("out %d, err %v", len(out), err)
	}
}

// flaky answers every fact Unknown the first time it is asked, and true
// after: an API that failed once (a 5xx, a rate limit) and then answers.
type flaky struct {
	mu sync.Mutex
	n  int
}

func (f *flaky) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.n == 1 {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "503"}
	}
	return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
}

// TestApplyFixesReplaysUnknown: a fact the
// run answered Unknown is Unknown in the run again too, though the
// resolver would answer it now, so a finding on it that the fixes do not
// touch is the same, and the fixes are not refused.
func TestApplyFixesReplaysUnknown(t *testing.T) {
	cond, _ := FactEq(facts.TestFlag{Name: "x"}, true)
	onFlag := testRule{meta: asking(meta("on-flag"), facts.KindTestFlag), check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			c.Report(FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Condition: &cond})
		}
		return nil
	}}
	in, _ := Enumerate(fstest.MapFS{wfPath: {Data: []byte(twoSteps)}})
	reg, _ := newRegistry([]Rule{marker("mark", "m", SafetySafe), onFlag}, true)
	r := &flaky{}
	rep := Run(context.Background(), in, reg, r)
	if a, err := ApplyFixes(context.Background(), in, reg, r, rep, SafetySafe); err != nil || len(a.Files) != 1 {
		t.Errorf("files %d, err %v", len(a.Files), err)
	}
}
