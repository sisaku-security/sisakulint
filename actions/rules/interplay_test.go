package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/internal/corpus"
)

// interplayInput is an input of the matrix of fixes, and the resolver its
// runs answer from.
type interplayInput struct {
	name string
	dir  string
	r    func() facts.Resolver
}

func storeResolver(t *testing.T, path string) func() facts.Resolver {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := facts.LoadStore(b)
	if err != nil {
		t.Fatal(err)
	}
	return func() facts.Resolver { return store }
}

// interplayInputs are the example of every rule, the cases of
// testdata/interplay, and, with ACTIONS_CORPUS=full and a corpus, every
// repository of yaml/corpus/files/real-world, files/sisakuintel and
// files/labeler-token with the answers of TestCorpus. The cases of
// testdata/interplay hold the interactions known; the repositories of the
// corpus look for ones not known, and had found none by 2026-11, so the
// default run leaves them to the full run.
func interplayInputs(t *testing.T) []interplayInput {
	t.Helper()
	ins := []interplayInput{{"all-rules", exampleDir, storeResolver(t, filepath.Join(exampleDir, "facts.json"))}}
	cases, err := os.ReadDir(filepath.Join("testdata", "interplay"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		dir := filepath.Join("testdata", "interplay", c.Name())
		ins = append(ins, interplayInput{"interplay/" + c.Name(), dir, storeResolver(t, filepath.Join(dir, "facts.json"))})
	}
	if !corpus.Full() {
		return ins
	}
	root, present, err := corpus.Locate()
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Log("no corpus: the matrix runs on the example and testdata/interplay only")
		return ins
	}
	for _, group := range []string{"real-world", "sisakuintel", "labeler-token"} {
		dir := filepath.Join(root, "files", group)
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if e.IsDir() {
				ins = append(ins, interplayInput{group + "/" + e.Name(), filepath.Join(dir, e.Name()), func() facts.Resolver { return anyRef{commits: true} }})
			}
		}
	}
	return ins
}

// TestFixInterplay is the matrix of fixes on the
// inputs of interplayInputs (checkInterplay). The inputs run in parallel,
// a subtest each.
func TestFixInterplay(t *testing.T) {
	all, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	inputs := interplayInputs(t)
	type result struct{ applied, changed int } // of checkInterplay
	results := make([]result, len(inputs))
	t.Run("inputs", func(t *testing.T) {
		for i, input := range inputs {
			t.Run(input.name, func(t *testing.T) {
				t.Parallel()
				in, err := lint.Enumerate(os.DirFS(input.dir))
				if err != nil {
					t.Fatal(err)
				}
				a, c, fixedAny := checkInterplay(t, input.name, in, all, input.r, func(out map[facts.InputPath][]byte) lint.Inputs { return fixedInputs(t, input.dir, out) })
				results[i] = result{a, c}
				// a case of testdata/interplay is there for its fixes: one that
				// fixes nothing (a workflow out of .github/workflows) shows nothing
				if strings.HasPrefix(input.name, "interplay/") && !fixedAny {
					t.Errorf("%s: no fix of any rule changed a file", input.name)
				}
			})
		}
	})
	applied, changed := 0, 0 // the inputs and rules whose fixes changed a file, and the findings of other rules that changed, for the log
	for _, r := range results {
		applied, changed = applied+r.applied, changed+r.changed
	}
	t.Logf("fixes applied on %d inputs and rules; %d findings of other rules raised or changed", applied, changed)
}

// checkInterplay checks the fixes of each rule on in, whose runs answer
// from r: the fixes of a rule R that fixes, alone and to review, are
// applied with every other rule skipped, and every rule runs on what they
// give (refix makes the inputs of the fixed bytes). A rule Q other than R
// with a finding there that every rule did not give before, or with one
// there before whose certainty or condition changed, must be one
// ApplyFixes says is unchecked: a field it reads changed. R's own new
// finding is ApplyFixes's to refuse, so a fix that does not apply alone
// fails here too. It gives the rules whose fixes changed a file, the
// findings of other rules that changed, and whether any fix changed a
// file (true when every rule failed before the fixes: that is reported,
// and not again as fixing nothing).
func checkInterplay(t *testing.T, name string, in lint.Inputs, all *lint.Registry, r func() facts.Resolver, refix func(map[facts.InputPath][]byte) lint.Inputs) (applied, changed int, fixedAny bool) {
	t.Helper()
	ctx := context.Background()
	// a finding is new unless one of the same fingerprint and kind was
	// there: the fingerprint has no kind, and a fix may change the kind of
	// a finding at the same place
	type found struct {
		fp   lint.Fingerprint
		kind lint.FindingKindID
	}
	was := lint.Run(ctx, in, all, r())
	if len(was.Errors) > 0 {
		t.Errorf("%s: every rule, before the fixes: %s", name, was.Errors[0].Message)
		return 0, 0, true
	}
	before := map[found]lint.Finding{}
	for _, f := range was.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		before[found{f.Fingerprint, f.Args.KindID()}] = f
	}
	for _, rule := range all.Rules() {
		m := rule.Meta()
		if len(m.FixKinds) == 0 {
			continue
		}
		s, err := lint.ParseSelector(m.ID.String())
		if err != nil {
			t.Fatal(err)
		}
		one, err := all.Select(lint.Only(s), lint.FactSources{})
		if err != nil {
			t.Fatal(err)
		}
		res := r()
		rep := lint.Run(ctx, in, one, res)
		a, err := lint.ApplyFixes(ctx, in, one, res, rep, lint.SafetyReview)
		if err != nil {
			t.Errorf("%s, %s alone: %v", name, m.ID, err)
			continue
		}
		if len(a.Files) == 0 {
			continue
		}
		fixedAny = true
		applied++
		said := map[lint.RuleID]bool{}
		for _, u := range a.Unchecked {
			said[u.Rule] = true
		}
		after := lint.Run(ctx, refix(a.Files), all, facts.First(replayed(t, rep), r()))
		// a rule that fails on the fixed files reports nothing there, so
		// what it would raise is not seen: that is a failure too
		if len(after.Errors) > 0 {
			t.Errorf("%s: every rule, after the fixes of %s: %s", name, m.ID, after.Errors[0].Message)
			continue
		}
		for _, f := range after.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Rule == m.ID {
				continue
			}
			old, there := before[found{f.Fingerprint, f.Args.KindID()}]
			if there && old.Certainty == f.Certainty && sameCondJSON(t, old.Condition, f.Condition) {
				continue
			}
			changed++
			if !said[f.Rule] {
				t.Errorf("%s: the fixes of %s raise or change %s at %s:%d, and no field %s reads changed", name, m.ID, f.Args.KindID(), f.Location.File.Input, f.Location.Span.Start, f.Rule)
			}
		}
	}
	return applied, changed, fixedAny
}

// sameCondJSON is whether a and b are the same condition in JSON, or both
// none.
func sameCondJSON(t *testing.T, a, b *lint.Condition) bool {
	t.Helper()
	if a == nil || b == nil {
		return a == b
	}
	x, err := a.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(x) == string(y)
}

// fixedInputs are the inputs of dir with the bytes of out in place of
// theirs, read again from a copy.
func fixedInputs(t *testing.T, dir string, out map[facts.InputPath][]byte) lint.Inputs {
	t.Helper()
	cp := t.TempDir()
	if err := os.CopyFS(cp, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	for n, b := range out {
		if err := os.WriteFile(filepath.Join(cp, n.String()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	in, err := lint.Enumerate(os.DirFS(cp))
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// replayed answers from the facts of rep, as ApplyFixes does its run again.
func replayed(t *testing.T, rep lint.Report) facts.Resolver {
	t.Helper()
	b, err := facts.EncodeFile(rep.Facts)
	if err != nil {
		t.Fatal(err)
	}
	s, err := facts.LoadStore(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
