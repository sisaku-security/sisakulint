package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestAdvisoryExampleResults: what the rule of each example of an advisory
// (# advisory:) reports on the example, run as CheckExamples runs it (the
// rule alone, with the facts of the example): each finding and each
// inconclusive place of the rule, with its kind, its file and its line.
// The check of a declaration holds only what the declaration says (a
// finding of the kind, none of the form's kinds, a place of the kind); the
// examples of an advisory keep the rest of what the Go tests of the
// advisories held (how many findings, where, and no inconclusive place)
// here. go test -update writes testdata/advisory-examples.golden. It reads
// the shared checks of every rule and quality rule (sharedChecks) of the
// rules of All: they are those of a registry of All alone but for the
// skipped rules of each run, which it does not read.
func TestAdvisoryExampleResults(t *testing.T) {
	var b strings.Builder
	n := 0
	for _, c := range sharedChecks(t).Of(securityRuleIDs()...) {
		e := c.Example
		if len(e.Notes.Advisories) == 0 {
			continue
		}
		n++
		var keys []string
		for _, p := range e.Notes.Advisories {
			keys = append(keys, p.ID().String())
		}
		fmt.Fprintf(&b, "%s %s %s %s (%s)\n", c.Rule, c.What, c.Declaration, exampleLabel(e), strings.Join(keys, ", "))
		if len(c.Runs) == 0 {
			fmt.Fprintf(&b, "\tnot run: %s\n", c.Why)
			continue
		}
		run := c.Runs[len(c.Runs)-1]
		for _, f := range run.Report.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			fmt.Fprintf(&b, "\tfinding %s %s\n", f.Args.KindID(), placeOf(t, run.Inputs, f.Location))
		}
		for _, g := range run.Report.FindingsWith(lint.CertaintyInconclusive) {
			fmt.Fprintf(&b, "\tinconclusive %s %s\n", g.InconclusiveKind, placeOf(t, run.Inputs, g.Location))
		}
	}
	if n == 0 {
		t.Fatal("no example of an advisory")
	}
	golden := filepath.Join("testdata", "advisory-examples.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if b.String() != string(want) {
		t.Errorf("what the rules report on the examples of the advisories differs from %s (go test -update):\n%s", golden, b.String())
	}
}

// exampleLabel is the name of e's main file, and the advisories' first key
// for an example of several files, whose main files have the same names.
func exampleLabel(e lint.Example) string {
	if len(e.Others) == 0 {
		return e.Name.String()
	}
	return e.Name.String() + " of " + e.Notes.Advisories[0].ID().String()
}

// placeOf is the file of l and its line, 1 the first.
func placeOf(t *testing.T, in lint.Inputs, l lint.Location) string {
	t.Helper()
	i, _ := in.Lookup(l.File.Input)
	if i.Tree == nil {
		return l.File.Input.String()
	}
	return fmt.Sprintf("%s:%d", l.File.Input, strings.Count(string(i.Tree.Bytes()[:l.Span.Start]), "\n")+1)
}
