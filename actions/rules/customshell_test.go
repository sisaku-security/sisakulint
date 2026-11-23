package rules

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// customShells are, for each shell: line of the examples, the custom shells
// of the same shell: the rules read their runs as they read the
// runs of the built-in shell, whatever their options in the list of
// taint.ShellInvocationOf.
var customShells = []struct {
	builtin string
	line    *regexp.Regexp
	custom  []string
}{
	{"bash", regexp.MustCompile(`(?m)^(\s*(?:- )?shell:\s*)bash[ \t]*$`), []string{"bash --noprofile --norc -eo pipefail {0}", "bash -e {0}"}},
	{"sh", regexp.MustCompile(`(?m)^(\s*(?:- )?shell:\s*)sh[ \t]*$`), []string{"sh -e {0}"}},
}

// TestCustomShellSameAsBash rewrites the shell: bash (shell: sh) of every
// example to the custom shells of the same shell, and checks that every
// rule and quality rule reports the same findings, inconclusive places and
// fixes: the reading of a run does not depend on options such as -e,
// pipefail or nounset.
func TestCustomShellSameAsBash(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	files := make([]int, len(customShells)) // the example files of each shell: line
	for _, m := range allMetas() {
		for _, e := range metaExamples(m) {
			key := e.Name.String() + "\x00" + e.Text
			if seen[key] {
				continue
			}
			seen[key] = true
			for i, s := range customShells {
				n := 0
				for _, f := range append([]string{e.Text}, othersText(e)...) {
					if s.line.MatchString(f) {
						n++
					}
				}
				if n == 0 {
					continue
				}
				files[i] += n
				want := shellRunSummary(t, reg, e, nil)
				for _, c := range s.custom {
					t.Run(e.Name.String()+"/"+c, func(t *testing.T) {
						re := rewriteShell(e, s.line, c)
						if got := shellRunSummary(t, reg, re, func(b string) string { return strings.ReplaceAll(b, "shell: "+c, "shell: "+s.builtin) }); !slices.Equal(got, want) {
							t.Errorf("with shell: %s\ngot  %q\nwant %q", c, got, want)
						}
					})
				}
			}
		}
	}
	// every file under examples with the line is a file of an example read
	// above, so that no example is left out
	for i, s := range customShells {
		n := 0
		err := filepath.WalkDir("examples", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml") {
				return err
			}
			b, err := os.ReadFile(path)
			if err == nil && s.line.Match(b) {
				n++
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 || files[i] != n {
			t.Errorf("the examples with shell: %s are %d files under examples and %d files of the examples read, want the same and more than 0", s.builtin, n, files[i])
		}
	}
}

// metaExamples are all the examples of m.
func metaExamples(m lint.Meta) []lint.Example {
	var out []lint.Example
	for _, k := range m.FindingKinds {
		out = append(append(out, k.TruePositives...), k.TrueNegatives...)
	}
	for _, u := range m.UndetectedForms {
		out = append(out, u.Examples...)
	}
	for _, k := range m.InconclusiveKinds {
		out = append(out, k.Examples...)
	}
	for _, f := range m.FalsePositiveForms {
		out = append(out, f.Examples...)
	}
	return out
}

func othersText(e lint.Example) []string {
	var out []string
	for _, o := range e.Others {
		out = append(out, o.Text)
	}
	return out
}

// rewriteShell is e with each line of every file that line matches put as
// shell: custom.
func rewriteShell(e lint.Example, line *regexp.Regexp, custom string) lint.Example {
	repl := "${1}" + custom
	e.Text = line.ReplaceAllString(e.Text, repl)
	e.Others = slices.Clone(e.Others)
	for i := range e.Others {
		e.Others[i].Text = line.ReplaceAllString(e.Others[i].Text, repl)
	}
	return e
}

// shellRunSummary are the findings, quality findings and inconclusive
// places of e (rule, kind, file, line, the kind of the fix) and the files
// of e with all the fixes applied, each put back by restore (nil: as it
// is), sorted.
func shellRunSummary(t *testing.T, reg *lint.Registry, e lint.Example, restore func(string) string) []string {
	t.Helper()
	if restore == nil {
		restore = func(b string) string { return b }
	}
	in, err := e.Inputs()
	if err != nil {
		t.Fatal(err)
	}
	text := map[facts.InputPath]string{e.Name: e.Text}
	for _, o := range e.Others {
		text[o.Name] = o.Text
	}
	line := func(l lint.Location) string {
		return fmt.Sprintf("%s:%d", l.File.Input, strings.Count(text[l.File.Input][:min(l.Span.Start, len(text[l.File.Input]))], "\n")+1)
	}
	r := exampleStore(t, e)
	rep := lint.Run(context.Background(), in, reg, r)
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		fix := ""
		if f.Fix != nil {
			fix = f.Fix.KindID.String()
		}
		out = append(out, fmt.Sprintf("finding %s %s %s %s", f.Rule, f.Args.KindID(), line(f.Location), fix))
	}
	for _, f := range rep.QualityFindings {
		out = append(out, fmt.Sprintf("quality %s %s %s", f.Rule, f.Args.KindID(), line(f.Location)))
	}
	for _, p := range rep.FindingsWith(lint.CertaintyInconclusive) {
		out = append(out, fmt.Sprintf("inconclusive %s %s %s", p.Rule, p.InconclusiveKind, line(p.Location)))
	}
	applied, err := lint.ApplyFixes(context.Background(), in, reg, r, rep, lint.SafetyReview)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range applied.Files {
		out = append(out, fmt.Sprintf("fixed %s\n%s", name, restore(string(b))))
	}
	slices.Sort(out)
	return out
}
