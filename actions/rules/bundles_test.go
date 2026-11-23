package rules

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// sameInputAllowed are the bundles of examples of the same input and runs
// that TestExampleInputsDistinct lets be, each the rule and then its
// examples as <what>/<ID of the file>. It only shrinks
// (TestSameInputAllowedShrinks): a bundle is mended by making the
// declarations one, or the inputs differ. The one left: the two false
// positives' conditions (an organization that forbids forking, a
// repository of a personal account, whose readers all write) are no fact
// yet.
var sameInputAllowed = [][]string{
	{"self-hosted-runner", "false-positive/owner-policy", "false-positive/readers-write", "true-positive/private"},
}

// sameInputAllowedOn20261029 is sameInputAllowed when it was made. A line
// of sameInputAllowed must be a part of a line of it, so that the list
// does not grow. Changing it is the owner's decision (a rule of the
// repository), not a mend of a bundle.
var sameInputAllowedOn20261029 = [][]string{
	{"self-hosted-runner", "false-positive/owner-policy", "false-positive/readers-write", "true-positive/private"},
}

// notesLine is a line of comment, the notes of an example among them.
var notesLine = regexp.MustCompile(`(?m)^[ \t]*#.*\n?`)

// exampleBundles are the bundles of the examples of locs whose input (the
// files without their notes, the name of the main file left out, and the
// facts) and runs (the kinds answered the other way; runs gives them by
// keyOf) are the same, of two or more examples: each the rule, then its
// examples as <what>/<ID> in order. A location is one file or directory:
// a true negative of several kinds is one.
func exampleBundles(locs []ExampleLocation, runs map[exampleKey][]lint.ExampleRun) [][]string {
	by := map[string][]string{}
	var keys []string
	for _, x := range locs {
		e := x.Example
		k := []string{x.Rule.String(), e.InputKind.String(), notesLine.ReplaceAllString(e.Text, "")}
		for _, o := range e.Others {
			k = append(k, o.Name.String(), notesLine.ReplaceAllString(o.Text, ""))
		}
		f, err := facts.EncodeFile(e.Facts)
		if err != nil {
			panic(err)
		}
		k = append(k, string(f))
		for _, r := range runs[keyOf(x.Rule, x.What, e)] {
			k = append(k, fmt.Sprint(r.Flipped))
		}
		key := strings.Join(k, "\x00")
		if _, ok := by[key]; !ok {
			keys = append(keys, key)
		}
		by[key] = append(by[key], x.What.String()+"/"+x.ID)
	}
	var out [][]string
	for _, key := range keys {
		if m := by[key]; len(m) > 1 {
			slices.Sort(m)
			out = append(out, append([]string{strings.SplitN(key, "\x00", 2)[0]}, m...))
		}
	}
	return out
}

// checkBundles are the errors of bundles against allowed: a bundle not in
// allowed, and a line of allowed that no bundle is.
func checkBundles(bundles, allowed [][]string) []string {
	var errs []string
	for _, b := range bundles {
		if !slices.ContainsFunc(allowed, func(a []string) bool { return slices.Equal(a, b) }) {
			errs = append(errs, b[0]+": "+strings.Join(b[1:], ", ")+" have the same input and runs: make their declarations one, or make the inputs differ")
		}
	}
	for _, a := range allowed {
		if !slices.ContainsFunc(bundles, func(b []string) bool { return slices.Equal(a, b) }) {
			errs = append(errs, a[0]+": "+strings.Join(a[1:], ", ")+" is no bundle now: remove the line of sameInputAllowed")
		}
	}
	return errs
}

// grownLines are the lines of allowed that are not a part of a line of
// frozen, of the same rule: a line or a member added.
func grownLines(allowed, frozen [][]string) [][]string {
	var out [][]string
	for _, a := range allowed {
		part := func(f []string) bool {
			return len(a) > 0 && len(f) > 0 && a[0] == f[0] && !slices.ContainsFunc(a[1:], func(m string) bool { return !slices.Contains(f[1:], m) })
		}
		if !slices.ContainsFunc(frozen, part) {
			out = append(out, a)
		}
	}
	return out
}

func bundleLocation(what lint.ExampleWhat, id, name, text string, fs []facts.Entry, others ...lint.ExampleFile) ExampleLocation {
	return ExampleLocation{What: what, Rule: lint.MustRuleID("r"), ID: id, Example: lint.Example{InputKind: lint.InputKindWorkflow, Name: facts.MustCleanInputPath(name), Text: text, Others: others, Facts: fs}}
}

// TestExampleBundles: examples whose files without their notes, facts and
// runs are the same are one bundle, whatever the name of the main file,
// also two directories whose main files have the same name; another
// fact, another kind answered the other way, or another name of another
// file makes another input.
func TestExampleBundles(t *testing.T) {
	ud := lint.ExampleUndetected
	wf := "on: push\njobs: {}\n"
	caller := func(name string) lint.ExampleFile {
		return lint.ExampleFile{InputKind: lint.InputKindWorkflow, Name: facts.MustCleanInputPath(name), Text: wf}
	}
	answer := []facts.Entry{{Query: facts.RepoPublic{}, RawAnswer: facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}}}
	flipped := bundleLocation(ud, "d", "d.yml", "on: issues\n", nil)
	locs := []ExampleLocation{
		bundleLocation(ud, "a", "a.yml", "# situation: a\n"+wf, nil),
		bundleLocation(ud, "b", "b.yml", "# situation: b\n"+wf, nil),
		bundleLocation(ud, "c", "c.yml", wf, answer),
		flipped,
		bundleLocation(ud, "d2", "d2.yml", "on: issues\n", nil),
		bundleLocation(ud, "e", ".github/workflows/called.yml", "on: workflow_call\n", nil, caller(".github/workflows/one.yml")),
		bundleLocation(ud, "f", ".github/workflows/called.yml", "on: workflow_call\n", nil, caller(".github/workflows/one.yml")),
		bundleLocation(ud, "g", ".github/workflows/called.yml", "on: workflow_call\n", nil, caller(".github/workflows/two.yml")),
	}
	runs := map[exampleKey][]lint.ExampleRun{keyOf(flipped.Rule, ud, flipped.Example): {{Flipped: []facts.Kind{facts.KindRepoPublic}}}}
	got := exampleBundles(locs, runs)
	want := [][]string{{"r", "undetected/a", "undetected/b"}, {"r", "undetected/e", "undetected/f"}}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("bundles %v, want %v", got, want)
	}
}

// TestCheckBundles: a bundle not in allowed is an error, one in allowed is
// not, and a line of allowed that no bundle is is an error.
func TestCheckBundles(t *testing.T) {
	a, b := []string{"r", "undetected/a", "undetected/b"}, []string{"r", "false-positive/x", "true-positive/y"}
	if errs := checkBundles([][]string{a}, nil); len(errs) != 1 || !strings.Contains(errs[0], "r: undetected/a, undetected/b") {
		t.Errorf("a bundle not allowed: %q", errs)
	}
	if errs := checkBundles([][]string{a}, [][]string{a}); len(errs) != 0 {
		t.Errorf("an allowed bundle: %q", errs)
	}
	if errs := checkBundles(nil, [][]string{b}); len(errs) != 1 || !strings.Contains(errs[0], "r: false-positive/x, true-positive/y") {
		t.Errorf("a line of allowed that no bundle is: %q", errs)
	}
}

// TestGrownLines: a new line, or a member added to a line, is grown; a
// line with a member taken out is not.
func TestGrownLines(t *testing.T) {
	frozen := [][]string{{"r", "a", "b", "c"}}
	for _, c := range []struct {
		name    string
		allowed [][]string
		grown   int
	}{
		{"same", [][]string{{"r", "a", "b", "c"}}, 0},
		{"shrunk", [][]string{{"r", "a", "b"}}, 0},
		{"member added", [][]string{{"r", "a", "b", "c", "d"}}, 1},
		{"line added", [][]string{{"r", "a", "b", "c"}, {"s", "x", "y"}}, 1},
		{"another rule", [][]string{{"s", "a", "b"}}, 1},
	} {
		if got := grownLines(c.allowed, frozen); len(got) != c.grown {
			t.Errorf("%s: grown %v", c.name, got)
		}
	}
}

// TestSameInputAllowedShrinks: sameInputAllowed has no line that its
// first version had not.
func TestSameInputAllowedShrinks(t *testing.T) {
	for _, g := range grownLines(sameInputAllowed, sameInputAllowedOn20261029) {
		t.Errorf("sameInputAllowed grew by %v: mend the bundle instead (adding a line is the owner's decision)", g)
	}
}

// TestExampleInputsDistinct: in a rule, no two examples have the same
// input and runs but the bundles of sameInputAllowed.
func TestExampleInputsDistinct(t *testing.T) {
	runs := map[exampleKey][]lint.ExampleRun{}
	for _, c := range sharedChecks(t).Of() {
		runs[keyOf(c.Rule, c.What, c.Example)] = c.Runs
	}
	for _, e := range checkBundles(exampleBundles(Examples(), runs), sameInputAllowed) {
		t.Error(e)
	}
}
