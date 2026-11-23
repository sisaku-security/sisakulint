package rules

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/attackrun"
	"github.com/gh-intel/sisakulint/actions/internal/jsonschema"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestExampleFixes applies the fixes of every true positive example, with
// the example's facts, and checks what TestCorpus and TestFixInterplay
// check of the corpus: a report without errors that fits its schema; the
// fixes of every rule, to review, applied at once, and the run scripts of
// bash they change still bash (checkFixedSyntax); the fixes of each rule
// alone, which change no finding of another rule unless ApplyFixes says it
// is unchecked (checkInterplay). An example of a rule of AttackMarkers
// whose findings of the rule all have a fix is run, fixed, with its attack
// value: the harm must not show, and no step may fail. The examples of a
// rule that fixes with an attack value but a finding without a fix
// (unattacked) are not run, as the harm stays where there is no fix. A
// kind that fixes must give a fix on each of its true positives, so that
// the test does not pass on none. The examples run in parallel, a subtest
// each (checkExampleFix).
func TestExampleFixes(t *testing.T) {
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	s := schemaSet(t)
	start := time.Now()
	var cases []exampleFixCase
	for _, rule := range All() {
		m := exampledMeta(rule)
		for _, k := range m.FindingKinds {
			for _, e := range k.TruePositives {
				name := k.ID.String() + " " + e.Name.String()
				if c := citedKey(e); c != "" { // two examples of several files have the same name
					name += " (" + c + ")"
				}
				cases = append(cases, exampleFixCase{m, k, e, name})
			}
		}
	}
	results := make([]exampleFixResult, len(cases))
	t.Run("examples", func(t *testing.T) {
		for i, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				results[i] = checkExampleFix(t, reg, s, c)
			})
		}
	})
	fixed, syntax, applied, changed, attacked := 0, 0, 0, 0, 0
	var skipped []string // the examples of unattacked's form that are not run
	var unfixed []string // the examples of unfixedCited's form
	var unrun []string   // the examples of unrunCited's form
	for i, r := range results {
		syntax, applied, changed = syntax+r.syntax, applied+r.applied, changed+r.changed
		if r.fixed {
			fixed++
		}
		if r.attacked {
			attacked++
		}
		if r.skipped {
			skipped = append(skipped, cases[i].name)
		}
		if r.unfixed {
			unfixed = append(unfixed, cases[i].name)
		}
		if r.unrun != attackrun.UnrunNone {
			unrun = append(unrun, cases[i].name+": "+r.unrun.String())
		}
	}
	if !slices.Equal(skipped, unattacked) {
		t.Errorf("the examples with an attack value and a finding without a fix are %q, want %q", skipped, unattacked)
	}
	if !slices.Equal(unfixed, unfixedCited) {
		t.Errorf("the cited examples with no finding that has a fix are %q, want %q", unfixed, unfixedCited)
	}
	if !slices.Equal(unrun, unrunCited) {
		t.Errorf("the cited examples whose fixed form the attack value does not run are %q, want %q", unrun, unrunCited)
	}
	t.Logf("%d examples (%d fixed, %d run scripts checked with bash -n); fixes of a rule applied on %d examples and rules, %d findings of other rules raised or changed; %d fixed examples run with their attack values, in %v",
		len(cases), fixed, syntax, applied, changed, attacked, time.Since(start))
}

// exampleFixCase is a true positive example of the kind k of the rule of
// m, named as TestExampleFixes names it.
type exampleFixCase struct {
	m    lint.Meta
	k    lint.FindingKind
	e    lint.Example
	name string
}

// exampleFixResult is what checkExampleFix found on one example, which
// TestExampleFixes gathers in the order of the examples: whether the fixes
// of every rule changed a file, the scripts checkFixedSyntax checked, what
// checkInterplay applied and changed, whether the fixed example ran with
// its attack value, and whether the example is one of unattacked,
// unfixedCited and unrunCited (unrun is why the attack value does not run
// its fixed form, attackrun.UnrunNone when it runs or is not tried).
type exampleFixResult struct {
	fixed                    bool
	syntax, applied, changed int
	attacked                 bool
	skipped, unfixed         bool
	unrun                    attackrun.UnrunReason
}

// checkExampleFix checks the fixes of the example of c (TestExampleFixes),
// on a subtest of its own.
func checkExampleFix(t *testing.T, reg *lint.Registry, s *jsonschema.Set, c exampleFixCase) exampleFixResult {
	ctx := context.Background()
	m, k, e, name := c.m, c.k, c.e, c.name
	var res exampleFixResult
	in, err := e.Inputs()
	if err != nil {
		t.Fatal(err)
	}
	r := func() facts.Resolver { return exampleStore(t, e) }
	rep := lint.Run(ctx, in, reg, r())
	if len(rep.Errors) > 0 {
		t.Errorf("%s: %s %s: %s", name, rep.Errors[0].Rule, rep.Errors[0].Input, rep.Errors[0].Message)
		return res
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate("report-v0.json", "#", b); err != nil {
		t.Errorf("%s: the report does not fit report-v0.json: %v", name, err)
	}
	// the findings of a reusable workflow of another repository have
	// no fix (remoteCalleeExamples): the file is not the input
	remote := strings.HasSuffix(e.Name.String(), "."+remoteCalleeLabel+".yml")
	if len(k.Fixes) > 0 && !remote && !slices.ContainsFunc(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), func(f lint.Finding) bool { return f.Args.KindID() == k.ID && f.Fix != nil }) {
		if citedKey(e) == "" {
			t.Errorf("%s: no finding of %s has a fix, so none is checked", name, k.ID)
		} else {
			res.unfixed = true
		}
	}
	n, all := checkFixedSyntax(t, name, in, reg, r(), rep)
	res.syntax = n
	res.fixed = len(all.Files) > 0
	res.applied, res.changed, _ = checkInterplay(t, name, in, reg, r, func(out map[facts.InputPath][]byte) lint.Inputs {
		in, err := fixedExample(t, e, out).Inputs()
		if err != nil {
			t.Fatal(err)
		}
		return in
	})
	marker := AttackMarkers[m.ID]
	if remote || marker == attackrun.MarkerNone || e.Notes.AttackValue.IsZero() || len(m.FixKinds) == 0 || len(k.Fixes) == 0 {
		return res // a kind that declares no fix gives its findings none
	}
	if !allFixed(rep, m.ID) {
		res.skipped = true
		return res
	}
	p, err := attackrun.Prepare(fixedExample(t, e, all.Files))
	if err != nil {
		t.Errorf("%s, fixed: %v", name, err)
		return res
	}
	if p.Unrun != attackrun.UnrunNone {
		if citedKey(e) == "" {
			t.Errorf("%s, fixed: not run: %s", name, p.Unrun)
		} else {
			res.unrun = p.Unrun
		}
		return res
	}
	seen, err := attackrun.Run(ctx, p)
	if err != nil {
		t.Errorf("%s, fixed: %v", name, err)
		return res
	}
	res.attacked = true
	if seen.Shows(marker) {
		t.Errorf("%s: the harm shows after the fixes; stdout %q, env %q, output %q, path %q", name, seen.Stdout, seen.Env, seen.Output, seen.Path)
	}
	// a step that fails may end before the harm, so it does not
	// show that the fixes took it away (attackResult)
	if slices.ContainsFunc(seen.Exits, func(c int) bool { return c != 0 }) {
		t.Errorf("%s, fixed: a step failed (exits %v, stubbed %v), so it does not show that the harm is gone; stdout %q", name, seen.Exits, seen.Stubbed, seen.Stdout)
	}
	return res
}

// unattacked are the true positive examples of a rule that fixes, with an
// attack value, that have a finding of the rule without a fix: the harm
// stays there after the fixes. TestExampleFixes does not run them, and
// fails when the list changes, so that one does not stop being run unseen.
var unattacked = []string{
	"code-injection.controlled called/action.yml (GHSA-9p44-j4g5-cfx5)",                         // the step Run SonarScanner: the input is the words of an array, with no quotes
	"code-injection.controlled controlled.ghsa-c3xh-98xp-6qhf.yml (GHSA-c3xh-98xp-6qhf)",        // the jobs release and zenclaw: the title is a word with no quotes inside $( ), and an assignment inside a case
	"code-injection.controlled controlled.ghsa-r4fj-r33x-8v88.yml (GHSA-r4fj-r33x-8v88)",        // the job wenxian: the body is inside $( ), whose output goes to $GITHUB_OUTPUT
	"code-injection.controlled controlled.ghsa-vxmw-7h4f-hqxh.action.yml (GHSA-vxmw-7h4f-hqxh)", // the name of the branch is in an expression with ||
	"code-injection.controlled .github/workflows/called.yml (GHSL-2024-277_Appsmith)",
	"code-injection.controlled controlled.ghsl-2024-319.yml (GHSL-2024-319_Trino_DB)", // the head branch is in single quotes
	"code-injection.controlled .github/workflows/called.yml (GHSL-2024-320_GHSL-2024-321_Eclipse)",
	"code-injection.controlled controlled.ghsl-2025-090.yml (GHSL-2025-090_harvester_harvester)",           // the title is in a here-document inside $( )
	"code-injection.controlled controlled.ghsl-2025-099.yml (GHSL-2025-099_cross-platform-actions_action)", // the name of the branch is in single quotes
	"code-injection.controlled controlled.ghsl-2025-103.yml (GHSL-2025-102_GHSL-2025-103_acl-anthology)",   // the body is in a here-document whose delimiter is quoted
	"code-injection.controlled controlled.ghsl-2025-104.yml (GHSL-2025-104_weaviate)",                      // the title is in single quotes, in the JSON of curl
	"code-injection.controlled called/action.yml (GHSA-65rg-554r-9j5x)",                                    // controlled.lychee-action
}

// citedKey is the key of the case an example cites: the key of its first
// advisory (# advisory:), else the key of its first source (# source:);
// "" for an example made for a declaration, which cites none.
func citedKey(e lint.Example) string {
	switch {
	case len(e.Notes.Advisories) != 0:
		return e.Notes.Advisories[0].ID().String()
	case len(e.Notes.Sources) != 0:
		return e.Notes.Sources[0].Key()
	}
	return ""
}

// unfixedCited are the true positive examples that cite a case (an
// advisory, # advisory:, or a file of a repository, # source:) of a kind
// with fixes, none of whose findings of the kind has a fix: the fixes of
// the rule do not reach the form of the case. An example made for a kind
// has a fixed finding; an example of a case keeps the form of the case.
// TestExampleFixes fails when the list changes.
var unfixedCited = []string{
	"artifact-poisoning.executed executed.ghsl-2024-125.yml (GHSL-2024-124_GHSL-2024-125_quarkus)",                  // the download has a path, which the fix does not move
	"artifact-poisoning.download download.snap-install.yml (nvidia/openshell:.github/workflows/release-canary.yml)", // the download has a path, which the fix does not move
	"code-injection.controlled .github/workflows/called.yml (GHSL-2024-277_Appsmith)",
	"code-injection.controlled controlled.ghsl-2024-319.yml (GHSL-2024-319_Trino_DB)", // the head branch is in single quotes
	"code-injection.controlled .github/workflows/called.yml (GHSL-2024-320_GHSL-2024-321_Eclipse)",
	"code-injection.controlled controlled.ghsl-2025-090.yml (GHSL-2025-090_harvester_harvester)",           // the title is in a here-document inside $( )
	"code-injection.controlled controlled.ghsl-2025-099.yml (GHSL-2025-099_cross-platform-actions_action)", // the name of the branch is in single quotes
	"code-injection.controlled controlled.ghsl-2025-103.yml (GHSL-2025-102_GHSL-2025-103_acl-anthology)",   // the body is in a here-document whose delimiter is quoted
	"code-injection.controlled controlled.ghsl-2025-104.yml (GHSL-2025-104_weaviate)",                      // the title is in single quotes, in the JSON of curl
}

// unrunCited are the true positive examples that cite a case (citedKey)
// whose findings the fixes fix, but whose fixed form the attack value does
// not run (attackrun.Prepare): the form of the case puts the value where
// the run of the attack does not follow it. TestExampleFixes fails when
// the list changes.
var unrunCited = []string{
	"code-injection.controlled controlled.ghsa-6q4m-7476-932w.action.yml (GHSA-6q4m-7476-932w): carrier-wrapped",                         // the head ref is inside ||
	"code-injection.controlled controlled.ghsa-8v8w-v8xg-79rf.action.yml (GHSA-8v8w-v8xg-79rf): carrier-wrapped",                         // the name of the branch is inside ||
	"code-injection.controlled .github/workflows/called.yml (GHSL-2024-031_GHSL-2024-032_Fabric_js): carrier-not-in-run",                 // the title goes through env into the script of actions/github-script
	"code-injection.controlled controlled.ghsl-2024-126.yml (GHSL-2024-126_Kong): carrier-not-in-run",                                    // the branch is in the script of actions/github-script
	"code-injection.controlled controlled.ghsl-2024-267.yml (GHSL-2024-266_GHSL-2024-267_Adobe_React_Spectrum_Charts): other-expression", // env.PR_BASE and the clone URL stay as expressions in the fixed script
	"code-injection.controlled controlled.ghsl-2024-275.yml (GHSL-2024-274_GHSL-2024-275_Cilium): carrier-wrapped",                       // the head ref is inside ||
}

// exampleStore answers what e's facts say, as the example catalog does.
func exampleStore(t *testing.T, e lint.Example) facts.Resolver {
	t.Helper()
	b, err := facts.EncodeFile(e.Facts)
	if err != nil {
		t.Fatal(err)
	}
	s, err := facts.LoadStore(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fixedExample is e with the files of out in place of its own.
func fixedExample(t *testing.T, e lint.Example, out map[facts.InputPath][]byte) lint.Example {
	t.Helper()
	e.Others = slices.Clone(e.Others)
	for name, b := range out {
		if name == e.Name {
			e.Text = string(b)
			continue
		}
		i := slices.IndexFunc(e.Others, func(o lint.ExampleFile) bool { return o.Name == name })
		if i < 0 {
			t.Fatalf("%s: the fixes changed %s, which is not a file of it", e.Name, name)
		}
		e.Others[i].Text = string(b)
	}
	return e
}

// allFixed is whether rep has a finding of the rule id, and each has a fix.
func allFixed(rep lint.Report, id lint.RuleID) bool {
	n := 0
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Rule == id {
			if f.Fix == nil {
				return false
			}
			n++
		}
	}
	return n > 0
}
