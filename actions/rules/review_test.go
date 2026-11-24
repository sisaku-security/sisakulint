package rules

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/attackrun"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// reviewExample is an example of the rule a-rule made up for the tests,
// its notes read from text.
func reviewExample(t *testing.T, what lint.ExampleWhat, id, text string, others ...lint.ExampleFile) ExampleLocation {
	t.Helper()
	n, err := lint.ParseExampleNotes(text)
	if err != nil {
		t.Fatal(err)
	}
	e := lint.Example{InputKind: lint.InputKindWorkflow, Name: facts.MustCleanInputPath(id + ".yml"), Text: text, Others: others, Notes: n}
	return ExampleLocation{What: what, Rule: lint.MustRuleID("a-rule"), ID: id, Path: "actions/rules/examples/" + what.String() + "/a-rule/" + id + ".yml", Declaration: "the form *x*", Example: e}
}

// TestExampleDocument: the heading, the path, the declaration and every
// file of the example, in that order; no facts.
func TestExampleDocument(t *testing.T) {
	caller := lint.ExampleFile{InputKind: lint.InputKindWorkflow, Name: facts.MustCleanInputPath(".github/workflows/caller.yml"), Text: "on: pull_request_target\n"}
	x := reviewExample(t, lint.ExampleFalsePositive, "x", "# situation: s\n# reason: r\n# cause: c\non: push\n", caller)
	x.Example.Facts = []facts.Entry{{}}
	want := "## false-positive a-rule / x\n\n" +
		"`actions/rules/examples/false-positive/a-rule/x.yml`\n\n" +
		"> the form \\*x\\*\n\n" +
		"`x.yml`\n\n" +
		"```yaml\n# situation: s\n# reason: r\n# cause: c\non: push\n```\n\n" +
		"`.github/workflows/caller.yml`\n\n" +
		"```yaml\non: pull_request_target\n```\n"
	if got := exampleDocument(x, attackrun.MarkerNone, nil); got != want {
		t.Errorf("exampleDocument =\n%s\nwant\n%s", got, want)
	}
}

// TestExampleDocumentAttack: each substitution of the attack value as a
// block of text after the files, then whether a test runs it.
func TestExampleDocumentAttack(t *testing.T) {
	x := reviewExample(t, lint.ExampleTruePositive, "said", "# situation: s\n# reason: r\n"+
		"# attack-value: github.event.issue.title = \"$(echo PWNED)\"\n# attack-run-behavior: b\n"+
		"on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n")
	subs := attackrun.Substitute(x.Example)
	if len(subs) == 0 {
		t.Fatal("the example has no substitution")
	}
	got := exampleDocument(x, attackrun.MarkerStdout, nil)
	for _, s := range subs {
		want := "\n\nAfter substitution, `" + s.File.String() + "` `" + s.Where + "`:\n\n" + lint.MarkdownCodeBlock("text", s.Text)
		if !strings.Contains(got, want) {
			t.Errorf("no\n%s\nin\n%s", want, got)
		}
	}
	c := attackrun.Check(x.Example, attackrun.MarkerStdout)
	if c == "" || !strings.HasSuffix(got, "\n\n("+c+")\n") {
		t.Errorf("the document does not end with (%s):\n%s", c, got)
	}
}

// TestExampleDocumentFence: a text with a run of three backquotes, a CR LF
// and no line break at its end is a code block that closes, the same each
// time.
func TestExampleDocumentFence(t *testing.T) {
	x := reviewExample(t, lint.ExampleUndetected, "f", "# situation: s\r\n# reason: r\r\n# cause: c\r\non: push\r\n# ```")
	got := exampleDocument(x, attackrun.MarkerNone, nil)
	if !strings.Contains(got, "\n````yaml\n") || !strings.HasSuffix(got, "# ```\n````\n") {
		t.Errorf("the code block does not close:\n%q", got)
	}
	if again := exampleDocument(x, attackrun.MarkerNone, nil); again != got {
		t.Error("two documents of the same example differ")
	}
}

// TestReviewDocumentPaths: every rule has one meta.md and a document of
// each of its examples at <what>/<id>.md, none twice; no quality rule has
// any.
func TestReviewDocumentPaths(t *testing.T) {
	docs, err := ReviewDocuments(sharedChecks(t))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	metas := map[lint.RuleID]int{}
	n := 0
	for _, d := range docs {
		key := d.Rule.String() + "/" + d.Path.String()
		if seen[key] {
			t.Errorf("%s twice", key)
		}
		seen[key] = true
		switch {
		case d.Path == metaDocument:
			metas[d.Rule]++
			if d.Example != nil {
				t.Errorf("%s has an example", key)
			}
		case d.Example == nil:
			t.Errorf("%s has no example", key)
		default:
			n++
			if want := d.Example.What.String() + "/" + d.Example.ID + ".md"; d.Path.String() != want {
				t.Errorf("%s: path %s, want %s", key, d.Path, want)
			}
		}
	}
	for _, r := range All() {
		if metas[r.Meta().ID] != 1 {
			t.Errorf("%s has %d meta.md", r.Meta().ID, metas[r.Meta().ID])
		}
	}
	for _, q := range Quality() {
		if metas[q.QualityMeta().ID] != 1 {
			t.Errorf("the quality rule %s has %d meta.md", q.QualityMeta().ID, metas[q.QualityMeta().ID])
		}
	}
	if !seen["missing-timeout-minutes/true-positive/job.md"] {
		t.Error("no document of the example job of the quality rule missing-timeout-minutes")
	}
	if want := len(Examples()); n != want {
		t.Errorf("%d documents of examples, want %d", n, want)
	}
	if !seen["ai-action-excessive-tools/true-negative/auto-mode.scrub.md"] {
		t.Error("no document of the example auto-mode.scrub, whose ID has a dot")
	}
}

// reviewDocs are the documents of the rule a-rule for the tests of
// reviewOf: its meta.md and two examples.
func reviewDocs(t *testing.T) []ReviewDocument {
	x := reviewExample(t, lint.ExampleFalsePositive, "x", "# situation: s\n# reason: r\n# cause: c\non: push\n")
	y := reviewExample(t, lint.ExampleTruePositive, "said", "# situation: s\n# reason: r\non: issues\n")
	return []ReviewDocument{
		{Rule: x.Rule, Path: metaDocument, Text: "## a-rule\n"},
		{Rule: x.Rule, Path: MustReviewPath("false-positive/x.md"), Text: "x\n", Example: &x},
		{Rule: y.Rule, Path: MustReviewPath("true-positive/said.md"), Text: "said\n", Example: &y},
	}
}

// approvedOf is the documents ds as approved documents, by their rules'
// directories.
func approvedOf(ds []ReviewDocument) fstest.MapFS {
	fsys := fstest.MapFS{"README.md": {Data: []byte("not a document\n")}}
	for _, d := range ds {
		fsys[d.Rule.String()+"/"+d.Path.String()] = &fstest.MapFile{Data: []byte(d.Text)}
	}
	return fsys
}

func reviewStateOf(t *testing.T, fsys fstest.MapFS, docs []ReviewDocument) ReviewState {
	t.Helper()
	s, err := reviewOf(fsys, docs, []lint.RuleID{lint.MustRuleID("a-rule")})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestReviewSame: every approved document is its review document.
func TestReviewSame(t *testing.T) {
	docs := reviewDocs(t)
	s := reviewStateOf(t, approvedOf(docs), docs)
	a := lint.MustRuleID("a-rule")
	if rs := s.Rules(); len(rs) != 1 || !rs[0].Reviewed || len(rs[0].Changed) != 0 || len(rs[0].Stale) != 0 {
		t.Errorf("Rules = %+v", rs)
	}
	if !s.RuleReviewed(a) || !s.MetaReviewed(a) || !s.ExampleReviewed(a, lint.ExampleFalsePositive, docs[1].Example.Example) {
		t.Error("not reviewed")
	}
}

// TestReviewChanged: meta.md differs by a byte; the examples stay
// reviewed, and the rule is not.
func TestReviewChanged(t *testing.T) {
	docs := reviewDocs(t)
	fsys := approvedOf(docs)
	fsys["a-rule/meta.md"] = &fstest.MapFile{Data: []byte("## a-rule.\n")}
	s := reviewStateOf(t, fsys, docs)
	a := lint.MustRuleID("a-rule")
	if rs := s.Rules(); len(rs[0].Changed) != 1 || rs[0].Changed[0].Path != metaDocument || rs[0].Reviewed {
		t.Errorf("Rules = %+v", rs)
	}
	if s.MetaReviewed(a) || s.RuleReviewed(a) || !s.ExampleReviewed(a, lint.ExampleTruePositive, docs[2].Example.Example) {
		t.Error("meta.md is reviewed, the rule is, or an example is not")
	}
}

// TestReviewMissing: a rule without approved documents has every document
// changed.
func TestReviewMissing(t *testing.T) {
	docs := reviewDocs(t)
	s := reviewStateOf(t, fstest.MapFS{}, docs)
	if rs := s.Rules(); len(rs[0].Changed) != 3 || rs[0].Reviewed {
		t.Errorf("Rules = %+v", rs)
	}
	if s.ExampleReviewed(lint.MustRuleID("a-rule"), lint.ExampleFalsePositive, docs[1].Example.Example) {
		t.Error("an example without an approved document is reviewed")
	}
}

// TestReviewStale: an approved document of no example now is stale, and
// the rule is not reviewed.
func TestReviewStale(t *testing.T) {
	docs := reviewDocs(t)
	fsys := approvedOf(docs)
	fsys["a-rule/false-positive/old.md"] = &fstest.MapFile{Data: []byte("old\n")}
	s := reviewStateOf(t, fsys, docs)
	if rs := s.Rules(); len(rs[0].Stale) != 1 || rs[0].Stale[0] != MustReviewPath("false-positive/old.md") || rs[0].Reviewed || s.RuleReviewed(lint.MustRuleID("a-rule")) {
		t.Errorf("Rules = %+v", rs)
	}
}

// TestReviewUnknownRule: the directory of a rule not in the registry is
// told, and no error; a file at the root is no rule's.
func TestReviewUnknownRule(t *testing.T) {
	docs := reviewDocs(t)
	fsys := approvedOf(docs)
	fsys["gone-rule/meta.md"] = &fstest.MapFile{Data: []byte("## gone-rule\n")}
	s := reviewStateOf(t, fsys, docs)
	if u := s.Unknown(); len(u) != 1 || u[0] != lint.MustRuleID("gone-rule") {
		t.Errorf("Unknown = %v", u)
	}
	if !s.RuleReviewed(lint.MustRuleID("a-rule")) {
		t.Error("a-rule is not reviewed")
	}
}

// TestReviewReal: the approved documents built in are read; how many rules
// are not reviewed is told, and fails nothing.
func TestReviewReal(t *testing.T) {
	s, err := Review(sharedChecks(t))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range s.Rules() {
		if !r.Reviewed {
			n++
		}
	}
	t.Logf("%d of %d rules not reviewed; directories of no rule: %v", n, len(s.Rules()), s.Unknown())
	if want := len(All()) + len(Quality()); len(s.Rules()) != want {
		t.Errorf("%d rules and quality rules, want %d", len(s.Rules()), want)
	}
}

// TestReviewOddShapes: an approved meta.md that is a directory is changed,
// and what is in it stale; the place of a rule's directory that is a file,
// and a directory of a name that is no rule ID, are errors.
func TestReviewOddShapes(t *testing.T) {
	docs := reviewDocs(t)
	fsys := approvedOf(docs)
	delete(fsys, "a-rule/meta.md")
	fsys["a-rule/meta.md/x"] = &fstest.MapFile{Data: []byte("x\n")}
	s := reviewStateOf(t, fsys, docs)
	if rs := s.Rules(); len(rs[0].Changed) != 1 || rs[0].Changed[0].Path != metaDocument || len(rs[0].Stale) != 1 || rs[0].Stale[0] != MustReviewPath("meta.md/x") {
		t.Errorf("Rules = %+v", rs)
	}
	for name, fsys := range map[string]fstest.MapFS{
		"a file of the rule": {"a-rule": &fstest.MapFile{Data: []byte("x\n")}},
		"no rule ID":         {"Not_A_Rule/meta.md": &fstest.MapFile{Data: []byte("x\n")}},
	} {
		if _, err := reviewOf(fsys, docs, []lint.RuleID{lint.MustRuleID("a-rule")}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestExampleKeysUnique: no two examples of a rule that show the same
// have the same main file, which the reviewed of an example is found by.
func TestExampleKeysUnique(t *testing.T) {
	seen := map[exampleKey]string{}
	for _, x := range Examples() {
		k := keyOf(x.Rule, x.What, x.Example)
		if p, ok := seen[k]; ok {
			t.Errorf("%s and %s have the same main file", p, x.Path)
		}
		seen[k] = x.Path
	}
}

// TestDeclarationTextTrueNegative: a true negative's declaration text is
// that of lint.TrueNegativeText for the kind its name starts with (the
// longest), a true positive's the consequence of the kind.
func TestDeclarationTextTrueNegative(t *testing.T) {
	m := codeInjection{}.Meta()
	var controlled lint.FindingText
	for _, k := range m.FindingKinds {
		if k.ID.String() == "code-injection.controlled" {
			controlled = k.FindingText
		}
	}
	if got, want := declarationText(m, lint.ExampleTrueNegative, "controlled.if-equal"), lint.TrueNegativeText(controlled); got != want {
		t.Errorf("true negative controlled.if-equal: %q, want %q", got, want)
	}
	if got := declarationText(m, lint.ExampleTruePositive, "controlled.caller"); got != controlled.Consequence {
		t.Errorf("true positive controlled.caller: %q, want the consequence %q", got, controlled.Consequence)
	}
}

// TestExampleDocumentFacts: after the files, the facts each run asked and
// their answers; a run that asked none says so; two runs say which kinds
// the second answered the other way; no run, no facts.
func TestExampleDocumentFacts(t *testing.T) {
	x := reviewExample(t, lint.ExampleFalsePositive, "x", "# situation: s\n# reason: r\n# cause: c\non: push\n")
	asked := lint.Report{Facts: []facts.Entry{{Query: facts.RepoWikiOpen{}, RawAnswer: facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}}}}
	flip := []facts.Kind{facts.KindRepoWikiOpen}
	files := exampleDocument(x, attackrun.MarkerNone, nil)
	for _, c := range []struct {
		name string
		runs []lint.ExampleRun
		want string
	}{
		{"none asked", []lint.ExampleRun{{}}, "\nThe rule asked no fact: the files alone decide what the rule reports.\n"},
		{"one run", []lint.ExampleRun{{Report: asked}}, "\nFacts the rule asked, and the answers the rule ran with:\n\n```text\nrepo.wiki-open = true\n```\n"},
		{"flipped only", []lint.ExampleRun{{Flipped: flip, Report: asked}}, "\nFacts the rule asked, and the answers the rule ran with:\n\n```text\nrepo.wiki-open = true (the answer that removes the finding)\n```\n"},
		{"two runs", []lint.ExampleRun{{Report: asked}, {Flipped: flip, Report: asked}}, "\nWith the answers of the facts file, the facts the rule asked:\n\n```text\nrepo.wiki-open = true\n```\n\n" +
			"With repo.wiki-open answered with the answer that removes the finding, the facts the rule asked:\n\n```text\nrepo.wiki-open = true (the answer that removes the finding)\n```\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := exampleDocument(x, attackrun.MarkerNone, c.runs); got != files+c.want {
				t.Errorf("exampleDocument =\n%s\nwant\n%s", got, files+c.want)
			}
		})
	}
}

// TestReviewDocumentFactsReal: the review documents of the rules say what
// facts the rule asked: argument-injection asks none on its example of
// pull-request, and code-injection's false positive wiki-closed runs twice.
func TestReviewDocumentFactsReal(t *testing.T) {
	docs, err := ReviewDocuments(sharedChecks(t))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"argument-injection undetected/pull-request.md": "The rule asked no fact: the files alone decide what the rule reports.",
		"code-injection false-positive/wiki-closed.md":  "answered with the answer that removes the finding, the facts the rule asked:",
	}
	for _, d := range docs {
		if w, ok := want[d.Rule.String()+" "+d.Path.String()]; ok {
			if !strings.Contains(d.Text, w) {
				t.Errorf("%s %s has no %q:\n%s", d.Rule, d.Path, w, d.Text)
			}
			delete(want, d.Rule.String()+" "+d.Path.String())
		}
	}
	for k := range want {
		t.Errorf("no review document %s", k)
	}
}

// TestSharedTrueNegative: a true negative named <kind>+<kind> is the
// true negative of each kind, and its declaration says both.
func TestSharedTrueNegative(t *testing.T) {
	m := exampledMeta(Credentials)
	var texts []lint.FindingText
	for _, k := range m.FindingKinds {
		if len(k.TrueNegatives) != 1 || k.TrueNegatives[0].Name.String() != "private+public.yml" {
			t.Errorf("%s: true negatives %v, not the one private+public.yml", k.ID, k.TrueNegatives)
		}
		texts = append(texts, k.FindingText)
	}
	if got, want := declarationText(m, lint.ExampleTrueNegative, "private+public"), lint.TrueNegativeText(texts...); got != want {
		t.Errorf("declaration %q, want %q", got, want)
	}
}

// TestReviewHasQuality: the state of the approved documents has each
// quality rule, as it has each rule.
func TestReviewHasQuality(t *testing.T) {
	s, err := Review(sharedChecks(t))
	if err != nil {
		t.Fatal(err)
	}
	have := map[lint.RuleID]bool{}
	for _, r := range s.Rules() {
		have[r.Rule] = true
	}
	for _, q := range Quality() {
		if !have[q.QualityMeta().ID] {
			t.Errorf("no review of the quality rule %s", q.QualityMeta().ID)
		}
	}
}

// TestDeclarationTextLabeled: a labeled example of a form has the text of
// the form.
func TestDeclarationTextLabeled(t *testing.T) {
	m := codeInjection{}.Meta()
	for _, l := range m.UndetectedForms {
		if got := declarationText(m, lint.ExampleUndetected, l.ID.String()+".ghsl-2026-229"); got != l.Text {
			t.Errorf("%s.ghsl-2026-229: %q, want %q", l.ID, got, l.Text)
		}
	}
}

// TestReviewRefusesUnmadeChecks: Review and ReviewDocuments refuse example
// checks that CheckAllExamples did not make, as a review document made of
// some rules' checks would be wrong.
func TestReviewRefusesUnmadeChecks(t *testing.T) {
	for _, c := range []*AllExampleChecks{nil, {}} {
		if _, err := Review(c); err == nil {
			t.Errorf("Review(%v): no error", c)
		}
		if _, err := ReviewDocuments(c); err == nil {
			t.Errorf("ReviewDocuments(%v): no error", c)
		}
	}
}

// TestAllExampleChecksOf: Of(id) is what CheckExamples gives for the rule
// id alone, in its order, and Of gives a slice of its own.
func TestAllExampleChecksOf(t *testing.T) {
	ctx := context.Background()
	c := sharedChecks(t)
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	got, want := c.Of(CodeInjectionID), reg.CheckExamples(ctx, CodeInjectionID)
	if len(got) == 0 || len(got) != len(want) {
		t.Fatalf("%d checks, want %d", len(got), len(want))
	}
	for i := range got {
		g, w := got[i], want[i]
		if g.Rule != w.Rule || g.What != w.What || g.Declaration != w.Declaration || g.Holds != w.Holds || g.Why != w.Why || g.Example.Name != w.Example.Name || len(g.Runs) != len(w.Runs) {
			t.Errorf("check %d: %s %s %s %s, want %s %s %s %s", i, g.Rule, g.What, g.Declaration, g.Example.Name, w.Rule, w.What, w.Declaration, w.Example.Name)
		}
	}
	all := c.Of()
	n := len(all)
	all[0] = lint.ExampleCheck{}
	if again := c.Of(); len(again) != n || again[0].Rule.String() == "" {
		t.Error("writing the slice of Of changed what Of gives")
	}
}
