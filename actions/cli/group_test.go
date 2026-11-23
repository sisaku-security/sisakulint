package cli

import (
	"context"
	"encoding/json"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/rules"
)

const textRepo = "testdata/text/repo"

// runText is the inputs of dir and their report, offline, with the
// assumptions: what Main has for the text.
func runText(t *testing.T, dir string) (lint.Report, lint.Inputs) {
	t.Helper()
	in, err := lint.Enumerate(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	return lint.Run(context.Background(), in, registry(t), facts.Assume(offline{})), in
}

func TestFoldConfirmed(t *testing.T) {
	rep, in := runText(t, textRepo)
	v := buildView(rep, in, registry(t))
	byKind := map[lint.FindingKindID]*fold{}
	for i, f := range v.confirmed {
		byKind[f.kind] = &v.confirmed[i]
	}
	sha := byKind[rules.CommitSHAUnpinned{}.KindID()]
	if sha == nil || sha.count() != 7 || len(sha.rows) != 3 {
		t.Fatalf("commit-sha.unpinned is not one fold of 7 in 3 rows: %+v", sha)
	}
	var counts []int
	for _, g := range sha.rows {
		counts = append(counts, len(g.results))
	}
	if !slices.Equal(counts, []int{4, 2, 1}) || !strings.HasPrefix(sha.rows[0].detected, "actions/checkout@v4 ") {
		t.Errorf("the rows are %v, first %q; want 4, 2, 1 from actions/checkout@v4", counts, sha.rows[0].detected)
	}
	if v.confirmed[0].severity != lint.SeverityCritical {
		t.Errorf("the first fold is %v, not critical", v.confirmed[0].severity)
	}
	// The findings of env.yml and issues.yml differ in the titles of their
	// fixes, (1 edits) and (2 edits), not in the kinds: one fold.
	ci := byKind[rules.CodeInjectionControlled{}.KindID()]
	if ci == nil || ci.count() != 5 || len(ci.rows) != 2 {
		t.Fatalf("code-injection.controlled is not one fold of 5 in 2 rows: %+v", ci)
	}
	kind, _ := fixKind(registry(t), rules.CodeInjectionID, rules.EnvVarID)
	if ci.fix == nil || ci.fix.title != kind.Title || ci.fix.safety != lint.SafetyReview {
		t.Errorf("the fix of the fold is %+v, want the title of the registry, %q", ci.fix, kind.Title)
	}
	wiki := byKind[rules.CodeInjectionWiki{}.KindID()]
	if wiki == nil || len(wiki.assumed) != 1 || wiki.assumed[0].text() != "repo.wiki-open = true" {
		t.Errorf("the gollum finding does not rest on repo.wiki-open: %+v", wiki)
	}
}

func TestGroupConditional(t *testing.T) {
	rep, in := runText(t, textRepo)
	v := buildView(rep, in, registry(t))
	if len(v.conditional) != 1 || v.conditional[0].rule != rules.ImpostorCommitID {
		t.Fatalf("conditional = %+v, want impostor-commit only", v.conditional)
	}
	c := v.conditional[0]
	want := "git.commit-ref repo=actions/cache sha=668228422ae6a00e4ad889ee87cd7109ec5666a7"
	if len(c.by) != 1 || c.by[0].what() != want || len(c.by[0].results) != 2 {
		t.Errorf("by = %+v, want %q for 2", c.by, want)
	}
	if !slices.Equal(c.why, []string{"offline: pass --facts or --online"}) {
		t.Errorf("why = %v", c.why)
	}
}

// Every finding is in one group, once: no grouping drops one.
func TestGroupEveryFindingOnce(t *testing.T) {
	rep, in := runText(t, textRepo)
	v := buildView(rep, in, registry(t))
	seen := map[string]int{}
	for _, f := range v.confirmed {
		for _, g := range f.rows {
			for _, r := range g.results {
				seen[r.Fingerprint.String()]++
			}
		}
	}
	for _, c := range v.conditional {
		for _, r := range c.results {
			seen[r.Fingerprint.String()]++
		}
	}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if seen[f.Fingerprint.String()] != 1 {
			t.Errorf("%s at %v is in %d groups", f.Rule, f.Location.Span, seen[f.Fingerprint.String()])
		}
	}
}

// TestGroupOrder: the order of the findings in the report changes nothing.
func TestGroupOrder(t *testing.T) {
	rep, in := runText(t, textRepo)
	want := project(buildView(rep, in, registry(t)))
	r := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		r.Shuffle(len(rep.Findings), func(i, j int) {
			rep.Findings[i], rep.Findings[j] = rep.Findings[j], rep.Findings[i]
		})
		if got := project(buildView(rep, in, registry(t))); got != want {
			t.Fatalf("another order of findings, another view:\n%s\nwant\n%s", got, want)
		}
	}
}

// project is v as text, enough to compare two views.
func project(v view) string {
	var b strings.Builder
	for _, f := range v.confirmed {
		b.WriteString(f.key() + "\n")
		for _, g := range f.rows {
			b.WriteString("  " + g.detected + "\n")
			for _, r := range g.results {
				b.WriteString("    " + r.Fingerprint.String() + "\n")
			}
		}
	}
	for _, c := range v.conditional {
		for _, d := range c.by {
			b.WriteString(d.what() + "\n")
			for _, r := range d.results {
				b.WriteString("  " + r.Fingerprint.String() + "\n")
			}
		}
	}
	return b.String()
}

func TestGroupInputs(t *testing.T) {
	rep, in := runText(t, textRepo)
	v := buildView(rep, in, registry(t))
	if len(v.inputs) != 1 || v.inputs[0].state != lint.InputStateInvalid || !v.inputs[0].diagnostics {
		t.Errorf("inputs = %+v, want bad.yml as invalid by diagnostics", v.inputs)
	}
}

// said is the args of a finding the tests make up: of the kind of r, with
// the message as it is.
type said struct {
	kind lint.FindingKindID
	text string
}

func (s said) KindID() lint.FindingKindID { return s.kind }
func (s said) Detected() string           { return s.text }
func (s said) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"kind_id": s.kind.String()})
}

// withNoFix is r with another fingerprint, message and NoFix.
func withNoFix(r lint.Finding, fp int, message string, reason ir.NoFixReason, note string) lint.Finding {
	r.Fingerprint = lint.Fingerprint{}
	r.Args = said{r.Args.KindID(), message}
	r.NoFix = &lint.NoFix{Reason: reason, Note: note}
	r.Anchor = strconv.Itoa(fp)
	return r
}

// withFix is r with another anchor, and its fix of the kind k and the
// title.
func withFix(r lint.Finding, fp int, k lint.FixKindID, title string) lint.Finding {
	r.Fingerprint = lint.Fingerprint{}
	r.Anchor = strconv.Itoa(fp)
	x := *r.Fix
	x.KindID, x.Title = k, title
	r.Fix = &x
	return r
}

// Findings that differ in the reason or the note for no fix, in the kind
// of a fix, or whose message and note meet at a NUL, are not one fold;
// findings that differ only in the message or the title of a fix are.
func TestFoldKeyApart(t *testing.T) {
	rep, in := runText(t, textRepo)
	var sha, ci lint.Finding
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		switch f.Args.KindID() {
		case rules.CommitSHAUnpinned{}.KindID():
			sha = f
		case rules.CodeInjectionControlled{}.KindID():
			ci = f
		}
	}
	for _, c := range []struct {
		name  string
		a, b  lint.Finding
		folds int
	}{
		{"the reason", withNoFix(sha, 1, "m", ir.NoFixReasonFact, "n"), withNoFix(sha, 2, "m", ir.NoFixReasonManual, "n"), 2},
		{"the note", withNoFix(sha, 1, "m", ir.NoFixReasonForm, "a is not a name"), withNoFix(sha, 2, "m", ir.NoFixReasonForm, "b is not a name"), 2},
		{"a NUL", withNoFix(sha, 1, "a\x00b", ir.NoFixReasonFact, "c"), withNoFix(sha, 2, "a", ir.NoFixReasonFact, "b\x00c"), 2},
		{"the message", withNoFix(sha, 1, "a", ir.NoFixReasonFact, "n"), withNoFix(sha, 2, "b", ir.NoFixReasonFact, "n"), 1},
		{"the fix title", withFix(ci, 1, rules.EnvVarID, "pin a to 1"), withFix(ci, 2, rules.EnvVarID, "pin a to 2"), 1},
		{"the fix kind", withFix(ci, 1, rules.EnvVarID, "t"), withFix(ci, 2, rules.EnvVarReviewID, "t"), 2},
	} {
		v := buildView(lint.Report{Findings: []lint.Finding{c.a, c.b}}, in, registry(t))
		if len(v.confirmed) != c.folds {
			t.Errorf("%s: %d folds, want %d", c.name, len(v.confirmed), c.folds)
		}
	}
}

// A leaf Eval did not reach is not in the facts of the report: it decides
// nothing.
func TestDecideOnlyUnknown(t *testing.T) {
	asked, skipped := facts.TestFlag{Name: "asked"}, facts.TestFlag{Name: "skipped"}
	cond := lint.All(lint.FactAbsent(asked), lint.FactAbsent(skipped))
	r := lint.Finding{FindingDraft: lint.FindingDraft{Rule: rules.ImpostorCommitID, Condition: &cond}, Certainty: lint.CertaintyConditional}
	known := map[string]facts.RawAnswer{queryKey(asked): {State: facts.StateUnknown, Reason: "offline"}}
	by, why := decide([]lint.Finding{r}, known, func(facts.InputPath) lint.LookupState { return lint.LookupFound })
	if len(by) != 1 || by[0].what() != queryText(asked) || !slices.Equal(why, []string{"offline"}) {
		t.Errorf("by %+v, why %v; want %s only", by, why, queryText(asked))
	}
}

// An input whose reason is the word diagnostics is not one with diagnostics.
func TestInputGroupsApart(t *testing.T) {
	gs := inputGroups([]lint.Input{
		{Name: facts.MustCleanInputPath("a.yml"), State: lint.InputStateInvalid, Reason: "diagnostics"},
		{Name: facts.MustCleanInputPath("b.yml"), State: lint.InputStateInvalid},
	})
	if len(gs) != 2 {
		t.Errorf("%d groups, want 2: %+v", len(gs), gs)
	}
}

// worst is the rows of the highest severity only, the most findings first,
// at most the limit.
func TestWorst(t *testing.T) {
	row := func(msg string, n int) group {
		g := group{detected: msg}
		for range n {
			g.results = append(g.results, lint.Finding{})
		}
		return g
	}
	folds := []fold{
		{severity: lint.SeverityCritical, kind: rules.CodeInjectionControlled{}.KindID(), rows: []group{row("b", 3), row("d", 2), row("a", 1), row("c", 1)}},
		{severity: lint.SeverityCritical, kind: rules.CodeInjectionWiki{}.KindID(), rows: []group{row("g", 4), row("e", 1), row("f", 1)}},
		{severity: lint.SeverityHigh, kind: rules.CommitSHAUnpinned{}.KindID(), rows: []group{row("h", 9)}},
	}
	rows, more := worst(folds, nil, 5)
	var got []string
	for _, w := range rows {
		got = append(got, w.row.detected)
	}
	if want := []string{"g", "b", "d", "a", "c"}; !slices.Equal(got, want) || more != 2 {
		t.Errorf("worst = %v and %d more; want %v and 2 more", got, more, want)
	}
	high, more := worst(folds[2:], nil, 5)
	if len(high) != 1 || high[0].severity != lint.SeverityHigh || more != 0 {
		t.Errorf("with no critical, worst = %+v and %d more; want the high row", high, more)
	}
	if none, more := worst(nil, nil, 5); len(none) != 0 || more != 0 {
		t.Errorf("worst of no fold = %+v and %d more", none, more)
	}
}

// An inconclusive finding of the highest severity is among the worst rows,
// marked; one of a lower severity is not.
func TestWorstInconclusive(t *testing.T) {
	high := []fold{{severity: lint.SeverityHigh, kind: rules.CommitSHAUnpinned{}.KindID(), rows: []group{{detected: "h", results: []lint.Finding{{}}}}}}
	gap := func(sev lint.Severity, note string) lint.Finding {
		return lint.Finding{FindingDraft: lint.FindingDraft{Rule: lint.MustRuleID("untrusted-checkout")}, Severity: sev, Certainty: lint.CertaintyInconclusive,
			InconclusiveKind: lint.MustInconclusiveKindID("checkout-ref-unknown"), Note: note}
	}
	rows, _ := worst(high, []lint.Finding{gap(lint.SeverityCritical, "c")}, 5)
	if len(rows) != 1 || !rows[0].inconclusive || rows[0].severity != lint.SeverityCritical || rows[0].row.detected != "c" || rows[0].kind != "untrusted-checkout.checkout-ref-unknown" {
		t.Errorf("a critical inconclusive finding over a high fold: %+v", rows)
	}
	rows, _ = worst(high, []lint.Finding{gap(lint.SeverityMedium, "m")}, 5)
	if len(rows) != 1 || rows[0].inconclusive {
		t.Errorf("a medium inconclusive finding beside a high fold: %+v", rows)
	}
	rows, _ = worst(high, []lint.Finding{gap(lint.SeverityHigh, "x")}, 5)
	if len(rows) != 2 {
		t.Errorf("an inconclusive finding of the same severity as the fold: %+v", rows)
	}
}

// A note that spells the next part of the key does not make two findings
// one fold: each part is quoted.
func TestFoldKeyBorder(t *testing.T) {
	rep, in := runText(t, textRepo)
	var sha lint.Finding
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Args.KindID() == (rules.CommitSHAUnpinned{}).KindID() {
			sha = f
		}
	}
	a := withNoFix(sha, 1, "m", ir.NoFixReasonForm, `n fix "env-var" 0`)
	b := withNoFix(sha, 2, "m", ir.NoFixReasonForm, "n")
	b.Fix = &lint.Fix{KindID: rules.EnvVarID, Title: "t"}
	if v := buildView(lint.Report{Findings: []lint.Finding{a, b}}, in, registry(t)); len(v.confirmed) != 2 {
		t.Errorf("%d folds, want 2: the note moved the border of the fixes", len(v.confirmed))
	}
}

// A fix of a kind the registry does not have is titled by its kind, so
// that the order of the findings does not choose the title of the fold.
func TestFoldUnknownFixKind(t *testing.T) {
	rep, in := runText(t, textRepo)
	var sha lint.Finding
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Args.KindID() == (rules.CommitSHAUnpinned{}).KindID() {
			sha = f
		}
	}
	k := lint.MustFixKindID("no-such-kind")
	a, b := withNoFix(sha, 1, "m", ir.NoFixReasonFact, "n"), withNoFix(sha, 2, "m", ir.NoFixReasonFact, "n")
	a.NoFix, b.NoFix = nil, nil
	a.Fix, b.Fix = &lint.Fix{KindID: k, Title: "title A"}, &lint.Fix{KindID: k, Title: "title B"}
	ab := buildView(lint.Report{Findings: []lint.Finding{a, b}}, in, registry(t))
	ba := buildView(lint.Report{Findings: []lint.Finding{b, a}}, in, registry(t))
	if len(ab.confirmed) != 1 || ab.confirmed[0].fix.title != ba.confirmed[0].fix.title {
		t.Errorf("the title of the fold is %q one way and %q the other", ab.confirmed[0].fix.title, ba.confirmed[0].fix.title)
	}
}

// TestFoldSideEffects: the fold line of a fix is followed by the side
// effects of the fixes of its findings, each once.
func TestFoldSideEffects(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/.github/workflows", 0o755); err != nil {
		t.Fatal(err)
	}
	src := "on: issues\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n      - run: if [[ x == ${{ github.event.issue.body }} ]]; then echo a; fi\n"
	if err := os.WriteFile(dir+"/.github/workflows/w.yml", []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	r := run(t, raw("--root", dir))
	for _, want := range []string{
		"    side effect: An unquoted place becomes one word: a value with blanks is no longer read as several words, and outside [[ ]] is no longer globbed.\n",
		"    side effect: On the right of ==, =, != or =~ inside [[ ]], the value is compared as a string, not matched as a pattern or a regular expression.\n",
	} {
		if strings.Count(r.stdout, want) != 1 {
			t.Errorf("%q %d times in\n%s%s", want, strings.Count(r.stdout, want), r.stdout, r.stderr)
		}
	}
}
