package lint

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// exprGap is a rule that reports each ${{ }} of the run of each step as
// inconclusive, at its span in the value.
func exprGap() Rule {
	return testRule{meta: gapMeta("expr-gap"), check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			r := s.Run.Value
			for _, p := range r.Parts {
				if p.Expr {
					sp, exact := r.Source(p.Span)
					c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: AtSpan(c.input, r.Base, sp, exact)})
				}
			}
		}
		return nil
	}}
}

// runGap is a rule that reports the run of each step as inconclusive, at
// the run itself.
func runGap() Rule {
	return testRule{meta: gapMeta("run-gap"), check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			if s.Run.Status == workflow.Present {
				c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, s.Run.Value.Base)})
			}
		}
		return nil
	}}
}

// identities are the KeyPath, SpanText and SpanLines of the inconclusive
// places of a run of rule on src.
func identities(t *testing.T, src string, rule Rule) [][3]string {
	t.Helper()
	rep := run(t, wf(src), nil, rule)
	if len(rep.Errors) != 0 {
		t.Fatalf("errors: %+v", rep.Errors)
	}
	var out [][3]string
	for _, g := range rep.FindingsWith(CertaintyInconclusive) {
		out = append(out, [3]string{g.KeyPath.String(), g.SpanText, g.SpanLines})
	}
	return out
}

const exprRun = `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          set -e
          echo "${{ steps.a.outputs.x }}"
`

func TestInconclusiveIdentity(t *testing.T) {
	got := identities(t, exprRun, exprGap())
	want := [][3]string{{"jobs.j.steps[0].run", "${{ steps.a.outputs.x }}", `echo "${{ steps.a.outputs.x }}"`}}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("identities = %q, want %q", got, want)
	}
}

func TestInconclusiveIdentityMultiline(t *testing.T) {
	// the span of a block scalar is the scalar as written, its indicator
	// included; the lines start with the key, and keep their indentation
	// past the indentation of the first line
	got := identities(t, exprRun, runGap())
	want := "|\n    set -e\n    echo \"${{ steps.a.outputs.x }}\""
	if len(got) != 1 || got[0][1] != want || got[0][2] != "- run: "+want {
		t.Errorf("identities = %q, want the span text %q, and the lines with the key", got, want)
	}
}

func TestInconclusiveIdentityWhitespace(t *testing.T) {
	base := identities(t, exprRun, exprGap())
	deeper := strings.ReplaceAll(exprRun, "\n      ", "\n        ") // the steps two more columns in
	for name, src := range map[string]string{
		"indented": deeper,
		"CRLF":     strings.ReplaceAll(exprRun, "\n", "\r\n"),
	} {
		if got := identities(t, src, exprGap()); len(got) != 1 || got[0] != base[0] {
			t.Errorf("%s: identities = %q, want %q", name, got, base)
		}
	}
	spaced := strings.Replace(exprRun, `echo "`, `echo  "`, 1)
	if got := identities(t, spaced, exprGap()); len(got) != 1 || got[0][2] == base[0][2] {
		t.Errorf("two spaces in the line: identities = %q, want SpanLines other than %q", got, base[0][2])
	}
}

const aliasRun = `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: &r echo "${{ steps.x.outputs.v }}"
  b:
    runs-on: ubuntu-latest
    steps:
      - run: *r
`

func TestInconclusiveIdentityAlias(t *testing.T) {
	got := identities(t, aliasRun, runGap())
	// the anchor's bytes, its property included, and the anchor's line
	value := `&r echo "${{ steps.x.outputs.v }}"`
	if len(got) != 2 || got[1][0] != "jobs.b.steps[0].run" || got[1][1] != value || got[1][2] != `- run: `+value {
		t.Fatalf("identities = %q, want the place through *r to have the text of the anchor", got)
	}
	changed := identities(t, strings.Replace(aliasRun, "outputs.v", "outputs.w", 1), runGap())
	if len(changed) != 2 || changed[1][1] == got[1][1] {
		t.Errorf("the anchor's value changed: identities = %q, want SpanText other than %q", changed, got[1][1])
	}
	spans := identities(t, aliasRun, exprGap())
	if len(spans) != 2 || spans[1][1] != "${{ steps.x.outputs.v }}" {
		t.Errorf("AtSpan through *r: identities = %q, want the span in the anchor", spans)
	}
}

func TestReportInconclusiveJSON(t *testing.T) {
	rep := run(t, wf(exprRun), nil, exprGap())
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"key_path":"jobs.j.steps[0].run","span_text":"${{ steps.a.outputs.x }}","span_lines":"echo \"${{ steps.a.outputs.x }}\""`) {
		t.Errorf("the JSON of the report: %s", b)
	}
	if err := schemas(t).Validate("report-v0.json", "#", b); err != nil {
		t.Errorf("the report does not fit report-v0.json: %v", err)
	}
}

// acceptanceFile is a file of acceptances with entries, each a JSON object.
func acceptanceFile(entries ...string) []byte {
	return []byte(`{"schema": "sisakulint/acceptances/v0", "inconclusive": [` + strings.Join(entries, ",") + `]}`)
}

// acceptanceEntry is an entry of the place of exprRun that exprGap reports,
// with fields replaced by those of change, a JSON object's members.
func acceptanceEntry(change string) string {
	m := map[string]any{"rule": "expr-gap", "kind_id": "expr-gap.g", "input": ".github/workflows/w.yml", "key_path": "jobs.j.steps[0].run",
		"span_text": "${{ steps.a.outputs.x }}", "span_lines": `echo "${{ steps.a.outputs.x }}"`, "reason": "steps.a writes a version"}
	if change != "" {
		if err := json.Unmarshal([]byte("{"+change+"}"), &m); err != nil {
			panic(err)
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func gapRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := newRegistry([]Rule{exprGap()}, true)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestLoadAcceptances(t *testing.T) {
	as, err := LoadAcceptances(acceptanceFile(acceptanceEntry(""), acceptanceEntry(`"span_text": "${{ steps.b.outputs.y }}"`)), gapRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	in, _ := facts.ParseInputPath(".github/workflows/w.yml")
	want := Acceptance{Rule: MustRuleID("expr-gap"), KindID: kindG, Input: in, KeyPath: KeyPath{"jobs.j.steps[0].run"},
		SpanText: "${{ steps.a.outputs.x }}", SpanLines: `echo "${{ steps.a.outputs.x }}"`, Reason: "steps.a writes a version"}
	if len(as) != 2 || as[0] != want || as[1].SpanText != "${{ steps.b.outputs.y }}" {
		t.Errorf("LoadAcceptances = %+v, want %+v first", as, want)
	}
}

func TestLoadAcceptancesErrors(t *testing.T) {
	for name, b := range map[string][]byte{
		"not JSON":            []byte("{"),
		"another schema":      []byte(`{"schema": "sisakulint/report/v0", "inconclusive": []}`),
		"an unknown key":      []byte(`{"schema": "sisakulint/acceptances/v0", "inconclusive": [], "findings": []}`),
		"a field missing":     acceptanceFile(`{"rule": "expr-gap", "kind_id": "expr-gap.g", "reason": "r"}`),
		"an unknown rule":     acceptanceFile(acceptanceEntry(`"rule": "other", "kind_id": "other.g"`)),
		"a kind undeclared":   acceptanceFile(acceptanceEntry(`"kind_id": "expr-gap.h"`)),
		"the last part alone": acceptanceFile(acceptanceEntry(`"kind_id": "g"`)),
		"another rule's kind": acceptanceFile(acceptanceEntry(`"kind_id": "other.g"`)),
		"a reason of spaces":  acceptanceFile(acceptanceEntry(`"reason": "  "`)),
		"an empty reason":     acceptanceFile(acceptanceEntry(`"reason": ""`)),
		"a bad input":         acceptanceFile(acceptanceEntry(`"input": "../w.yml"`)),
		"an entry twice":      acceptanceFile(acceptanceEntry(""), acceptanceEntry(`"reason": "another reason"`)),
		"a bad key path":      acceptanceFile(acceptanceEntry(`"key_path": "jobs..j"`)),
		"an input not clean":  acceptanceFile(acceptanceEntry(`"input": "./.github/workflows/w.yml"`)),
	} {
		if _, err := LoadAcceptances(b, gapRegistry(t)); err == nil {
			t.Errorf("%s: LoadAcceptances took %s", name, b)
		}
	}
	if _, err := LoadAcceptances(acceptanceFile(acceptanceEntry(`"rule": "other", "kind_id": "other.g"`), acceptanceEntry("")), gapRegistry(t)); err == nil || !strings.Contains(err.Error(), "inconclusive/0") {
		t.Errorf("the error %v does not say which entry", err)
	}
}

// twoExprRun has two places for exprGap with the same six fields, and one
// with another span.
const twoExprRun = `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ steps.a.outputs.x }}"
          echo "${{ steps.a.outputs.x }}"
          echo "${{ steps.b.outputs.y }}"
`

func TestAccept(t *testing.T) {
	rep := run(t, wf(exprRun), nil, exprGap())
	for _, change := range []string{`"rule": "other", "kind_id": "other.g"`, `"kind_id": "expr-gap.h"`, `"input": ".github/workflows/v.yml"`, `"key_path": "jobs.j.steps[1].run"`,
		`"span_text": "${{ steps.a.outputs.y }}"`, `"span_lines": "echo ${{ steps.a.outputs.x }}"`} {
		as, err := loadUnchecked(acceptanceFile(acceptanceEntry(change)))
		if err != nil {
			t.Fatal(err)
		}
		got, unmatched := Accept(rep, as)
		if got.FindingsWith(CertaintyInconclusive)[0].Acceptance != nil {
			t.Errorf("an acceptance with %s matched %+v", change, got.FindingsWith(CertaintyInconclusive)[0])
		}
		// the entry of another rule, kind or input that the run has not is
		// left out; the others are told
		if wantTold := !strings.Contains(change, `"rule"`) && !strings.Contains(change, `"input"`); (len(unmatched) == 1) != wantTold {
			t.Errorf("an acceptance with %s: unmatched %+v", change, unmatched)
		}
	}
	as, err := LoadAcceptances(acceptanceFile(acceptanceEntry("")), gapRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	got, unmatched := Accept(rep, as)
	if a := got.FindingsWith(CertaintyInconclusive)[0].Acceptance; a == nil || a.Reason != "steps.a writes a version" || len(unmatched) != 0 {
		t.Errorf("Accept = %+v, unmatched %+v; want the place accepted", got.FindingsWith(CertaintyInconclusive), unmatched)
	}
	if rep.FindingsWith(CertaintyInconclusive)[0].Acceptance != nil {
		t.Error("Accept changed the report it was given")
	}
}

// loadUnchecked reads a file of acceptances with a registry that has the
// rules other and expr-gap, expr-gap with the kinds g and h: an entry may
// name what the run of exprGap has not.
func loadUnchecked(b []byte) ([]Acceptance, error) {
	m := gapMeta("expr-gap")
	m.InconclusiveKinds = append(m.InconclusiveKinds, InconclusiveKind{ID: MustInconclusiveKindID("h"), Text: "another place", Disposition: Todo(NeedSameFile), Examples: []Example{exampleOf("h.yml")}})
	reg, err := newRegistry([]Rule{testRule{meta: m}, testRule{meta: gapMeta("other")}}, true)
	if err != nil {
		return nil, err
	}
	return LoadAcceptances(b, reg)
}

func TestAcceptSameIdentity(t *testing.T) {
	rep := run(t, wf(twoExprRun), nil, exprGap())
	as, err := LoadAcceptances(acceptanceFile(acceptanceEntry("")), gapRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Accept(rep, as)
	var n []bool
	for _, g := range got.FindingsWith(CertaintyInconclusive) {
		n = append(n, g.Acceptance != nil)
	}
	if len(n) != 3 || !n[0] || !n[1] || n[2] {
		t.Errorf("accepted = %v, want the two places of steps.a", n)
	}
}

func TestAcceptUnmatched(t *testing.T) {
	rep := run(t, wf(exprRun), nil, exprGap())
	as, err := loadUnchecked(acceptanceFile(acceptanceEntry(`"span_text": "${{ steps.c.outputs.z }}"`), acceptanceEntry(`"rule": "other", "kind_id": "other.g"`),
		acceptanceEntry(`"input": ".github/workflows/v.yml"`)))
	if err != nil {
		t.Fatal(err)
	}
	_, unmatched := Accept(rep, as)
	// other did not run, and v.yml is no input that was read
	if len(unmatched) != 1 || unmatched[0].SpanText != "${{ steps.c.outputs.z }}" {
		t.Errorf("unmatched = %+v, want the entry of a rule that ran and an input that was read", unmatched)
	}
	rep.Inputs[0].State = InputStateExcluded
	if _, unmatched := Accept(rep, as); len(unmatched) != 0 {
		t.Errorf("unmatched = %+v, want none of an input left out", unmatched)
	}
}

func TestReportAcceptanceJSON(t *testing.T) {
	as, err := LoadAcceptances(acceptanceFile(acceptanceEntry("")), gapRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	rep, _ := Accept(run(t, wf(twoExprRun), nil, exprGap()), as)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), `"acceptance":{"reason":"steps.a writes a version"}`) != 2 || strings.Count(string(b), `"acceptance"`) != 2 {
		t.Errorf("the JSON of the report: %s", b)
	}
	if err := schemas(t).Validate("report-v0.json", "#", b); err != nil {
		t.Errorf("the report does not fit report-v0.json: %v", err)
	}
}

// stepGap is a rule that reports each step as inconclusive, at the step.
func stepGap() Rule {
	return testRule{meta: gapMeta("step-gap"), check: func(_ context.Context, c *RuleContext) error {
		for _, s := range steps(c) {
			c.Inconclusive(InconclusiveDraft{KindID: kindG, Location: At(c.input, s.Base)})
		}
		return nil
	}}
}

const stepWith = `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: out
        if: github.event_name == 'push'
`

// TestInconclusiveIdentityStep: a place that is a whole step keeps the indentation of its lines past the first, so
// that moving a key into with changes the texts; the depth of the step
// does not.
func TestInconclusiveIdentityStep(t *testing.T) {
	base := identities(t, stepWith, stepGap())
	want := "uses: actions/download-artifact@v4\n  with:\n    path: out\n  if: github.event_name == 'push'"
	if len(base) != 1 || base[0][1] != want || base[0][2] != "- "+want {
		t.Fatalf("identities = %q, want the span text %q", base, want)
	}
	moved := strings.Replace(stepWith, "        if:", "          if:", 1) // into with
	if got := identities(t, moved, stepGap()); len(got) != 1 || got[0][1] == base[0][1] {
		t.Errorf("if moved into with: identities = %q, want texts other than %q", got, base)
	}
	deeper := strings.ReplaceAll(stepWith, "\n      ", "\n        ")
	if got := identities(t, deeper, stepGap()); len(got) != 1 || got[0] != base[0] {
		t.Errorf("the step two columns in: identities = %q, want %q", got, base)
	}
}

// TestInconclusiveIdentityBreaks: a
// line break may be CR LF, LF or CR, and the last line may have none.
func TestInconclusiveIdentityBreaks(t *testing.T) {
	base := identities(t, exprRun, runGap())
	for name, src := range map[string]string{
		"CR LF":               strings.ReplaceAll(exprRun, "\n", "\r\n"),
		"CR":                  strings.ReplaceAll(exprRun, "\n", "\r"),
		"no break at the end": strings.TrimSuffix(exprRun, "\n"),
	} {
		if got := identities(t, src, runGap()); len(got) != 1 || got[0] != base[0] {
			t.Errorf("%s: identities = %q, want %q", name, got, base)
		}
	}
}

func TestParseKeyPath(t *testing.T) {
	for _, s := range []string{"", "jobs", "jobs.build.steps[0].run", "jobs.build.steps[checkout].uses", `jobs["a.b"].steps[1]`, `env["X Y"]`, "on.push.branches[2]"} {
		if k, err := ParseKeyPath(s); err != nil || k.String() != s {
			t.Errorf("ParseKeyPath(%q) = %v, %v", s, k, err)
		}
	}
	for _, s := range []string{".jobs", "jobs.", "jobs..a", "jobs[", "jobs[a.b]", `jobs["a]`, "jobs.a b", "[0]x"} {
		if _, err := ParseKeyPath(s); err == nil {
			t.Errorf("ParseKeyPath took %q", s)
		}
	}
}

// TestLoadAcceptancesQuality: an entry of a
// quality rule says the rule is a quality rule.
func TestLoadAcceptancesQuality(t *testing.T) {
	reg, err := newRegistry([]Rule{exprGap()}, true, testQuality{m: goodQualityMeta()})
	if err != nil {
		t.Fatal(err)
	}
	b := acceptanceFile(acceptanceEntry(`"rule": "` + goodQualityMeta().ID.String() + `", "kind_id": "` + goodQualityMeta().ID.String() + `.g"`))
	if _, err := LoadAcceptances(b, reg); err == nil || !strings.Contains(err.Error(), "quality rule") {
		t.Errorf("LoadAcceptances = %v, want the error of a quality rule", err)
	}
}
