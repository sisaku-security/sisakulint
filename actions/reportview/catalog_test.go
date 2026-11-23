package reportview

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/attackrun"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/rules"
)

func TestCatalog(t *testing.T) {
	reg, err := lint.NewRegistry(rules.All(), rules.Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	checks := reg.CheckExamples(context.Background())
	c, err := BuildCatalog(context.Background(), reg, checks, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, entries := 0, 0
	for _, r := range c.Rules {
		n++
		var m struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(r.Meta, &m); err != nil || m.ID != r.Rule.String() {
			t.Errorf("%s: the meta of %q (%v)", r.Rule, m.ID, err)
		}
		for _, e := range r.Entries {
			entries++
			if e.Situation == "" || e.Reason == "" {
				t.Errorf("%s %s: no situation or reason", r.Rule, e.ID)
			}
			if rules.AttackMarkers[r.Rule] == attackrun.MarkerNone && e.Checked != "" {
				t.Errorf("%s %s: checked %q, of a rule whose examples are not run", r.Rule, e.ID, e.Checked)
			}
			if len(e.Runs) == 0 || len(e.Runs[0].Page.Files) == 0 {
				t.Errorf("%s %s: no run, or no file to show", r.Rule, e.ID)
			}
		}
	}
	if want := len(reg.Rules()) + len(reg.QualityRules()); n != want || entries != len(checks) {
		t.Errorf("%d rules of %d, %d entries of %d checks", n, want, entries, len(checks))
	}
	for _, r := range c.Rules {
		if r.Quality != reg.IsQuality(r.Rule) {
			t.Errorf("%s: quality %v", r.Rule, r.Quality)
		}
	}
	page, err := c.HTML()
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := bytes.Cut(page, []byte(`<script type="application/json" id="catalog-data">`))
	data, _, _ := bytes.Cut(rest, []byte("</script>"))
	if !bytes.Contains(page, []byte("<title>sisakulint examples</title>")) {
		t.Error("the catalog's page is not titled as the examples")
	}
	if !ok || bytes.ContainsAny(data, "<>") || !json.Valid(data) {
		t.Error("the data of the catalog is not escaped JSON in its script")
	}
	if c.Boundary == nil || len(c.Boundary.Runs) == 0 {
		t.Error("the catalog has no boundary")
	}
}

// fakeReview approves one example by its text, and the Meta of the rules
// in meta.
type fakeReview struct {
	text string
	meta map[lint.RuleID]bool
}

func (f fakeReview) ExampleReviewed(_ lint.RuleID, _ lint.ExampleWhat, e lint.Example) bool {
	return e.Text == f.text
}
func (f fakeReview) MetaReviewed(r lint.RuleID) bool { return f.meta[r] }
func (f fakeReview) RuleReviewed(lint.RuleID) bool   { return false }

// TestCatalogReviewedByDocument: an entry is reviewed when the review says
// its example is, and a rule shows whether its Meta and itself are.
func TestCatalogReviewedByDocument(t *testing.T) {
	ex := lint.Example{Text: "# situation: s\n# reason: r\non: push\n"}
	other := lint.Example{Text: ex.Text + "jobs: {}\n"}
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	id := rules.CommitSHA.Meta().ID
	c, err := BuildCatalog(context.Background(), reg, []lint.ExampleCheck{
		{Rule: id, What: lint.ExampleTruePositive, Declaration: id, Example: ex, Holds: true},
		{Rule: id, What: lint.ExampleTruePositive, Declaration: id, Example: other, Holds: true},
	}, nil, fakeReview{text: ex.Text, meta: map[lint.RuleID]bool{id: true}})
	if err != nil {
		t.Fatal(err)
	}
	if es := c.Rules[0].Entries; !es[0].Reviewed || es[1].Reviewed {
		t.Errorf("reviewed: %v, %v", es[0].Reviewed, es[1].Reviewed)
	}
	if r := c.Rules[0]; !r.MetaReviewed || r.Reviewed {
		t.Errorf("rule: meta reviewed %v, reviewed %v", r.MetaReviewed, r.Reviewed)
	}
}

// TestCatalogOneRule: a catalog of one rule has the meta of that rule only.
func TestCatalogOneRule(t *testing.T) {
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	id := rules.CommitSHA.Meta().ID
	c, err := BuildCatalog(context.Background(), reg, reg.CheckExamples(context.Background(), id), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 1 || c.Rules[0].Rule != id || len(c.Rules[0].Meta) == 0 {
		t.Fatalf("the catalog of %s: %d rules", id, len(c.Rules))
	}
	page, err := c.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(page, []byte(`"meta":`)); n != 1 {
		t.Errorf("the page has %d metas, not the one of %s", n, id)
	}
}

// TestCatalogAllRules: each run has the page of every rule on its example
// with its facts, and both pages have every file of the example; on the undetected form no-line-break of envvar-injection,
// that page has the finding of code-injection the page of the rule has not.
func TestCatalogAllRules(t *testing.T) {
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	checks := reg.CheckExamples(ctx)
	c, err := BuildCatalog(ctx, reg, checks, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	kinds := func(p Page) []string {
		var out []string
		for _, f := range p.Findings {
			out = append(out, f.KindID)
		}
		return out
	}
	i, seen := 0, false
	for _, r := range c.Rules {
		for _, e := range r.Entries {
			x := checks[i]
			i++
			for j, run := range e.Runs {
				files := len(filesOfInputs(x.Runs[j].Inputs))
				if len(run.Page.Files) != files || len(run.AllRules.Files) != files {
					t.Errorf("%s %s run %d: %d and %d files in the pages, not the %d of the example", r.Rule, e.ID, j, len(run.Page.Files), len(run.AllRules.Files), files)
				}
				all, err := reg.RunExampleAs(ctx, x.Example, x.Runs[j])
				if err != nil {
					t.Fatal(err)
				}
				var got, want []string
				for _, f := range run.AllRules.Findings {
					got = append(got, f.Fingerprint.String())
				}
				for _, f := range all.Report.Findings {
					want = append(want, f.Fingerprint.String())
				}
				slices.Sort(got)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Errorf("%s %s run %d: the findings of every rule %v, with its facts %v", r.Rule, e.ID, j, got, want)
				}
			}
			if r.Rule == rules.EnvvarInjectionID && e.ID == "no-line-break" {
				seen = true
				const ci = "code-injection.controlled"
				if got := kinds(e.Runs[0].AllRules); !slices.Contains(got, ci) {
					t.Errorf("no-line-break: every rule gives %v, without %s", got, ci)
				}
				if got := kinds(e.Runs[0].Page); slices.Contains(got, ci) {
					t.Errorf("no-line-break: the rule's page has %s: %v", ci, got)
				}
			}
		}
	}
	if !seen {
		t.Error("no entry of the undetected form no-line-break of envvar-injection")
	}
}

func TestCatalogAttack(t *testing.T) {
	text := "# situation: s\n# reason: r\n# attack-value: github.event.issue.title = \"x\\ny\"\n# attack-run-behavior: b\non:\n  issues:\n    types: [opened]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n"
	n, err := lint.ParseExampleNotes(text)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	e := lint.Example{InputKind: lint.InputKindWorkflow, Name: facts.MustCleanInputPath("w.yml"), Text: text, Notes: n}
	rule := rules.CodeInjectionID
	c, err := BuildCatalog(context.Background(), reg, []lint.ExampleCheck{{Rule: rule, What: lint.ExampleTruePositive, Declaration: rule, Example: e, Holds: true}}, map[lint.RuleID]attackrun.Marker{rule: attackrun.MarkerStdout}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := c.Rules[0].Entries[0]
	if got.AttackCarrier != "github.event.issue.title" || got.AttackValue != "x\ny" || got.AttackRunBehavior != "b" || got.Checked != "run by a test" ||
		len(got.Substitutions) != 1 || got.Substitutions[0].Text != "echo x\ny" {
		t.Errorf("%+v", got)
	}
}

// TestCatalogFacets: the catalog has every axis of the facets with all its
// values, each with what it is, for the page to group the rules by.
func TestCatalogFacets(t *testing.T) {
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	c, err := BuildCatalog(context.Background(), reg, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	axes := lint.FacetAxes()
	if len(c.Facets) != len(axes) {
		t.Fatalf("%d facets, want %d", len(c.Facets), len(axes))
	}
	for i, a := range axes {
		f := c.Facets[i]
		if f.Facet != a.Facet || f.Key != a.Facet.Key() || f.Description == "" || len(f.Values) != len(a.Values) {
			t.Errorf("the facet %d is %+v, want %s with %d values", i, f, a.Facet, len(a.Values))
			continue
		}
		for j, v := range f.Values {
			if v.Value.String() != a.Values[j].String() || v.Description == "" {
				t.Errorf("%s: the value %d is %+v", a.Facet, j, v)
			}
		}
	}
	b, err := json.Marshal(c.Facets[0])
	if err != nil || !bytes.Contains(b, []byte(`"facet":"weakness","key":"weakness"`)) || !bytes.Contains(b, []byte(`{"value":"script-injection","description":`)) {
		t.Errorf("the facet is written %s, %v", b, err)
	}
}

// TestCatalogTerms: the catalog has the terms, and which of them a key of
// the meta of a rule has, by its registry path.
func TestCatalogTerms(t *testing.T) {
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	c, err := BuildCatalog(context.Background(), reg, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Terms struct {
			Definitions struct {
				ItemNames []struct{ Name, Text string } `json:"item_names"`
			} `json:"definitions"`
			Paths struct {
				ItemNames map[string]string `json:"item_names"`
				Values    map[string]string `json:"values"`
				Metrics   map[string]string `json:"metrics"`
			} `json:"paths"`
		} `json:"terms"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if n := len(got.Terms.Definitions.ItemNames); n == 0 || got.Terms.Definitions.ItemNames[0].Name != "commit" {
		t.Errorf("the item names of the catalog are %d, first %+v", n, got.Terms.Definitions.ItemNames)
	}
	if p := got.Terms.Paths; p.ItemNames["threat.actors.run_starters"] != "run starters" || p.Values["threat.actors.run_starters.run_starter"] != "run-starter" || p.Metrics["VC"] != "impact" {
		t.Errorf("the paths of the catalog are %+v", p)
	}
}

// TestCatalogArguments: a rule of the catalog has the arguments of each of
// its kinds, which the JSON of the registry does not have.
func TestCatalogArguments(t *testing.T) {
	reg, err := lint.NewRegistry(rules.All(), rules.Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	ci := lint.MustRuleID("code-injection")
	c, err := BuildCatalog(context.Background(), reg, reg.CheckExamples(context.Background(), ci), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 1 {
		t.Fatalf("rules %d, want 1", len(c.Rules))
	}
	as := c.Rules[0].Arguments[lint.MustFindingKindID("code-injection.controlled")]
	i := slices.IndexFunc(as, func(a CatalogArgument) bool { return a.Name.String() == "expr_ref" })
	if i < 0 || as[i].Text == "" || !as[i].InDetected {
		t.Errorf("code-injection.controlled: arguments %+v, want expr_ref with a text, in detected", as)
	}
	mt := lint.MustRuleID("missing-timeout-minutes")
	c, err = BuildCatalog(context.Background(), reg, reg.CheckExamples(context.Background(), mt), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 1 || !c.Rules[0].Quality {
		t.Fatalf("rules %+v, want the quality rule alone", c.Rules)
	}
	as = c.Rules[0].Arguments[lint.MustFindingKindID("missing-timeout-minutes.job")]
	if len(as) == 0 || as[0].Text == "" {
		t.Errorf("missing-timeout-minutes.job: arguments %+v", as)
	}
}

// TestCatalogRunFactLines: each run has the facts its rule asked, and those
// every rule asked on the example; on the undetected form pull-request of
// argument-injection, the rule asks none and another rule asks
// repo.default-token-write.
func TestCatalogRunFactLines(t *testing.T) {
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	checks := reg.CheckExamples(ctx, rules.ArgumentInjectionID, rules.CodeInjectionID)
	c, err := BuildCatalog(ctx, reg, checks, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	i, seen := 0, false
	for _, r := range c.Rules {
		for _, e := range r.Entries {
			x := checks[i]
			i++
			for j, run := range e.Runs {
				all, err := reg.RunExampleAs(ctx, x.Example, x.Runs[j])
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(run.FactLines, x.Runs[j].FactLines()) || !slices.Equal(run.AllFactLines, all.FactLines()) {
					t.Errorf("%s %s run %d: facts %q and %q", r.Rule, e.ID, j, run.FactLines, run.AllFactLines)
				}
			}
			if r.Rule == rules.ArgumentInjectionID && e.ID == "pull-request" {
				seen = true
				b, err := json.Marshal(e.Runs[0])
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(b, []byte(`"fact_lines":[]`)) || !slices.Contains(e.Runs[0].AllFactLines, "repo.default-token-write = true") {
					t.Errorf("pull-request: facts %q and %q", e.Runs[0].FactLines, e.Runs[0].AllFactLines)
				}
			}
		}
	}
	if !seen {
		t.Error("no entry of the undetected form pull-request of argument-injection")
	}
}

// TestCatalogAdvisories: the index has each advisory's page once, with
// each example whose notes cite it, its rule and whether it holds; an
// example of no advisory is in no row.
func TestCatalogAdvisories(t *testing.T) {
	const ghsl = "https://securitylab.github.com/advisories/GHSL-2026-229_ipdxco_unified-github-workflows/"
	const ghsa = "https://github.com/advisories/GHSA-mrrh-fwg8-r2c3"
	ex := func(name, advisories string) lint.Example {
		text := "# situation: s\n# reason: r\n" + advisories + "on: push\n"
		n, err := lint.ParseExampleNotes(text)
		if err != nil {
			t.Fatal(err)
		}
		return lint.Example{InputKind: lint.InputKindWorkflow, Name: facts.MustCleanInputPath(name), Text: text, Notes: n}
	}
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	a, b := rules.CommitSHA.Meta().ID, rules.ImpostorCommit.Meta().ID
	c, err := BuildCatalog(context.Background(), reg, []lint.ExampleCheck{
		{Rule: a, What: lint.ExampleTruePositive, Declaration: a, Example: ex("a.yml", "# advisory: "+ghsl+"\n# advisory: "+ghsa+"\n"), Holds: true},
		{Rule: a, What: lint.ExampleTruePositive, Declaration: a, Example: ex("none.yml", ""), Holds: true},
		{Rule: b, What: lint.ExampleUndetected, Declaration: b, Example: ex("b.yml", "# advisory: "+ghsl+"\n"), Holds: false},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Advisories) != 2 || c.Advisories[0].ID.String() != "GHSA-mrrh-fwg8-r2c3" || c.Advisories[1].URL.String() != ghsl {
		t.Fatalf("advisories %+v", c.Advisories)
	}
	es := c.Advisories[1].Entries
	if len(es) != 2 || es[0].Rule != a || es[0].Entry != 0 || es[0].Example != "a.yml" || !es[0].Holds || es[1].Rule != b || es[1].Entry != 0 || es[1].Holds || es[1].ID != b.String() {
		t.Errorf("entries of %s: %+v", ghsl, es)
	}
	page, err := c.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte(`"advisories":[{"id":"GHSA-mrrh-fwg8-r2c3"`)) {
		t.Error("the page has no index of the advisories")
	}
}

// TestCatalogAddedTruePositive: a true positive whose notes name an added
// attacker has the run that adds no attacker, with no finding of its rule,
// and the run that adds the attacker, named for the attacker, whose page
// of every rule has the finding of the kind.
func TestCatalogAddedTruePositive(t *testing.T) {
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, err := BuildCatalog(ctx, reg, reg.CheckExamples(ctx, rules.AIActionPromptInjectionID), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, r := range c.Rules {
		for _, e := range r.Entries {
			if e.Example != "env.maintainer-run-value.yml" {
				continue
			}
			seen = true
			if !e.Holds || len(e.Runs) != 2 || e.Runs[0].Facts != "answers" || e.Runs[1].Facts != "added attacker: variables-writer" {
				var names []string
				for _, run := range e.Runs {
					names = append(names, run.Facts)
				}
				t.Fatalf("holds %v (%s), runs %q", e.Holds, e.Why, names)
			}
			if len(e.Runs[0].Page.Findings) != 0 || len(e.Runs[1].Page.Findings) == 0 || len(e.Runs[1].AllRules.Findings) == 0 {
				t.Errorf("findings: %d, %d, with every rule %d", len(e.Runs[0].Page.Findings), len(e.Runs[1].Page.Findings), len(e.Runs[1].AllRules.Findings))
			}
		}
	}
	if !seen {
		t.Error("no entry of env.maintainer-run-value.yml")
	}
}
