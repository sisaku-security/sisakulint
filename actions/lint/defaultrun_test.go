package lint

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// defaultRuns is a registry of a-rule (always), test (a quality rule of
// DefaultRunNamed), facts (a rule of DefaultRunFacts of
// package.advisories) and given (a rule of DefaultRunGivenFacts of
// repo.action-list).
func defaultRuns(t *testing.T) *Registry {
	t.Helper()
	q := goodQualityMeta()
	q.DefaultRun = DefaultRunNamed()
	f := meta("facts")
	f.DefaultRun = DefaultRunFacts(facts.KindPackageAdvisories)
	g := meta("given")
	g.DefaultRun = DefaultRunGivenFacts(facts.KindRepoActionList)
	reg, err := newRegistry([]Rule{testRule{meta: meta("a-rule")}, testRule{meta: f}, testRule{meta: g}}, true, testQuality{m: q})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// TestSelectDefaultRun: the zero Selection and Skip leave out the rules
// whose DefaultRun does not hold, and Select remembers them; Only runs what
// it names whatever the DefaultRun, and leaves out the others as named
// out.
func TestSelectDefaultRun(t *testing.T) {
	reg := defaultRuns(t)
	a, n, f, g := MustRuleID("a-rule"), MustRuleID("test"), MustRuleID("facts"), MustRuleID("given")
	online := FactSources{Online: true}
	answered := FactSources{AnsweredKinds: []facts.Kind{facts.KindPackageAdvisories}}
	listed := FactSources{Online: true, AnsweredKinds: []facts.Kind{facts.KindRepoActionList}}
	for _, c := range []struct {
		name      string
		s         Selection
		src       FactSources
		runs      []RuleID // in the order of IDs; nil: no rule is left, an error
		byDefault []RuleID
	}{
		{"every rule, offline", Selection{}, FactSources{}, []RuleID{a}, []RuleID{f, g, n}},
		{"every rule, online", Selection{}, online, []RuleID{a, f}, []RuleID{g, n}},
		{"every rule, answered", Selection{}, answered, []RuleID{a, f}, []RuleID{g, n}},
		{"every rule, online and the list answered", Selection{}, listed, []RuleID{a, f, g}, []RuleID{n}},
		{"Only given, offline", Only(Selector{g}), FactSources{}, []RuleID{g}, nil},
		{"Skip a-rule, offline", Skip(Selector{a}), FactSources{}, nil, nil},
		{"Skip facts, online", Skip(Selector{f}), online, []RuleID{a}, []RuleID{g, n}},
		{"Skip named, offline", Skip(Selector{n}), FactSources{}, []RuleID{a}, []RuleID{f, g}},
		{"Only facts, offline", Only(Selector{f}), FactSources{}, []RuleID{f}, nil},
		{"Only named", Only(Selector{n}), FactSources{}, []RuleID{n}, nil},
		{"Only a-rule, offline", Only(Selector{a}), FactSources{}, []RuleID{a}, nil},
		{"Only named and a-rule", Only(Selector{n}, Selector{a}), FactSources{}, []RuleID{a, n}, nil},
	} {
		got, err := reg.Select(c.s, c.src)
		if c.runs == nil {
			if err == nil {
				t.Errorf("%s: no error though no rule is left", c.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var runs, byDefault []RuleID
		for _, rule := range got.Rules() {
			runs = append(runs, rule.Meta().ID)
		}
		for _, q := range got.QualityRules() {
			runs = append(runs, q.QualityMeta().ID)
		}
		slices.SortFunc(runs, func(x, y RuleID) int { return strings.Compare(x.s, y.s) })
		for _, id := range got.Skipped() {
			if got.NotRunByDefault(id) {
				byDefault = append(byDefault, id)
			}
		}
		if !slices.Equal(runs, c.runs) || !slices.Equal(byDefault, c.byDefault) {
			t.Errorf("%s: runs %v, by default %v; want %v, %v", c.name, runs, byDefault, c.runs, c.byDefault)
		}
	}
}

// TestRegistryDefaultRun: DefaultRun answers for the rules a registry has
// and for those Select left out; the registry of NewRegistry has every
// rule, and a Select of what Select gave keeps what it left out by default.
func TestRegistryDefaultRun(t *testing.T) {
	reg := defaultRuns(t)
	if !reg.IsQuality(MustRuleID("test")) || len(reg.Rules()) != 3 {
		t.Errorf("NewRegistry: quality %v, rules %d; want the named quality rule and three rules", reg.IsQuality(MustRuleID("test")), len(reg.Rules()))
	}
	sel, err := reg.Select(Selection{}, FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	again, err := sel.Select(Skip(), FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	if !again.NotRunByDefault(MustRuleID("facts")) || !again.NotRunByDefault(MustRuleID("test")) {
		t.Errorf("Select of Select: not run by default %v, %v; want both", again.NotRunByDefault(MustRuleID("facts")), again.NotRunByDefault(MustRuleID("test")))
	}
	if !sel.DefaultRun(MustRuleID("test")).IsNamed() {
		t.Error("test: not DefaultRunNamed after Select")
	}
	if _, ok := sel.DefaultRun(MustRuleID("facts")).FactKinds(); !ok {
		t.Error("facts: not DefaultRunFacts after Select")
	}
	if k, ok := sel.DefaultRun(MustRuleID("given")).FactKinds(); !ok || !slices.Equal(k, []facts.Kind{facts.KindRepoActionList}) {
		t.Errorf("given: FactKinds %v, %v after Select", k, ok)
	}
	if d := sel.DefaultRun(MustRuleID("a-rule")); d.IsNamed() {
		t.Error("a-rule: not always")
	} else if _, ok := d.FactKinds(); ok {
		t.Error("a-rule: not always")
	}
}

// TestRegistryJSONDefaultRun: the registry gives default_run of every rule
// and quality rule, and default_run_fact_kinds of facts only, as the schema
// says.
func TestRegistryJSONDefaultRun(t *testing.T) {
	b, err := defaultRuns(t).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas(t).Validate("registry-v0.json", "#", b); err != nil {
		t.Errorf("%v\n%s", err, b)
	}
	var doc struct {
		Rules   []map[string]json.RawMessage `json:"rules"`
		Quality []map[string]json.RawMessage `json:"quality_rules"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range append(doc.Rules, doc.Quality...) {
		var id string
		if err := json.Unmarshal(r["id"], &id); err != nil {
			t.Fatal(err)
		}
		got[id] = string(r["default_run"]) + " " + string(r["default_run_fact_kinds"])
	}
	want := map[string]string{"a-rule": `"always" `, "facts": `"facts" ["package.advisories"]`, "given": `"given-facts" ["repo.action-list"]`, "test": `"named" `}
	if !maps.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
}

// TestNewRegistryDefaultRun: NewRegistry checks the DefaultRun of a rule
// and of a quality rule.
func TestNewRegistryDefaultRun(t *testing.T) {
	m := meta("facts")
	m.DefaultRun = DefaultRunFacts(facts.KindPackageAdvisories, facts.KindPackageAdvisories)
	if _, err := newRegistry([]Rule{testRule{meta: m}}, true); err == nil {
		t.Error("a rule: a kind twice is not an error")
	}
	q := goodQualityMeta()
	q.DefaultRun = m.DefaultRun
	if _, err := newRegistry(nil, true, testQuality{m: q}); err == nil {
		t.Error("a quality rule: a kind twice is not an error")
	}
}

// TestExplainDefaultRun: --explain gives the line of the DefaultRun of
// every rule and quality rule: its value, then its sentence.
func TestExplainDefaultRun(t *testing.T) {
	out, err := defaultRuns(t).Explain(nil, "c")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		nDefaultRun.is(`always: ` + md(DefaultRun{}.Text())),
		nDefaultRun.is(`named: ` + md(DefaultRunNamed().Text())),
		nDefaultRun.is(`facts: ` + md(DefaultRunFacts(facts.KindPackageAdvisories).Text())),
		nDefaultRun.is(`given-facts: ` + md(DefaultRunGivenFacts(facts.KindRepoActionList).Text())),
	} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q:\n%s", want, s)
		}
	}
	if n := strings.Count(s, nDefaultRun.name+": "); n != 4 {
		t.Errorf("%d lines of the default run, want 4:\n%s", n, s)
	}
}

// TestDefaultRunHolds: always holds in every run, named in none, and facts
// with --online or with an answer of one of its kinds.
func TestDefaultRunHolds(t *testing.T) {
	adv, tags := facts.KindPackageAdvisories, facts.KindGitCommitTags
	for _, c := range []struct {
		name string
		d    DefaultRun
		src  FactSources
		want bool
	}{
		{"always, offline", DefaultRun{}, FactSources{}, true},
		{"named, online", DefaultRunNamed(), FactSources{Online: true}, false},
		{"facts, offline", DefaultRunFacts(adv), FactSources{}, false},
		{"facts, online", DefaultRunFacts(adv), FactSources{Online: true}, true},
		{"facts, its kind answered", DefaultRunFacts(adv), FactSources{AnsweredKinds: []facts.Kind{tags, adv}}, true},
		{"facts, another kind answered", DefaultRunFacts(adv), FactSources{AnsweredKinds: []facts.Kind{tags}}, false},
		{"facts of two kinds, the second answered", DefaultRunFacts(tags, adv), FactSources{AnsweredKinds: []facts.Kind{adv}}, true},
		{"given facts, offline", DefaultRunGivenFacts(adv), FactSources{}, false},
		{"given facts, online alone", DefaultRunGivenFacts(adv), FactSources{Online: true}, false},
		{"given facts, its kind answered", DefaultRunGivenFacts(adv), FactSources{AnsweredKinds: []facts.Kind{adv}}, true},
		{"given facts, online and its kind answered", DefaultRunGivenFacts(adv), FactSources{Online: true, AnsweredKinds: []facts.Kind{tags, adv}}, true},
		{"given facts, another kind answered", DefaultRunGivenFacts(adv), FactSources{Online: true, AnsweredKinds: []facts.Kind{tags}}, false},
	} {
		if got := c.d.holds(c.src); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestDefaultRunCheck: the kinds of facts are kinds, each once.
func TestDefaultRunCheck(t *testing.T) {
	adv := facts.KindPackageAdvisories
	for _, c := range []struct {
		name string
		d    DefaultRun
		ok   bool
	}{
		{"always", DefaultRun{}, true},
		{"named", DefaultRunNamed(), true},
		{"facts", DefaultRunFacts(adv), true},
		{"a kind twice", DefaultRunFacts(adv, adv), false},
		{"not a kind", DefaultRunFacts(facts.Kind(250)), false},
		{"given facts", DefaultRunGivenFacts(adv), true},
		{"given facts, a kind twice", DefaultRunGivenFacts(adv, adv), false},
	} {
		if err := c.d.check(); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestDefaultRunText: the sentence --explain and the text give.
func TestDefaultRunText(t *testing.T) {
	if got := (DefaultRun{}).Text(); got != "in a run without --rule, the rule runs unless --skip-rule names the rule" {
		t.Errorf("always: %q", got)
	}
	if got, want := DefaultRunNamed().Text(), "the rule runs only when --rule names the rule"; got != want {
		t.Errorf("named: %q", got)
	}
	got := DefaultRunFacts(facts.KindPackageAdvisories, facts.KindGitCommitTags).Text()
	want := "the rule runs, with all its kinds of findings (also those that need no fact), when --rule names the rule; in a run without --rule, the rule runs when --online is given, or when --facts or --fact gives a found or absent answer to any fact of package.advisories or git.commit-tags"
	if got != want {
		t.Errorf("facts: %q", got)
	}
	got = DefaultRunGivenFacts(facts.KindRepoActionList).Text()
	want = "the rule runs, with all its kinds of findings, when --rule names the rule; in a run without --rule, the rule runs only when --facts or --fact (also the key facts or fact of a configuration file) answers the fact repo.action-list with found (a value) or with absent (an answer, written in a file of facts or in --fact, that the fact does not exist); a fact that the file of facts and --fact leave out has no answer, and then the rule does not run, and --online alone does not make the rule run either"
	if got != want {
		t.Errorf("given facts: %q", got)
	}
}
