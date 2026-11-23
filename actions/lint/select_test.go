package lint

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

func threeRules(t *testing.T) *Registry {
	t.Helper()
	reg, err := newRegistry([]Rule{testRule{meta: meta("a-rule")}, testRule{meta: meta("b-rule")}, testRule{meta: meta("c-rule")}}, true)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func sel(t *testing.T, ids ...string) []Selector {
	t.Helper()
	var out []Selector
	for _, id := range ids {
		s, err := ParseSelector(id)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func idsOf(reg *Registry) []string {
	var out []string
	for _, r := range reg.Rules() {
		out = append(out, r.Meta().ID.String())
	}
	return out
}

func strsOf(ids []RuleID) []string {
	var out []string
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

func TestParseSelector(t *testing.T) {
	if _, err := ParseSelector("commit-sha"); err != nil {
		t.Errorf("a rule's ID: %v", err)
	}
	for s, want := range map[string]string{
		"commit-sha.unpinned": "a kind of finding is not taken yet",
		"Commit-SHA":          "not kebab-case",
		"":                    "not kebab-case",
		"a b":                 "not kebab-case",
	} {
		if _, err := ParseSelector(s); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want an error with %q", s, err, want)
		}
	}
}

func TestSelect(t *testing.T) {
	reg := threeRules(t)
	for _, c := range []struct {
		name         string
		s            Selection
		ran, skipped []string
	}{
		{"none", Selection{}, []string{"a-rule", "b-rule", "c-rule"}, nil},
		{"only", Only(sel(t, "c-rule", "a-rule")...), []string{"a-rule", "c-rule"}, []string{"b-rule"}},
		{"skip", Skip(sel(t, "b-rule")...), []string{"a-rule", "c-rule"}, []string{"b-rule"}},
		{"twice", Skip(sel(t, "b-rule", "b-rule")...), []string{"a-rule", "c-rule"}, []string{"b-rule"}},
	} {
		got, err := reg.Select(c.s, FactSources{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !slices.Equal(idsOf(got), c.ran) || !slices.Equal(strsOf(got.Skipped()), c.skipped) {
			t.Errorf("%s: ran %v, skipped %v; want %v, %v", c.name, idsOf(got), strsOf(got.Skipped()), c.ran, c.skipped)
		}
		for _, id := range c.skipped {
			if _, ok := got.Meta(MustRuleID(id)); ok {
				t.Errorf("%s: Meta of %s, which is skipped", c.name, id)
			}
		}
	}
	if len(idsOf(reg)) != 3 || len(reg.Skipped()) != 0 {
		t.Error("Select changed the registry it was called on")
	}
}

func TestSelectRejects(t *testing.T) {
	reg := threeRules(t)
	if _, err := reg.Select(Only(sel(t, "nope")...), FactSources{}); err == nil || !strings.Contains(err.Error(), `no rule has the ID "nope" (the rules are a-rule, b-rule, c-rule)`) {
		t.Errorf("an unknown ID: %v", err)
	}
	if _, err := reg.Select(Skip(sel(t, "a-rule", "b-rule", "c-rule")...), FactSources{}); err == nil || !strings.Contains(err.Error(), "no rule is left to run") {
		t.Errorf("no rule left: %v", err)
	}
	once, err := reg.Select(Skip(sel(t, "a-rule")...), FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := once.Select(Skip(sel(t, "a-rule")...), FactSources{}); err == nil {
		t.Error("an ID skipped already is not in the registry, so it is unknown")
	}
	twice, err := once.Select(Skip(sel(t, "b-rule")...), FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strsOf(twice.Skipped()); !slices.Equal(got, []string{"a-rule", "b-rule"}) {
		t.Errorf("skipped twice: %v", got)
	}
}

func TestRunSkipped(t *testing.T) {
	reg, err := threeRules(t).Select(Skip(sel(t, "b-rule")...), FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	in, err := Single(InputBytes{Name: facts.MustCleanInputPath(wfPath), Bytes: []byte(twoSteps)})
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), in, reg, mapResolver{})
	if got := strsOf(rep.SkippedRules); !slices.Equal(got, []string{"b-rule"}) {
		t.Errorf("Report.Skipped %v", got)
	}
	b, err := rep.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"skipped_rules":["b-rule"]`) {
		t.Errorf("no skipped_rules in %s", b)
	}
	if err := schemas(t).Validate("report-v0.json", "#", b); err != nil {
		t.Errorf("the report does not fit report-v0.json: %v", err)
	}
}

func TestRunDoesNotAskForSkipped(t *testing.T) {
	asker := func(id string) Rule {
		m := asking(meta(id), facts.KindTestFlag)
		return testRule{meta: m, check: func(ctx context.Context, c *RuleContext) error {
			facts.TestFlag{Name: id}.Ask(ctx, c.Resolver)
			return nil
		}}
	}
	full, err := newRegistry([]Rule{asker("a-rule"), asker("b-rule")}, true)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := full.Select(Skip(sel(t, "b-rule")...), FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	in, err := Single(InputBytes{Name: facts.MustCleanInputPath(wfPath), Bytes: []byte(twoSteps)})
	if err != nil {
		t.Fatal(err)
	}
	c := &counting{}
	Run(context.Background(), in, reg, c)
	if c.n != 1 {
		t.Errorf("asked %d facts, want 1: the skipped rule asks nothing", c.n)
	}
}
