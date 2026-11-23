package lint

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestDefinitionsOrder: the value groups are in the order Terms writes
// them.
func TestDefinitionsOrder(t *testing.T) {
	var got []string
	for _, g := range Definitions().ValueGroups {
		got = append(got, g.ID.String())
	}
	want := []string{"attacker", "run-starter", "gain", "weakness", "attack-means", "disposition", "need", "added-attacker", "decider", "safety", "severity", "likelihood", "input-kind", "fact-kind",
		"attack-vector", "attack-complexity", "attack-requirements", "privileges-required", "user-interaction", "impact", "exploit-maturity", "score-rating"}
	if !slices.Equal(got, want) {
		t.Errorf("the value groups are\n%q\nwant\n%q", got, want)
	}
	d := Definitions()
	if len(d.ItemNames) != len(itemNames) || d.ItemNames[0].Name != "commit" {
		t.Errorf("the item names are %d, first %q", len(d.ItemNames), d.ItemNames[0].Name)
	}
	if len(d.TextTerms) != len(textTerms) || d.TextTerms[0].Name != "privileged event" {
		t.Errorf("the text terms are %d, first %q", len(d.TextTerms), d.TextTerms[0].Name)
	}
}

// TestValueGroupIDsAreDefs: the ID of each value group is the name of a
// definition of schema/registry-v0.json.
func TestValueGroupIDsAreDefs(t *testing.T) {
	b, err := os.ReadFile("schema/registry-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	for _, g := range Definitions().ValueGroups {
		if _, ok := s.Defs[g.ID.String()]; !ok {
			t.Errorf("the value group %s is no $defs of registry-v0.json", g.ID)
		}
		if len(g.Values) == 0 {
			t.Errorf("the value group %s has no values", g.ID)
		}
	}
}

// TestDefinitionsFactKindItems: each kind of fact says where its facts
// come from, whether --online answers them, and the assumed value.
func TestDefinitionsFactKindItems(t *testing.T) {
	items := map[string][]string{}
	for _, g := range Definitions().ValueGroups {
		if g.ID == vgFactKind {
			for _, v := range g.Values {
				items[v.Name] = v.Items
			}
		}
	}
	for _, c := range []struct {
		kind string
		want []string
	}{
		{"repo.public", []string{"provider: repo-setting: ", "--online answers a fact of the kind only when", "assumed value: true ("}},
		{"repo.allow-forking", []string{"provider: repo-setting: ", "--online answers a fact of the kind only when", "assumed value: none"}},
		{"git.commit-ref", []string{"provider: github: ", "--online answers the facts of the kind", "assumed value: none"}},
		{"checkout.executed", []string{"provider: user-supplied: ", "--online does not answer the facts of the kind", "assumed value: true ("}},
	} {
		got := items[c.kind]
		if len(got) != len(c.want) {
			t.Errorf("%s: items %q, want %d", c.kind, got, len(c.want))
			continue
		}
		for i, w := range c.want {
			if !strings.HasPrefix(got[i], w) {
				t.Errorf("%s: item %d %q, want it to start with %q", c.kind, i, got[i], w)
			}
		}
	}
}

// TestDefinitionsFactKindOnline: the line of --online says the condition of
// a kind that --online answers only of a named repository, or only false.
func TestDefinitionsFactKindOnline(t *testing.T) {
	lines := map[string]string{}
	for _, g := range Definitions().ValueGroups {
		if g.ID == vgFactKind {
			for _, v := range g.Values {
				lines[v.Name] = v.Items[1]
			}
		}
	}
	for kind, want := range map[string]string{
		"git.commit-ref":    "--online answers the facts of the kind",
		"repo.public":       "--online answers a fact of the kind only when the fact names a repository (--repo)",
		"repo.wiki-open":    "--online answers a fact of the kind only when the fact names a repository (--repo), and only when the answer is false",
		"checkout.executed": "--online does not answer the facts of the kind",
	} {
		if lines[kind] != want {
			t.Errorf("%s: %q, want %q", kind, lines[kind], want)
		}
	}
}
