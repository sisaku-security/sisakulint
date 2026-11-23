package lint

import (
	"slices"
	"strings"
	"testing"
)

// TestFacetsAxes: Axes gives each axis, in the order of FacetAxes, with
// the values the rule has; an axis is written by its key.
func TestFacetsAxes(t *testing.T) {
	f := Facets{Weakness: []Weakness{WeaknessAgentHijack, WeaknessGateBypass}, AttackMeans: []AttackMeans{AttackMeansString}}
	var got []string
	for _, a := range f.Axes() {
		var vs []string
		for _, v := range a.Values {
			vs = append(vs, v.String())
		}
		got = append(got, a.Facet.Key()+"="+strings.Join(vs, ","))
	}
	if want := []string{"weakness=agent-hijack,gate-bypass", "attack_means=string"}; !slices.Equal(got, want) {
		t.Errorf("Axes: %v, want %v", got, want)
	}
	for i, a := range FacetAxes() {
		if a.Facet != f.Axes()[i].Facet || len(a.Values) == 0 || a.Facet.Description() == "" {
			t.Errorf("the axis %d of FacetAxes is %s with %d values and the description %q", i, a.Facet, len(a.Values), a.Facet.Description())
		}
	}
	if b, err := FacetAttackMeans.MarshalJSON(); err != nil || string(b) != `"attack-means"` {
		t.Errorf("FacetAttackMeans is written %s, %v", b, err)
	}
}

// TestNewRegistryFacets: a rule needs a value on each axis, each once, and
// no unset value.
func TestNewRegistryFacets(t *testing.T) {
	for _, c := range []struct {
		name   string
		facets Facets
		want   string
	}{
		{"no weakness", Facets{AttackMeans: []AttackMeans{AttackMeansNone}}, "no value of the facet weakness"},
		{"no attack means", Facets{Weakness: []Weakness{WeaknessCredentialLeak}}, "no value of the facet attack-means"},
		{"twice", Facets{Weakness: []Weakness{WeaknessCredentialLeak, WeaknessCredentialLeak}, AttackMeans: []AttackMeans{AttackMeansNone}}, "the facet weakness has credential-leak twice"},
		{"unset", Facets{Weakness: []Weakness{WeaknessUnset}, AttackMeans: []AttackMeans{AttackMeansNone}}, "is not a value of the facet weakness"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := meta("a")
			m.Facets = c.facets
			_, err := newRegistry([]Rule{testRule{meta: m}}, true)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("NewRegistry: %v, want %q", err, c.want)
			}
		})
	}
	if _, err := newRegistry([]Rule{testRule{meta: meta("a")}}, true); err != nil {
		t.Errorf("the facets of meta: %v", err)
	}
}
