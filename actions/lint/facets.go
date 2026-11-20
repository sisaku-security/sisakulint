package lint

import "fmt"

// Weakness is the kind of flaw of a workflow through which what an
// attacker does becomes harm: an axis of Facets. Its values and what they
// mean are the oneOf of $defs/weakness in schema/registry-v0.json
// (enum_gen.go).
type Weakness uint8

// AttackMeans is what an attacker puts into the run: an axis of Facets.
// Its values and what they mean are the oneOf of $defs/attack-means in
// schema/registry-v0.json (enum_gen.go).
type AttackMeans uint8

// Facet is an axis of Facets: which way a rule is sorted. Its values,
// Facets, Axes and FacetValue are generated from $defs/facets of
// schema/registry-v0.json (enum_gen.go), the one place that names the
// axes.
type Facet uint8

// FacetAxes are the axes, each with all its values, in the order of the
// schema.
func FacetAxes() []FacetAxis { return facetsAll().Axes() }

// checkFacets checks that m has a value on each axis, each once, and no
// value that is not one.
func checkFacets(m Meta) error {
	for _, a := range m.Facets.Axes() {
		if len(a.Values) == 0 {
			return fmt.Errorf("no value of the facet %s; a rule says where it sorts on each axis", a.Facet)
		}
		for i, v := range a.Values {
			if !v.valid() {
				return fmt.Errorf("%v is not a value of the facet %s", v, a.Facet)
			}
			for _, w := range a.Values[:i] {
				if w.String() == v.String() {
					return fmt.Errorf("the facet %s has %s twice", a.Facet, v)
				}
			}
		}
	}
	return nil
}
