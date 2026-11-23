package lint

import (
	"encoding/json"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestItemNamesHavePaths: each item name has paths in the JSON of a rule,
// or is among those without, and not both.
func TestItemNamesHavePaths(t *testing.T) {
	has := map[string]bool{}
	for _, x := range itemNamePaths {
		if len(x.paths) == 0 {
			t.Errorf("the item name %s has no paths in itemNamePaths", x.n.name)
		}
		has[x.n.name] = true
	}
	without := map[string]bool{}
	for _, x := range itemNamesWithoutPath {
		without[x.n.name] = true
		if has[x.n.name] {
			t.Errorf("the item name %s has paths and is among those without", x.n.name)
		}
	}
	for _, n := range itemNames {
		if !has[n.name] && !without[n.name] {
			t.Errorf("the item name %s has no paths and is not among those without (itemNamePaths, itemNamesWithoutPath)", n.name)
		}
	}
}

// schemaPaths are the registry paths of $defs/meta of
// schema/registry-v0.json, through $ref, oneOf, anyOf, allOf, items and
// properties, without the examples; under each, the value groups its
// values refer to by $ref ($defs of Definitions), and the metrics (the
// const of a sibling key metric) under which each is. consts are the
// values a path takes by const (the disposition of each kind of form, the
// names of the metrics). A keyword the walk does not follow, by which the
// schema could have keys the walk misses, fails the test.
func schemaPaths(t *testing.T) (refs map[string]map[string][]string, consts map[string][]string) {
	// defs are the definitions of the registry's schema and of the facts'
	// schema it refers to, by the prefix of a $ref
	defs := map[string]map[string]map[string]any{}
	for prefix, file := range map[string]string{"#/$defs/": "schema/registry-v0.json", "facts-v0.json#/$defs/": "../facts/schema/facts-v0.json"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var s struct {
			Defs map[string]map[string]any `json:"$defs"`
		}
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		defs[prefix] = s.Defs
	}
	groups := map[string]bool{}
	for _, g := range Definitions().ValueGroups {
		groups[g.ID.String()] = true
	}
	out := map[string]map[string][]string{} // path -> value group -> metrics
	consts = map[string][]string{}
	skip := map[string]bool{"examples": true, "true_positives": true, "true_negatives": true}
	// narrow is, by property, the values an enum of the same object lets
	// the property take: a branch of oneOf whose const of the property is
	// not among them is a key the object never has
	var walk func(node map[string]any, p RegistryPath, metric string, narrow map[string][]string, depth int)
	walk = func(node map[string]any, p RegistryPath, metric string, narrow map[string][]string, depth int) {
		if depth > 30 {
			t.Fatalf("the schema is deeper than 30 at %s", p)
		}
		for _, k := range []string{"patternProperties", "if", "then", "else", "not", "prefixItems", "dependentSchemas"} {
			if _, ok := node[k]; ok {
				t.Fatalf("the schema has %s at %s, which the walk does not follow", k, p)
			}
		}
		for _, k := range []string{"additionalProperties", "unevaluatedProperties"} {
			// false closes the object: the walk sees every key the
			// properties of the node and of its $ref and oneOf give
			if a, ok := node[k]; ok && a != false {
				t.Fatalf("the schema has %s %v at %s, which the walk does not follow", k, a, p)
			}
		}
		var target map[string]any
		if ref, ok := node["$ref"].(string); ok {
			for prefix, ds := range defs {
				if name, ok := strings.CutPrefix(ref, prefix); ok {
					target = ds[name]
				}
			}
			if target == nil {
				t.Fatalf("the schema refers to %s at %s, which the walk does not find", ref, p)
			}
		}
		if c, ok := node["const"].(string); ok && p.keys != "" {
			consts[p.keys] = append(consts[p.keys], c)
		}
		if ref, ok := node["$ref"].(string); ok {
			name := strings.TrimPrefix(ref, "#/$defs/")
			if groups[name] && p.keys != "" {
				if out[p.keys] == nil {
					out[p.keys] = map[string][]string{}
				}
				out[p.keys][name] = append(out[p.keys][name], metric)
			}
			walk(target, p, metric, narrowed(node, narrow), depth+1)
		}
		for _, k := range []string{"oneOf", "anyOf", "allOf"} {
			for _, x := range asList(node[k]) {
				if !excluded(x, narrowed(node, narrow)) {
					walk(x, p, metric, narrowed(node, narrow), depth+1)
				}
			}
		}
		if items, ok := node["items"].(map[string]any); ok {
			walk(items, p, metric, nil, depth+1)
		}
		props, _ := node["properties"].(map[string]any)
		m := metric
		if mp, ok := props["metric"].(map[string]any); ok {
			if c, ok := mp["const"].(string); ok {
				m = c
			}
		}
		for k, v := range props {
			if skip[k] {
				continue
			}
			c := p.child(k)
			if out[c.keys] == nil {
				out[c.keys] = map[string][]string{}
			}
			walk(v.(map[string]any), c, m, nil, depth+1)
		}
	}
	walk(defs["#/$defs/"]["meta"], RegistryPath{}, "", nil, 0)
	return out, consts
}

// narrowed is narrow with the enums of the properties of node.
func narrowed(node map[string]any, narrow map[string][]string) map[string][]string {
	props, _ := node["properties"].(map[string]any)
	out := map[string][]string{}
	for k, v := range narrow {
		out[k] = v
	}
	for k, v := range props {
		if e, ok := v.(map[string]any)["enum"].([]any); ok {
			var vs []string
			for _, x := range e {
				if s, ok := x.(string); ok {
					vs = append(vs, s)
				}
			}
			out[k] = vs
		}
	}
	return out
}

// excluded is whether the branch x of a oneOf has a const of a property
// that narrow leaves out.
func excluded(x map[string]any, narrow map[string][]string) bool {
	props, _ := x["properties"].(map[string]any)
	for k, vs := range narrow {
		p, _ := props[k].(map[string]any)
		if c, ok := p["const"].(string); ok && !slices.Contains(vs, c) {
			return true
		}
	}
	return false
}

func asList(v any) []map[string]any {
	xs, _ := v.([]any)
	var out []map[string]any
	for _, x := range xs {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// TestTermPathsCoverSchema: each registry path of the schema has an item
// name, a value group or an axis, or is among the paths without an item
// name; each path of the tables is in the schema; and the schema's paths
// take in every path of the rules of the registry's golden JSON.
func TestTermPathsCoverSchema(t *testing.T) {
	ps, _ := schemaPaths(t)
	if len(ps) == 0 {
		t.Fatal("the schema has no paths")
	}
	tp := TermPathsOf()
	known := func(p string) bool {
		_, n := tp.ItemNames[registryPath(p)]
		_, v := tp.Values[registryPath(p)]
		_, a := tp.Axes[registryPath(p)]
		return n || v || a || withoutItemName(registryPath(p)) != ""
	}
	var missing []string
	for p := range ps {
		if !known(p) {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	for _, p := range missing {
		t.Errorf("the registry path %s has no item name, value group or axis, and is not among pathsWithoutItemName", p)
	}
	var tables []string
	for p := range tp.ItemNames {
		tables = append(tables, p.keys)
	}
	for p := range tp.Values {
		tables = append(tables, p.keys)
	}
	for p := range tp.Axes {
		tables = append(tables, p.keys)
	}
	for _, x := range pathsWithoutItemName {
		tables = append(tables, x.p)
	}
	for _, p := range tables {
		if _, ok := ps[p]; !ok {
			t.Errorf("the registry path %s of the tables is not in schema/registry-v0.json", p)
		}
	}
	b, err := os.ReadFile("../rules/testdata/registry.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Rules []any `json:"rules"`
	}
	if err := json.Unmarshal(b, &reg); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var collect func(v any, p RegistryPath)
	collect = func(v any, p RegistryPath) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if k == "examples" || k == "true_positives" || k == "true_negatives" {
					continue
				}
				seen[p.child(k).keys] = true
				collect(c, p.child(k))
			}
		case []any:
			for _, c := range x {
				collect(c, p)
			}
		}
	}
	for _, r := range reg.Rules {
		collect(r, RegistryPath{})
	}
	for p := range seen {
		if _, ok := ps[p]; !ok {
			t.Errorf("the path %s of the registry's golden JSON is not among the paths found in the schema", p)
		}
	}
}

// TestTermPathsValueRefs: a path whose values refer by $ref to the
// definition of a value group has that value group (an axis for a facet,
// by the metric for a CVSS metric); and a path of a value group refers to
// it, or takes only values of it by const.
func TestTermPathsValueRefs(t *testing.T) {
	tp := TermPathsOf()
	all, consts := schemaPaths(t)
	metrics := map[string]string{}
	for m, g := range tp.Metrics {
		metrics[m.String()] = g.String()
	}
	for p, refs := range all {
		for def, ms := range refs {
			for _, metric := range ms {
				switch {
				case metric != "" && p == "finding_kinds.cvss.metrics.value":
					if got := metrics[metric]; got != def {
						t.Errorf("the metric %s refers to %s, but Metrics has %q", metric, def, got)
					}
				case tp.Axes[registryPath(p)].String() == def, tp.Values[registryPath(p)].String() == def:
				default:
					t.Errorf("the values of %s refer to %s, but the path has the value group %q", p, def, tp.Values[registryPath(p)])
				}
			}
		}
	}
	names := consts["finding_kinds.cvss.metrics.metric"]
	sort.Strings(names)
	var keys []string
	for m := range metrics {
		keys = append(keys, m)
	}
	sort.Strings(keys)
	if strings.Join(names, ",") != strings.Join(keys, ",") {
		t.Errorf("the metrics of the schema are %v, but Metrics has %v", names, keys)
	}
	values := map[string]map[string]bool{}
	for _, g := range Definitions().ValueGroups {
		values[g.ID.String()] = map[string]bool{}
		for _, v := range g.Values {
			values[g.ID.String()][v.Name] = true
		}
	}
	for p, g := range tp.Values {
		if _, ok := all[p.keys][g.String()]; ok {
			continue
		}
		cs := consts[p.keys]
		if len(cs) == 0 {
			t.Errorf("the path %s has the value group %s, but its values do not refer to it in the schema", p, g)
		}
		for _, c := range cs {
			if !values[g.String()][c] {
				t.Errorf("the path %s takes %q by const, which is no value of its value group %s", p, c, g)
			}
		}
	}
}

// TestTermPathsExamples: some lookups by the meaning of the key.
func TestTermPathsExamples(t *testing.T) {
	tp := TermPathsOf()
	for p, want := range map[string]string{
		"threat.preconditions": "precondition", "finding_kinds.preconditions": "preconditions", "finding_kinds.cvss.b": "CVSS-B",
		"threat.actors.run_starters": "run starters", "default_run_fact_kinds": "default run", "undetected_forms.decided_by": "decided by",
	} {
		if got := tp.ItemNames[registryPath(p)].name; got != want {
			t.Errorf("the item name of %s is %q, want %q", p, got, want)
		}
	}
	for p, want := range map[string]string{
		"threat.actors.run_starters.run_starter": "run-starter", "finding_kinds.severity_basis.impact.level": "impact", "default_run_fact_kinds": "fact-kind",
	} {
		if got := tp.Values[registryPath(p)].String(); got != want {
			t.Errorf("the value group of %s is %q, want %q", p, got, want)
		}
	}
	if got := tp.Axes[registryPath("facets.attack_means")].String(); got != "attack-means" {
		t.Errorf("the axis of facets.attack_means is %q", got)
	}
	if got := tp.Metrics[MetricName{"VC"}].String(); got != "impact" {
		t.Errorf("the value group of the metric VC is %q", got)
	}
}
