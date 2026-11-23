package lint

import (
	"encoding/json"
	"os"
	"testing"
)

// goldenRegistry is the registry of the rules of actions/rules, as its
// golden file has it, read into maps.
func goldenRegistry(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile("../rules/testdata/registry.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// firstOf is the first item of list for which ok is true.
func firstOf(t *testing.T, list any, ok func(map[string]any) bool) map[string]any {
	t.Helper()
	for _, x := range list.([]any) {
		if m := x.(map[string]any); ok(m) {
			return m
		}
	}
	t.Fatal("no item of the golden registry fits the case")
	return nil
}

// clone is a deep copy of v.
func clone(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestSchemaConstraints: the registry's schema says what the registry
// checks in Go (one at least, each once, a field only with a value of
// another): an item of the golden registry fits it, and the same item
// broken in one place does not.
func TestSchemaConstraints(t *testing.T) {
	s := schemas(t)
	reg := goldenRegistry(t)
	rules, quality := reg["rules"], reg["quality_rules"]
	every := func(map[string]any) bool { return true }
	withSafe := func(want string) func(map[string]any) bool {
		return func(m map[string]any) bool {
			for _, f := range m["fix_kinds"].([]any) {
				if f.(map[string]any)["safety"] == want {
					return true
				}
			}
			return false
		}
	}
	fixKind := func(m map[string]any, safety string) map[string]any {
		for _, f := range m["fix_kinds"].([]any) {
			if f := f.(map[string]any); f["safety"] == safety {
				return f
			}
		}
		return nil
	}
	defaultRun := func(want string) func(map[string]any) bool {
		return func(m map[string]any) bool { return m["default_run"] == want }
	}
	kind0 := func(m map[string]any) map[string]any { return m["finding_kinds"].([]any)[0].(map[string]any) }
	for _, c := range []struct {
		name  string
		def   string // under #/$defs/
		list  any
		pick  func(map[string]any) bool
		spoil func(m map[string]any)
	}{
		{"no finding kind", "meta", rules, every, func(m map[string]any) { m["finding_kinds"] = []any{} }},
		{"no actor", "meta", rules, every, func(m map[string]any) { m["threat"].(map[string]any)["actors"] = []any{} }},
		{"no gain", "meta", rules, every, func(m map[string]any) {
			m["threat"].(map[string]any)["actors"].([]any)[0].(map[string]any)["gains"] = []any{}
		}},
		{"no attacker of a kind", "meta", rules, every, func(m map[string]any) { kind0(m)["attackers"] = []any{} }},
		{"no true positive", "meta", rules, every, func(m map[string]any) { kind0(m)["true_positives"] = []any{} }},
		{"no true negative", "meta", rules, every, func(m map[string]any) { kind0(m)["true_negatives"] = []any{} }},
		{"no weakness", "meta", rules, every, func(m map[string]any) { m["facets"].(map[string]any)["weakness"] = []any{} }},
		{"a weakness twice", "meta", rules, every, func(m map[string]any) {
			f := m["facets"].(map[string]any)
			w := f["weakness"].([]any)
			f["weakness"] = append(w, w[0])
		}},
		{"no attack means", "meta", rules, every, func(m map[string]any) { m["facets"].(map[string]any)["attack_means"] = []any{} }},
		{"a quality rule run by facts with no fact kind", "quality-meta", quality, defaultRun("given-facts"), func(m map[string]any) { m["default_run_fact_kinds"] = []any{} }},
		{"an attack means twice", "meta", rules, every, func(m map[string]any) {
			f := m["facets"].(map[string]any)
			a := f["attack_means"].([]any)
			f["attack_means"] = append(a, a[0])
		}},
		{"fact kinds of a rule that always runs", "meta", rules, defaultRun("always"), func(m map[string]any) {
			m["default_run_fact_kinds"] = []any{"repo.wiki-open"}
		}},
		{"a rule run by facts without fact kinds", "meta", rules, defaultRun("given-facts"), func(m map[string]any) { delete(m, "default_run_fact_kinds") }},
		{"a rule run by facts with no fact kind", "meta", rules, defaultRun("given-facts"), func(m map[string]any) { m["default_run_fact_kinds"] = []any{} }},
		{"a side effect of a safe fix", "meta", rules, withSafe("safe"), func(m map[string]any) {
			f := fixKind(m, "safe")
			f["possible_side_effects"] = []any{map[string]any{"id": "unquoted-one-word", "text": "x"}}
		}},
		{"no side effect of a fix to review", "meta", rules, withSafe("review"), func(m map[string]any) {
			fixKind(m, "review")["possible_side_effects"] = []any{}
		}},
		{"a quality rule of no kind", "quality-meta", quality, every, func(m map[string]any) { m["finding_kinds"] = []any{} }},
		{"no true positive of a quality kind", "quality-meta", quality, every, func(m map[string]any) { kind0(m)["true_positives"] = []any{} }},
		{"no true negative of a quality kind", "quality-meta", quality, every, func(m map[string]any) { kind0(m)["true_negatives"] = []any{} }},
		{"a quality rule run by facts without fact kinds", "quality-meta", quality, defaultRun("given-facts"), func(m map[string]any) { delete(m, "default_run_fact_kinds") }},
		{"fact kinds of a quality rule that always runs", "quality-meta", quality, defaultRun("always"), func(m map[string]any) {
			m["default_run_fact_kinds"] = []any{"repo.wiki-open"}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := clone(t, firstOf(t, c.list, c.pick))
			ok, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Validate("registry-v0.json", "#/$defs/"+c.def, ok); err != nil {
				t.Fatalf("the golden item does not fit: %v", err)
			}
			c.spoil(m)
			bad, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Validate("registry-v0.json", "#/$defs/"+c.def, bad); err == nil {
				t.Errorf("the schema takes %s", bad)
			}
		})
	}
}

// formsOf are the items under key of every rule of list.
func formsOf(list any, key string) []any {
	var out []any
	for _, r := range list.([]any) {
		if fs, ok := r.(map[string]any)[key].([]any); ok {
			out = append(out, fs...)
		}
	}
	return out
}

// TestSchemaDispositions: the schema of a declaration takes the fields of
// its disposition, and no other: an item of the golden registry fits it,
// and the same item broken in one place does not.
func TestSchemaDispositions(t *testing.T) {
	s := schemas(t)
	reg := goldenRegistry(t)
	rules, quality := reg["rules"], reg["quality_rules"]
	disposition := func(want string) func(map[string]any) bool {
		return func(m map[string]any) bool { return m["disposition"] == want }
	}
	factKinds := func(m map[string]any) bool { _, ok := m["fact_kinds"]; return ok }
	metrics := func(list any) []any {
		var out []any
		for _, r := range list.([]any) {
			for _, k := range r.(map[string]any)["finding_kinds"].([]any) {
				if c, ok := k.(map[string]any)["cvss"].(map[string]any); ok {
					out = append(out, c["metrics"].([]any)...)
				}
			}
		}
		return out
	}
	every := func(map[string]any) bool { return true }
	for _, c := range []struct {
		name  string
		def   string
		items []any
		pick  func(map[string]any) bool
		spoil func(m map[string]any)
	}{
		{"a todo without needs", "undetected-form", formsOf(rules, "undetected_forms"), disposition("todo"), func(m map[string]any) { delete(m, "needs") }},
		{"a need twice", "undetected-form", formsOf(rules, "undetected_forms"), disposition("todo"), func(m map[string]any) {
			n := m["needs"].([]any)
			m["needs"] = append(n, n[0])
		}},
		{"no need", "undetected-form", formsOf(rules, "undetected_forms"), disposition("todo"), func(m map[string]any) { m["needs"] = []any{} }},
		{"a limitation with a rule", "undetected-form", formsOf(rules, "undetected_forms"), disposition("limitation"), func(m map[string]any) { m["rule"] = "commit-sha" }},
		{"an other-rule without its rule", "undetected-form", formsOf(rules, "undetected_forms"), disposition("other-rule"), func(m map[string]any) { delete(m, "rule") }},
		{"a no-added-gain with decided_by", "undetected-form", formsOf(rules, "undetected_forms"), disposition("no-added-gain"), func(m map[string]any) { m["decided_by"] = "run-time" }},
		{"an inconclusive kind of other-rule", "inconclusive-kind", formsOf(rules, "inconclusive_kinds"), disposition("limitation"), func(m map[string]any) {
			delete(m, "decided_by")
			m["disposition"], m["rule"] = "other-rule", "commit-sha"
		}},
		{"a false positive form of no kind", "false-positive-form", formsOf(rules, "false_positive_forms"), disposition("todo"), func(m map[string]any) { m["finding_kinds"] = []any{} }},
		{"fact kinds and a disposition", "false-positive-form", formsOf(rules, "false_positive_forms"), factKinds, func(m map[string]any) {
			m["disposition"], m["needs"] = "todo", []any{"fact"}
		}},
		{"fact kinds and a disposition without its fields", "false-positive-form", formsOf(rules, "false_positive_forms"), factKinds, func(m map[string]any) { m["disposition"] = "todo" }},
		{"a limitation with fact kinds", "false-positive-form", formsOf(rules, "false_positive_forms"), disposition("limitation"), func(m map[string]any) {
			m["fact_kinds"] = []any{map[string]any{"kind": "repo.wiki-open", "provider": "repo-setting"}}
		}},
		{"no fact kind", "false-positive-form", formsOf(rules, "false_positive_forms"), factKinds, func(m map[string]any) { m["fact_kinds"] = []any{} }},
		{"a quality todo without needs", "quality-undetected-form", formsOf(quality, "undetected_forms"), disposition("todo"), func(m map[string]any) { delete(m, "needs") }},
		{"a quality limitation with a rule", "quality-undetected-form", formsOf(quality, "undetected_forms"), disposition("limitation"), func(m map[string]any) { m["rule"] = "commit-sha" }},
		{"a quality no-added-gain", "quality-undetected-form", formsOf(quality, "undetected_forms"), disposition("limitation"), func(m map[string]any) {
			delete(m, "decided_by")
			m["disposition"] = "no-added-gain"
		}},
		{"a quality false positive form of neither", "quality-false-positive-form", formsOf(quality, "false_positive_forms"), disposition("todo"), func(m map[string]any) {
			delete(m, "disposition")
			delete(m, "needs")
		}},
		{"a quality false positive form of both", "quality-false-positive-form", formsOf(quality, "false_positive_forms"), disposition("todo"), func(m map[string]any) {
			m["fact_kinds"] = []any{map[string]any{"kind": "repo.wiki-open", "provider": "repo-setting"}}
		}},
		{"a metric of another metric's value", "metric", metrics(rules), func(m map[string]any) bool { return m["metric"] == "AV" }, func(m map[string]any) { m["value"] = "H" }},
		{"a metric without its reason", "metric", metrics(rules), every, func(m map[string]any) { delete(m, "reason") }},
		{"a metric with another key", "metric", metrics(rules), every, func(m map[string]any) { m["note"] = "x" }},
		{"a limitation without decided_by", "undetected-form", formsOf(rules, "undetected_forms"), disposition("limitation"), func(m map[string]any) { delete(m, "decided_by") }},
		{"a quality limitation without decided_by", "quality-undetected-form", formsOf(quality, "undetected_forms"), disposition("limitation"), func(m map[string]any) { delete(m, "decided_by") }},
		{"an inconclusive todo with decided_by", "inconclusive-kind", formsOf(rules, "inconclusive_kinds"), disposition("todo"), func(m map[string]any) { m["decided_by"] = "run-time" }},
		{"an inconclusive kind with finding kinds", "inconclusive-kind", formsOf(rules, "inconclusive_kinds"), disposition("todo"), func(m map[string]any) { m["finding_kinds"] = []any{} }},
		{"a quality false positive form of no kind", "quality-false-positive-form", formsOf(quality, "false_positive_forms"), disposition("todo"), func(m map[string]any) { m["finding_kinds"] = []any{} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := clone(t, firstOf(t, c.items, c.pick))
			ok, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Validate("registry-v0.json", "#/$defs/"+c.def, ok); err != nil {
				t.Fatalf("the golden item does not fit: %v", err)
			}
			c.spoil(m)
			bad, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Validate("registry-v0.json", "#/$defs/"+c.def, bad); err == nil {
				t.Errorf("the schema takes %s", bad)
			}
		})
	}
}

// TestSchemaQualityFactKinds: a quality false positive form of fact kinds
// (the golden registry has none: made from one of a disposition) takes no
// field of a disposition and one fact kind at least.
func TestSchemaQualityFactKinds(t *testing.T) {
	s := schemas(t)
	reg := goldenRegistry(t)
	base := clone(t, firstOf(t, formsOf(reg["quality_rules"], "false_positive_forms"), func(m map[string]any) bool { return m["disposition"] == "todo" }))
	delete(base, "disposition")
	delete(base, "needs")
	base["fact_kinds"] = []any{map[string]any{"kind": "repo.wiki-open", "provider": "repo-setting"}}
	check := func(m map[string]any, ok bool) {
		t.Helper()
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Validate("registry-v0.json", "#/$defs/quality-false-positive-form", b); (err == nil) != ok {
			t.Errorf("Validate(%s) = %v, want ok=%v", b, err, ok)
		}
	}
	check(base, true)
	withDecider := clone(t, base)
	withDecider["decided_by"] = "run-time"
	check(withDecider, false)
	noFactKind := clone(t, base)
	noFactKind["fact_kinds"] = []any{}
	check(noFactKind, false)
}

// TestSchemaAddedAttackers: a list of added attackers (of a declaration and
// of a report) has one at least, each once.
func TestSchemaAddedAttackers(t *testing.T) {
	s := schemas(t)
	for data, ok := range map[string]bool{
		`["read-member"]`:                   true,
		`["read-member", "triage-account"]`: true,
		`[]`:                                false,
		`["read-member", "read-member"]`:    false,
	} {
		if err := s.Validate("registry-v0.json", "#/$defs/added-attackers", []byte(data)); (err == nil) != ok {
			t.Errorf("Validate(%s) = %v, want ok=%v", data, err, ok)
		}
	}
}
