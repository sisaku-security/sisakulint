package jsonschema

import (
	"strings"
	"testing"
)

func load(t *testing.T, files map[string]string, opt Options) *Set {
	t.Helper()
	m := map[string][]byte{}
	for k, v := range files {
		m[k] = []byte(v)
	}
	s, err := Load(m, opt)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s
}

func TestLoadKeepsOrderAndAnnotations(t *testing.T) {
	s := load(t, map[string]string{"a.json": `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$defs": {
			"z": {"type": "object", "properties": {"b": {"type": "string"}, "a": {"type": "boolean"}},
			      "required": ["b"], "additionalProperties": false,
			      "description": "Z", "x-from": "test", "x-value": {"$ref": "#/$defs/y"}},
			"y": {"type": "array", "items": {"type": "integer"}}
		}
	}`}, Options{SchemaAnnotations: []string{"x-value"}})
	root := s.Root("a.json")
	if len(root.Defs) != 2 || root.Defs[0].Name != "z" || root.Defs[1].Name != "y" {
		t.Fatalf("Defs = %+v, want z then y", root.Defs)
	}
	z := root.Defs[0].Schema
	if len(z.Properties) != 2 || z.Properties[0].Name != "b" || z.Properties[1].Name != "a" {
		t.Errorf("Properties = %+v, want b then a", z.Properties)
	}
	if z.Description != "Z" || string(z.Annotations["x-from"]) != `"test"` {
		t.Errorf("Description = %q, x-from = %s", z.Description, z.Annotations["x-from"])
	}
	v := z.SchemaAnnotations["x-value"]
	if v == nil || v.Resolve().Type != TypeArray || v.Resolve().Items.Type != TypeInteger {
		t.Errorf("x-value = %+v, want the array of y", v)
	}
	if !z.AdditionalFalse || len(z.Required) != 1 {
		t.Errorf("AdditionalFalse = %v, Required = %v", z.AdditionalFalse, z.Required)
	}
}

func TestLookup(t *testing.T) {
	s := load(t, map[string]string{"a.json": `{"$defs": {"t.x": {"oneOf": [{"type": "string"}, {"type": "null"}]}, "a/b": {"type": "string"}}}`}, Options{})
	for _, c := range []struct{ ptr, typ string }{
		{"#/$defs/t.x/oneOf/1", "null"},
		{"#/$defs/a~1b", "string"},
	} {
		sch, err := s.Lookup("a.json", c.ptr)
		if err != nil || sch.Type.String() != c.typ {
			t.Errorf("Lookup(%s) = %+v, %v; want type %s", c.ptr, sch, err, c.typ)
		}
	}
	if _, err := s.Lookup("a.json", "#/$defs/nope"); err == nil {
		t.Error("Lookup of a missing def: no error")
	}
}

func TestLoadRejects(t *testing.T) {
	for _, c := range []struct {
		name, src, want string
	}{
		{"anyOf", `{"anyOf": [{"type": "string"}]}`, "anyOf"},
		{"allOf", `{"allOf": []}`, "allOf"},
		{"if", `{"if": {}}`, "if"},
		{"patternProperties", `{"patternProperties": {}}`, "patternProperties"},
		{"$id", `{"$id": "x"}`, "$id"},
		{"number", `{"type": "number"}`, "number"},
		{"type list", `{"type": ["string", "null"]}`, "type"},
		{"additionalProperties true", `{"additionalProperties": true}`, "additionalProperties"},
		{"$schema of another draft", `{"$schema": "http://json-schema.org/draft-07/schema#"}`, "$schema"},
		{"nested $schema", `{"$defs": {"a": {"$schema": "https://json-schema.org/draft/2020-12/schema"}}}`, "$schema"},
		{"missing ref", `{"$ref": "#/$defs/none"}`, "none"},
		{"missing file", `{"$ref": "b.json#/$defs/x"}`, "b.json"},
		{"ref cycle", `{"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/a"}}}`, "cycle"},
		{"self ref", `{"$defs": {"a": {"$ref": "#/$defs/a"}}}`, "cycle"},
		{"oneOf back to itself", `{"$defs": {"a": {"oneOf": [{"$ref": "#/$defs/a"}]}}}`, "cycle"},
		{"ref to a oneOf back to it", `{"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"oneOf": [{"type": "string"}, {"$ref": "#/$defs/a"}]}}}`, "cycle"},
		{"bad pattern", `{"pattern": "("}`, "pattern"},
		{"negative minLength", `{"minLength": -1}`, "minLength"},
		{"negative minItems", `{"minItems": -1}`, "minItems"},
		{"minItems not an integer", `{"minItems": 1.5}`, "minItems"},
		{"uniqueItems false", `{"uniqueItems": false}`, "uniqueItems"},
		{"uniqueItems not a boolean", `{"uniqueItems": 1}`, "uniqueItems"},
		{"unevaluatedProperties a schema", `{"unevaluatedProperties": {}}`, "unevaluatedProperties"},
		{"unevaluatedProperties true", `{"unevaluatedProperties": true}`, "unevaluatedProperties"},
		{"required not strings", `{"required": [1]}`, "required"},
		{"duplicate key", `{"type": "string", "type": "null"}`, "type"},
		{"not an object", `[]`, "object"},
		{"unknown x- schema annotation is fine but bad JSON is not", `{"x-a": }`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(map[string][]byte{"a.json": []byte(c.src)}, Options{})
			if err == nil {
				t.Fatalf("Load(%s): no error", c.src)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestLoadCrossFileRef(t *testing.T) {
	s := load(t, map[string]string{
		"a.json": `{"$defs": {"q": {"$ref": "b.json#/$defs/s"}}}`,
		"b.json": `{"$defs": {"s": {"type": "string", "minLength": 2}}}`,
	}, Options{})
	sch, err := s.Lookup("a.json", "#/$defs/q")
	if err != nil {
		t.Fatal(err)
	}
	if r := sch.Resolve(); r.Type != TypeString || r.MinLength == nil || *r.MinLength != 2 {
		t.Errorf("Resolve = %+v, want b.json's s", r)
	}
}
