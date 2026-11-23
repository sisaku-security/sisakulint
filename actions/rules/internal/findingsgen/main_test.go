package main

import (
	"os"
	"strings"
	"testing"
)

func read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestUpToDate checks that finding_gen.go is what the schema gives; run go
// generate in actions/rules when it fails.
func TestUpToDate(t *testing.T) {
	got, err := Generate(read(t, "../../schema/findings-v0.json"), read(t, "../../../facts/schema/facts-v0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(read(t, "../../finding_gen.go")) {
		t.Error("finding_gen.go is not what the schema gives: run go generate in actions/rules")
	}
}

// ${{ }} stays, {expr_ref} is replaced.
func TestDetectedBraces(t *testing.T) {
	got, err := Generate(read(t, "../../schema/findings-v0.json"), read(t, "../../../facts/schema/facts-v0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `return a.ExprRef + " is written into " + textSinkKind(a.SinkKind) + " by ${{ }}, and an attacker controls it on " + joined(a.ControlledOn, func(x workflow.EventName) string { return x.String() })`+"\n") {
		t.Errorf("the detected text of code-injection.controlled is not made as it should be:\n%s", got)
	}
}

// A brace that is not an argument may be in x-consequence.
func TestImpactBraces(t *testing.T) {
	s := `{"$defs": {"args": {"oneOf": [{"$ref": "#/$defs/r.k"}]}, "r.k": {"type": "object",
		"properties": {"kind_id": {"const": "r.k"}}, "required": ["kind_id"], "additionalProperties": false,
		"x-detected": "x", "x-consequence": "${{ }} runs", "x-remedy": "r"}}}`
	if _, err := Generate([]byte(s), read(t, "../../../facts/schema/facts-v0.json")); err != nil {
		t.Errorf("${{ }} in x-consequence: %v", err)
	}
}

func TestGenerateRejects(t *testing.T) {
	facts := read(t, "../../../facts/schema/facts-v0.json")
	kind := func(props, detected string) string {
		return `{"$defs": {"args": {"oneOf": [{"$ref": "#/$defs/r.k"}]}, "r.k": {"type": "object",
			"properties": {"kind_id": {"const": "r.k"}` + props + `}, "required": ["kind_id"` + reqs(props) + `],
			"additionalProperties": false, "x-detected": "` + detected + `", "x-consequence": "i", "x-remedy": "r"}}}`
	}
	for _, c := range []struct{ name, schema, want string }{
		{"a placeholder with no argument", kind(`, "a": {"type": "string"}`, "{b}"), "{b}"},
		{"an object argument", kind(`, "a": {"type": "object"}`, "{a}"), "argument a"},
		{"an argument not snake_case", kind(`, "my-ref": {"type": "string"}`, "{my-ref}"), "my-ref"},
		{"required with no such property", strings.Replace(kind(``, "x"), `"required": ["kind_id"`, `"required": ["kind_id", "zz"`, 1), "zz"},
		{"an array of arrays", kind(`, "a": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}}`, "{a}"), "argument a"},
		{"no x-detected", strings.Replace(kind(``, "x"), `"x-detected": "x", `, ``, 1), "x-detected"},
		{"no x-consequence", strings.Replace(kind(``, "x"), `, "x-consequence": "i"`, ``, 1), "x-consequence"},
		{"an empty x-remedy", strings.Replace(kind(``, "x"), `"x-remedy": "r"`, `"x-remedy": ""`, 1), "x-remedy"},
		{"an argument in x-consequence", strings.Replace(kind(`, "a": {"type": "string"}`, "{a}"), `"x-consequence": "i"`, `"x-consequence": "{a} moves"`, 1), "x-consequence"},
		{"an argument in x-remedy", strings.Replace(kind(`, "a": {"type": "string"}`, "{a}"), `"x-remedy": "r"`, `"x-remedy": "pin {a}"`, 1), "x-remedy"},
		{"an x-message left", strings.Replace(kind(``, "x"), `"x-detected": "x"`, `"x-detected": "x", "x-message": "x"`, 1), "x-message"},
		{"a name not <rule>.<kind>", strings.ReplaceAll(kind(``, "x"), "r.k", "r.k.z"), "r.k.z"},
		{"unevaluatedProperties", strings.Replace(kind(``, "x"), `"additionalProperties": false`, `"additionalProperties": false, "unevaluatedProperties": false`, 1), "shape"},
		{"a oneOf of objects", strings.Replace(kind(`, "a": {"type": "string"}`, "{a}"), `"additionalProperties": false`, `"additionalProperties": false, "oneOf": [{"properties": {"a": {"const": "b"}}}]`, 1), "shape"},
		{"a kind that is a $ref", strings.Replace(strings.Replace(kind(``, "x"), `"r.k": {"type": "object",`, `"r.k": {"$ref": "#/$defs/body", "unevaluatedProperties": false}, "body": {"type": "object",`, 1), `"$defs": {"args"`, `"$defs": {"args"`, 1), "not a $ref"},
		{"a kind not in args", strings.Replace(kind(``, "x"), `"oneOf": [{"$ref": "#/$defs/r.k"}]`, `"oneOf": []`, 1), "args"},
		{"an enumeration without x-text", `{"$defs": {"e": {"oneOf": [{"const": "a", "description": "A."}]},
			"args": {"oneOf": [{"$ref": "#/$defs/r.k"}]}, "r.k": {"type": "object",
			"properties": {"kind_id": {"const": "r.k"}, "a": {"$ref": "#/$defs/e"}}, "required": ["kind_id", "a"],
			"additionalProperties": false, "x-detected": "{a}", "x-consequence": "i", "x-remedy": "r"}}}`, "x-text"},
	} {
		_, err := Generate([]byte(c.schema), facts)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want one that says %q", c.name, err, c.want)
		}
	}
}

// reqs are the names of the properties in props, as more of required.
func reqs(props string) string {
	if props == "" {
		return ""
	}
	name := strings.SplitN(strings.TrimPrefix(props, `, "`), `"`, 2)[0]
	return `, "` + name + `"`
}

// argSchema is a schema of the one kind r.k with the properties props (each
// a "name": schema, after kind_id), required in the order of names, the
// definitions defs (each a "name": schema) and the text detected.
func argSchema(props, names, defs, detected string) []byte {
	return []byte(`{"$defs": {` + defs + `"args": {"oneOf": [{"$ref": "#/$defs/r.k"}]}, "r.k": {"type": "object",
		"properties": {"kind_id": {"const": "r.k"}` + props + `}, "required": ["kind_id"` + names + `],
		"additionalProperties": false, "x-detected": "` + detected + `", "x-consequence": "i", "x-remedy": "r"}}}`)
}

// argsOf is the Go source of the arguments of r.k in what Generate gives
// for src.
func argsOf(t *testing.T, src []byte) string {
	t.Helper()
	got, err := Generate(src, read(t, "../../../facts/schema/facts-v0.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(got), "Arguments: []lint.KindArgument{")
	if !ok {
		t.Fatalf("no Arguments in:\n%s", got)
	}
	// the rest of the line of the variable, without the brace that ends
	// the FindingText
	line, _, _ := strings.Cut(after, "\n")
	return strings.TrimSuffix(line, "}")
}

// The arguments are in the order detected names them, then in the order of
// required, those not in detected marked.
func TestArgumentsInDetectedOrder(t *testing.T) {
	src := argSchema(`, "a": {"type": "string", "description": "An A."}, "b": {"type": "string", "description": "A B."}, "c": {"type": "string", "description": "A C."}`,
		`, "a", "b", "c"`, ``, "{b} then {a} and {b}")
	want := `{Name: lint.MustKindArgumentName("b"), Text: "A B.", InDetected: true}, {Name: lint.MustKindArgumentName("a"), Text: "An A.", InDetected: true}, {Name: lint.MustKindArgumentName("c"), Text: "A C.", InDetected: false}}`
	if got := argsOf(t, src); got != want {
		t.Errorf("arguments\n got %s\nwant %s", got, want)
	}
}

const enumDef = `"x": {"description": "An X.", "oneOf": [{"const": "v", "description": "V."}], "x-text": {"v": "v"}}, `

// An argument without a description of its own has that of what it refers
// to.
func TestArgumentTextFromRef(t *testing.T) {
	src := argSchema(`, "a": {"$ref": "#/$defs/x"}`, `, "a"`, enumDef, "{a}")
	if got := argsOf(t, src); !strings.Contains(got, `Text: "An X."`) {
		t.Errorf("arguments %s: want the text of $defs/x", got)
	}
}

// An array without a description has that of its items.
func TestArgumentTextFromItems(t *testing.T) {
	src := argSchema(`, "a": {"type": "array", "items": {"$ref": "#/$defs/x"}}`, `, "a"`, enumDef, "{a}")
	if got := argsOf(t, src); !strings.Contains(got, `Text: "An X."`) {
		t.Errorf("arguments %s: want the text of $defs/x", got)
	}
}

func TestArgumentWithoutText(t *testing.T) {
	src := argSchema(`, "a": {"type": "string"}`, `, "a"`, ``, "{a}")
	if _, err := Generate(src, read(t, "../../../facts/schema/facts-v0.json")); err == nil || !strings.Contains(err.Error(), "argument a has no description") {
		t.Errorf("an argument with no description anywhere: err %v, want one that names argument a", err)
	}
}

// ${{ }} in detected names no argument.
func TestArgumentsIgnoreExpressionBraces(t *testing.T) {
	src := argSchema(`, "a": {"type": "string", "description": "An A."}`, `, "a"`, ``, "{a} by ${{ }}")
	if got := argsOf(t, src); !strings.Contains(got, `InDetected: true}}`) {
		t.Errorf("arguments %s: want a in detected", got)
	}
}

// The arguments detected does not name follow the order of required, not
// that of the properties.
func TestArgumentsInRequiredOrder(t *testing.T) {
	src := argSchema(`, "a": {"type": "string", "description": "An A."}, "b": {"type": "string", "description": "A B."}, "c": {"type": "string", "description": "A C."}`,
		`, "c", "a", "b"`, ``, "{b}")
	want := `{Name: lint.MustKindArgumentName("b"), Text: "A B.", InDetected: true}, {Name: lint.MustKindArgumentName("c"), Text: "A C.", InDetected: false}, {Name: lint.MustKindArgumentName("a"), Text: "An A.", InDetected: false}}`
	if got := argsOf(t, src); got != want {
		t.Errorf("arguments\n got %s\nwant %s", got, want)
	}
}

// The description nearest to the argument wins: its own, then that of each
// schema on the way of $ref, then that of the items of an array.
func TestArgumentTextNearest(t *testing.T) {
	refY := `"y": {"description": "A Y.", "$ref": "#/$defs/x"}, `
	for _, c := range []struct{ name, prop, defs, want string }{
		{"its own before the ref", `{"$ref": "#/$defs/x", "description": "Its own."}`, enumDef, "Its own."},
		{"the first ref on the way", `{"$ref": "#/$defs/y"}`, enumDef + refY, "A Y."},
		{"the items' own before their ref", `{"type": "array", "items": {"$ref": "#/$defs/x", "description": "An item."}}`, enumDef, "An item."},
		{"a fact's definition", `{"$ref": "facts-v0.json#/$defs/repo"}`, ``, "A repository, owner/name."},
	} {
		got := argsOf(t, argSchema(`, "a": `+c.prop, `, "a"`, c.defs, "{a}"))
		if !strings.Contains(got, `Text: "`+c.want) {
			t.Errorf("%s: arguments %s, want the text %q", c.name, got, c.want)
		}
	}
}

// A name required twice is one argument.
func TestArgumentsRequiredTwice(t *testing.T) {
	src := argSchema(`, "a": {"type": "string", "description": "An A."}`, `, "a", "a"`, ``, "x")
	if got := argsOf(t, src); strings.Count(got, `MustKindArgumentName("a")`) != 1 {
		t.Errorf("arguments %s: want a once", got)
	}
}

// TestArrayArgumentTakesItemKeywords: minItems and uniqueItems on an array
// argument change no Go type.
func TestArrayArgumentTakesItemKeywords(t *testing.T) {
	plain := argSchema(`, "a": {"description": "An A.", "type": "array", "items": {"type": "string"}}`, `, "a"`, ``, "{a}")
	with := argSchema(`, "a": {"description": "An A.", "type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string"}}`, `, "a"`, ``, "{a}")
	facts := read(t, "../../../facts/schema/facts-v0.json")
	p, err := Generate(plain, facts)
	if err != nil {
		t.Fatal(err)
	}
	w, err := Generate(with, facts)
	if err != nil {
		t.Fatal(err)
	}
	if string(p) != string(w) {
		t.Errorf("minItems and uniqueItems changed the generated file")
	}
}
