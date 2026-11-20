package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestUpToDate(t *testing.T) {
	src, err := os.ReadFile("../../schema/facts-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := Generate(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../query_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("query_gen.go is not up to date; run go generate ./actions/facts/")
	}
}

// schema builds a facts schema with the kinds given as $defs members and
// a query that lists them.
func schema(kinds map[string]string, order ...string) string {
	var defs, refs []string
	for _, k := range order {
		defs = append(defs, `"`+k+`": `+kinds[k])
		refs = append(refs, `{"$ref": "#/$defs/`+k+`"}`)
	}
	return `{"$defs": {
		"repo": {"type": "string", "pattern": "^[a-z]+/[a-z]+$", "x-go-type": "Repo"},
		"loose": {"type": "string", "pattern": "^.*$", "x-go-type": "Repo"},
		"bare": {"type": "string", "x-go-type": "Repo"},
		` + fromDef + `,
		` + strings.Join(defs, ",\n") + `,
		"query": {"oneOf": [` + strings.Join(refs, ", ") + `]}
	}}`
}

const fromDef = `"provider": {"oneOf": [{"const": "github", "description": "a"}, {"const": "test", "description": "t"}]}`

const flagKind = `{"type": "object", "description": "a flag",
	"properties": {"kind": {"const": "test.flag"}, "name": {"type": "string", "minLength": 1}},
	"required": ["kind", "name"], "additionalProperties": false,
	"x-value": {"type": "boolean"}, "x-provider": "test"}`

func TestGenerateShape(t *testing.T) {
	repoKind := `{"type": "object",
		"properties": {"kind": {"const": "test.repo-list"}, "repo": {"$ref": "#/$defs/repo"}, "ref-name": {"type": "string"}},
		"required": ["kind", "repo", "ref-name"], "additionalProperties": false,
		"x-value": {"type": "array", "items": {"type": "string"}}, "x-provider": "github", "x-permission": "contents: read"}`
	b, err := Generate([]byte(schema(map[string]string{"test.flag": flagKind, "test.repo-list": repoKind}, "test.flag", "test.repo-list")))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"type TestFlag struct {\n\tName string\n}",
		"func (TestFlag) Kind() Kind { return KindTestFlag }",
		"func (q TestFlag) Ask(ctx context.Context, r Resolver) Answer[bool]",
		"type TestRepoList struct {\n\tRepo    Repo\n\tRefName string\n}",
		"func (q TestRepoList) Ask(ctx context.Context, r Resolver) Answer[[]string]",
		"\tKindUnset Kind = iota\n\tKindTestFlag\n\tKindTestRepoList\n",
		`{Kind: KindTestRepoList, Provider: ProviderGitHub, Permission: Permission{scope: "contents", write: false}`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the output does not contain %q:\n%s", want, b)
		}
	}
}

// An argument may be left out only when it is of an x-go-type whose zero
// value is none and whose pattern refuses the empty string: then no fact
// has two spellings, none and empty.
func TestOptionalArgument(t *testing.T) {
	kind := func(prop string) string {
		return `{"type": "object",
		"properties": {"kind": {"const": "test.opt"}, "repo": ` + prop + `, "name": {"type": "string"}},
		"required": ["kind", "name"], "additionalProperties": false,
		"x-value": {"type": "boolean"}, "x-provider": "test"}`
	}
	b, err := Generate([]byte(schema(map[string]string{"test.opt": kind(`{"$ref": "#/$defs/repo"}`)}, "test.opt")))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"if !q.Repo.IsZero() {\n\t\tfs = append(fs, field{\"repo\", q.Repo})\n\t}",
		"fs = append(fs, field{\"name\", q.Name})",
		"return encodeFields(\"test.opt\", fs...)",
		"case TestOpt:\n\t\tq.Repo = r\n\t\treturn q, true",
	} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("the generated code has no %q:\n%s", want, b)
		}
	}
	for _, c := range []struct{ name, prop string }{
		{"a pattern that takes the empty string", `{"$ref": "#/$defs/loose"}`},
		{"no pattern", `{"$ref": "#/$defs/bare"}`},
		{"a string", `{"type": "string", "minLength": 1}`},
	} {
		if _, err := Generate([]byte(schema(map[string]string{"test.opt": kind(c.prop)}, "test.opt"))); err == nil || !strings.Contains(err.Error(), "required") {
			t.Errorf("%s: err = %v, want one that says the argument must be required", c.name, err)
		}
	}
}

func TestGenerateAssume(t *testing.T) {
	assumed := strings.Replace(flagKind, `"x-provider": "test"`, `"x-provider": "test", "x-assume": {"value": true, "reason": "the worst case"}`, 1)
	b, err := Generate([]byte(schema(map[string]string{"test.flag": assumed}, "test.flag")))
	if err != nil {
		t.Fatal(err)
	}
	want := `{Kind: KindTestFlag, Provider: ProviderTest, Permission: Permission{}, Description: "a flag", AssumedValue: json.RawMessage("true"), AssumedReason: "the worst case"}`
	if !strings.Contains(string(b), want) {
		t.Errorf("the output does not contain %q:\n%s", want, b)
	}
	plain, err := Generate([]byte(schema(map[string]string{"test.flag": flagKind}, "test.flag")))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "AssumedValue:") {
		t.Errorf("a kind without x-assume has no assumption:\n%s", plain)
	}
}

func TestGenerateRejects(t *testing.T) {
	kind := func(name, props, rest string, req ...string) string {
		required := `"kind"`
		for _, r := range req {
			required += `, "` + r + `"`
		}
		return `{"type": "object", "properties": {"kind": {"const": "` + name + `"}` + props + `},
			"required": [` + required + `], "additionalProperties": false` + rest + `}`
	}
	for _, c := range []struct {
		name, kind, def, want string
	}{
		{"syntax outside the subset", "test.a", kind("test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "test", "anyOf": []`), "anyOf"},
		{"const differs from the key", "test.a", kind("test.b", "", `, "x-value": {"type": "boolean"}, "x-provider": "test"`), "const"},
		{"upper case name", "Test.a", kind("Test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "test"`), "name"},
		{"one segment", "test", kind("test", "", `, "x-value": {"type": "boolean"}, "x-provider": "test"`), "name"},
		{"empty segment", "test..a", kind("test..a", "", `, "x-value": {"type": "boolean"}, "x-provider": "test"`), "name"},
		{"array argument", "test.a", kind("test.a", `, "l": {"type": "array", "items": {"type": "string"}}`, `, "x-value": {"type": "boolean"}, "x-provider": "test"`, "l"), "argument"},
		{"object argument", "test.a", kind("test.a", `, "o": {"type": "object"}`, `, "x-value": {"type": "boolean"}, "x-provider": "test"`, "o"), "argument"},
		{"no x-value", "test.a", kind("test.a", "", `, "x-provider": "test"`), "x-value"},
		{"bad x-provider", "test.a", kind("test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "web"`), "x-provider"},
		{"x-permission without a level", "test.a", kind("test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "github", "x-permission": "contents"`), "x-permission"},
		{"x-permission with an unknown level", "test.a", kind("test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "github", "x-permission": "contents: admin"`), "x-permission"},
		{"x-permission in upper case", "test.a", kind("test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "github", "x-permission": "Contents: read"`), "x-permission"},
		{"object value", "test.a", kind("test.a", "", `, "x-value": {"type": "object"}, "x-provider": "test"`), "x-value"},
		{"not closed", "test.a", `{"type": "object", "properties": {"kind": {"const": "test.a"}}, "required": ["kind"], "x-value": {"type": "boolean"}, "x-provider": "test"}`, "additionalProperties"},
		{"optional argument", "test.a", `{"type": "object", "properties": {"kind": {"const": "test.a"}, "n": {"type": "string"}}, "required": ["kind"], "additionalProperties": false, "x-value": {"type": "boolean"}, "x-provider": "test"}`, "required"},
		{"x-assume off x-value", "test.a", kind("test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "test", "x-assume": {"value": "yes", "reason": "r"}`), "x-assume"},
		{"x-assume without a reason", "test.a", kind("test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "test", "x-assume": {"value": true}`), "x-assume"},
		{"x-assume with another member", "test.a", kind("test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "test", "x-assume": {"value": true, "reason": "r", "why": "w"}`), "x-assume"},
		{"unevaluatedProperties", "test.a", kind("test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "test", "unevaluatedProperties": false`), "shape"},
		{"a oneOf of objects", "test.a", kind("test.a", `, "n": {"type": "string"}`, `, "x-value": {"type": "boolean"}, "x-provider": "test", "oneOf": [{"properties": {"n": {"const": "a"}}}]`, "n"), "shape"},
		{"x-assume of an api kind", "test.a", kind("test.a", "", `, "x-value": {"type": "boolean"}, "x-provider": "github", "x-assume": {"value": true, "reason": "r"}`), "x-assume"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Generate([]byte(schema(map[string]string{c.kind: c.def}, c.kind)))
			if err == nil {
				t.Fatal("no error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestGenerateRejectsSchemaLevel(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{"unknown x-go-type", `{"$defs": {` + fromDef + `, "repo": {"type": "string", "x-go-type": "Branch"}, "query": {"oneOf": [{"$ref": "#/$defs/repo"}]}}}`, "x-go-type"},
		{"query misses a kind", `{"$defs": {` + fromDef + `, "test.a": ` + strings.ReplaceAll(flagKind, "test.flag", "test.a") + `, "test.b": ` + strings.ReplaceAll(flagKind, "test.flag", "test.b") + `, "query": {"oneOf": [{"$ref": "#/$defs/test.a"}]}}}`, "query"},
		{"no query", `{"$defs": {` + fromDef + `, "test.flag": ` + flagKind + `}}`, "query"},
		{"a kind that is a $ref", `{"$defs": {` + fromDef + `, "body": ` + strings.ReplaceAll(flagKind, "test.flag", "test.a") + `, "test.a": {"$ref": "#/$defs/body", "unevaluatedProperties": false}, "query": {"oneOf": [{"$ref": "#/$defs/test.a"}]}}}`, "not a $ref"},
		{"no provider", `{"$defs": {"test.flag": ` + flagKind + `, "query": {"oneOf": [{"$ref": "#/$defs/test.flag"}]}}}`, "provider"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Generate([]byte(c.src))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestValueTakesItemKeywords: minItems and uniqueItems on the array of
// x-value change no Go type.
func TestValueTakesItemKeywords(t *testing.T) {
	k := strings.ReplaceAll(flagKind, `"x-value": {"type": "boolean"}`, `"x-value": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string"}}`)
	b, err := Generate([]byte(schema(map[string]string{"test.flag": k}, "test.flag")))
	if err != nil {
		t.Fatal(err)
	}
	if want := "Answer[[]string]"; !strings.Contains(string(b), want) {
		t.Errorf("the output does not contain %q:\n%s", want, b)
	}
}
