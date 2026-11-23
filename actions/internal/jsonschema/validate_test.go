package jsonschema

import (
	"strings"
	"testing"
)

const validateSchema = `{
	"$defs": {
		"str":    {"type": "string"},
		"bool":   {"type": "boolean"},
		"int":    {"type": "integer"},
		"null":   {"type": "null"},
		"arr":    {"type": "array", "items": {"type": "string"}},
		"const":  {"const": {"a": [1, "x"]}},
		"enum":   {"enum": ["a", 1, null]},
		"pat":    {"type": "string", "pattern": "^[a-z]+/[a-z]+$"},
		"min":    {"type": "string", "minLength": 2},
		"obj":    {"type": "object", "properties": {"k": {"const": "v"}, "n": {"type": "integer"}},
		           "required": ["k"], "additionalProperties": false},
		"open":   {"type": "object", "properties": {"k": {"type": "string"}}},
		"one":    {"oneOf": [{"type": "string"}, {"type": "string", "minLength": 3}, {"type": "integer"}]},
		"ref":    {"$ref": "#/$defs/min"},
		"refand": {"$ref": "#/$defs/str", "minLength": 2},
		"other":  {"$ref": "b.json#/$defs/b"},
		"anytype": {"minLength": 2},
		"patonly": {"pattern": "^a$"},
		"mini":   {"type": "array", "minItems": 1},
		"uniq":   {"type": "array", "uniqueItems": true}
	}
}`

func TestValidate(t *testing.T) {
	s := load(t, map[string]string{"a.json": validateSchema, "b.json": `{"$defs": {"b": {"type": "boolean"}}}`}, Options{})
	for _, c := range []struct {
		def  string
		data string
		ok   bool
	}{
		{"str", `"x"`, true}, {"str", `1`, false},
		{"bool", `false`, true}, {"bool", `"false"`, false},
		{"int", `-3`, true}, {"int", `1.5`, false}, {"int", `true`, false},
		{"null", `null`, true}, {"null", `0`, false},
		{"arr", `["a","b"]`, true}, {"arr", `["a",1]`, false}, {"arr", `{}`, false},
		{"const", `{"a":[1,"x"]}`, true}, {"const", ` { "a" : [ 1 , "x" ] } `, true}, {"const", `{"a":[1,"y"]}`, false},
		{"enum", `"a"`, true}, {"enum", `null`, true}, {"enum", `"1"`, false},
		{"pat", `"actions/checkout"`, true}, {"pat", `"Actions/checkout"`, false}, {"pat", `3`, false}, {"patonly", `3`, true}, {"patonly", `"b"`, false},
		{"min", `"ab"`, true}, {"min", "\"\xc3\xa9\"", false}, {"min", "\"\xc3\xa9\xc3\xa9\"", true},
		{"obj", `{"k":"v","n":1}`, true}, {"obj", `{"n":1}`, false}, {"obj", `{"k":"v","z":1}`, false}, {"obj", `{"k":"w"}`, false},
		{"open", `{"k":"v","z":1}`, true}, {"open", `[]`, false},
		{"one", `"ab"`, true}, {"one", `"abc"`, false}, {"one", `7`, true}, {"one", `null`, false},
		{"ref", `"ab"`, true}, {"ref", `"a"`, false},
		{"refand", `"ab"`, true}, {"refand", `"a"`, false}, {"refand", `1`, false},
		{"other", `true`, true}, {"other", `"true"`, false},
		{"anytype", `5`, true}, {"anytype", `"a"`, false},
		{"mini", `[]`, false}, {"mini", `["a"]`, true},
		{"uniq", `["a","b"]`, true}, {"uniq", `["a","a"]`, false},
		{"uniq", `[{"a":1,"b":2},{"b":2,"a":1}]`, false}, {"uniq", `[[1],[1,2]]`, true},
		{"uniq", `[1.5]`, false}, {"uniq", `"x"`, false},
	} {
		err := s.Validate("a.json", "#/$defs/"+c.def, []byte(c.data))
		if (err == nil) != c.ok {
			t.Errorf("Validate(%s, %s) = %v, want ok=%v", c.def, c.data, err, c.ok)
		}
	}
}

func TestValidateSaysWhere(t *testing.T) {
	s := load(t, map[string]string{"a.json": `{"$defs": {"o": {"type": "object", "properties": {"list": {"type": "array", "items": {"type": "string"}}}}}}`}, Options{})
	err := s.Validate("a.json", "#/$defs/o", []byte(`{"list": ["a", 2]}`))
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"/list/1", "type"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

func TestValidateRejectsBadData(t *testing.T) {
	s := load(t, map[string]string{"a.json": `{"$defs": {"s": {"type": "object"}}}`}, Options{})
	for _, data := range []string{`{"a":1,"a":2}`, `{`, `1.5e400`} {
		if err := s.Validate("a.json", "#/$defs/s", []byte(data)); err == nil {
			t.Errorf("Validate(%s): no error", data)
		}
	}
}

// validateEach checks each instance against the schema at #/$defs/s of
// src: ok gives whether it should pass.
func validateEach(t *testing.T, src string, cases map[string]bool) {
	t.Helper()
	s := load(t, map[string]string{"a.json": src}, Options{})
	for data, ok := range cases {
		err := s.Validate("a.json", "#/$defs/s", []byte(data))
		if (err == nil) != ok {
			t.Errorf("Validate(%s) = %v, want ok=%v", data, err, ok)
		}
	}
}

// TestUnevaluatedOneOfFailingBranch: the names that a branch of oneOf
// evaluates count only when the branch matches.
func TestUnevaluatedOneOfFailingBranch(t *testing.T) {
	validateEach(t, `{"$defs": {"s": {"type": "object", "properties": {"k": {}},
		"oneOf": [{"properties": {"k": {"const": "a"}, "x": {}}}, {"properties": {"k": {"const": "b"}}}],
		"unevaluatedProperties": false}}}`, map[string]bool{
		`{"k":"a","x":1}`: true,
		`{"k":"b","x":1}`: false,
		`{"k":"b"}`:       true,
		`{"k":"a","y":1}`: false,
	})
}

// TestUnevaluatedRefSibling: a $ref and the keywords beside it both
// evaluate names.
func TestUnevaluatedRefSibling(t *testing.T) {
	validateEach(t, `{"$defs": {
		"d": {"oneOf": [{"properties": {"t": {"const": "p"}, "r": {}}, "required": ["r"]}, {"properties": {"t": {"const": "q"}}}]},
		"s": {"type": "object", "properties": {"id": {}}, "required": ["t"], "$ref": "#/$defs/d", "unevaluatedProperties": false}}}`, map[string]bool{
		`{"id":1,"t":"p","r":1}`: true,
		`{"id":1,"t":"q","r":1}`: false,
		`{"id":1,"t":"q","z":1}`: false,
		`{"id":1,"t":"q"}`:       true,
	})
}

// TestUnevaluatedNested: unevaluatedProperties looks at the names of its
// own place only, and additionalProperties false evaluates every name.
func TestUnevaluatedNested(t *testing.T) {
	validateEach(t, `{"$defs": {"s": {"type": "object",
		"properties": {"o": {"type": "object", "properties": {"a": {}}, "unevaluatedProperties": false}},
		"unevaluatedProperties": false}}}`, map[string]bool{
		`{"o":{"a":1}}`:       true,
		`{"o":{"b":1}}`:       false,
		`{"o":{"a":1},"b":1}`: false,
		`{"o":{"a":1,"o":1}}`: false,
		// the names the inner object evaluates are of its own place
		`{"o":{"a":1},"a":1}`: false,
	})
	validateEach(t, `{"$defs": {"s": {"type": "object", "properties": {"a": {}},
		"additionalProperties": false, "unevaluatedProperties": false}}}`, map[string]bool{
		`{"a":1}`: true,
		`{"b":1}`: false,
	})
	// an inner object closed by unevaluatedProperties evaluates every name
	// of its place for the place around it
	validateEach(t, `{"$defs": {
		"in": {"type": "object", "properties": {"a": {}}, "unevaluatedProperties": false},
		"s": {"$ref": "#/$defs/in", "unevaluatedProperties": false}}}`, map[string]bool{
		`{"a":1}`: true,
		`{"b":1}`: false,
	})
}

// TestOneOfNoneSaysEachBranch: when no branch of oneOf matches, the error
// says what each branch found.
func TestOneOfNoneSaysEachBranch(t *testing.T) {
	s := load(t, map[string]string{"a.json": `{"$defs": {"s": {"oneOf": [
		{"type": "object", "properties": {"k": {"const": "a"}}, "required": ["k"]},
		{"type": "object", "properties": {"k": {"const": "b"}, "n": {"type": "integer"}}, "required": ["k", "n"]}]}}}`}, Options{})
	err := s.Validate("a.json", "#/$defs/s", []byte(`{"k":"c"}`))
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"oneOf/0/properties/k/const", "oneOf/1/required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

// TestInteger: a number is an integer by its value, however it is written,
// and a far exponent is answered without computing the power.
func TestInteger(t *testing.T) {
	for _, c := range []struct {
		num string
		n   int64
		ok  bool
	}{
		{"1", 1, true}, {"1.0", 1, true}, {"1e0", 1, true}, {"100e-2", 1, true}, {"-0.0", 0, true},
		{"9007199254740992", 1 << 53, true}, {"9007199254740992.0", 1 << 53, true},
		{"9007199254740993", 0, false}, {"1.5", 0, false}, {"1e-1", 0, false},
		{"1e100000", 0, false}, {"1e-100000", 0, false}, {"0e99999999999999999999", 0, true}, {"5E99999999999999999999", 0, false},
		{"1.5e1", 15, true}, {"120e-1", 12, true}, {"-12e-1", 0, false}, {"0.0e5", 0, true}, {"-9007199254740992", -(1 << 53), true},
		{"0.0001e4", 1, true}, {"10000000000000000e-1", 1000000000000000, true}, {"1e16", 0, false},
		{"1" + strings.Repeat("0", 1<<20), 0, false}, {"0." + strings.Repeat("0", 1<<20) + "1e1048578", 10, true},
	} {
		n, ok := integer(c.num)
		if n != c.n || ok != c.ok {
			t.Errorf("integer(%s) = %d, %v; want %d, %v", c.num, n, ok, c.n, c.ok)
		}
	}
}
