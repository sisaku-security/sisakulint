package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The schema of SARIF 2.1.0, of OASIS Standard Errata 01, as written at
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
// (fetched 2026-10-30; sha256 below).
const (
	sarifSchemaFile   = "testdata/sarif-schema-2.1.0.json"
	sarifSchemaSHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
)

// draft4 checks a value against the schema of SARIF, a JSON Schema of
// draft 04, with the keywords the schema uses: $ref (to #/definitions/),
// type, properties, required, additionalProperties, items, enum, pattern,
// minItems, uniqueItems, minimum, maximum, anyOf and oneOf. Of the others,
// it reads none: description, default, title, id and $schema say nothing
// of a value, and format is a check draft 04 leaves to the validator.
// newDraft4 refuses a schema with any other keyword, so that the check
// never means less than the schema says.
type draft4 struct {
	root map[string]any
}

var draft4Checks = []string{"$ref", "type", "properties", "required", "additionalProperties", "items", "enum", "pattern", "minItems", "uniqueItems", "minimum", "maximum", "anyOf", "oneOf"}
var draft4Ignored = []string{"description", "default", "title", "id", "$schema", "format", "definitions"}

func newDraft4(b []byte) (*draft4, error) {
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	var walk func(s map[string]any, at string) error
	walk = func(s map[string]any, at string) error {
		for k, v := range s {
			if !slices.Contains(draft4Checks, k) && !slices.Contains(draft4Ignored, k) {
				return fmt.Errorf("%s: the keyword %s is not checked", at, k)
			}
			switch k {
			case "properties", "definitions":
				for n, sub := range v.(map[string]any) {
					if err := walk(sub.(map[string]any), at+"/"+k+"/"+n); err != nil {
						return err
					}
				}
			case "items", "additionalProperties":
				if sub, ok := v.(map[string]any); ok {
					if err := walk(sub, at+"/"+k); err != nil {
						return err
					}
				}
			case "anyOf", "oneOf":
				for i, sub := range v.([]any) {
					if err := walk(sub.(map[string]any), fmt.Sprintf("%s/%s/%d", at, k, i)); err != nil {
						return err
					}
				}
			case "pattern":
				if _, err := regexp.Compile(v.(string)); err != nil {
					return fmt.Errorf("%s: %w", at, err)
				}
			}
		}
		return nil
	}
	if err := walk(root, "#"); err != nil {
		return nil, err
	}
	return &draft4{root}, nil
}

// check gives the places in v where v does not match the schema.
func (d *draft4) check(v any) []string {
	var errs []string
	d.match(d.root, v, "", &errs)
	return errs
}

func (d *draft4) match(s map[string]any, v any, at string, errs *[]string) {
	fail := func(format string, a ...any) { *errs = append(*errs, at+": "+fmt.Sprintf(format, a...)) }
	if ref, ok := s["$ref"].(string); ok {
		name, ok := strings.CutPrefix(ref, "#/definitions/")
		target, _ := d.root["definitions"].(map[string]any)[name].(map[string]any)
		if !ok || target == nil {
			fail("the $ref %s is not of a definition", ref)
			return
		}
		d.match(target, v, at, errs)
	}
	if t, ok := s["type"]; ok {
		var types []string
		switch t := t.(type) {
		case string:
			types = []string{t}
		case []any:
			for _, x := range t {
				types = append(types, x.(string))
			}
		}
		if !slices.ContainsFunc(types, func(t string) bool { return isType(v, t) }) {
			fail("not of the type %v", types)
			return
		}
	}
	if e, ok := s["enum"].([]any); ok && !slices.ContainsFunc(e, func(x any) bool { return reflect.DeepEqual(x, v) }) {
		fail("%v is not one of %v", v, e)
	}
	switch v := v.(type) {
	case string:
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(v) {
			fail("%q does not match %s", v, p)
		}
	case float64:
		if m, ok := s["minimum"].(float64); ok && v < m {
			fail("%v is below %v", v, m)
		}
		if m, ok := s["maximum"].(float64); ok && v > m {
			fail("%v is above %v", v, m)
		}
	case []any:
		if m, ok := s["minItems"].(float64); ok && float64(len(v)) < m {
			fail("%d items, fewer than %v", len(v), m)
		}
		if u, _ := s["uniqueItems"].(bool); u {
			for i := range v {
				for j := range i {
					if reflect.DeepEqual(v[i], v[j]) {
						fail("the items %d and %d are equal", j, i)
					}
				}
			}
		}
		if items, ok := s["items"].(map[string]any); ok {
			for i, x := range v {
				d.match(items, x, fmt.Sprintf("%s/%d", at, i), errs)
			}
		}
	case map[string]any:
		required, _ := s["required"].([]any)
		for _, r := range required {
			if _, ok := v[r.(string)]; !ok {
				fail("no %s", r)
			}
		}
		props, _ := s["properties"].(map[string]any)
		for k, x := range v {
			if p, ok := props[k]; ok {
				d.match(p.(map[string]any), x, at+"/"+k, errs)
				continue
			}
			switch a := s["additionalProperties"].(type) {
			case bool:
				if !a {
					fail("the property %s is not allowed", k)
				}
			case map[string]any:
				d.match(a, x, at+"/"+k, errs)
			}
		}
	}
	if as, ok := s["anyOf"].([]any); ok {
		n := d.matching(as, v, at)
		if n == 0 {
			fail("matches none of anyOf")
		}
	}
	if ones, ok := s["oneOf"].([]any); ok {
		if n := d.matching(ones, v, at); n != 1 {
			fail("matches %d of oneOf, not one", n)
		}
	}
}

// matching is how many of the schemas ss v matches.
func (d *draft4) matching(ss []any, v any, at string) int {
	n := 0
	for _, s := range ss {
		var errs []string
		d.match(s.(map[string]any), v, at, &errs)
		if len(errs) == 0 {
			n++
		}
	}
	return n
}

func isType(v any, t string) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == float64(int64(f))
	case "null":
		return v == nil
	}
	return false
}

// sarifSchemaCheck is the check of the schema of SARIF; it fails t when
// the copy is not the one fetched.
func sarifSchemaCheck(t *testing.T) *draft4 {
	t.Helper()
	b, err := os.ReadFile(sarifSchemaFile)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != sarifSchemaSHA256 {
		t.Fatalf("%s is not the schema fetched (sha256 %x)", sarifSchemaFile, sum)
	}
	d, err := newDraft4(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// decodeSARIF is b as the values the check reads.
func decodeSARIF(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("%v:\n%s", err, b)
	}
	return v
}

func TestDraft4(t *testing.T) {
	d := sarifSchemaCheck(t)
	good := `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": [{"message": {"text": "m"}, "level": "error",
		"locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.yml"}, "region": {"startLine": 1, "startColumn": 1}}}]}]}]}`
	if errs := d.check(decodeSARIF(t, []byte(good))); len(errs) != 0 {
		t.Fatalf("a valid log: %v", errs)
	}
	for name, bad := range map[string]string{
		"no version":             `{"runs": []}`,
		"a level not of enum":    `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": [{"message": {"text": "m"}, "level": "fatal"}]}]}`,
		"a line below minimum":   `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": [{"message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a"}, "region": {"startLine": 0}}}]}]}]}`,
		"equal items":            `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x", "rules": [{"id": "a"}, {"id": "a"}]}}}]}`,
		"a property not allowed": `{"version": "2.1.0", "runs": [], "extra": 1}`,
		"a region of no anyOf":   `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": [{"message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a"}, "region": {"endLine": 2}}}]}]}]}`,
		"a message of nothing":   `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": [{"message": {}}]}]}`,
	} {
		if errs := d.check(decodeSARIF(t, []byte(bad))); len(errs) == 0 {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := newDraft4([]byte(`{"definitions": {"a": {"dependencies": {}}}}`)); err == nil {
		t.Error("a schema with a keyword not checked is no error")
	}
}
