// Package jsonschema reads and checks against a subset of JSON Schema
// draft 2020-12: the one the schemas of the contract layer are written in.
// The generator of the fact kinds reads the schemas with it, and tests
// check the JSON the packages write against them.
//
// The keywords are $schema (the root only, draft 2020-12), $defs, $ref,
// oneOf, const, type, enum, pattern, minLength, properties, required,
// additionalProperties (false only), items, minItems, uniqueItems (true
// only), unevaluatedProperties (false only) and description, with the
// annotations whose names start with x-. Load rejects any other keyword,
// so that a schema never means more than this package checks. The only
// numbers are integers of at most 2^53 (type integer; no number), so that
// Canonical can write them exactly. A number is an integer by its value:
// 1.0 and 1e0 are the integer 1.
//
// unevaluatedProperties false rejects a member of an object that no
// keyword at the same place of the instance evaluated. Here the names a
// schema evaluates are those of its properties that the object has, every
// name when it has additionalProperties false or unevaluatedProperties
// false, those its $ref evaluates, and those of the one branch of its
// oneOf that matches: a branch that does not match evaluates nothing.
// uniqueItems compares the items as Canonical writes them, and an array
// with an item Canonical cannot write fails it.
//
// A pattern is a Go regexp, not an ECMA-262 one. The two agree on the
// patterns the schemas use (classes, anchors, repetition).
package jsonschema

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const draft = "https://json-schema.org/draft/2020-12/schema"

// Options says how to read annotations.
type Options struct {
	// SchemaAnnotations are the x- annotations whose values are schemas
	// (such as x-value). They are read and checked like any other schema,
	// and reached by Lookup through their names.
	SchemaAnnotations []string
}

// Named is a member of $defs or properties.
type Named struct {
	Name   string
	Schema *Schema
}

// Schema is one schema of a file.
type Schema struct {
	File    string // the name given to Load
	Pointer string // where it is in the file, as a JSON Pointer fragment (#/...)

	Ref             string
	Type            Type
	Const           json.RawMessage   // canonical; nil when absent
	Enum            []json.RawMessage // nil when absent; empty for enum: []
	Pattern         string
	MinLength       *int
	Properties      []Named // in the order written
	Required        []string
	AdditionalFalse bool // additionalProperties: false
	Items           *Schema
	MinItems        *int
	UniqueItems     bool // uniqueItems: true
	OneOf           []*Schema
	// UnevaluatedFalse is unevaluatedProperties: false.
	UnevaluatedFalse bool
	Defs             []Named // in the order written
	Description      string

	Annotations       map[string]json.RawMessage // x- annotations that are not schemas, as written
	SchemaAnnotations map[string]*Schema

	target *Schema // what Ref points to
	re     *regexp.Regexp
}

// Target is what the $ref of s points to, or nil when s has no $ref.
func (s *Schema) Target() *Schema { return s.target }

// Resolve follows $ref until a schema without one.
func (s *Schema) Resolve() *Schema {
	for s.target != nil {
		s = s.target
	}
	return s
}

// ShapesObject is whether s has a keyword that changes which members an
// object has by its values: unevaluatedProperties false, or a oneOf with a
// branch that is not a const (a branch of an object). A generator that
// makes a Go type of the properties of s cannot write that in the type.
// minItems and uniqueItems change no type, and are not among these.
func (s *Schema) ShapesObject() bool {
	if s.UnevaluatedFalse {
		return true
	}
	for _, o := range s.OneOf {
		if o.Const == nil {
			return true
		}
	}
	return false
}

// Property returns the schema of the property name.
func (s *Schema) Property(name string) (*Schema, bool) {
	for _, p := range s.Properties {
		if p.Name == name {
			return p.Schema, true
		}
	}
	return nil, false
}

// Set is the schemas of some files, whose $ref may point into each other.
type Set struct {
	roots map[string]*Schema
	opt   Options
}

// Load reads files, a map from a name (such as facts-v0.json) to its
// content. A $ref is #/... inside the same file or name#/... into another
// file of the map.
func Load(files map[string][]byte, opt Options) (*Set, error) {
	s := &Set{roots: map[string]*Schema{}, opt: opt}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	var all []*Schema
	for _, n := range names {
		v, err := parse(files[n])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		root, err := s.read(v, n, "#", true, &all)
		if err != nil {
			return nil, err
		}
		s.roots[n] = root
	}
	for _, sch := range all {
		if sch.Ref == "" {
			continue
		}
		file, ptr, _ := strings.Cut(sch.Ref, "#")
		if file == "" {
			file = sch.File
		}
		t, err := s.Lookup(file, "#"+ptr)
		if err != nil {
			return nil, fmt.Errorf("%s%s: $ref %q: %w", sch.File, sch.Pointer, sch.Ref, err)
		}
		sch.target = t
	}
	// A cycle of $ref and oneOf checks the same place of an instance
	// again and again: Validate would not end.
	state := map[*Schema]int{} // 1: on the way, 2: done
	var visit func(sch *Schema) error
	visit = func(sch *Schema) error {
		switch state[sch] {
		case 1:
			return fmt.Errorf("%s%s: a cycle of $ref and oneOf at one place of the instance", sch.File, sch.Pointer)
		case 2:
			return nil
		}
		state[sch] = 1
		next := slices.Clone(sch.OneOf)
		if sch.target != nil {
			next = append(next, sch.target)
		}
		for _, n := range next {
			if err := visit(n); err != nil {
				return err
			}
		}
		state[sch] = 2
		return nil
	}
	for _, sch := range all {
		if err := visit(sch); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Root is the schema of the whole file, or nil.
func (s *Set) Root(file string) *Schema { return s.roots[file] }

// Lookup finds the schema at pointer (#/... ) in file. The steps are
// $defs/name, properties/name, items, oneOf/index and the names of the
// schema annotations.
func (s *Set) Lookup(file, pointer string) (*Schema, error) {
	sch, ok := s.roots[file]
	if !ok {
		return nil, fmt.Errorf("no schema file %s", file)
	}
	rest, ok := strings.CutPrefix(pointer, "#")
	if !ok {
		return nil, fmt.Errorf("%s is not a fragment", pointer)
	}
	if rest == "" {
		return sch, nil
	}
	if !strings.HasPrefix(rest, "/") {
		return nil, fmt.Errorf("%s is not a JSON Pointer", pointer)
	}
	steps := strings.Split(rest[1:], "/")
	for i := 0; i < len(steps); i++ {
		step := unescapePointer(steps[i])
		next := func() (string, error) {
			i++
			if i >= len(steps) {
				return "", fmt.Errorf("%s: %s wants a name after it", pointer, step)
			}
			return unescapePointer(steps[i]), nil
		}
		var found *Schema
		switch step {
		case "$defs", "properties":
			name, err := next()
			if err != nil {
				return nil, err
			}
			list := sch.Defs
			if step == "properties" {
				list = sch.Properties
			}
			for _, d := range list {
				if d.Name == name {
					found = d.Schema
				}
			}
			if found == nil {
				return nil, fmt.Errorf("%s: no %s %s", pointer, step, name)
			}
		case "items":
			found = sch.Items
		case "oneOf":
			idx, err := next()
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(idx)
			if err != nil || n < 0 || n >= len(sch.OneOf) {
				return nil, fmt.Errorf("%s: no oneOf %s", pointer, idx)
			}
			found = sch.OneOf[n]
		default:
			found = sch.SchemaAnnotations[step]
		}
		if found == nil {
			return nil, fmt.Errorf("%s: no %s", pointer, step)
		}
		sch = found
	}
	return sch, nil
}

// Type is the type keyword of a schema, of the types this subset takes (no
// number, no list of types).
type Type uint8

const (
	TypeAny Type = iota // no type keyword
	TypeObject
	TypeArray
	TypeString
	TypeBoolean
	TypeInteger
	TypeNull
)

var typeNames = [...]string{"", "object", "array", "string", "boolean", "integer", "null"}

// String is the type as a schema writes it; empty for TypeAny.
func (t Type) String() string { return typeNames[t] }

// typeNamed is the type a schema writes as s.
func typeNamed(s string) (Type, bool) {
	for t, n := range typeNames {
		if t != int(TypeAny) && n == s {
			return Type(t), true
		}
	}
	return TypeAny, false
}

func (s *Set) read(v *value, file, at string, root bool, all *[]*Schema) (*Schema, error) {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%s%s: %s", file, at, fmt.Sprintf(format, a...))
	}
	if v.kind != kObject {
		return nil, fail("a schema must be an object, not %s", kindNames[v.kind])
	}
	sch := &Schema{File: file, Pointer: at}
	*all = append(*all, sch)
	sub := func(e *value, step string) (*Schema, error) {
		return s.read(e, file, at+"/"+step, false, all)
	}
	named := func(e *value, kw string) ([]Named, error) {
		if e.kind != kObject {
			return nil, fail("%s must be an object", kw)
		}
		var out []Named
		for _, m := range e.obj {
			c, err := sub(m.val, kw+"/"+escapePointer(m.key))
			if err != nil {
				return nil, err
			}
			out = append(out, Named{m.key, c})
		}
		return out, nil
	}
	for _, m := range v.obj {
		kw, e := m.key, m.val
		var err error
		switch kw {
		case "$schema":
			if !root || e.kind != kString || e.str != draft {
				return nil, fail("$schema must be %s, and only at the root", draft)
			}
		case "$defs":
			sch.Defs, err = named(e, kw)
		case "properties":
			sch.Properties, err = named(e, kw)
		case "$ref":
			if e.kind != kString || e.str == "" {
				return nil, fail("$ref must be a string")
			}
			sch.Ref = e.str
		case "type":
			if e.kind != kString {
				return nil, fail("type must be one string")
			}
			if e.str == "number" {
				return nil, fail("type number is not accepted; use integer")
			}
			t, ok := typeNamed(e.str)
			if !ok {
				return nil, fail("unknown type %q", e.str)
			}
			sch.Type = t
		case "const":
			sch.Const, err = canon(e)
		case "enum":
			if e.kind != kArray {
				return nil, fail("enum must be an array")
			}
			sch.Enum = []json.RawMessage{} // enum: [] takes no value
			for _, x := range e.arr {
				c, cerr := canon(x)
				if cerr != nil {
					return nil, fail("enum: %v", cerr)
				}
				sch.Enum = append(sch.Enum, c)
			}
		case "pattern":
			if e.kind != kString {
				return nil, fail("pattern must be a string")
			}
			sch.re, err = regexp.Compile(e.str)
			if err != nil {
				return nil, fail("pattern: %v", err)
			}
			sch.Pattern = e.str
		case "minLength", "minItems":
			n, ok := integer(e.num)
			if e.kind != kNumber || !ok || n < 0 {
				return nil, fail("%s must be a non-negative integer", kw)
			}
			k := int(n)
			if kw == "minLength" {
				sch.MinLength = &k
			} else {
				sch.MinItems = &k
			}
		case "uniqueItems":
			if e.kind != kBool || !e.b {
				return nil, fail("uniqueItems must be true")
			}
			sch.UniqueItems = true
		case "unevaluatedProperties":
			if e.kind != kBool || e.b {
				return nil, fail("unevaluatedProperties must be false")
			}
			sch.UnevaluatedFalse = true
		case "required":
			if e.kind != kArray {
				return nil, fail("required must be an array of strings")
			}
			for _, x := range e.arr {
				if x.kind != kString {
					return nil, fail("required must be an array of strings")
				}
				sch.Required = append(sch.Required, x.str)
			}
		case "additionalProperties":
			if e.kind != kBool || e.b {
				return nil, fail("additionalProperties must be false")
			}
			sch.AdditionalFalse = true
		case "items":
			sch.Items, err = sub(e, kw)
		case "oneOf":
			if e.kind != kArray || len(e.arr) == 0 {
				return nil, fail("oneOf must be a non-empty array")
			}
			for i, x := range e.arr {
				c, cerr := sub(x, kw+"/"+strconv.Itoa(i))
				if cerr != nil {
					return nil, cerr
				}
				sch.OneOf = append(sch.OneOf, c)
			}
		case "description":
			if e.kind != kString {
				return nil, fail("description must be a string")
			}
			sch.Description = e.str
		default:
			if !strings.HasPrefix(kw, "x-") {
				return nil, fail("keyword %s is not in the subset this package reads", kw)
			}
			if slices.Contains(s.opt.SchemaAnnotations, kw) {
				c, cerr := sub(e, escapePointer(kw))
				if cerr != nil {
					return nil, cerr
				}
				if sch.SchemaAnnotations == nil {
					sch.SchemaAnnotations = map[string]*Schema{}
				}
				sch.SchemaAnnotations[kw] = c
				continue
			}
			raw, cerr := canon(e)
			if cerr != nil {
				return nil, fail("%s: %v", kw, cerr)
			}
			if sch.Annotations == nil {
				sch.Annotations = map[string]json.RawMessage{}
			}
			sch.Annotations[kw] = raw
		}
		if err != nil {
			return nil, fail("%v", err)
		}
	}
	return sch, nil
}
