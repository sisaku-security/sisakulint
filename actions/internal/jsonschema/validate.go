package jsonschema

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Validate checks data against the schema at pointer in file. The error
// says where in data (a JSON Pointer) and which keyword failed.
func (s *Set) Validate(file, pointer string, data []byte) error {
	sch, err := s.Lookup(file, pointer)
	if err != nil {
		return err
	}
	v, err := parse(data)
	if err != nil {
		return err
	}
	_, err = check(sch, v, "")
	return err
}

// check checks v against s. On an object it gives the names of v that s
// evaluates (see the package doc), for an unevaluatedProperties around it.
func check(s *Schema, v *value, at string) (map[string]bool, error) {
	fail := func(kw, format string, a ...any) error {
		return fmt.Errorf("%s: %s (%s%s/%s)", pointerOr(at), fmt.Sprintf(format, a...), s.File, s.Pointer, kw)
	}
	evaluated := map[string]bool{}
	add := func(names map[string]bool) {
		for n := range names {
			evaluated[n] = true
		}
	}
	if s.target != nil {
		names, err := check(s.target, v, at)
		if err != nil {
			return nil, err
		}
		add(names)
	}
	if s.Type != TypeAny && !hasType(v, s.Type) {
		return nil, fail("type", "%s is not %s", kindNames[v.kind], s.Type)
	}
	if s.Const != nil && !same(v, s.Const) {
		return nil, fail("const", "not the constant %s", s.Const)
	}
	if s.Enum != nil {
		ok := false
		for _, e := range s.Enum {
			ok = ok || same(v, e)
		}
		if !ok {
			return nil, fail("enum", "not one of the values of enum")
		}
	}
	if v.kind == kString {
		if s.re != nil && !s.re.MatchString(v.str) {
			return nil, fail("pattern", "%q does not match %s", v.str, s.Pattern)
		}
		if s.MinLength != nil && utf8.RuneCountInString(v.str) < *s.MinLength {
			return nil, fail("minLength", "shorter than %d", *s.MinLength)
		}
	}
	if v.kind == kObject {
		for _, r := range s.Required {
			if _, ok := v.get(r); !ok {
				return nil, fail("required", "no %s", r)
			}
		}
		for _, m := range v.obj {
			p, ok := s.Property(m.key)
			if !ok {
				if s.AdditionalFalse {
					return nil, fail("additionalProperties", "%s is not a property", m.key)
				}
				continue
			}
			if _, err := check(p, m.val, at+"/"+escapePointer(m.key)); err != nil {
				return nil, err
			}
			evaluated[m.key] = true
		}
	}
	if v.kind == kArray {
		if s.MinItems != nil && len(v.arr) < *s.MinItems {
			return nil, fail("minItems", "fewer items than %d", *s.MinItems)
		}
		if s.Items != nil {
			for i, e := range v.arr {
				if _, err := check(s.Items, e, at+"/"+strconv.Itoa(i)); err != nil {
					return nil, err
				}
			}
		}
		if s.UniqueItems {
			seen := map[string]int{}
			for i, e := range v.arr {
				c, err := canon(e)
				if err != nil {
					return nil, fail("uniqueItems", "cannot compare the items: %v", err)
				}
				if j, dup := seen[string(c)]; dup {
					return nil, fail("uniqueItems", "the items %d and %d are equal", j, i)
				}
				seen[string(c)] = i
			}
		}
	}
	if s.OneOf != nil {
		var matched []map[string]bool
		var errs []string
		for _, o := range s.OneOf {
			names, err := check(o, v, at)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			matched = append(matched, names)
		}
		switch len(matched) {
		case 1:
			add(matched[0])
		case 0:
			return nil, fail("oneOf", "none of the schemas of oneOf match: %s", strings.Join(errs, "; "))
		default:
			return nil, fail("oneOf", "%d of the schemas of oneOf match, not 1", len(matched))
		}
	}
	if v.kind == kObject {
		if s.UnevaluatedFalse {
			for _, m := range v.obj {
				if !evaluated[m.key] {
					return nil, fail("unevaluatedProperties", "%s is not a property that the schema evaluates", m.key)
				}
			}
		}
		if s.AdditionalFalse || s.UnevaluatedFalse {
			for _, m := range v.obj {
				evaluated[m.key] = true
			}
		}
	}
	return evaluated, nil
}

func hasType(v *value, t Type) bool {
	switch t {
	case TypeInteger:
		_, ok := integer(v.num)
		return v.kind == kNumber && ok
	case TypeObject:
		return v.kind == kObject
	case TypeArray:
		return v.kind == kArray
	case TypeString:
		return v.kind == kString
	case TypeBoolean:
		return v.kind == kBool
	case TypeNull:
		return v.kind == kNull
	}
	return false
}

// same is whether v is the value whose canonical form is c. A value
// without a canonical form (a number that is not an integer) is never the
// same as one with.
func same(v *value, c []byte) bool {
	b, err := canon(v)
	return err == nil && bytes.Equal(b, c)
}
